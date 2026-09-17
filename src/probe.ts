/**
 * Nível B — sondagem de inicialização por `simulateTransaction` NÃO ASSINADA.
 *
 * Por que este módulo existe, em uma medição: no top 25 de mainnet por invocações,
 * **23 dos 66 achados** eram `initialization-front-running` sobre inicializadores de um
 * tiro que JÁ dispararam (`docs/PRECISION-TOP25.md`). O documento afirmava no presente
 * ("qualquer endereço pode inicializar primeiro") uma janela que fechou meses atrás.
 * Uma chamada de RPC read-only fecha as 23 sem ler uma linha de fonte — é o predicado de
 * maior retorno medido até aqui, e é o que este arquivo faz.
 *
 * **O que este módulo NUNCA faz:** assinar, submeter, gastar fee, tocar em chave real.
 * A transação é construída sobre um keypair descartável gerado na hora (simulação não
 * exige conta financiada nem assinatura) e entregue direto ao `simulateTransaction`.
 * Não existe caminho de código daqui até `sendTransaction`.
 *
 * **As quatro classificações, e por que três delas NÃO fecham o achado:**
 *
 *  1. `guarded` — reverteu com `Error(Contract, #n)` e `n` casa, via enum de erro do spec,
 *     com um caso de nome "já inicializado". É a única reversão que prova a guarda.
 *  2. `inconclusive: reverted-other` — reverteu com outro erro. Os argumentos são
 *     PLACEHOLDERS: uma validação de parâmetro pode ter abortado ANTES da guarda, então
 *     esta reversão não diz nada sobre a guarda. Tratar como `guarded` seria inventar.
 *  3. `open` — a simulação **teve sucesso**: com argumentos arbitrários, de uma conta
 *     qualquer, o inicializador roda AGORA. É o único caso que torna o achado real, e por
 *     isso ele sobe de severidade e sai com destaque no documento.
 *  4. `inconclusive: error` / `unsupported-arg-type` — falha de rede, timeout, ou um tipo
 *     do spec que não sabemos construir. Lacuna declarada, nunca silêncio.
 *
 * A URL do RPC fica nesta função e nas chamadas de rede: nada dela entra em `ProbeResult`,
 * que vai para dentro dos dois documentos. Toda mensagem de erro passa por `redactUrl`.
 */

import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  Networks,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";
import { endpointDe, redactUrl } from "./spec.ts";
import type { ErrEnum } from "./model.ts";
import type { Finding } from "./detect.ts";

export type ProbeKind = "guarded" | "open" | "inconclusive";

/** Motivo estruturado — o `detail` humano é derivado dele, mas o código é estável. */
export type ProbeReason =
  | "already-initialized"
  | "simulation-succeeded"
  | "reverted-other"
  | "unsupported-arg-type"
  | "error";

export type ProbeResult = {
  kind: ProbeKind;
  /** motivo legível, já redigido (sem URL) */
  detail: string;
  /** a sondagem é observação on-chain: sempre nível B */
  tier: "B";
  reason: ProbeReason;
  entrypoint: string;
  /** ledger em que o nó simulou — é o que prende a afirmação a um instante */
  ledger?: number;
};

const M = {
  jaInicializado: (code: number, enumName: string, caseName: string) =>
    `simulation reverted with Error(Contract, #${code}) = \`${enumName}::${caseName}\`, an already-initialized guard: the one-shot initializer has already fired on this instance`,
  revertidoOutro: (erro: string) =>
    `simulation reverted, but not with an already-initialized error (${erro}) — the placeholder arguments may have failed validation before reaching the guard, so this neither confirms nor denies the guard`,
  revertidoSemCodigo: (erro: string) =>
    `simulation reverted with a host error carrying no contract error code (${erro}) — inconclusive about the guard`,
  sucesso: (fn: string) =>
    `the simulation of \`${fn}\` SUCCEEDED with placeholder arguments from a throwaway account: the initializer can be executed right now by any address`,
  tipoNaoSuportado: (tipo: string, param: string) =>
    `argument \`${param}\` has spec type \`${tipo}\`, which this prober cannot build a placeholder for; no simulation was attempted`,
  erroRpc: (e: string) => `probe did not complete: ${e}`,
  timeout: (s: number) => `probe timed out after ${s} s`,
  semPrazo: "probe skipped: the run's global timeout was already spent",
};

/**
 * Nome do caso de erro que significa "já inicializado". É reconhecimento de NOME, e o nome
 * vem do enum de erro do próprio contrato (spec), não de um chute nosso sobre o código
 * numérico: `#1` é `AlreadyInitialized` num contrato e `InvalidAmount` em outro.
 */
export const JA_INICIALIZADO_RE = /already.?init|initialized|AlreadyExists|Initialized/i;

/** `Error(Contract, #12)` — a forma que o RPC devolve no campo `error` da simulação. */
const CONTRACT_ERR_RE = /Error\(Contract,\s*#(\d+)\)/;

/** G-address válido e determinístico, para quando o alvo não serve de placeholder. */
export const ENDERECO_PLACEHOLDER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)).publicKey();

/* ------------------------------------------------------------------ *
 * Adaptadores de forma XDR — mesma razão de `spec.ts`: `decodeStream(…, "raw")`
 * devolve objetos planos, a API de união devolve métodos. Lemos as duas.
 * ------------------------------------------------------------------ */
const call = (o: any, k: string): any => (typeof o?.[k] === "function" ? o[k]() : o?.[k]);
const kindOf = (e: any): string => {
  const k = typeof e?.switch === "function" ? e.switch() : (e?.type ?? e?.kind);
  return typeof k === "string" ? k : (k?.name ?? String(k));
};
const sym = (v: any): string => {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v)) return v.toString();
  if (v.bytes) return Buffer.from(v.bytes).toString();
  if (typeof v.name === "string") return v.name;
  return String(v);
};
const tipoNome = (t: any): string => {
  const raw = typeof t?.switch === "function" ? t.switch().name : (t?.type ?? t?._switch?.name ?? t);
  return String(raw);
};

/** Erro interno do construtor de argumentos — carrega o tipo que fez desistir. */
class TipoNaoSuportado extends Error {
  tipo: string;
  constructor(tipo: string) {
    super(tipo);
    this.tipo = tipo;
  }
}

/** Índice `nome do UDT → entrada do spec`, para resolver `scSpecTypeUdt` recursivamente. */
function indiceDeUdts(entries: unknown[]): Map<string, any> {
  const m = new Map<string, any>();
  for (const e of entries as any[]) {
    const kind = kindOf(e);
    const arm =
      kind === "scSpecEntryUdtStructV0" ? "udtStructV0"
      : kind === "scSpecEntryUdtUnionV0" ? "udtUnionV0"
      : kind === "scSpecEntryUdtEnumV0" ? "udtEnumV0"
      : kind === "scSpecEntryUdtErrorEnumV0" ? "udtErrorEnumV0"
      : undefined;
    if (!arm) continue;
    const body = call(e, arm);
    m.set(sym(call(body, "name")), { kind, body });
  }
  return m;
}

/**
 * Placeholder para um `ScSpecTypeDef`. Os defaults são deliberadamente inertes — 0, false,
 * "x", vetor vazio — porque o objetivo não é passar na validação do contrato, é chegar até
 * a guarda de "já inicializado". Quando os argumentos falham antes dela, a classificação
 * devolvida é `inconclusive`, nunca `guarded`.
 */
function valorPara(t: any, udts: Map<string, any>, contractId: string, profundidade = 0): xdr.ScVal {
  if (profundidade > 8) throw new TipoNaoSuportado("recursion-depth");
  const nome = tipoNome(t);
  switch (nome) {
    case "scSpecTypeVal":
    case "scSpecTypeVoid":
      return xdr.ScVal.scvVoid();
    case "scSpecTypeBool":
      return xdr.ScVal.scvBool(false);
    case "scSpecTypeU32":
      return xdr.ScVal.scvU32(0);
    case "scSpecTypeI32":
      return xdr.ScVal.scvI32(0);
    case "scSpecTypeU64":
      return nativeToScVal(0n, { type: "u64" });
    case "scSpecTypeI64":
      return nativeToScVal(0n, { type: "i64" });
    case "scSpecTypeTimepoint":
      return nativeToScVal(0n, { type: "timepoint" });
    case "scSpecTypeDuration":
      return nativeToScVal(0n, { type: "duration" });
    case "scSpecTypeU128":
      return nativeToScVal(0n, { type: "u128" });
    case "scSpecTypeI128":
      return nativeToScVal(0n, { type: "i128" });
    case "scSpecTypeU256":
      return nativeToScVal(0n, { type: "u256" });
    case "scSpecTypeI256":
      return nativeToScVal(0n, { type: "i256" });
    case "scSpecTypeBytes":
      return xdr.ScVal.scvBytes(Buffer.alloc(0));
    case "scSpecTypeString":
      return xdr.ScVal.scvString("x");
    case "scSpecTypeSymbol":
      return xdr.ScVal.scvSymbol("x");
    case "scSpecTypeAddress":
    case "scSpecTypeMuxedAddress": {
      // O endereço do próprio contrato é o placeholder mais inofensivo que existe: ele já
      // é, por definição, um endereço válido naquela rede. Se o alvo não for um contract id
      // (alvo local), cai num G-address fixo e válido.
      const a = StrKey.isValidContract(contractId) ? contractId : ENDERECO_PLACEHOLDER;
      return new Address(a).toScVal();
    }
    case "scSpecTypeOption":
      // `None` é o placeholder honesto de um opcional: não inventa valor.
      return xdr.ScVal.scvVoid();
    case "scSpecTypeVec":
      return xdr.ScVal.scvVec([]);
    case "scSpecTypeMap":
      return xdr.ScVal.scvMap([]);
    case "scSpecTypeBytesN": {
      const n = Number(call(call(t, "bytesN"), "n") ?? 32);
      return xdr.ScVal.scvBytes(Buffer.alloc(Number.isFinite(n) && n >= 0 ? n : 32));
    }
    case "scSpecTypeTuple": {
      const ts = call(call(t, "tuple"), "valueTypes") ?? [];
      return xdr.ScVal.scvVec(ts.map((x: any) => valorPara(x, udts, contractId, profundidade + 1)));
    }
    case "scSpecTypeUdt": {
      const alvo = sym(call(call(t, "udt"), "name"));
      const u = udts.get(alvo);
      if (!u) throw new TipoNaoSuportado(`udt:${alvo || "?"}`);
      return valorParaUdt(u, udts, contractId, profundidade + 1);
    }
    // `Result` e `Error` não têm forma de argumento de entrada que faça sentido sondar.
    default:
      throw new TipoNaoSuportado(nome.replace(/^scSpecType/, "").toLowerCase() || "unknown");
  }
}

function valorParaUdt(u: { kind: string; body: any }, udts: Map<string, any>, contractId: string, prof: number): xdr.ScVal {
  if (u.kind === "scSpecEntryUdtEnumV0" || u.kind === "scSpecEntryUdtErrorEnumV0") {
    const cases = call(u.body, "cases") ?? [];
    const v = cases.length ? Number(call(cases[0], "value")) : 0;
    return xdr.ScVal.scvU32(Number.isFinite(v) ? v : 0);
  }
  if (u.kind === "scSpecEntryUdtUnionV0") {
    const cases = call(u.body, "cases") ?? [];
    if (!cases.length) throw new TipoNaoSuportado(`union:${sym(call(u.body, "name"))}`);
    const c = cases[0];
    const ck = kindOf(c);
    if (ck === "scSpecUdtUnionCaseVoidV0" || ck === "scSpecUdtUnionCaseV0Void") {
      return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(sym(call(call(c, "voidCase"), "name")))]);
    }
    const tup = call(c, "tupleCase");
    const nome = sym(call(tup, "name"));
    const ts = call(tup, "type") ?? [];
    return xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol(nome),
      ...ts.map((x: any) => valorPara(x, udts, contractId, prof + 1)),
    ]);
  }
  // struct: campos nomeados viram mapa com chaves símbolo (ordenadas); campos "0","1",…
  // são tuple-struct e viram vetor — é assim que o host representa cada um.
  const fields = call(u.body, "fields") ?? [];
  const nomes = fields.map((f: any) => sym(call(f, "name")));
  const tuple = nomes.length > 0 && nomes.every((n: string) => /^\d+$/.test(n));
  if (tuple) {
    return xdr.ScVal.scvVec(fields.map((f: any) => valorPara(call(f, "type"), udts, contractId, prof + 1)));
  }
  const entradas = fields
    .map((f: any) => ({ k: sym(call(f, "name")), t: call(f, "type") }))
    .sort((a: any, b: any) => (a.k < b.k ? -1 : a.k > b.k ? 1 : 0))
    .map(
      (f: any) =>
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol(f.k),
          val: valorPara(f.t, udts, contractId, prof + 1),
        }),
    );
  return xdr.ScVal.scvMap(entradas);
}

export type ArgsConstruidos =
  | { ok: true; args: xdr.ScVal[] }
  | { ok: false; tipo: string; param: string };

/**
 * Argumentos placeholder de um entrypoint, derivados do contract spec do WASM.
 *
 * Exportada porque é o pedaço testável sem rede: dado um spec, ou ela constrói a lista
 * inteira ou ela desiste NOMEANDO o tipo que não soube construir — nunca "quase constrói".
 */
export function buildArgs(entries: unknown[], fnName: string, contractId: string): ArgsConstruidos {
  const udts = indiceDeUdts(entries);
  const fn = (entries as any[]).find(
    (e) => kindOf(e) === "scSpecEntryFunctionV0" && sym(call(call(e, "functionV0"), "name")) === fnName,
  );
  if (!fn) return { ok: false, tipo: "unknown-function", param: fnName };
  const inputs = call(call(fn, "functionV0"), "inputs") ?? [];
  const args: xdr.ScVal[] = [];
  for (const i of inputs) {
    const param = sym(call(i, "name"));
    try {
      args.push(valorPara(call(i, "type"), udts, contractId));
    } catch (e) {
      const tipo = e instanceof TipoNaoSuportado ? e.tipo : String((e as Error)?.message ?? e);
      return { ok: false, tipo, param };
    }
  }
  return { ok: true, args };
}

/* ------------------------------------------------------------------ *
 * A ida à rede — injetável, para que o teste nunca abra socket.
 * ------------------------------------------------------------------ */

export type SimOutcome = {
  /** a simulação completou sem erro de execução do contrato */
  ok: boolean;
  /** string de erro devolvida pelo nó quando `ok === false` */
  error?: string;
  latestLedger?: number;
};

export type Simulate = (input: { contractId: string; fn: string; args: xdr.ScVal[] }) => Promise<SimOutcome>;

/** Passphrase da rede a partir do RÓTULO (nunca da URL — a URL pode ser credencial). */
export function passphraseDe(rede: string): string {
  if (rede === "testnet") return Networks.TESTNET;
  if (rede === "futurenet") return Networks.FUTURENET;
  return Networks.PUBLIC;
}

/**
 * `Simulate` real. Monta a transação sobre um keypair DESCARTÁVEL e a entrega ao
 * `simulateTransaction`. Nenhuma assinatura, nenhuma submissão, nenhuma conta financiada:
 * a simulação não exige nada disso, e é por isso que a sondagem é read-only de verdade.
 */
export function simulateViaRpc(endpoint: string, rede: string): Simulate {
  const server = new rpc.Server(endpointDe(endpoint));
  const networkPassphrase = passphraseDe(rede);
  return async ({ contractId, fn, args }) => {
    const origem = Keypair.random().publicKey();
    const tx = new TransactionBuilder(new Account(origem, "0"), { fee: BASE_FEE, networkPassphrase })
      .addOperation(new Contract(contractId).call(fn, ...args))
      .setTimeout(30)
      .build();
    const sim = await server.simulateTransaction(tx);
    const latestLedger = (sim as { latestLedger?: number }).latestLedger;
    if (rpc.Api.isSimulationError(sim)) return { ok: false, error: String(sim.error), latestLedger };
    return { ok: true, latestLedger };
  };
}

/** Recorta a mensagem de erro do nó para uma linha de documento, já redigida. */
// Corta o dump de diagnóstico do host (que carrega tópicos entre colchetes: o validador
// leria `[error, …]` como tópico de baseline) e troca colchetes por parênteses.
const curto = (s: string, n = 220): string => {
  const semLog = redactUrl(String(s)).split(/Event log/i)[0];
  const limpo = semLog.replace(/\s+/g, " ").replace(/\[/g, "(").replace(/\]/g, ")").trim();
  return limpo.length > n ? `${limpo.slice(0, n - 1)}…` : limpo;
};

/** Caso de erro do spec que corresponde ao código devolvido pelo contrato. */
export function casoDeErro(errors: ErrEnum[], code: number): { enumName: string; caseName: string } | undefined {
  for (const en of errors) {
    const c = en.cases.find((x) => x.value === code);
    if (c) return { enumName: en.name, caseName: c.name };
  }
  return undefined;
}

/** Classifica o resultado bruto da simulação. Separada para ser testável sem rede. */
export function classificar(fn: string, out: SimOutcome, errors: ErrEnum[]): Omit<ProbeResult, "entrypoint"> {
  if (out.ok) {
    return { kind: "open", reason: "simulation-succeeded", detail: M.sucesso(fn), tier: "B", ledger: out.latestLedger };
  }
  const erro = String(out.error ?? "");
  const m = CONTRACT_ERR_RE.exec(erro);
  if (!m) {
    return {
      kind: "inconclusive", reason: "reverted-other",
      detail: M.revertidoSemCodigo(curto(erro)), tier: "B", ledger: out.latestLedger,
    };
  }
  const code = Number(m[1]);
  const caso = casoDeErro(errors, code);
  if (caso && JA_INICIALIZADO_RE.test(caso.caseName)) {
    return {
      kind: "guarded", reason: "already-initialized",
      detail: M.jaInicializado(code, caso.enumName, caso.caseName), tier: "B", ledger: out.latestLedger,
    };
  }
  const rotulo = caso ? `Error(Contract, #${code}) = \`${caso.enumName}::${caso.caseName}\`` : `Error(Contract, #${code})`;
  return {
    kind: "inconclusive", reason: "reverted-other",
    detail: M.revertidoOutro(rotulo), tier: "B", ledger: out.latestLedger,
  };
}

/** Prazo por sondagem: uma simulação pendurada não pode comer o `--timeout` inteiro. */
export const PROBE_TIMEOUT_MS = 20_000;
/** Simultaneidade: o RPC público devolve 429 sob rajada. */
export const PROBE_CONCURRENCY = 4;

function comPrazo<T>(p: Promise<T>, ms: number, aoEstourar: () => T): Promise<T> {
  let timer: NodeJS.Timeout;
  const prazo = new Promise<T>((res) => {
    timer = setTimeout(() => res(aoEstourar()), ms);
    timer.unref?.();
  });
  void p.catch(() => {});
  return Promise.race([p, prazo]).finally(() => clearTimeout(timer!));
}

export type ProbeOptions = {
  contractId: string;
  /** achados já numerados; só os de `family === "init"` são sondados */
  findings: Finding[];
  /** entradas XDR cruas do contract spec — é delas que saem os argumentos */
  specEntries: unknown[];
  errors: ErrEnum[];
  /** injetável; sem ela, `endpoint` + `rede` montam a sonda real */
  simulate?: Simulate;
  endpoint?: string;
  /** RÓTULO da rede (mainnet/testnet/…), nunca a URL */
  rede?: string;
  concurrency?: number;
  timeoutMs?: number;
  /** instante limite absoluto (epoch ms) herdado do `--timeout` da execução */
  deadline?: number;
  onProgress?: (msg: string) => void;
};

/** Achados que esta sonda sabe tratar: família `init` com entrypoint de verdade. */
export const sondaveis = (findings: Finding[]): Finding[] =>
  findings.filter((f) => f.family === "init" && f.entrypoint && !f.entrypoint.startsWith("<"));

/**
 * Sonda cada achado de init e devolve o resultado por id de achado.
 *
 * Nunca lança: uma sondagem que falha vira `inconclusive`, porque "não consegui sondar" é
 * uma afirmação legítima e "não sondei" apresentado como "está guardado" não é.
 */
export async function probeInitFindings(opts: ProbeOptions): Promise<Map<string, ProbeResult>> {
  const alvos = sondaveis(opts.findings);
  const out = new Map<string, ProbeResult>();
  if (!alvos.length) return out;

  const simulate = opts.simulate ?? simulateViaRpc(opts.endpoint ?? "mainnet", opts.rede ?? "mainnet");
  const porSonda = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const limite = Math.max(1, opts.concurrency ?? PROBE_CONCURRENCY);

  const fila = [...alvos];
  const trabalhar = async (): Promise<void> => {
    for (;;) {
      const f = fila.shift();
      if (!f) return;
      const id = f.id ?? `${f.stride}.?`;
      const restante = opts.deadline ? opts.deadline - Date.now() : Number.POSITIVE_INFINITY;
      if (restante <= 0) {
        out.set(id, { kind: "inconclusive", reason: "error", detail: M.semPrazo, tier: "B", entrypoint: f.entrypoint });
        continue;
      }
      const construidos = buildArgs(opts.specEntries, f.entrypoint, opts.contractId);
      if (!construidos.ok) {
        out.set(id, {
          kind: "inconclusive", reason: "unsupported-arg-type",
          detail: M.tipoNaoSuportado(construidos.tipo, construidos.param), tier: "B", entrypoint: f.entrypoint,
        });
        continue;
      }
      const ms = Math.min(porSonda, restante);
      const r = await comPrazo(
        simulate({ contractId: opts.contractId, fn: f.entrypoint, args: construidos.args })
          .then((o) => classificar(f.entrypoint, o, opts.errors))
          .catch((e): Omit<ProbeResult, "entrypoint"> => ({
            kind: "inconclusive", reason: "error",
            detail: M.erroRpc(curto(String((e as Error)?.message ?? e))), tier: "B",
          })),
        ms,
        (): Omit<ProbeResult, "entrypoint"> => ({
          kind: "inconclusive", reason: "error", detail: M.timeout(Math.round(ms / 1000)), tier: "B",
        }),
      );
      out.set(id, { ...r, entrypoint: f.entrypoint });
    }
  };

  await Promise.all(Array.from({ length: Math.min(limite, alvos.length) }, trabalhar));
  return out;
}

/** Contagem por classificação — é o que o CLI e o MCP imprimem. */
export function resumoDeProbes(probes: Iterable<ProbeResult>): { guarded: number; open: number; inconclusive: number; total: number } {
  let guarded = 0, open = 0, inconclusive = 0, total = 0;
  for (const p of probes) {
    total++;
    if (p.kind === "guarded") guarded++;
    else if (p.kind === "open") open++;
    else inconclusive++;
  }
  return { guarded, open, inconclusive, total };
}
