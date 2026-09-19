import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import { createHash } from "node:crypto";
import { analyzeModule } from "./analyze.ts";
import { detectFull, lacunas } from "./detect.ts";
import { fetchWasm, modelFromEntries, parseSpecEntries, endpointDe, redactUrl, rotuloDaRede } from "./spec.ts";
import { inferStorageKeys } from "./storagekeys.ts";
import { buildDfd } from "./render/dfd.ts";
import { deriveMonitors } from "./monitors.ts";
import { observe } from "./events.ts";
import { probeInitFindings, resumoDeProbes, sondaveis } from "./probe.ts";
import type { ArtifactContext } from "./artifact.ts";

/** Formato canônico de um contract id Soroban (StrKey `C` + 55 chars base32). */
export const CONTRACT_ID_RE = /^C[A-Z2-7]{55}$/;

const M = {
  naoDerivavel: "⟨not derivable from the file⟩",
  observando: (rede: string) => `observing on-chain events on ${rede}, ~15 s…`,
  janela: (ledgers: number, horas: number, de: number, ate: number, insuf: boolean, topics: number, paginas: number, limite: string) =>
    `observed window: ${ledgers} ledgers (~${horas} h, ${de}–${ate})${insuf ? " — insufficient for a baseline" : ""}, ${topics} distinct topics, ${paginas} getEvents ${paginas === 1 ? "page" : "pages"}, limited by ${limite}`,
  falhou: (erro: string) => `on-chain observation failed: ${erro}`,
  timeout: (s: number) => `timed out after ${s} s`,
  sondando: (n: number) => `probing ${n} init ${n === 1 ? "finding" : "findings"} with unsigned simulateTransaction…`,
  sondado: (g: number, o: number, i: number) => `probe: ${g} guarded · ${o} open · ${i} inconclusive`,
  baselineProbe: (k: string, d: string, l: number | undefined) =>
    `init probe (B, unsigned simulateTransaction${l ? `, ledger ${l}` : ""}): ${k} — ${d}`,
};

/**
 * O que vai nas células "On-chain address" quando o alvo é um arquivo local cujo nome não
 * carrega o contract id. Um caminho de arquivo ali seria um endereço inválido apresentado
 * como endereço — o revisor copiaria e o filtro não casaria com nada.
 *
 * É texto, então depende do idioma corrente: use a função. A constante fica como o valor
 * padrão (inglês) para quem precisa de uma comparação estática.
 */
export const enderecoNaoDerivavel = (): string => M.naoDerivavel;
export const ENDERECO_NAO_DERIVAVEL = "⟨not derivable from the file⟩";

/** O alvo é um arquivo local? `.wasm` por extensão, ou qualquer caminho que exista em disco. */
export function isLocalTarget(target: string): boolean {
  return target.endsWith(".wasm") || existsSync(target);
}

export type ResolvedTarget = {
  wasm: Uint8Array;
  wasmHash?: string;
  /** endereço on-chain, ou o marcador quando o alvo é arquivo e o nome não o revela */
  contractId: string;
  /** caminho do arquivo analisado, quando o alvo foi um arquivo local */
  analyzedFile?: string;
};

/**
 * Resolução de alvo única para `inspect`, `analyze` e `artifact`: arquivo local se ele
 * existe (ou termina em `.wasm`), senão busca o WASM deployado pelo contract id.
 *
 * Quando o alvo é arquivo, o contract id só é afirmado se o **nome** do arquivo for um
 * StrKey de contrato — é como o corpus é nomeado. Caso contrário o endereço sai marcado
 * como não derivável em vez de receber o caminho do arquivo (AQ-6).
 */
export async function resolveTarget(target: string, endpoint: string): Promise<ResolvedTarget> {
  if (isLocalTarget(target)) {
    const wasm = new Uint8Array(readFileSync(target));
    const base = basename(target).replace(/\.wasm$/i, "");
    // O wasm hash do ledger é, por definição, o sha256 dos bytes do módulo — para um
    // arquivo local ele é derivável e vale como fato A (conferível contra `getLedgerEntries`).
    const wasmHash = createHash("sha256").update(wasm).digest("hex");
    return {
      wasm,
      wasmHash,
      contractId: CONTRACT_ID_RE.test(base) ? base : enderecoNaoDerivavel(),
      analyzedFile: target,
    };
  }
  const { wasm, wasmHash } = await fetchWasm(target, endpoint);
  return { wasm, wasmHash, contractId: target };
}

/** Deadline global: o observe() não é cancelável, então corremos contra um timer. */
function comPrazo<T>(p: Promise<T>, ms: number): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) return p;
  let timer: NodeJS.Timeout;
  const prazo = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(M.timeout(Math.round(ms / 1000)))), ms);
  });
  // A promessa perdedora continua viva; engolir a rejeição evita unhandled rejection.
  void p.catch(() => {});
  return Promise.race([p, prazo]).finally(() => clearTimeout(timer!)) as Promise<T>;
}

/**
 * Monta o ArtifactContext completo. A ordem importa: o DFD precisa das chaves de
 * storage, e os monitores precisam do DFD e das observações.
 * `generatedAt` entra de fora — nenhum módulo abaixo lê relógio, para que a saída
 * seja reprodutível em teste.
 */
export async function buildContext(opts: {
  target: string;
  /**
   * Rede: nome conhecido (`mainnet`/`testnet`) ou URL de RPC. Quando é URL, o RÓTULO que vai
   * para `ctx.network` é derivado da passphrase que o nó devolve — a URL nunca é o rótulo,
   * porque um RPC pago carrega a API key no path e o rótulo é renderizado nos documentos.
   */
  network: string;
  /**
   * Endpoint de RPC já resolvido, quando o chamador (o CLI) também já resolveu o rótulo.
   * Fica em variável local: não entra no `ArtifactContext` e não é renderizado em lugar nenhum.
   */
  rpcUrl?: string;
  generatedAt: string;
  /** pular a ida à rede para observar eventos (nível B) */
  offline?: boolean;
  /** prazo total da fase de observação, em ms (0 = sem prazo) */
  timeoutMs?: number;
  /**
   * Sondar os achados de init com `simulateTransaction` não assinada (nível B). Default
   * `true` quando online. `--no-probe` desliga.
   */
  probe?: boolean;
  /** progresso legível para stderr — o CLI liga isto; testes não */
  onProgress?: (msg: string) => void;
}): Promise<ArtifactContext> {
  // Separação de credencial: `rpcUrl` é por onde falamos com a rede; `rede` é o rótulo que os
  // documentos, o DFD e o sumário do CLI mostram. Uma URL de RPC pode ser um segredo; um
  // rótulo nunca é. Quando o `-n` foi uma URL, o rótulo vem de UMA chamada `getNetwork`;
  // se ela falhar, o rótulo é `custom` — e não a URL.
  const rpcUrl = opts.rpcUrl ?? endpointDe(opts.network);
  const rede = /:\/\//.test(opts.network) ? await rotuloDaRede(rpcUrl) : opts.network;

  const alvo = await resolveTarget(opts.target, rpcUrl);
  const wasm = alvo.wasm;

  const analysis = analyzeModule(wasm);
  const { findings } = detectFull(analysis, wasm);
  const specEntries = parseSpecEntries(wasm);
  const specParts = modelFromEntries(specEntries);

  const ctx: ArtifactContext = {
    contractId: alvo.contractId,
    network: rede,
    generatedAt: opts.generatedAt,
    spec: {
      contractId: alvo.contractId, network: rede,
      // Sem isto o hash que `resolveTarget` acabou de ler on-chain ficava no caminho e o
      // documento saía dizendo "hash do WASM não capturado na geração" sobre um alvo por
      // contract id — o campo que prende o plano ao binário que está no ar.
      wasmHash: alvo.wasmHash,
      wasmBytes: wasm.length, observed: [], warnings: [],
      analyzedFile: alvo.analyzedFile,
      ...specParts,
    },
    analysis,
    findings,
    gaps: lacunas(findings),
    storageKeys: inferStorageKeys(wasm).map((k) => ({ key: k.key, confidence: k.confidence })),
  };

  ctx.dfd = buildDfd(ctx);

  // Nível B só existe para contrato deployado: um .wasm local não tem histórico on-chain.
  // As três situações abaixo são afirmações DIFERENTES e o documento precisa distingui-las:
  // pulada de propósito, tentada e falhada, ou coletada (mesmo que com zero ocorrências).
  if (opts.offline || alvo.analyzedFile) {
    ctx.offline = true;
  } else {
    opts.onProgress?.(M.observando(rede));
    try {
      const obs = await comPrazo(observe(opts.target, rpcUrl), opts.timeoutMs ?? 0);
      ctx.observations = obs;
      // `limitedBy`/`pagesUsed` não cabem em `Observations` (congelado em artifact.ts) e
      // viajam no modelo, que já chega inteiro a todos os renderizadores.
      ctx.spec.windowLimitedBy = obs.limitedBy;
      ctx.spec.windowPagesUsed = obs.pagesUsed;
      const w = obs.window;
      opts.onProgress?.(
        M.janela(w.ledgers, w.approxHours, w.fromLedger, w.toLedger, Boolean(w.insufficient), obs.events.length, obs.pagesUsed, obs.limitedBy),
      );
    } catch (e) {
      // Engolir a falha faria o documento sair byte a byte igual ao de `--offline` e
      // afirmar que nenhuma janela foi coletada — falso sobre a tentativa.
      // O erro do RPC costuma embutir a URL chamada, e ele vai para dentro dos documentos.
      ctx.observationError = redactUrl(String((e as Error)?.message ?? e));
      opts.onProgress?.(M.falhou(ctx.observationError));
    }
  }

  // Sondagem de init (nível B) antes dos monitores: o baseline do monitor de init cita o
  // resultado, e um monitor derivado antes da sondagem citaria uma janela que a sondagem
  // acabou de fechar. Só acontece online, com alvo por contract id.
  if (!ctx.offline && !alvo.analyzedFile && opts.probe !== false && CONTRACT_ID_RE.test(alvo.contractId)) {
    const alvos = sondaveis(findings);
    if (alvos.length) {
      opts.onProgress?.(M.sondando(alvos.length));
      const probes = await probeInitFindings({
        contractId: alvo.contractId,
        findings,
        specEntries,
        errors: ctx.spec.errors,
        endpoint: rpcUrl,
        rede,
        deadline: opts.timeoutMs ? Date.now() + opts.timeoutMs : undefined,
      });
      if (probes.size) {
        ctx.spec.probes = Object.fromEntries(probes);
        const r = resumoDeProbes(probes.values());
        opts.onProgress?.(M.sondado(r.guarded, r.open, r.inconclusive));
      }
    }
  }

  ctx.monitors = deriveMonitors(ctx);
  // O baseline do monitor de init passa a citar a sondagem. É acréscimo de TEXTO: o
  // `baselineTier` continua vindo da janela de eventos, porque a sondagem responde "a
  // janela de front-running está aberta?", não "qual é a taxa deste evento?".
  if (ctx.spec.probes && ctx.monitors?.length) {
    const porAchado = ctx.spec.probes;
    for (const m of ctx.monitors) {
      const p = porAchado[m.threatId];
      if (!p) continue;
      m.baseline = `${M.baselineProbe(p.kind, p.detail, p.ledger)} ${m.baseline}`;
    }
  }
  return ctx;
}
