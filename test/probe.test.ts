/**
 * A sondagem de init — o predicado de maior retorno medido até agora.
 *
 * `docs/PRECISION-TOP25.md`: 23 dos 66 achados do top 25 de mainnet eram front-running de
 * um inicializador que já tinha disparado. Este arquivo guarda as duas metades do
 * predicado: construir argumentos placeholder a partir do spec, e classificar o que o nó
 * devolve **sem** inflar `inconclusive` para `guarded`.
 *
 * NENHUM teste aqui vai à rede: a função de simulação é injetada.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { xdr, scValToNative } from "@stellar/stellar-sdk";
import {
  buildArgs,
  casoDeErro,
  classificar,
  probeInitFindings,
  resumoDeProbes,
  sondaveis,
  type ProbeResult,
  type SimOutcome,
  type Simulate,
} from "../src/probe.ts";
import type { Finding } from "../src/detect.ts";
import type { ErrEnum } from "../src/model.ts";
import { setLang } from "../src/i18n.ts";
import { buildContext } from "../src/pipeline.ts";
import { renderThreatModel } from "../src/render/threatmodel.ts";

const CONTRATO = "CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ";

/** O SDK devolve união XDR ora com métodos, ora como objeto plano; lemos as duas formas. */
const tipoDe = (v: any): string => (typeof v?.switch === "function" ? v.switch().name : String(v?.type));

/* ------------------------------------------------------------------ *
 * Um spec montado à mão — u32, address, string, vec<u32> e um struct.
 * ------------------------------------------------------------------ */

const T = xdr.ScSpecTypeDef;
const entrada = (name: string, type: xdr.ScSpecTypeDef) =>
  new xdr.ScSpecFunctionInputV0({ doc: "", name, type });

const STRUCT_CFG = xdr.ScSpecEntry.scSpecEntryUdtStructV0(
  new xdr.ScSpecUdtStructV0({
    doc: "", lib: "", name: "Cfg",
    fields: [
      new xdr.ScSpecUdtStructFieldV0({ doc: "", name: "fee", type: T.scSpecTypeU32() }),
      new xdr.ScSpecUdtStructFieldV0({ doc: "", name: "admin", type: T.scSpecTypeAddress() }),
    ],
  }),
);

const FN_INIT = xdr.ScSpecEntry.scSpecEntryFunctionV0(
  new xdr.ScSpecFunctionV0({
    doc: "", name: "initialize",
    inputs: [
      entrada("n", T.scSpecTypeU32()),
      entrada("admin", T.scSpecTypeAddress()),
      entrada("nome", T.scSpecTypeString()),
      entrada("pesos", T.scSpecTypeVec(new xdr.ScSpecTypeVec({ elementType: T.scSpecTypeU32() }))),
      entrada("cfg", T.scSpecTypeUdt(new xdr.ScSpecTypeUdt({ name: "Cfg" }))),
    ],
    outputs: [],
  }),
);

/** Mesmo spec, mas o UDT referido não existe: é o caso de desistir NOMEANDO o tipo. */
const FN_ORFA = xdr.ScSpecEntry.scSpecEntryFunctionV0(
  new xdr.ScSpecFunctionV0({
    doc: "", name: "init_orfa",
    inputs: [entrada("x", T.scSpecTypeUdt(new xdr.ScSpecTypeUdt({ name: "NaoExiste" })))],
    outputs: [],
  }),
);

const ENTRIES = [STRUCT_CFG, FN_INIT, FN_ORFA];

const ERROS: ErrEnum[] = [
  { name: "Erro", cases: [{ name: "AlreadyInitialized", value: 3 }, { name: "InvalidAmount", value: 7 }] },
];

const achado = (id: string, entrypoint = "initialize"): Finding => ({
  id, stride: "Elevation", class: "initialization-front-running", entrypoint,
  title: `\`${entrypoint}\``, evidence: [], severity: "Medium", family: "init", sound: true,
});

/* ------------------------------------------------------------------ *
 * Construtor de argumentos
 * ------------------------------------------------------------------ */

test("o construtor de argumentos cobre u32, address, string, vec e struct do spec", () => {
  const r = buildArgs(ENTRIES, "initialize", CONTRATO);
  assert.ok(r.ok, `desistiu do que devia saber construir: ${JSON.stringify(r)}`);
  assert.deepEqual(r.args.map(tipoDe), ["scvU32", "scvAddress", "scvString", "scvVec", "scvMap"]);

  // Os placeholders são inertes de propósito: o objetivo é CHEGAR à guarda, não passar
  // na validação do contrato. E o endereço é o do próprio contrato — válido por definição.
  assert.deepEqual(r.args.map((a) => scValToNative(a)), [
    0,
    CONTRATO,
    "x",
    [],
    { admin: CONTRATO, fee: 0 },
  ]);

  // Toda a lista precisa serializar: um placeholder que não vira XDR não sonda nada.
  for (const a of r.args) assert.ok(Buffer.from(a.toXDR()).length > 0);
});

test("tipo que a sonda não sabe construir vira desistência NOMEADA, não argumento chutado", () => {
  const r = buildArgs(ENTRIES, "init_orfa", CONTRATO);
  assert.equal(r.ok, false);
  if (r.ok) return;
  assert.match(r.tipo, /udt:NaoExiste/);
  assert.equal(r.param, "x");
});

test("função que não está no spec não produz argumentos vazios silenciosos", () => {
  const r = buildArgs(ENTRIES, "nao_existe", CONTRATO);
  assert.equal(r.ok, false);
});

/* ------------------------------------------------------------------ *
 * As quatro classificações
 * ------------------------------------------------------------------ */

/** Simulação injetada: devolve sempre o mesmo desfecho. */
const fixa = (o: SimOutcome): Simulate => async () => o;

const sondar = async (sim: Simulate, findings = [achado("Elevation.1")]): Promise<ProbeResult> => {
  const m = await probeInitFindings({
    contractId: CONTRATO, findings, specEntries: ENTRIES, errors: ERROS, simulate: sim,
  });
  const r = m.get(findings[0].id!);
  assert.ok(r, "achado de init sondável saiu sem resultado");
  return r;
};

test("(1) reversão com erro de já-inicializado do spec é a ÚNICA que fecha o achado", async () => {
  const r = await sondar(fixa({ ok: false, error: "HostError: Error(Contract, #3)", latestLedger: 64_000_000 }));
  assert.equal(r.kind, "guarded");
  assert.equal(r.reason, "already-initialized");
  assert.equal(r.ledger, 64_000_000);
  assert.match(r.detail, /AlreadyInitialized/);
});

test("(2) qualquer outro erro de contrato é inconclusivo — o argumento placeholder pode ter caído antes da guarda", async () => {
  const r = await sondar(fixa({ ok: false, error: "HostError: Error(Contract, #7)", latestLedger: 1 }));
  assert.equal(r.kind, "inconclusive");
  assert.equal(r.reason, "reverted-other");
  assert.match(r.detail, /InvalidAmount/);
  // O ponto do teste: um código de erro que existe no spec mas NÃO é de init nunca vira guarda.
  assert.doesNotMatch(r.detail, /already-initialized guard/);
});

test("(2b) erro de host sem código de contrato também é inconclusivo, não guarda", async () => {
  const r = await sondar(fixa({ ok: false, error: "HostError: Error(WasmVm, InvalidAction)" }));
  assert.equal(r.kind, "inconclusive");
  assert.equal(r.reason, "reverted-other");
});

test("(3) simulação BEM-SUCEDIDA é o único caso que torna o achado real", async () => {
  const r = await sondar(fixa({ ok: true, latestLedger: 42 }));
  assert.equal(r.kind, "open");
  assert.equal(r.reason, "simulation-succeeded");
  assert.match(r.detail, /SUCCEEDED/);
});

test("(4) falha de rede vira inconclusivo com a mensagem REDIGIDA — a URL pode ser credencial", async () => {
  const simulate: Simulate = async () => {
    throw new Error("fetch failed: POST https://rpc.exemplo.dev/v2/CHAVE-SECRETA returned 502");
  };
  const r = await sondar(simulate);
  assert.equal(r.kind, "inconclusive");
  assert.equal(r.reason, "error");
  assert.doesNotMatch(r.detail, /CHAVE-SECRETA/, "a API key do RPC vazou para dentro do documento");
  assert.match(r.detail, /rpc\.exemplo\.dev/);
});

test("simulação pendurada não come o prazo da execução: estoura e vira inconclusivo", async () => {
  const simulate: Simulate = () => new Promise(() => {});
  const m = await probeInitFindings({
    contractId: CONTRATO, findings: [achado("Elevation.1")], specEntries: ENTRIES, errors: ERROS,
    simulate, timeoutMs: 30,
  });
  const r = m.get("Elevation.1")!;
  assert.equal(r.kind, "inconclusive");
  assert.equal(r.reason, "error");
});

test("tipo não suportado não chega a simular — e diz isso", async () => {
  let chamou = false;
  const simulate: Simulate = async () => { chamou = true; return { ok: true }; };
  const r = await sondar(simulate, [achado("Elevation.9", "init_orfa")]);
  assert.equal(chamou, false, "sondou com argumentos que não soube construir");
  assert.equal(r.kind, "inconclusive");
  assert.equal(r.reason, "unsupported-arg-type");
});

/* ------------------------------------------------------------------ *
 * Seleção, agregação e idioma
 * ------------------------------------------------------------------ */

test("só a família `init` é sondada — a sonda não opina sobre achado que não é dela", () => {
  const fs: Finding[] = [
    achado("Elevation.1"),
    { ...achado("Elevation.2", "set_admin"), family: "auth", class: "unauthenticated-state-mutation" },
    { ...achado("DoS.1", "<contrato>"), family: "sdk" },
  ];
  assert.deepEqual(sondaveis(fs).map((f) => f.id), ["Elevation.1"]);
});

test("vários achados de init saem todos com resultado, e o resumo soma o que saiu", async () => {
  const porEp: Record<string, SimOutcome> = {
    initialize: { ok: false, error: "Error(Contract, #3)" },
    init_dois: { ok: true },
    init_tres: { ok: false, error: "Error(Contract, #7)" },
  };
  const simulate: Simulate = async ({ fn }) => porEp[fn];
  const entries = [
    ...ENTRIES,
    xdr.ScSpecEntry.scSpecEntryFunctionV0(new xdr.ScSpecFunctionV0({ doc: "", name: "init_dois", inputs: [], outputs: [] })),
    xdr.ScSpecEntry.scSpecEntryFunctionV0(new xdr.ScSpecFunctionV0({ doc: "", name: "init_tres", inputs: [], outputs: [] })),
  ];
  const m = await probeInitFindings({
    contractId: CONTRATO, specEntries: entries, errors: ERROS, simulate,
    findings: [achado("Elevation.1"), achado("Elevation.2", "init_dois"), achado("Elevation.3", "init_tres")],
  });
  assert.equal(m.size, 3);
  assert.deepEqual(resumoDeProbes(m.values()), { guarded: 1, open: 1, inconclusive: 1, total: 3 });
});

test("casoDeErro resolve o código pelo enum do próprio contrato, não por convenção nossa", () => {
  assert.deepEqual(casoDeErro(ERROS, 3), { enumName: "Erro", caseName: "AlreadyInitialized" });
  assert.equal(casoDeErro(ERROS, 99), undefined);
  // Sem enum no spec, #3 não vira "já inicializado" por sorte de número.
  assert.equal(classificar("initialize", { ok: false, error: "Error(Contract, #3)" }, []).kind, "inconclusive");
});

test("o detalhe da sondagem segue o idioma da execução", async () => {
  try {
    setLang("pt");
    const r = await sondar(fixa({ ok: true }));
    assert.match(r.detail, /TEVE SUCESSO/);
  } finally {
    setLang("en");
  }
});


/* ------------------------------------------------------------------ *
 * O que a sondagem escreve no threat model.
 * ------------------------------------------------------------------ */

const CORPUS = new URL("../corpus/", import.meta.url).pathname;
/**
 * Contrato do corpus com achados de init que carregam evidência C "a confirmar" — é ele
 * que exercita o callout de fechamento, que só existe quando há o que confirmar.
 */
const ALVO_INIT = `${CORPUS}CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm`;

const comProbe = async (r: Partial<ProbeResult>) => {
  const ctx = await buildContext({ target: ALVO_INIT, network: "mainnet", generatedAt: "2026-01-01", offline: true });
  const alvos = sondaveis(ctx.findings);
  assert.ok(alvos.length, "o corpus perdeu o contrato com achado de init; a regressão ficou sem guarda");
  ctx.spec.probes = Object.fromEntries(
    alvos.map((f) => [f.id!, {
      kind: "guarded", reason: "already-initialized", tier: "B", entrypoint: f.entrypoint,
      detail: "detalhe da sondagem", ledger: 64_123_456, ...r,
    } as ProbeResult]),
  );
  return renderThreatModel(ctx);
};

test("a linha de sondagem sai como nível B, com o ledger e o entrypoint", async () => {
  const md = await comProbe({});
  assert.match(md, /Init probe \(tier B\)/);
  assert.match(md, /Probe \(unsigned simulateTransaction, ledger 64123456\)/);
  assert.match(md, /\*\*guarded\*\* — detalhe da sondagem/);
});

test("`guarded` fecha o achado POR OBSERVAÇÃO, e não com o callout de \"ainda não é um achado\"", async () => {
  const md = await comProbe({});
  assert.match(md, /front-running window is closed on this instance/);
  assert.match(md, /residual risk is limited to a future re-deploy/);
  assert.match(md, /This finding is closed by observation/);
});

test("`open` sai alto: o inicializador roda AGORA e o documento manda tratar como High", async () => {
  const md = await comProbe({ kind: "open", reason: "simulation-succeeded" });
  assert.match(md, /⚠ \*\*The initializer executed successfully in simulation with placeholder arguments/);
  assert.match(md, /any address can initialize this instance NOW — treat as High until confirmed/);
  // Um achado aberto continua precisando de confirmação: o callout NÃO vira "fechado".
  assert.doesNotMatch(md, /closed by observation/);
});

test("`inconclusive` não fecha nem abre — diz por que não resolveu", async () => {
  const md = await comProbe({ kind: "inconclusive", reason: "reverted-other" });
  assert.match(md, /placeholder arguments can fail validation before reaching the guard/);
  assert.doesNotMatch(md, /closed by observation/);
  assert.match(md, /This finding is not yet a finding/);
});

test("sem sondagem o documento fica como era — nenhuma linha de nível B inventada", async () => {
  const ctx = await buildContext({ target: ALVO_INIT, network: "mainnet", generatedAt: "2026-01-01", offline: true });
  const md = renderThreatModel(ctx);
  assert.doesNotMatch(md, /Init probe \(tier B\)/);
});
