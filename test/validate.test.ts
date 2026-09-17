/**
 * Testes adversariais do validador. Cada um é uma mutação que JÁ passou verde numa versão
 * anterior de `src/validate.ts`, medida contra artefato real de contrato de mainnet. O que
 * eles protegem não é o formato do documento — é a regra de evidência: nenhum `ok` pode sair
 * de casamento de palavra, e nenhuma inferência pode vestir o crachá de fato.
 *
 * Desde que o validador passou a decidir pelo DADO, a mutação adversarial mudou de lugar: não
 * adianta mais editar a prosa do documento (o validador não a lê), e por isso os testes mutam
 * o que o renderizador leria — `ctx.findings`, os monitores, as observações. O markdown só é
 * mutilado onde a conferência que sobrou é estrutural: id que sumiu, título que sumiu.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildContext } from "../src/pipeline.ts";
import { renderThreatModel } from "../src/render/threatmodel.ts";
import { renderMonitoringPlan } from "../src/render/monitoring.ts";
import { validateThreatModel, validateMonitoringPlan } from "../src/validate.ts";
import { deriveMonitors } from "../src/monitors.ts";
import type { ArtifactContext, Observations } from "../src/artifact.ts";

const CORPUS = new URL("../corpus/", import.meta.url).pathname;
/** 76 entrypoints, 8 ameaças em 2 letras — o contrato mais denso do corpus. */
const ALVO = "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm";
const DATA = "2026-09-17";

const ctxAlvo = async (): Promise<ArtifactContext> =>
  buildContext({ target: CORPUS + ALVO, network: "mainnet", generatedAt: DATA, offline: true });

/**
 * Tudo que barra a submissão, junto. O relatório separa o que a FERRAMENTA deveria ter
 * fechado (`blockers`) do que só a equipe fecha (`needsInput`); onde o teste cobra "isto
 * barra a submissão" sem cobrar de quem é a pendência, a lista é a união das duas.
 */
const pendencias = (r: { blockers: string[]; needsInput?: string[] }) => [...r.blockers, ...(r.needsInput ?? [])];

const item = (r: { items: { question: string; status: string; detail: string }[] }, frag: string) => {
  const i = r.items.find((x) => x.question.includes(frag));
  assert.ok(i, `item de checklist não encontrado: ${frag}`);
  return i;
};

/* ------------------------------------------------------------------ *
 * Evidência: nível vem do DADO, não da marca no texto
 * ------------------------------------------------------------------ */

test("ameaça sustentada só por inferência (C) é blocker, e o documento não muda isso", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  assert.equal(item(validateThreatModel(ctx, tm), "evidence tier").status, "ok");

  // A afirmação inflada não é mais uma marca reescrita no markdown: é a evidência que não
  // sustenta o fato. Um achado cuja evidência é toda C é exatamente "C apresentado como A".
  const soC = {
    ...ctx,
    findings: ctx.findings.map((f) => ({ ...f, evidence: f.evidence.map((e) => ({ ...e, tier: "C" as const })) })),
  };
  const r = validateThreatModel(soC as typeof ctx, tm);
  assert.equal(item(r, "evidence tier").status, "gap");
  assert.ok(r.blockers.some((b) => /supported only by inference \(tier C\)/.test(b)), "achado só-C passou como fato");
  assert.ok(r.blockers.some((b) => /never present C as A/.test(b)), "o blocker não cita a regra que ele protege");
  assert.equal(r.submittable, false);
  assert.equal(r.verdict, "not-submittable");
});

test("ameaça sem evidência nenhuma é blocker", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const sem = { ...ctx, findings: ctx.findings.map((f, i) => (i === 0 ? { ...f, evidence: [] } : f)) };
  const r = validateThreatModel(sem as typeof ctx, tm);
  assert.ok(r.blockers.some((b) => b.includes(`Threat ${ctx.findings[0].id} has no evidence at all`)));
  assert.equal(item(r, "evidence tier").status, "gap");
});

/* ------------------------------------------------------------------ *
 * Remediação: o template é escolhido pela CLASSE do achado
 * ------------------------------------------------------------------ */

test("classe sem remediação escrita sai declarada como lacuna, não como remediação derivada", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const r = validateThreatModel(ctx, tm);
  const d = item(r, "remediations address").detail;

  // `third-party-state-tampering` cai no `default` de `remediacoes()`: o renderizador escreve
  // a lacuna declarada. É saída honesta (PROBLEMA.md: campo vazio > enchimento) e por isso não
  // é blocker — mas o checklist precisa dizer que aquela ameaça espera remediação humana.
  const semTemplate = ctx.findings.filter((f) => f.class === "third-party-state-tampering");
  assert.ok(semTemplate.length, "o corpus mudou: o contrato de referência não tem classe sem remediação escrita");
  for (const f of semTemplate) assert.ok(d.includes(f.id!), `${f.id} não foi declarado como lacuna de remediação: ${d}`);
  assert.match(d, /no remediation is written for their class/);
  assert.ok(!r.blockers.some((b) => /remediation/i.test(b)), `lacuna declarada virou blocker: ${r.blockers.join(" | ")}`);
});

test("remediação que não chegou ao documento é blocker (conferência estrutural do id)", async () => {
  const ctx = await ctxAlvo();
  const alvo = ctx.findings[0].id!;
  // apaga só os ids `X.n.R.m` daquela ameaça: a ameaça continua no documento, a remediação não
  const semRem = renderThreatModel(ctx).replace(new RegExp(`${alvo.replace(".", "\\.")}\\.R\\.\\d+`, "g"), "—");
  const r = validateThreatModel(ctx, semRem);
  assert.ok(r.blockers.some((b) => b === `Threat ${alvo} has no remediation in the document.`), r.blockers.join(" | "));
  assert.equal(item(r, "remediations address").status, "gap");
});

test("ameaça que sumiu do documento é blocker", async () => {
  const ctx = await ctxAlvo();
  const alvo = ctx.findings[0].id!;
  const sem = renderThreatModel(ctx).replace(new RegExp(`(?<![\\w.])${alvo.replace(".", "\\.")}(?![\\w.])`, "g"), "X.0");
  const r = validateThreatModel(ctx, sem);
  assert.ok(r.blockers.some((b) => b.includes(`${alvo} exists in the analysis but does not appear`)), r.blockers.join(" | "));
});

test("seção oficial ausente é blocker", async () => {
  const ctx = await ctxAlvo();
  const sem = renderThreatModel(ctx).replace("## What can go wrong?", "## Stuff");
  const r = validateThreatModel(ctx, sem);
  assert.ok(r.blockers.some((b) => b.includes('Section "What can go wrong?" missing')), r.blockers.join(" | "));
});

/* ------------------------------------------------------------------ *
 * As seis letras
 * ------------------------------------------------------------------ */

test("letra do STRIDE sem issue bloqueia a submissão, mesmo com a lacuna bem declarada", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const r = validateThreatModel(ctx, tm);

  const LETRAS = ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"] as const;
  const comAchado = new Set(ctx.findings.map((f) => f.stride));
  const lacunas = LETRAS.filter((l) => !comAchado.has(l));
  assert.ok(lacunas.length >= 2, `o contrato de referência não tem letra em lacuna: ${lacunas.join(", ")}`);

  for (const l of lacunas) {
    // Letra vazia barra a submissão como PREENCHIMENTO da equipe: a planilha da própria
    // lacuna diz qual é a superfície, e não há análise que a feche.
    assert.ok(
      (r.needsInput ?? []).some((b) => b.includes(`STRIDE letter ${l} has no issue`)),
      `letra ${l} está em lacuna e não entrou em needsInput`,
    );
    assert.ok(
      (r.needsInput ?? []).some((b) => b.includes(`fill it from the worksheet in the ${l} gap section`)),
      `a pendência de ${l} não diz de onde tirar a issue`,
    );
    assert.ok(
      !r.blockers.some((b) => b.includes(`STRIDE letter ${l} has no issue`)),
      `letra ${l} saiu como falha da ferramenta, e não como preenchimento da equipe`,
    );
  }
  assert.equal(r.submittable, false, "documento com letra sem issue saiu como submetível");
  assert.notEqual(r.verdict, "submittable");

  const it = item(r, "STRIDE letter");
  assert.equal(it.status, "gap");
  assert.ok(
    it.detail.includes(`${LETRAS.length - lacunas.length} of 6 letters filled.`),
    `o detalhe não conta as letras preenchidas: ${it.detail}`,
  );
  assert.ok(tm.includes("Declared gaps"), "a seção de lacunas declaradas sumiu do documento");
});

test("com as seis letras cobertas por achado, nenhum blocker de letra sobra", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const modelo = ctx.findings[0];
  const findings = (["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"] as const).map((stride, i) => ({
    ...modelo,
    id: `${stride}.${i + 1}`,
    stride,
  }));
  const comTodas = { ...ctx, findings, gaps: [] };
  const texto = `${tm}\n${findings.map((f) => `**${f.id}** — ${f.title} (${f.stride}) ${f.id}.R.1`).join("\n")}\n`;
  const r = validateThreatModel(comTodas as typeof ctx, texto);
  assert.ok(!r.blockers.some((b) => /has no issue/.test(b)), "blocker de letra vazia com as seis preenchidas");
  assert.ok(item(r, "STRIDE letter").detail.includes("6 of 6 letters filled."), "a contagem não chegou a 6 de 6");
});

test("achado que não chegou ao documento não conta como letra preenchida", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const letra = ctx.findings[0].stride;
  const daLetra = ctx.findings.filter((f) => f.stride === letra).map((f) => f.id!);
  let sem = tm;
  for (const id of daLetra) sem = sem.replace(new RegExp(`(?<![\\w.])${id.replace(".", "\\.")}(?![\\w.])`, "g"), "X.0");
  const r = validateThreatModel(ctx, sem);
  assert.ok(r.blockers.some((b) => b.startsWith(`Letter ${letra}:`)), r.blockers.join(" | "));
});

/* ------------------------------------------------------------------ *
 * Baseline: número conferido contra a janela observada
 * ------------------------------------------------------------------ */

test("baseline nível B é conferido contra a observação, não só contra o tier", async () => {
  const ctx = await ctxAlvo();
  const observations: Observations = {
    window: { fromLedger: 1000, toLedger: 18280, ledgers: 17280, approxHours: 24, insufficient: false },
    events: [{ topic: "deposit", count: 7, firstLedger: 1000, lastLedger: 18280, ratePerHour: 0.29 }],
    declaredButUnseen: [],
  };
  const comObs = { ...ctx, observations };
  const mentiroso = (ctx.monitors ?? []).slice(0, 2).map((m) => ({
    ...m,
    baseline: "412 emissions of [deposit] in the window of 17280 ledgers (~24 h, ledgers 1000–18280) ⇒ 17/h.",
    baselineTier: "B" as const,
    status: "Tuning" as const,
  }));
  assert.ok(mentiroso.length, "contrato de referência não produziu monitor");
  const md = renderMonitoringPlan({ ...comObs, monitors: mentiroso });
  const r = validateMonitoringPlan(comObs, md, mentiroso);
  assert.ok(r.blockers.some((b) => /does not match the observation/.test(b)), "baseline inventado passou como observado");
  assert.equal(item(r, "baseline grounded").status, "gap");
  // Nenhum monitor deste documento é `Active` (a §5 afirma isso), então a pergunta sobre
  // precisão de alerta não tem o que medir — o que ela não pode é sair ✔.
  assert.equal(item(r, "historically accurate").status, "n/a");
  assert.match(item(r, "historically accurate").detail, /No monitor is Active yet/);

  const fantasma = mentiroso.map((m) => ({ ...m, baseline: "12 emissions of [topic_that_does_not_exist] in the window of 17280 ledgers ⇒ 0.5/h." }));
  const r2 = validateMonitoringPlan(comObs, md, fantasma);
  assert.ok(r2.blockers.some((b) => /observed window does not contain/.test(b)), "baseline sobre tópico nunca observado passou");
});

test("baseline derivado da observação real não vira falso positivo", async () => {
  const base = await buildContext({ target: CORPUS + "CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm", network: "mainnet", generatedAt: DATA, offline: true }).catch(() => undefined);
  if (!base) return; // o corpus é montado por varredura; se este contrato sumir, o teste não se aplica
  const topicos = base.spec.events.flatMap((e) => e.prefixTopics);
  if (!topicos.length) return;
  const observations: Observations = {
    window: { fromLedger: 1000, toLedger: 18280, ledgers: 17280, approxHours: 24, insufficient: false },
    events: topicos.slice(0, 2).map((t, i) => ({ topic: t, count: 30 + i, firstLedger: 1000, lastLedger: 18280, ratePerHour: 1.25 })),
    declaredButUnseen: topicos.slice(2),
  };
  const ctx: ArtifactContext = { ...base, observations };
  ctx.monitors = deriveMonitors(ctx);
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors);
  assert.equal(
    r.blockers.filter((b) => /does not match the observation|does not contain/.test(b)).length,
    0,
    "baseline honesto, derivado da própria janela, foi acusado de divergir dela",
  );
});

test("baseline nível B sem nenhuma observação no contexto é blocker", async () => {
  const ctx = await ctxAlvo();
  const mons = (ctx.monitors ?? []).slice(0, 1).map((m) => ({ ...m, baselineTier: "B" as const, baseline: "3 emissions per day." }));
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), mons);
  assert.ok(r.blockers.some((b) => /declares a tier B baseline with no on-chain observation/.test(b)), r.blockers.join(" | "));
});

/* ------------------------------------------------------------------ *
 * Off-chain: a âncora é o que a análise deixou de fora
 * ------------------------------------------------------------------ */

test("ameaça descoberta e sem lacuna declarada não passa como fronteira off-chain declarada", async () => {
  const ctx = await ctxAlvo();
  // Sem letra em lacuna, e com as ameaças restantes todas FORA da tabela de controle fora da
  // chain (elas têm observável derivável), tirar os monitores deixa-as descobertas e sem nada
  // a que prender a fronteira off-chain.
  const comObservavel = new Set((deriveMonitors(ctx) ?? []).map((m) => m.threatId));
  const semAncora = { ...ctx, gaps: [], findings: ctx.findings.filter((f) => comObservavel.has(f.id!)) };
  assert.ok(semAncora.findings.length, "contrato de referência não tem ameaça com observável derivável");
  assert.equal(item(validateMonitoringPlan(semAncora as typeof ctx, renderMonitoringPlan(ctx), []), "off-chain").status, "gap");
  // o documento real prende a fronteira às letras sem achado derivável
  assert.equal(item(validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors ?? []), "off-chain").status, "ok");
});

test("justificativa derivada do dado não é acusada de ausente", async () => {
  // Repudiate é a classe que o renderizador manda para a seção de controle fora da chain.
  const ctx = await buildContext({ target: CORPUS + "CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV.wasm", network: "mainnet", generatedAt: DATA, offline: true }).catch(() => undefined);
  if (!ctx) return;
  const semMonitor = ctx.findings.filter((f) => f.id && !(ctx.monitors ?? []).some((m) => m.threatId === f.id));
  if (!semMonitor.length) return;
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors ?? []);
  assert.ok(
    !r.blockers.some((b) => /no non-monitorability justification/.test(b)),
    "o validador afirmou que falta justificativa sobre ameaça que a §5 cobre com controle nomeado",
  );
});

/* ------------------------------------------------------------------ *
 * AQ-1 — janela coletada e vazia não sustenta limiar
 * ------------------------------------------------------------------ */

test("janela com zero eventos vira lacuna e bloqueia a submissão do plano", async () => {
  const ctx = await ctxAlvo();
  const comJanelaVazia: ArtifactContext = {
    ...ctx,
    offline: undefined,
    observations: {
      window: { fromLedger: 1_000, toLedger: 31_000, ledgers: 30_001, approxHours: 48, insufficient: false },
      events: [],
      declaredButUnseen: [],
    },
  };
  comJanelaVazia.monitors = deriveMonitors(comJanelaVazia);
  const md = renderMonitoringPlan(comJanelaVazia);
  const r = validateMonitoringPlan(comJanelaVazia, md, comJanelaVazia.monitors ?? []);
  assert.equal(item(r, "baseline grounded").status, "gap", "janela vazia apresentada como baseline conferido");
  assert.ok(
    r.blockers.some((b) => /absence of traffic, not a traffic profile/.test(b)),
    "janela sem tráfego nenhum não virou blocker",
  );
  assert.equal(r.submittable, false);
  assert.match(md, /absence of traffic, not a traffic profile/);
});

/* ------------------------------------------------------------------ *
 * Fonte única: a §6 do documento é o relatório que o CLI imprime
 * ------------------------------------------------------------------ */

/** Lê a tabela da §6 do plano renderizado: [pergunta, situação]. */
function checklistDoDocumento(md: string): [string, string][] {
  const i = md.indexOf("## Did we do a good job?");
  assert.ok(i > 0, "o plano renderizado não tem a seção do checklist");
  const linhas = md.slice(i).split("\n").filter((l) => l.startsWith("|"));
  return linhas
    .slice(2) // cabeçalho + separador
    .map((l) => l.replace(/^\|/, "").replace(/\|$/, "").split(/(?<!\\)\|/).map((c) => c.trim()))
    .filter((c) => c.length >= 2)
    .map((c) => [c[0], c[1]] as [string, string]);
}

test("a §6 renderizada e o veredito do CLI são o mesmo relatório", async () => {
  const ctx = await ctxAlvo();
  const md = renderMonitoringPlan(ctx);
  const rel = validateMonitoringPlan(ctx, md, ctx.monitors ?? []);
  const doDoc = checklistDoDocumento(md);
  assert.equal(doDoc.length, rel.items.length, "a §6 tem um número de linhas diferente do relatório do CLI");
  rel.items.forEach((it, i) => {
    assert.equal(doDoc[i][0], it.question.replace(/\|/g, "\\|"), `pergunta ${i} divergiu entre documento e relatório`);
    const esperado = it.status === "ok" ? "✔ ok" : it.status === "gap" ? "⚠ gap" : "n/a";
    assert.equal(doDoc[i][1], esperado, `situação de "${it.question}" divergiu entre documento e relatório`);
  });
  // e os blockers listados no documento são os mesmos do relatório
  for (const b of rel.blockers) assert.ok(md.includes(b.replace(/\|/g, "\\|")), `blocker ausente do documento: ${b}`);
});

/* ------------------------------------------------------------------ *
 * SHIP-05 por monitor — "sem baseline" tem três causas e três textos
 *
 *  (a) não houve janela;  (b) houve janela e ela não sustenta ESTE limiar;
 *  (c) o monitor não passa por getEvents — nenhuma janela produziria o baseline dele.
 * ------------------------------------------------------------------ */

/** Contrato com evento no spec: é o que dá monitor de evento (`getEvents` executável). */
const COM_EVENTO = "CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm";
const ctxComEvento = async (): Promise<ArtifactContext> =>
  buildContext({ target: CORPUS + COM_EVENTO, network: "mainnet", generatedAt: DATA, offline: true });

const JANELA: Observations["window"] = { fromLedger: 1000, toLedger: 18280, ledgers: 17280, approxHours: 24, insufficient: false };

test("(1a) sem janela nenhuma: o blocker do monitor de evento diz que a coleta não aconteceu", async () => {
  const ctx = await ctxComEvento();
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors ?? []);
  const b = r.blockers.filter((x) => /No observation window: tier B collection not run/.test(x));
  assert.equal(b.length, 1, `esperado exatamente um blocker de janela ausente: ${r.blockers.join(" | ")}`);
  assert.ok(!/not event-based/.test(b[0]), "caso (a) saiu com o texto do caso (c)");
});

test("(1c) monitor que não passa por getEvents não é acusado de falta de janela", async () => {
  // Todos os monitores deste contrato são de inspeção de transação: nenhum vira getEvents.
  const ctx = await ctxAlvo();
  const comJanela: ArtifactContext = { ...ctx, offline: undefined, observations: { window: JANELA, events: [{ topic: "x", count: 5, firstLedger: 1000, lastLedger: 18280, ratePerHour: 0.2 }], declaredButUnseen: [] } };
  const md = renderMonitoringPlan(comJanela);
  const r = validateMonitoringPlan(comJanela, md, comJanela.monitors ?? []);
  assert.ok(pendencias(r).length, "contrato de referência não produziu pendência de baseline");
  assert.ok(
    (r.needsInput ?? []).some((b) => /not event-based; its baseline is the current on-chain value/.test(b)),
    `caso (c) não saiu como preenchimento: ${pendencias(r).join(" | ")}`,
  );
  assert.ok(
    !pendencias(r).some((b) => /No observation window/.test(b)),
    "o validador afirmou que não há janela num documento que imprime a janela",
  );
  assert.doesNotMatch(md, /no observation window was collected/i);
  assert.match(md, /to be recorded at plan approval/);
});

test("(1b) zero observado sustenta qualquer-ocorrência, não limiar de taxa", async () => {
  const base = await ctxComEvento();
  const observations: Observations = {
    window: JANELA,
    events: [{ topic: "tw_fund", count: 40, firstLedger: 1000, lastLedger: 18280, ratePerHour: 1.6 }],
    declaredButUnseen: ["tw_init"],
  };
  const ctx: ArtifactContext = { ...base, offline: undefined, observations };
  ctx.monitors = deriveMonitors(ctx);
  const zero = (ctx.monitors ?? []).filter((m) => /tw_init/.test(m.baseline));
  assert.ok(zero.length, "o contrato de referência não produziu baseline de zero observado");

  const md = renderMonitoringPlan(ctx);
  assert.match(md, /An observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold/);
  const r = validateMonitoringPlan(ctx, md, ctx.monitors ?? []);
  assert.ok(!r.blockers.some((b) => /an observed zero is a measurement/.test(b)), "zero medido com gatilho de qualquer ocorrência virou blocker");

  const comLimiar = zero.map((m) => ({
    ...m,
    trigger: "More than 12 occurrences of [tw_init] in 1 h (3× the rate measured in the observed window).",
  }));
  const r2 = validateMonitoringPlan(ctx, md, comLimiar);
  assert.ok(
    r2.blockers.some((b) => /an observed zero is a measurement, but it supports only an any-occurrence trigger/.test(b)),
    `limiar de taxa sobre zero medido passou: ${r2.blockers.join(" | ")}`,
  );
});

test("as três causas de ausência de baseline não compartilham texto", async () => {
  const semJanela = await ctxComEvento();
  const a = validateMonitoringPlan(semJanela, renderMonitoringPlan(semJanela), semJanela.monitors ?? [])
    .blockers.find((b) => /has no baseline/.test(b))!;
  const curta: ArtifactContext = {
    ...semJanela,
    offline: undefined,
    observations: { window: { ...JANELA, insufficient: true }, events: [], declaredButUnseen: [] },
  };
  curta.monitors = deriveMonitors(curta);
  const b = validateMonitoringPlan(curta, renderMonitoringPlan(curta), curta.monitors ?? [])
    .blockers.find((x) => /declared insufficient/.test(x))!;
  const fill = await ctxAlvo();
  const c = (validateMonitoringPlan(fill, renderMonitoringPlan(fill), fill.monitors ?? []).needsInput ?? [])
    .find((x) => /not event-based/.test(x))!;
  assert.ok(a && b && c, "uma das três causas não produziu pendência");
  assert.equal(new Set([a, b, c]).size, 3, "duas causas diferentes saíram com o mesmo texto");
});

/* ------------------------------------------------------------------ *
 * §6: "é monitor de evento?" é pergunta estrutural, não textual
 * ------------------------------------------------------------------ */

test("monitor não-evento que declara o mecanismo não é acusado de getEvents que nunca dispara", async () => {
  const ctx = await ctxAlvo();
  const mons = ctx.monitors ?? [];
  assert.ok(mons.length, "contrato de referência não produziu monitor");
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), mons);
  assert.ok(
    !/no executable getEvents filter/.test(item(r, "concrete observable signal").detail),
    "monitor de inspeção de transação, com o mecanismo escrito na linha, foi acusado de nunca disparar",
  );
  // apagando o mecanismo do CAMPO do monitor, o mesmo monitor volta a ser decorativo
  const mudos = mons.map((m) => ({ ...m, observable: "Something worth watching.", trigger: "Any occurrence." }));
  const r2 = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), mudos);
  assert.match(item(r2, "concrete observable signal").detail, /no executable getEvents filter/);
});

test("a cobertura de topics do spec só se aplica a monitor de evento", async () => {
  const ctx = await ctxComEvento();
  assert.ok(ctx.spec.events.length, "contrato de referência não declara evento no spec");
  const mons = ctx.monitors ?? [];
  const extra = { ...mons[0], id: `${mons[0].threatId}.M.9`, observable: "instance wasm hash read via getLedgerEntries", trigger: "Periodic check (getLedgerEntries)." };
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), [...mons, extra]);
  const d = item(r, "concrete observable signal").detail;
  assert.ok(!/M\.9/.test(d), `monitor de ledger entry foi cobrado por citar topic do spec: ${d}`);
  assert.match(d, /every event-based monitor cites a topic declared in the spec/);
});

test("monitor que não aparece no documento é blocker", async () => {
  const ctx = await ctxAlvo();
  const mons = ctx.monitors ?? [];
  const md = renderMonitoringPlan(ctx).replace(new RegExp(mons[0].id.replace(/\./g, "\\."), "g"), "—");
  const r = validateMonitoringPlan(ctx, md, mons);
  assert.ok(r.blockers.some((b) => b.includes(`Monitor ${mons[0].id} is in the plan's data and does not appear`)), r.blockers.join(" | "));
});

/* ------------------------------------------------------------------ *
 * §5 e §6 falando do mesmo documento
 * ------------------------------------------------------------------ */

test("sem monitor `Active`, a linha de precisão histórica nunca sai ✔", async () => {
  const ctx = await ctxComEvento();
  const observations: Observations = {
    window: JANELA,
    events: [{ topic: "tw_fund", count: 40, firstLedger: 1000, lastLedger: 18280, ratePerHour: 1.6 }],
    declaredButUnseen: ["tw_init"],
  };
  const comObs: ArtifactContext = { ...ctx, offline: undefined, observations };
  comObs.monitors = deriveMonitors(comObs);
  const mons = comObs.monitors ?? [];
  assert.ok(mons.length && mons.every((m) => m.status !== "Active"), "a derivação passou a nascer com monitor Active");

  const md = renderMonitoringPlan(comObs);
  const r = validateMonitoringPlan(comObs, md, mons);
  const linha = item(r, "historically accurate");
  assert.notEqual(linha.status, "ok", "monitor em Tuning/Planned foi contado como alerta com histórico");
  assert.equal(linha.status, "n/a");
  assert.match(linha.detail, /No monitor is Active yet/);
  assert.match(linha.detail, /none has alert history/);
  assert.doesNotMatch(linha.detail, /The single active monitor|active monitors have/);
  assert.match(md, /No monitor leaves this document as `Active`/);

  const ligado = mons.map((m, i) => (i === 0 ? { ...m, status: "Active" as const } : m));
  const r2 = validateMonitoringPlan(comObs, md, ligado);
  assert.notEqual(item(r2, "historically accurate").status, "n/a");
});

/* ------------------------------------------------------------------ *
 * Zero observado de tópico one-shot não é baseline conferido
 * ------------------------------------------------------------------ */

test("zero observado em gatilho de qualquer-ocorrência não conta como baseline conferido", async () => {
  const base = await ctxComEvento();
  const observations: Observations = {
    window: JANELA,
    events: [{ topic: "tw_fund", count: 40, firstLedger: 1000, lastLedger: 18280, ratePerHour: 1.6 }],
    declaredButUnseen: ["tw_init"],
  };
  const ctx: ArtifactContext = { ...base, offline: undefined, observations };
  ctx.monitors = deriveMonitors(ctx);
  const zero = (ctx.monitors ?? []).filter((m) => /tw_init/.test(m.baseline));
  assert.ok(zero.length, "o contrato de referência não produziu baseline de zero observado");

  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors ?? []);
  const d = item(r, "baseline grounded").detail;
  assert.match(d, /an observed zero \(measurement\)/);
  assert.match(d, /not count as checked against the window/);
  for (const m of zero) assert.ok(d.includes(m.id), `o baseline de zero de ${m.id} não foi declarado como não conferido`);
  assert.ok(!r.blockers.some((b) => /observed zero is a measurement, but it supports only/.test(b)));
  assert.notEqual(item(r, "historically accurate").status, "ok");
  assert.match(d, /0 baselines with the count checked against the window/);
});

/* ------------------------------------------------------------------ *
 * Uma linha ✔ não pode apontar para um bloqueio aberto
 * ------------------------------------------------------------------ */

test("monitor nem executável por getEvents nem completamente especificado rebaixa a linha de sinal", async () => {
  const ctx = await ctxAlvo();
  const mons = ctx.monitors ?? [];
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), mons);
  const sinal = item(r, "concrete observable signal");
  assert.equal(sinal.status, "gap", "linha ✔ sobre monitor com preenchimento em aberto");
  assert.match(sinal.detail, /neither executable through getEvents nor fully specified/);
  const citados = mons.filter((m) => sinal.detail.includes(m.id));
  assert.ok(citados.length, "a linha não nomeia nenhum monitor incompleto");
  assert.ok(
    citados.some((m) => pendencias(r).some((b) => b.includes(m.id))),
    "a linha aponta um monitor incompleto que o documento não lista como bloqueio",
  );

  // com o preenchimento fechado à mão — durabilidade escolhida, chave inteira — a ressalva some
  const preenchidos = mons.map((m) => ({
    ...m,
    observable: "diff of the persistent entry `params` across ledgers (getLedgerEntries)",
    trigger: "Any occurrence of the observable on this row.",
  }));
  const d2 = item(validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), preenchidos), "concrete observable signal").detail;
  assert.ok(!/neither executable through getEvents nor fully specified/.test(d2), `${d2}`);
});

/**
 * Varredura de forma, e é o que impede a volta do defeito por outro texto: se o detalhe de
 * uma linha precisou dizer que algo ainda tem de ser escrito, preenchido ou definido, aquela
 * linha não é `ok`. Vale sobre contratos de perfis diferentes.
 */
test("nenhuma linha ✔ carrega pendência no próprio detalhe", async () => {
  const alvos = [ALVO, COM_EVENTO, "CAM7DY53G63XA4AJRS24Z6VFYAFSSF76C3RZ45BE5YU3FQS5255OOABP.wasm"];
  const PENDENCIA = /\bhas to\b|\bmust\b|to be filled|to be defined|⟨/i;
  for (const alvo of alvos) {
    const ctx = await buildContext({ target: CORPUS + alvo, network: "mainnet", generatedAt: DATA, offline: true });
    const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), ctx.monitors ?? []);
    for (const it of r.items) {
      if (it.status !== "ok") continue;
      assert.ok(!PENDENCIA.test(it.detail), `${alvo} — linha ✔ com pendência no detalhe: ${it.question} → ${it.detail}`);
    }
  }
});

/* ------------------------------------------------------------------ *
 * Dono: não existe no dado, então é sempre preenchimento da equipe
 * ------------------------------------------------------------------ */

test("dono do alerta é sempre preenchimento da equipe, nunca falha da ferramenta", async () => {
  const ctx = await ctxAlvo();
  const mons = ctx.monitors ?? [];
  const r = validateMonitoringPlan(ctx, renderMonitoringPlan(ctx), mons);
  const it = item(r, "named owner");
  assert.equal(it.status, "gap", "linha de dono saiu ✔ sobre uma coluna que é preenchimento em toda linha");
  assert.ok(
    (r.needsInput ?? []).some((b) => b.includes(`Assign an owner and a notification channel to ${mons.length}`)),
    `a pendência de dono não entrou em needsInput: ${pendencias(r).join(" | ")}`,
  );
  assert.ok(!r.blockers.some((b) => /Assign an owner/.test(b)), "dono saiu como falha da ferramenta");
});

/* ------------------------------------------------------------------ *
 * Veredito de três estados
 * ------------------------------------------------------------------ */

test("veredito separa falha da ferramenta de preenchimento da equipe", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const r = validateThreatModel(ctx, tm);

  // O documento gerado não tem blocker da ferramenta: o que sobra é preenchimento.
  assert.deepEqual(r.blockers, [], `a ferramenta deixou pendência própria: ${r.blockers.join(" | ")}`);
  assert.equal(r.verdict, "needs-input");
  assert.equal(r.submittable, false);
  assert.equal(r.submittable, r.verdict === "submittable", "submittable e verdict discordam");
  assert.ok(
    (r.needsInput ?? []).some((b) => /Write section 1/.test(b)),
    `a lacuna da §1 não entrou em needsInput: ${(r.needsInput ?? []).join(" | ")}`,
  );
  assert.match(tm, /\*\*NEEDS INPUT\.\*\*/);
  assert.match(tm, /### Input the team must provide before submitting/);
  for (const b of r.needsInput ?? []) assert.ok(tm.includes(b), `pendência ausente do documento: ${b}`);

  // afirmação que a análise não sustenta é falha da FERRAMENTA: volta a not-submittable
  const soC = {
    ...ctx,
    findings: ctx.findings.map((f) => ({ ...f, evidence: f.evidence.map((e) => ({ ...e, tier: "C" as const })) })),
  };
  const ri = validateThreatModel(soC as typeof ctx, tm);
  assert.equal(ri.verdict, "not-submittable");
  assert.ok(ri.blockers.length, "evidência que não sustenta o achado não produziu blocker da ferramenta");
});

test("com as seis letras e a §1 escritas, não sobra preenchimento", async () => {
  const ctx = await ctxAlvo();
  const tm = renderThreatModel(ctx);
  const modelo = ctx.findings[0];
  const findings = (["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"] as const).map((stride, i) => ({
    ...modelo,
    id: `${stride}.${i + 1}`,
    stride,
  }));
  const comTodas = { ...ctx, findings, gaps: [] };
  // a equipe escreveu a §1 (o aviso de lacuna sai do documento) e as seis letras têm issue
  const texto = `${tm.replace(/\*\*Gap to be filled by the team\.\*\*/g, "**About this protocol.**")}\n${findings
    .map((f) => `**${f.id}** — ${f.title} (${f.stride}) ${f.id}.R.1`)
    .join("\n")}\n`;
  const r = validateThreatModel(comTodas as typeof ctx, texto);
  assert.deepEqual(r.needsInput, [], `sobrou preenchimento: ${(r.needsInput ?? []).join(" | ")}`);
  assert.equal(r.verdict, r.blockers.length ? "not-submittable" : "submittable");
  assert.equal(r.submittable, r.blockers.length === 0);
});

/* ------------------------------------------------------------------ *
 * Agregação por família no detalhamento
 * ------------------------------------------------------------------ */

/** AMM de mainnet com 5 achados `initialization-front-running` da mesma forma. */
const AMM = "CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV.wasm";

test("cinco achados de init da mesma família saem num bloco só, sem perder id nenhum", async () => {
  const ctx = await buildContext({ target: CORPUS + AMM, network: "mainnet", generatedAt: DATA, offline: true });
  const init = ctx.findings.filter((f) => f.class === "initialization-front-running");
  assert.equal(init.length, 5, `o corpus mudou: esperados 5 achados de init, vieram ${init.length}`);
  assert.ok(init.every((f) => f.family === "init"), "achado de init sem família");

  const tm = renderThreatModel(ctx);

  // um único bloco de detalhamento para os cinco
  const titulos = tm.match(/^#### Elevation\.\d+.*$/gm) ?? [];
  assert.equal(titulos.length, 1, `esperado um bloco agregado, vieram ${titulos.length}: ${titulos.join(" | ")}`);
  assert.match(titulos[0], /^#### Elevation\.1 – Elevation\.5 — `initialization-front-running` in 5 entrypoints$/);

  const bloco = tm.slice(tm.indexOf(titulos[0]));
  for (const f of init) {
    const re = new RegExp(`^\\| \\*\\*${f.id}\\*\\* \\| \`${f.entrypoint}\` \\| \\[A\\]\\+\\[C\\] \\| ${f.severity} \\|`, "m");
    assert.match(bloco, re, `linha da tabela agregada ausente para ${f.id}`);
  }
  assert.match(bloco, /\*\*Per-ID anchors:\*\*/);

  // e o validador continua achando cada id — nada de âncora perdida
  const r = validateThreatModel(ctx, tm);
  for (const f of init) {
    assert.ok(!r.blockers.some((b) => b.includes(`${f.id} exists in the analysis`)), `${f.id} sumiu do documento`);
  }
  assert.deepEqual(r.blockers, [], `agregação criou blocker: ${r.blockers.join(" | ")}`);

  // agregar é de apresentação: a tabela de ameaças e as remediações mantêm os cinco ids
  for (const f of init) {
    assert.ok(tm.includes(`**${f.id}** — `), `${f.id} sumiu da tabela de ameaças`);
    assert.ok(tm.includes(`${f.id}.R.1`), `${f.id} sumiu das remediações`);
  }
});
