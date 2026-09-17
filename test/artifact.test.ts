import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { buildContext } from "../src/pipeline.ts";
import { renderThreatModel } from "../src/render/threatmodel.ts";
import { renderMonitoringPlan } from "../src/render/monitoring.ts";
import { validateThreatModel, validateMonitoringPlan } from "../src/validate.ts";
import { setLang, type Lang } from "../src/i18n.ts";
import type { ArtifactContext, Monitor, Observations } from "../src/artifact.ts";

const CORPUS = new URL("../corpus/", import.meta.url).pathname;
const amostra = readdirSync(CORPUS).filter((f) => f.endsWith(".wasm")).slice(0, 6);
const DATA = "2026-09-17";

async function gerar(f: string, lang: Lang = "en") {
  // `buildContext` aplica `setLang` — o idioma vale para todos os renderizadores.
  const ctx = await buildContext({ target: CORPUS + f, network: "mainnet", generatedAt: DATA, offline: true, lang });
  return { ctx, tm: renderThreatModel(ctx), mp: renderMonitoringPlan(ctx) };
}

/**
 * Nível B injetado. O corpus é offline por construção (arquivo `.wasm` não tem histórico
 * on-chain), então as frases que dependem de janela observada só são exercitáveis com a
 * observação montada à mão — e são exatamente as que um revisor compara contra a seção B
 * do mesmo documento.
 */
const observacao = (over: Partial<Observations["window"]> = {}, eventos = 1): Observations => ({
  window: { fromLedger: 1_000, toLedger: 134_000, ledgers: 133_000, approxHours: 186, insufficient: false, ...over },
  events: eventos
    ? [{ topic: "transfer", count: 412, firstLedger: 1_000, lastLedger: 134_000, ratePerHour: 2.2 }]
    : [],
  declaredButUnseen: ["paused"],
});

const monitorB = (threatId: string, baselineTier: Monitor["baselineTier"]): Monitor => ({
  id: `${threatId}.M.9`,
  threatId,
  observable: "events with topic `transfer`",
  trigger: "rate above baseline",
  baseline: "412 events in ~186 h",
  baselineTier,
  severity: "Medium",
  response: "investigate",
  status: "Planned",
});

test("geração é determinística: mesma entrada, mesma saída", async () => {
  const a = await gerar(amostra[0]);
  const b = await gerar(amostra[0]);
  assert.equal(a.tm, b.tm, "threat model variou entre execuções");
  assert.equal(a.mp, b.mp, "monitoring plan variou entre execuções");
});

test("threat model tem as quatro seções do template oficial", async () => {
  for (const f of amostra) {
    const { tm } = await gerar(f);
    for (const sec of ["What are we working on?", "What can go wrong?", "What are we going to do about it?", "Did we do a good job?"]) {
      assert.ok(tm.includes(sec), `${f}: falta a seção "${sec}"`);
    }
  }
});

test("monitoring plan tem as seis seções do template oficial", async () => {
  for (const f of amostra) {
    const { mp } = await gerar(f);
    for (const sec of ["What are we monitoring?", "What could go wrong?", "What does exploitation look like on-chain?", "What will we monitor for?", "What happens when an alert fires?", "Did we do a good job?"]) {
      assert.ok(mp.includes(sec), `${f}: falta a seção "${sec}"`);
    }
  }
});

test("todo monitor rastreia até uma ameaça existente", async () => {
  for (const f of amostra) {
    const { ctx } = await gerar(f);
    const ids = new Set(ctx.findings.map((x) => x.id));
    for (const m of ctx.monitors ?? []) {
      assert.ok(ids.has(m.threatId), `${f}: monitor ${m.id} aponta para ameaça inexistente ${m.threatId}`);
      assert.match(m.id, new RegExp(`^${m.threatId.replace(".", "\\.")}\\.M\\.\\d+$`), `${f}: id de monitor fora do padrão: ${m.id}`);
    }
  }
});

test("baseline sem observação nunca vira número inventado", async () => {
  for (const f of amostra) {
    const { ctx } = await gerar(f);
    for (const m of ctx.monitors ?? []) {
      if (m.baselineTier === "none") {
        assert.ok(/sem baseline|não derivável|a definir|insuficiente|no baseline|not derivable|to be defined|insufficient|⟨/i.test(m.baseline),
          `${f}: ${m.id} sem observação mas com baseline afirmativo: "${m.baseline}"`);
      }
    }
  }
});

test("validador aponta lacuna em vez de aprovar tudo", async () => {
  let comGap = 0;
  for (const f of amostra) {
    const { ctx, tm, mp } = await gerar(f);
    const v1 = validateThreatModel(ctx, tm);
    const v2 = validateMonitoringPlan(ctx, mp, ctx.monitors ?? []);
    for (const v of [v1, v2]) {
      assert.ok(v.items.length > 0, `${f}: validador sem itens`);
      for (const i of v.items) assert.ok(i.detail.length > 15, `${f}: item "${i.question}" sem justificativa`);
      if (v.items.some((i) => i.status === "gap")) comGap++;
    }
  }
  // Em modo offline não há nível B: um validador que aprovasse tudo estaria quebrado.
  assert.ok(comGap > 0, "nenhuma lacuna apontada em nenhum documento — validador suspeito");
});

test("letras do STRIDE sem achado aparecem como lacuna declarada, não preenchidas", async () => {
  for (const f of amostra) {
    const { ctx, tm } = await gerar(f);
    for (const g of ctx.gaps) {
      assert.ok(tm.includes(g), `${f}: lacuna ${g} não aparece no documento`);
    }
  }
});

test("o threat model sai em inglês por padrão", async () => {
  const { tm } = await gerar(amostra[0]);
  for (const t of [
    "### Analyzed object",
    "### How to read the evidence",
    "| Tier | Means | Who can verify |",
    "### Exported surface",
    "**Gap to be filled by the team.**",
    "Human review is mandatory before submission",
  ]) {
    assert.ok(tm.includes(t), `saída em inglês sem "${t}"`);
  }
  // Nenhuma marca de português nas seções que este módulo renderiza.
  assert.ok(!tm.includes("Lacuna a preencher pela equipe"), "texto em português na saída padrão");
  // Tokens language-neutral: os outros módulos casam com eles por regex.
  assert.ok(tm.includes("What are we working on?") && tm.includes("Did we do a good job?"), "cabeçalhos do template alterados");
  assert.match(tm, /\*\*\[[ABC]\]\*\*|_Sem|No threat derivable/);
});

test("--lang pt mantém o threat model em português", async (t) => {
  t.after(() => setLang("en"));
  const { tm } = await gerar(amostra[0], "pt");
  for (const s of [
    "### Objeto analisado",
    "### Como ler a evidência",
    "| Nível | Significa | Quem consegue verificar |",
    "### Superfície exportada",
    "**Lacuna a preencher pela equipe.**",
    "Revisão humana é obrigatória antes de submeter",
  ]) {
    assert.ok(tm.includes(s), `saída em português sem "${s}"`);
  }
  // Os quatro cabeçalhos oficiais são do template e NÃO se traduzem.
  for (const sec of ["What are we working on?", "What can go wrong?", "What are we going to do about it?", "Did we do a good job?"]) {
    assert.ok(tm.includes(sec), `cabeçalho oficial "${sec}" traduzido por engano`);
  }
});

/* ------------------------------------------------------------------ *
 * Afirmações que um revisor derruba comparando seções do mesmo documento.
 * Cada teste abaixo nasce de uma frase que estava insustentável nos
 * exemplos gerados — a regressão é que ela volte.
 * ------------------------------------------------------------------ */

test("a frase de nível B só promete baseline real quando algum monitor o ancora", async () => {
  const { ctx } = await gerar(amostra[0]);
  const alvo = ctx.findings[0]?.id ?? "Elevation.1";

  // (a) janela observada e NENHUM monitor com baseline de nível B: o documento não pode
  // dizer que a observação "permite baseline real" — ninguém a usou.
  const semAncora: ArtifactContext = {
    ...ctx, offline: false, observations: observacao(), monitors: [monitorB(alvo, "none")],
  };
  const tmSem = renderThreatModel(semAncora);
  assert.match(tmSem, /no monitor in the sibling plan\s+could anchor a baseline on it/);
  assert.ok(tmSem.includes("133000 ledgers, ~186 h, 412 events across 1 topic"),
    "a frase sem âncora precisa dizer o que FOI observado, em números");
  assert.ok(!tmSem.includes("allows a real baseline"), "promessa de baseline sem monitor que o ancore");

  // (b) com monitor de nível B, a mesma janela passa a sustentar a frase.
  const comAncora: ArtifactContext = { ...semAncora, monitors: [monitorB(alvo, "B")] };
  const tmCom = renderThreatModel(comAncora);
  assert.match(tmCom, /1 monitor in the sibling plan anchors\s+a baseline on it/);

  // (c) zero tráfego na janela: o motivo muda, e é o motivo que o revisor confere.
  const semTrafego: ArtifactContext = { ...semAncora, observations: observacao({}, 0) };
  assert.ok(renderThreatModel(semTrafego).includes("no event of any topic was observed"),
    "janela vazia precisa dizer que não há de onde tirar taxa");
});

test("a negativa de alcançabilidade não é apresentada como prova sem escopo", async () => {
  for (const f of amostra) {
    const { tm } = await gerar(f);
    // Nenhuma variante de "a negativa é prova" sobrevive: a negativa é sólida PARA ESTE
    // call graph, e nada diz sobre auth dentro de um callee ou no `__check_auth`.
    for (const proibido of [/\bis proof\b/, /\bare proof\b/, /holds? as proof\b/, /stops? being proof\b/, /count as proof\b/]) {
      assert.ok(!proibido.test(tm), `${f}: afirmação de prova sem escopo — ${proibido}`);
    }
    // Toda ocorrência restante de "proof" tem de ser negação ou prova off-chain de ação,
    // nunca a solidez da análise.
    for (const m of tm.matchAll(/[^.\n]*\bproof\b[^.\n]*/g)) {
      assert.match(m[0], /not proof|no off-chain proof|off-chain proof/,
        `${f}: uso de "proof" fora das negações: ${m[0].trim().slice(0, 120)}`);
    }
    assert.ok(tm.includes("sound negative for this module's call graph"),
      `${f}: falta a afirmação precisa que substitui "is proof"`);
  }
});

test("módulo que exporta __check_auth declara que a negativa de require_auth é o esperado", async () => {
  const { ctx } = await gerar(amostra[0]);
  const semConta = renderThreatModel(ctx);
  assert.ok(!semConta.includes("so it is a **custom account**"), "nota de conta customizada em contrato que não é uma");

  const conta: ArtifactContext = {
    ...ctx,
    spec: { ...ctx.spec, fns: [...ctx.spec.fns, { name: "__check_auth", params: [], returns: "void", doc: "", traits: [] }] },
  };
  const tm = renderThreatModel(conta);
  assert.ok(tm.includes("__check_auth"), "o documento não nomeia o `__check_auth` exportado");
  assert.match(tm, /custom account.*authorization is implemented/s);
  assert.ok(tm.includes("is not itself a finding"), "falta dizer que a negativa ali é a forma esperada");
});

/** Exporta `__constructor` E `initialize` — o init é segunda etapa, não o init do deploy. */
const CTOR_MAIS_INIT = "CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ.wasm";
/** Não exporta `__constructor`: aí sim "mover para o construtor" é a remediação certa. */
const SEM_CTOR = "CAG5LRYQ5JVEUI5TEID72EYOVX44TTUJT5BQR2J6J77FH65PCCFAJDDH.wasm";

test("com `__constructor` exportado, a remediação de init não manda redeployar a instância viva", async () => {
  const { ctx, tm } = await gerar(CTOR_MAIS_INIT);
  assert.ok(ctx.analysis.entrypoints.some((e) => e.name === "__constructor"), "o caso perdeu o pressuposto");
  const init = ctx.findings.find((f) => f.class === "initialization-front-running");
  assert.ok(init, "o caso perdeu o achado de init");

  assert.ok(
    !/Move `\w+`'s initialization into `__constructor`/.test(tm),
    "documento manda mover a inicialização para um `__constructor` que já existe",
  );
  assert.ok(tm.includes("The contract already exports `__constructor`"), "a remediação ignora o construtor existente");
  assert.ok(
    tm.includes(`verify in the source that \`${init!.entrypoint}\` is guarded against re-initialization`),
    "a remediação não manda verificar a guarda no fonte",
  );
  assert.match(tm, /`has_contract_data` path suggests it is|no `has_contract_data` is reachable/);
  assert.ok(tm.includes("close the finding as accepted"), "falta o desfecho de aceitação quando a guarda existe");
  assert.ok(tm.includes("gate it on the admin the constructor recorded"), "falta o desfecho para quando não há guarda");
  assert.ok(tm.includes("Redeploying the live instance is not on the table"), "falta recusar o redeploy explicitamente");
});

test("sem `__constructor`, mover a inicialização para o construtor continua sendo a remediação", async () => {
  const { ctx, tm } = await gerar(SEM_CTOR);
  assert.ok(!ctx.analysis.entrypoints.some((e) => e.name === "__constructor"), "o caso perdeu o pressuposto");
  const init = ctx.findings.find((f) => f.class === "initialization-front-running");
  assert.ok(init, "o caso perdeu o achado de init");
  assert.ok(
    tm.includes(`Move \`${init!.entrypoint}\`'s initialization into \`__constructor\``),
    "a remediação de init sumiu onde ela é a certa",
  );
  assert.ok(!tm.includes("The contract already exports `__constructor`"), "afirmou construtor onde não há");
});

/** Células da tabela da seção 3 que declaram lacuna em vez de remediação. */
function celulasDeLacuna(tm: string): string[] {
  const i = tm.indexOf("## What are we going to do about it?");
  assert.ok(i > 0, "o documento não tem a seção de remediações");
  const fim = tm.indexOf("\n---", i);
  return tm
    .slice(i, fim > 0 ? fim : undefined)
    .split("\n")
    .filter((l) => l.startsWith("|") && l.includes("_No remediation"))
    .map((l) => l.replace(/^\|[^|]*\|/, "").replace(/\|\s*$/, "").trim());
}

test("as células de lacuna da seção 3 citam a planilha da própria letra, e nunca se repetem", async () => {
  let comLacuna = 0;
  for (const f of amostra) {
    const { tm } = await gerar(f);
    const celulas = celulasDeLacuna(tm);
    if (!celulas.length) continue;
    comLacuna++;
    // O cabeçalho do próprio documento promete "nunca preenchido com genérico": quatro células
    // idênticas eram exatamente isso, com a promessa impressa duas seções acima.
    assert.equal(new Set(celulas).size, celulas.length, `${f}: células de lacuna repetidas na seção 3`);
    for (const c of celulas) {
      assert.ok(
        c.includes("The work this letter leaves for the review:"),
        `${f}: célula de lacuna sem o trabalho da letra: ${c.slice(0, 120)}`,
      );
      assert.ok(c.includes(" gap"), `${f}: a célula não aponta a lacuna de onde tirar o trabalho: ${c.slice(0, 120)}`);
    }
  }
  assert.ok(comLacuna > 0, "nenhum contrato da amostra tem letra em lacuna: o teste não conferiu nada");
});

test("cada letra em lacuna cita a superfície da SUA seção, não a do vizinho", async () => {
  const { tm } = await gerar(amostra[0]);
  const celulas = celulasDeLacuna(tm);
  const porLetra = new Map(
    tm
      .split("\n")
      .filter((l) => l.startsWith("|") && l.includes("_No remediation"))
      .map((l) => [l.split("|")[1].trim(), l] as const),
  );
  if (porLetra.has("Spoofing")) {
    assert.match(porLetra.get("Spoofing")!, /Spoofing gap/);
    assert.match(porLetra.get("Spoofing")!, /key|custody/i);
  }
  if (porLetra.has("Information disclosure")) {
    assert.match(porLetra.get("Information disclosure")!, /inferred storage key|declared event topic/);
    assert.match(porLetra.get("Information disclosure")!, /Information-disclosure gap/);
  }
  assert.ok(celulas.length >= 2, "amostra sem duas letras em lacuna");
});

test("a lacuna de Spoofing separa entrypoint administrativo de operação do próprio chamador", async () => {
  let conferidos = 0;
  for (const f of amostra) {
    const { ctx, tm } = await gerar(f);
    if (!tm.includes("Where identity is asserted in this contract")) continue;
    const autenticam = ctx.analysis.entrypoints.filter((e) => !e.name.startsWith("__") && e.reaches.has("require_auth"));
    if (!autenticam.length) continue;
    conferidos++;
    // A separação é heurística de nome e o documento tem que dizer isso — senão é nível C
    // vestido de trabalho derivado do bytecode.
    assert.ok(tm.includes("This split is a name-shape heuristic (tier C), not a bytecode fact"),
      `${f}: a separação admin/usuário saiu sem se declarar heurística`);
    const admin = /^(set|transfer|commit|apply|revert)_|^(upgrade|pause)(_|$)|^(kill|admin|initialize)/i;
    const usuarios = autenticam.filter((e) => !admin.test(e.name)).map((e) => e.name);
    if (usuarios.length) {
      assert.ok(tm.includes("the caller authorizing"), `${f}: não diz que o user-shaped autoriza o próprio endereço`);
      assert.ok(tm.includes("User-shaped"), `${f}: os entrypoints de usuário não foram separados`);
      // e a frase antiga, que mandava rastrear TODOS até um detentor de chave, não pode sobrar
      assert.ok(
        !/reach `require_auth\*` \([^)]*\) — those are the calls whose `Address`/.test(tm),
        `${f}: sobrou a lista única mandando rastrear todo require_auth até um detentor de chave`,
      );
    }
  }
  assert.ok(conferidos > 0, "nenhum contrato da amostra exercitou a lacuna de Spoofing com require_auth");
});

test("achado de inicialização com tráfego observado vira risco de re-inicialização", async () => {
  const { ctx } = await gerar(amostra[0]);
  const init = ctx.findings.filter((f) => f.class === "initialization-front-running");
  assert.ok(init.length, "o corpus não trouxe achado de inicialização: o teste não conferiu nada");

  const comTrafego: ArtifactContext = { ...ctx, offline: false, observations: observacao() };
  const tm = renderThreatModel(comTrafego);
  assert.ok(tm.includes("Tier B/C note"), "falta a nota que reconcilia o nível C com o nível B");
  assert.match(tm, /412 events over ~186 h/);
  assert.ok(tm.includes("already initialized"), "a nota não diz o que o tráfego indica");
  assert.ok(tm.includes("re-initialization"), "a nota não nomeia o risco residual");
  assert.match(tm, /has_contract_data` (IS|IS NOT) in the reachable set of/);

  // Sem observação, a nota não pode aparecer: ela é uma afirmação de nível B.
  assert.ok(!renderThreatModel(ctx).includes("Tier B/C note"), "nota de nível B sem janela observada");
});

test("as duas contagens de entrypoint saem explícitas, para casar com o monitoring plan", async () => {
  for (const f of amostra) {
    const { ctx, tm } = await gerar(f);
    const exportados = ctx.analysis.entrypoints.length;
    const invocaveis = ctx.analysis.entrypoints.filter((e) => !e.name.startsWith("__")).length;
    if (!invocaveis) continue;
    assert.ok(tm.includes(`${exportados} exported, ${invocaveis} invocable`),
      `${f}: o documento não imprime as duas contagens (${exportados}/${invocaveis})`);
    assert.ok(tm.includes(exportados === invocaveis ? "the two counts coincide" : "CAP-0058"),
      `${f}: a diferença entre as contagens não é explicada`);
  }
});

test("a lacuna de DoS hedgia a positiva de TTL em vez de listar getters", async () => {
  for (const f of amostra) {
    const { ctx, tm } = await gerar(f);
    if (!tm.includes("`extend_*_ttl` family")) continue;
    assert.match(tm, /\d+ exports? reach(es)? the `extend_\*_ttl` family, the nearest at \d+ hops?/);
    assert.ok(tm.includes("Read that count as an over-approximation"), `${f}: positiva de TTL sem ressalva`);
    // No máximo 6 nomes antes do corte — a lista de 90 nomes era o próprio ruído.
    const m = /`extend_\*_ttl` family[^(]*\(([^)]*)\)/.exec(tm);
    assert.ok(m, `${f}: lista de TTL não encontrada`);
    const nomes = m![1].split(" and ")[0].split(", ").filter((x) => x.startsWith("`"));
    assert.ok(nomes.length <= 6, `${f}: ${nomes.length} nomes na lista de TTL`);
    void ctx;
  }
});

test("a lacuna de Spoof/Info cita a superfície deste contrato, não só o texto estrutural", async () => {
  const docs = await Promise.all(amostra.slice(0, 3).map((f) => gerar(f)));
  const trechos = docs.map(({ tm }) => {
    const s = /\*\*Where identity is asserted in this contract:\*\*(.*)/.exec(tm);
    assert.ok(s, "lacuna de Spoof sem linha específica do contrato");
    return s![1];
  });
  // Dois contratos diferentes não podem produzir a MESMA frase: era o defeito original.
  assert.ok(new Set(trechos).size > 1, "a linha de Spoof é idêntica entre contratos");
  for (const { tm } of docs) {
    assert.ok(tm.includes("The concrete surface to review in this contract:"), "lacuna de Info sem superfície concreta");
  }
});

test("a ausência de tópico na janela não é chamada de janela curta quando ela é longa", async () => {
  const { ctx } = await gerar(amostra[0]);
  const longa: ArtifactContext = { ...ctx, offline: false, observations: observacao() };
  const tmLonga = renderThreatModel(longa);
  assert.ok(tmLonga.includes("Absence over a ~186 h window"), "janela longa descrita como curta");
  assert.ok(!tmLonga.includes("window this short"), "janela de 186 h chamada de curta");

  const curta: ArtifactContext = {
    ...ctx, offline: false, observations: observacao({ insufficient: true, ledgers: 120, approxHours: 1 }),
  };
  assert.ok(renderThreatModel(curta).includes("window this short"), "janela insuficiente sem a ressalva");
});

test("a pergunta sobre o DFD não se responde com tautologia", async () => {
  const { tm } = await gerar(amostra[0]);
  assert.ok(!tm.includes("Within this document, yes"), "resposta tautológica sobre o DFD de volta");
  assert.ok(tm.includes("The tool cannot answer this one."), "a resposta não declara o que a ferramenta não sabe");
  assert.match(tm, /the diagram's \d+ trust boundar(y|ies) over \d+ `process` nodes?/);
});

test("a remediação de mutação silenciosa não afirma que o plano irmão não cobre a ação", async () => {
  const alvo = amostra.map((f) => f);
  let conferidos = 0;
  for (const f of alvo) {
    const { ctx, tm } = await gerar(f);
    if (!ctx.findings.some((x) => x.class === "silent-mutation")) continue;
    assert.ok(!tm.includes("stay outside the monitoring plan by construction"), `${f}: afirmação contradita pelo plano irmão`);
    assert.ok(tm.includes("outside *event-based* monitoring"), `${f}: falta a precisão sobre o tipo de monitoramento`);
    assert.ok(tm.includes("getLedgerEntries"), `${f}: falta a alternativa de diff de estado`);
    conferidos++;
  }
  assert.ok(conferidos > 0, "nenhuma mutação silenciosa no corpus: o teste não conferiu nada");
});

test("a lacuna de Tampering declara ausência de sinal, não ordem correta", async () => {
  for (const f of amostra) {
    const { tm } = await gerar(f);
    if (!tm.includes("`write-before-auth`")) continue;
    assert.ok(!tm.includes("No body reached by an export has its first write preceding"),
      `${f}: no-signal apresentado como resultado negativo`);
    if (tm.includes("The write-before-auth detector compares offsets")) {
      assert.ok(tm.includes("absence of signal"), `${f}: falta dizer que é ausência de sinal`);
    }
  }
});

test("--lang pt acompanha as frases reescritas", async (t) => {
  t.after(() => setLang("en"));
  const { ctx, tm } = await gerar(amostra[0], "pt");
  assert.match(tm, /\d+ exportados, \d+ entrypoints? invoc/);
  assert.ok(tm.includes("A ferramenta não responde esta."), "resposta do DFD não traduzida");
  assert.ok(tm.includes("negativa sólida para o call graph deste módulo"), "escopo da negativa não traduzido");
  assert.ok(tm.includes("Onde a identidade é afirmada neste contrato:"), "lacuna de Spoof não traduzida");

  const comTrafego: ArtifactContext = { ...ctx, offline: false, observations: observacao() };
  const tmB = renderThreatModel(comTrafego);
  assert.ok(tmB.includes("Nota de nível B/C."), "nota de inicialização não traduzida");
  assert.ok(tmB.includes("janela de ~186 h"), "ressalva de janela não traduzida");
  assert.ok(tmB.includes("nenhum monitor do plano irmão"), "frase de nível B sem âncora não traduzida");
});
