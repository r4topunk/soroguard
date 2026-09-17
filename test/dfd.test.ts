import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { analyzeModule, type ModuleAnalysis } from "../src/analyze.ts";
import { inferStorageKeys } from "../src/storagekeys.ts";
import { buildDfd } from "../src/render/dfd.ts";
import { setLang } from "../src/i18n.ts";
import { detect } from "../src/detect.ts";
import { STORAGE_WRITE_FNS } from "../src/hostfns.ts";
import type { ArtifactContext, Dfd } from "../src/artifact.ts";
import type { ContractModel } from "../src/model.ts";

const CORPUS = new URL("../corpus/", import.meta.url).pathname;
const files = readdirSync(CORPUS).filter((f) => f.endsWith(".wasm"));
const load = (f: string) => new Uint8Array(readFileSync(CORPUS + f));

const ctxDe = (
  contractId: string,
  analysis: ModuleAnalysis,
  storageKeys?: { key: string; confidence: "certain" | "likely" }[],
): ArtifactContext => ({
  contractId,
  network: "mainnet",
  // data fixa: o renderizador não lê relógio, então o mesmo binário sai idêntico sempre
  generatedAt: "2026-01-01T00:00:00.000Z",
  spec: {} as ContractModel,
  analysis,
  findings: [],
  gaps: [],
  storageKeys,
});

/**
 * Validador estrutural do subconjunto da gramática de flowchart que `dfd.ts` emite.
 * Sem parser oficial do Mermaid porque o projeto não aceita dependência nova — então a
 * checagem é sobre o que de fato quebra o parser: id inválido, subgraph não fechado,
 * aresta cujo nó não existe e rótulo com caractere de controle.
 */
const RESERVADAS = new Set(["end", "graph", "subgraph", "click", "class", "classDef", "style", "linkStyle", "o", "x", "flowchart", "default"]);
const FORMAS = [
  /^([A-Za-z_][A-Za-z0-9_]*)\(\["(.*)"\]\)$/,
  /^([A-Za-z_][A-Za-z0-9_]*)\[\("(.*)"\)\]$/,
  /^([A-Za-z_][A-Za-z0-9_]*)\[\["(.*)"\]\]$/,
  /^([A-Za-z_][A-Za-z0-9_]*)\["(.*)"\]$/,
];

function erros(dfd: Dfd): string[] {
  const e: string[] = [];
  const linhas = dfd.mermaid.split("\n");
  const util = linhas.filter((l) => !l.startsWith("%%"));
  if (util[0] !== "flowchart LR") e.push(`cabeçalho inesperado: ${util[0]}`);

  const decl = new Set<string>();
  const subg = new Set<string>();
  const arestas: [string, string][] = [];
  const rotulos: string[] = [];
  let prof = 0, maxProf = 0;

  for (const raw of linhas) {
    const t = raw.trim();
    if (!t || t.startsWith("%%") || t === "flowchart LR") continue;
    if (t === "end") { if (--prof < 0) e.push("`end` sem subgraph aberto"); continue; }
    let m: RegExpExecArray | null;
    if ((m = /^subgraph ([A-Za-z_][A-Za-z0-9_]*)\["(.*)"\]$/.exec(t))) {
      subg.add(m[1]); rotulos.push(m[2]); maxProf = Math.max(maxProf, ++prof); continue;
    }
    if ((m = /^([A-Za-z_][A-Za-z0-9_]*) (?:-->|-\.->)\|"(.*)"\| ([A-Za-z_][A-Za-z0-9_]*)$/.exec(t))) {
      arestas.push([m[1], m[3]]); rotulos.push(m[2]); continue;
    }
    if (/^classDef [A-Za-z][A-Za-z0-9_]* [a-z-]+:#?[0-9a-zA-Z]+(,[a-z-]+:#?[0-9a-zA-Z]+)*$/.test(t)) continue;
    if ((m = /^class ([A-Za-z_][A-Za-z0-9_,]*) [A-Za-z][A-Za-z0-9_]*$/.exec(t))) {
      for (const id of m[1].split(",")) if (!decl.has(id)) e.push(`class aponta para nó não declarado: ${id}`);
      continue;
    }
    const forma = FORMAS.map((f) => f.exec(t)).find(Boolean);
    if (!forma) { e.push(`linha fora da gramática: ${t}`); continue; }
    if (decl.has(forma[1])) e.push(`nó declarado duas vezes: ${forma[1]}`);
    decl.add(forma[1]);
    rotulos.push(forma[2]);
  }

  if (prof !== 0) e.push(`subgraph não fechado (saldo ${prof})`);
  if (maxProf > 1) e.push(`subgraph aninhado: ${maxProf}`);
  for (const id of [...decl, ...subg]) if (RESERVADAS.has(id)) e.push(`id reservado pelo mermaid: ${id}`);
  for (const id of subg) if (decl.has(id)) e.push(`id colide entre subgraph e nó: ${id}`);
  for (const r of rotulos) { const mau = /["#<>|{}`]/.exec(r); if (mau) e.push(`rótulo com ${mau[0]}: ${r.slice(0, 50)}`); }

  const tocados = new Set<string>();
  for (const [a, b] of arestas) {
    if (!decl.has(a)) e.push(`aresta órfã: ${a} não declarado`);
    if (!decl.has(b)) e.push(`aresta órfã: ${b} não declarado`);
    tocados.add(a); tocados.add(b);
  }
  // nó único é a saída legítima do módulo sem entrypoint: declara a lacuna
  if (decl.size > 1) for (const id of decl) if (!tocados.has(id)) e.push(`nó isolado: ${id}`);

  const modelo = new Set(dfd.nodes.map((n) => n.id));
  for (const id of modelo) if (!decl.has(id)) e.push(`nó do modelo ausente do mermaid: ${id}`);
  for (const id of decl) if (!modelo.has(id)) e.push(`nó do mermaid ausente do modelo: ${id}`);
  if (dfd.edges.length !== arestas.length) e.push(`modelo ${dfd.edges.length} arestas × mermaid ${arestas.length}`);
  const emFronteira = new Set<string>();
  for (const b of dfd.boundaries) {
    if (!subg.has(b.id)) e.push(`fronteira sem subgraph: ${b.id}`);
    for (const id of b.contains) {
      if (!modelo.has(id)) e.push(`fronteira ${b.id} contém id inexistente: ${id}`);
      if (emFronteira.has(id)) e.push(`nó em duas fronteiras: ${id}`);
      emFronteira.add(id);
    }
  }
  if (subg.size !== dfd.boundaries.length) e.push("subgraphs != fronteiras");
  return e;
}

test("mermaid do DFD é sintaticamente válido em todo o corpus, com e sem chaves inferidas", () => {
  assert.ok(files.length >= 5, `corpus pequeno demais: ${files.length}`);
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    let chaves: { key: string; confidence: "certain" | "likely" }[] | undefined;
    try { chaves = inferStorageKeys(wasm).map((k) => ({ key: k.key, confidence: k.confidence })); } catch { chaves = undefined; }
    for (const k of [chaves?.length ? chaves : undefined, undefined]) {
      const e = erros(buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an, k)));
      assert.deepEqual(e, [], `${f}: ${e.join(" | ")}`);
    }
  }
});

test("entrypoint sem require_auth alcançável fica fora da fronteira autenticada", () => {
  for (const f of files) {
    const an = analyzeModule(load(f));
    const dfd = buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an));
    const auth = dfd.boundaries.find((b) => b.id === "tb_auth");
    if (!auth) continue;
    const dentro = new Set(auth.contains);
    for (const n of dfd.nodes) {
      if (n.kind !== "process" || !dentro.has(n.id)) continue;
      const ep = an.entrypoints.find((x) => x.name === n.entrypoint)!;
      const alcanca = ep.reaches.has("require_auth") || ep.reaches.has("require_auth_for_args");
      assert.ok(alcanca, `${f}: ${n.entrypoint} está na fronteira autenticada sem alcançar require_auth*`);
    }
  }
});

test("todo entrypoint exportado vira exatamente um processo com um chamador", () => {
  for (const f of files) {
    const an = analyzeModule(load(f));
    const dfd = buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an));
    const procs = dfd.nodes.filter((n) => n.kind === "process");
    assert.equal(procs.length, an.entrypoints.length, `${f}: processos != entrypoints`);
    const externos = new Set(dfd.nodes.filter((n) => n.kind === "external").map((n) => n.id));
    for (const p of procs) {
      const entradas = dfd.edges.filter((e) => e.to === p.id && externos.has(e.from));
      assert.equal(entradas.length, 1, `${f}: ${p.id} tem ${entradas.length} chamadores externos`);
    }
  }
});

test("o diagrama não afirma acesso por chave de storage, que a análise não atribui", () => {
  const f = files[0];
  const an = analyzeModule(load(f));
  const dfd = buildDfd(ctxDe("CTESTE", an, [{ key: "Admin", confidence: "certain" }]));
  const stores = new Set(dfd.nodes.filter((n) => n.kind === "store").map((n) => n.id));
  const procs = new Set(dfd.nodes.filter((n) => n.kind === "process").map((n) => n.id));
  const chave = dfd.nodes.find((n) => n.kind === "store" && n.label.startsWith("Admin"))!;
  assert.ok(chave, "chave inferida não virou data store");
  for (const e of dfd.edges) {
    if (e.to !== chave.id) continue;
    assert.ok(!procs.has(e.from), "aresta processo → chave afirma atribuição que o contexto não dá");
    assert.ok(stores.has(e.from), "chave deve pender do store do contrato");
  }
});

test("módulo sem entrypoint declara a lacuna em vez de emitir diagrama vazio", () => {
  const vazio = {
    entrypoints: [], imports: [], unreachableImports: [],
    hasIndirectAnywhere: false, soundness: "sound", writeBeforeAuth: new Map(),
  } as unknown as ModuleAnalysis;
  const dfd = buildDfd(ctxDe("CVAZIO", vazio));
  assert.deepEqual(erros(dfd), []);
  assert.equal(dfd.nodes.length, 1);
  assert.match(dfd.nodes[0].label, /No exported entrypoint/);
});

/**
 * Os três testes abaixo existem porque o diagrama e a tabela de ameaças saem do MESMO
 * binário no MESMO laudo. Se divergirem sobre a força de uma afirmação, o revisor tem dois
 * documentos do mesmo contrato se contradizendo — que é pior que qualquer um dos dois
 * sozinho estar errado.
 */

test("toda positiva do diagrama carrega saltos, e o † concorda com o limiar de detect.ts", () => {
  for (const f of files) {
    const an = analyzeModule(load(f));
    const dfd = buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an));
    for (const n of dfd.nodes) {
      if (n.kind !== "process") continue;
      const ep = an.entrypoints.find((x) => x.name === n.entrypoint)!;
      const corpo = n.label.split(" ⚠ ")[0];
      // A negativa "nenhuma host function alcançada" é conferível com um wasm-objdump.
      // Só pode aparecer quando o alcance é de fato vazio.
      if (/— no host function reached$/.test(corpo)) {
        assert.equal(ep.reaches.size, 0, `${f}: ${ep.name} rotulado sem alcance mas alcança ${[...ep.reaches]}`);
        continue;
      }
      const semMarca = /— reaches (\d+) host function\(s\), none from /.exec(corpo);
      if (semMarca) {
        assert.equal(Number(semMarca[1]), ep.reaches.size, `${f}: ${ep.name} conta host functions errado`);
        continue;
      }
      const marcas = corpo.split("): ")[1];
      assert.ok(marcas, `${f}: ${ep.name} sem lista de marcadores: ${n.label}`);
      for (const m of marcas.split(", ")) {
        const mm = /^(.+?) (\d+)(†?)$/.exec(m);
        // Nenhuma positiva pode aparecer nua: sem o número de saltos ela seria afirmada
        // com a força de um fato, que é exatamente o que docs/CALIBRACAO.md proíbe.
        assert.ok(mm, `${f}: ${ep.name} tem marcador sem contagem de saltos: "${m}"`);
        assert.equal(mm[3] === "†", Number(mm[2]) > 2, `${f}: ${ep.name} marcador "${m}" com † fora do limiar`);
      }
    }
  }
});

test("a contagem de saltos da escrita é a mesma de detect.ts, e o † nunca contradiz a severidade", () => {
  let conferidos = 0;
  for (const f of files) {
    const an = analyzeModule(load(f));
    const dfd = buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an));
    const byEp = new Map(dfd.nodes.filter((n) => n.kind === "process").map((n) => [(n as any).entrypoint as string, n.label]));
    for (const fi of detect(an)) {
      if (fi.class !== "unauthenticated-state-mutation" && fi.class !== "initialization-front-running") continue;
      const label = byEp.get(fi.entrypoint);
      assert.ok(label, `${f}: achado em ${fi.entrypoint} sem processo no diagrama`);
      // A mesma conta de detect.ts: primeira write fn alcançável, pathTo.length - 1.
      const ep = an.entrypoints.find((x) => x.name === fi.entrypoint)!;
      const p = [...STORAGE_WRITE_FNS].map((x) => ep.pathTo.get(x)).filter(Boolean)[0] as readonly number[];
      const hops = p.length - 1;
      assert.match(label!, new RegExp(`write ${hops}(†|[^0-9†]|$)`), `${f}: ${fi.entrypoint} — diagrama diverge dos ${hops} saltos do achado`);
      // O † do diagrama marca UMA coisa: caminho > 2 saltos, positiva provavelmente por helper.
      // Essa equivalência vale sempre.
      assert.equal(label!.includes(`write ${hops}†`), hops > 2, `${f}: ${fi.entrypoint} — † e ${hops} saltos discordam`);
      // Para `unauthenticated-state-mutation` a severidade continua sendo função dos saltos, e o
      // † tem de acompanhar. Para `initialization-front-running` NÃO: desde que a regra de
      // severidade passou a exigir também a ausência da guarda de já-inicializado
      // (`has_contract_data` alcançável ⇒ Medium mesmo a 1 salto), a severidade deixou de ser
      // derivável dos saltos — e exigir a equivalência aqui era exigir que a figura mostrasse
      // uma informação que ela não carrega.
      if (fi.class === "unauthenticated-state-mutation") {
        assert.equal(label!.includes(`write ${hops}†`), fi.severity === "Medium", `${f}: ${fi.entrypoint} — † e severidade ${fi.severity} discordam`);
      }
      conferidos++;
    }
  }
  assert.ok(conferidos > 0, "nenhum achado de escrita sem auth no corpus: o teste não conferiu nada");
});

test("a solidez da negativa é por entrypoint, como em detect.ts, não do módulo", () => {
  let mistos = 0;
  for (const f of files) {
    const an = analyzeModule(load(f));
    const dfd = buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an));
    const porId = new Map(dfd.nodes.map((n) => [n.id, n]));
    for (const e of dfd.edges) {
      if (!e.label.startsWith("invokes — no authorization check")) continue;
      const alvo = porId.get(e.to)!;
      const ep = an.entrypoints.find((x) => x.name === (alvo as any).entrypoint)!;
      assert.equal(
        e.label.includes("sound for this call graph"),
        ep.callGraphComplete,
        `${f}: ${ep.name} — aresta afirma solidez diferente de ep.callGraphComplete`,
      );
    }
    // `an.soundness` degrada por call_indirect em QUALQUER corpo, inclusive inalcançável.
    // Se o diagrama usasse esse campo, contratos assim rebaixariam negativas que a tabela
    // de ameaças afirma como sólidas — é esse caso que o corpus precisa exercitar.
    if (an.soundness !== "sound" && an.entrypoints.some((e) => e.callGraphComplete)) mistos++;
  }
  assert.ok(mistos > 0, "o corpus não tem módulo aproximado com entrypoint sólido: o teste não exercita a divergência");
});

test("nenhuma aresta afirma host function nua — toda positiva é rotulada como alcance", () => {
  const NUA = /^(call|try_call|contract_event|put_contract_data|del_contract_data)\b/;
  for (const f of files) {
    const an = analyzeModule(load(f));
    for (const e of buildDfd(ctxDe(f.replace(/\.wasm$/, ""), an)).edges) {
      assert.ok(!NUA.test(e.label), `${f}: aresta "${e.label}" afirma a host function em vez do alcance até ela`);
    }
  }
});

/**
 * O diagrama sai em inglês por padrão; `--lang pt` continua produzindo o texto equivalente.
 * O estado de idioma é global, então o teste o devolve para `en` com `t.after`.
 */
test("rótulos saem em inglês por padrão e em português com setLang(\"pt\")", (t) => {
  t.after(() => setLang("en"));
  const an = analyzeModule(load(files[0]));
  const ctx = ctxDe("CTESTE", an, [{ key: "Admin", confidence: "certain" }]);

  const en = buildDfd(ctx);
  assert.ok(en.mermaid.includes("data-flow diagram derived from the deployed WASM"), "cabeçalho em inglês ausente");
  assert.ok(en.mermaid.includes("%% legend: reaches X n ="), "legenda em inglês ausente");
  assert.ok(en.nodes.some((n) => n.kind === "store" && n.label === "Contract storage"), "store em inglês ausente");
  assert.ok(en.nodes.some((n) => n.kind === "store" && n.label === "Admin (certain)"), "chave em inglês ausente");
  assert.ok(en.boundaries.some((b) => b.id === "tb_externo" && b.label.startsWith("Outside the contract")), "fronteira em inglês ausente");
  // A fronteira aberta é a única do diagrama que AFIRMA uma negativa. O rótulo diz até
  // onde ela vale — "sólida" seco seria prova de algo que só vale para este call graph.
  const abertaEn = en.boundaries.find((b) => b.id === "tb_aberto");
  if (abertaEn) {
    assert.ok(abertaEn.label.includes("no path reaches require_auth* in this module"), `fronteira aberta sem escopo: ${abertaEn.label}`);
    assert.ok(!/solid negative/.test(abertaEn.label), `fronteira aberta ainda diz "solid negative": ${abertaEn.label}`);
  }
  assert.ok(!/stops being proof/.test(en.mermaid), "o diagrama ainda apresenta a negativa como prova");
  assert.deepEqual(erros(en), []);

  setLang("pt");
  const pt = buildDfd(ctx);
  assert.ok(pt.mermaid.includes("data-flow diagram derivado do WASM deployado"), "cabeçalho em português ausente");
  assert.ok(pt.mermaid.includes("%% legenda: alcança X n ="), "legenda em português ausente");
  assert.ok(pt.nodes.some((n) => n.kind === "store" && n.label === "Storage do contrato"), "store em português ausente");
  assert.ok(pt.nodes.some((n) => n.kind === "store" && n.label === "Admin (certa)"), "chave em português ausente");
  assert.ok(pt.boundaries.some((b) => b.id === "tb_externo" && b.label.startsWith("Fora do contrato")), "fronteira em português ausente");
  const abertaPt = pt.boundaries.find((b) => b.id === "tb_aberto");
  if (abertaPt) {
    assert.ok(abertaPt.label.includes("nenhum caminho alcança require_auth* neste módulo"), `fronteira aberta sem escopo: ${abertaPt.label}`);
  }
  assert.ok(!/deixa de ser prova/.test(pt.mermaid), "o diagrama em português ainda apresenta a negativa como prova");
  assert.deepEqual(erros(pt), []);

  // Ids de nó e de fronteira são language-neutral: outros módulos casam com eles por regex.
  assert.deepEqual(en.nodes.map((n) => n.id), pt.nodes.map((n) => n.id));
  assert.deepEqual(en.boundaries.map((b) => b.id), pt.boundaries.map((b) => b.id));
});
