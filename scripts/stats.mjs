// Gera o bloco de números que README.md e docs/HANDOFF.md publicam.
//
// Existe por um motivo específico: antes disto, cada documento carregava um número
// escrito à mão, e quatro deles discordavam entre si (25/29/6/9 testes contra 43 reais,
// 2,7 achados/contrato contra 2,3). Um documento que erra a própria contagem de testes
// não é confiável sobre falso positivo. Aqui todo número é derivado na hora:
//
//   testes        → `node --test test/*.test.ts` (executa de verdade, não conta `test(`)
//   corpus        → detectores rodados sobre `corpus/*.wasm`, igual a `calibrate.mjs`
//   SDK/advisory  → `readSdkMeta` + `advisoriesFor` sobre os mesmos bytes
//   linhas        → wc -l de `src/**/*.ts` + `test/**/*.ts`
//
// Uso:
//   node scripts/stats.mjs              imprime o bloco (markdown) em stdout
//   node scripts/stats.mjs --write      substitui o bloco entre os marcadores
//                                       <!-- stats:start --> / <!-- stats:end -->
//                                       em README.md (en) e docs/HANDOFF.md (pt)
//   node scripts/stats.mjs --no-tests   pula a execução da suíte (mais rápido; a linha
//                                       de testes sai como "não medido")
import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { analyzeModule } from "../src/analyze.ts";
import { detectFull } from "../src/detect.ts";
import { readSdkMeta, advisoriesFor } from "../src/sdkver.ts";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const CORPUS = join(ROOT, "corpus");

const argv = process.argv.slice(2);
const WRITE = argv.includes("--write");
const RUN_TESTS = !argv.includes("--no-tests");

/** O advisory cujo alcance o pitch cita nominalmente. Casado por prefixo do id. */
const CVE = "CVE-2026-26267";

/* ------------------------------------------------------------------ *
 * Corpus: detectores + metadados de SDK, sobre os mesmos bytes.
 * ------------------------------------------------------------------ */

function medirCorpus() {
  const files = readdirSync(CORPUS).filter((f) => f.endsWith(".wasm")).sort();
  const byClass = new Map(), supr = new Map();
  let contracts = 0, entrypoints = 0, unsound = 0, parseFail = 0, findings = 0;
  let sdkDeclared = 0, sdkAffected = 0, sdkUnparseable = 0;

  for (const f of files) {
    const bytes = new Uint8Array(readFileSync(join(CORPUS, f)));
    let an;
    try { an = analyzeModule(bytes); } catch { parseFail++; continue; }
    contracts++;
    entrypoints += an.entrypoints.length;
    if (an.soundness === "approximate") unsound++;

    const r = detectFull(an, bytes);
    findings += r.findings.length;
    for (const fd of r.findings) byClass.set(fd.class, (byClass.get(fd.class) ?? 0) + 1);
    for (const sp of r.suppressed) supr.set(sp.motivo, (supr.get(sp.motivo) ?? 0) + 1);

    // `rssdkver` é o dado que só o artefato deployado tem. Versão presente mas não
    // parseável NÃO conta como "declarada e avaliada": é lacuna, não ausência de risco.
    const { version } = readSdkMeta(bytes);
    if (version) {
      sdkDeclared++;
      const advs = advisoriesFor(version);
      if (advs.some((a) => a.id.startsWith(CVE))) sdkAffected++;
      else if (!/^v?\d+\.\d+\.\d+/.test(version.trim())) sdkUnparseable++;
    }
  }
  return { files: files.length, contracts, entrypoints, unsound, parseFail, findings,
    byClass, supr, sdkDeclared, sdkAffected, sdkUnparseable };
}

/**
 * `calibration.json` é escrito por `calibrate.mjs`. Não é a fonte dos números daqui
 * (ele pode estar velho); serve de checagem cruzada: divergência significa que alguém
 * mexeu em detector e não rodou a calibração.
 */
function conferirCalibracao(c) {
  const p = join(CORPUS, "calibration.json");
  if (!existsSync(p)) return "corpus/calibration.json ausente (rode `node scripts/calibrate.mjs`)";
  let j;
  try { j = JSON.parse(readFileSync(p, "utf8")); } catch { return "corpus/calibration.json ilegível"; }
  const diffs = [];
  for (const [k, v] of [["contracts", c.contracts], ["entrypoints", c.entrypoints],
    ["totalFindings", c.findings], ["unsound", c.unsound]]) {
    if (j[k] !== v) diffs.push(`${k}: calibration.json=${j[k]} medido=${v}`);
  }
  return diffs.length ? `DIVERGE de corpus/calibration.json — ${diffs.join("; ")}` : undefined;
}

/* ------------------------------------------------------------------ *
 * Testes: executados, não contados por regex. `test(` em comentário ou
 * dentro de string contaria como teste que ninguém rodou.
 * ------------------------------------------------------------------ */

function medirTestes() {
  if (!RUN_TESTS) return undefined;
  const r = spawnSync(process.execPath, ["--test", "test/*.test.ts"], {
    cwd: ROOT, encoding: "utf8", shell: false, maxBuffer: 64 * 1024 * 1024,
  });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const num = (label) => {
    const m = new RegExp(`^(?:[#\\u2139\\s\\u001b\\[0-9;m]*)?\\s*${label}\\s+(\\d+)\\s*$`, "m").exec(
      out.replace(/\[[0-9;]*m/g, ""),
    );
    return m ? Number(m[1]) : undefined;
  };
  const total = num("tests"), pass = num("pass"), fail = num("fail");
  if (total === undefined) return { erro: "não foi possível ler a contagem de `node --test`" };
  return { total, pass, fail, ok: r.status === 0 };
}

/* ------------------------------------------------------------------ *
 * Linhas de código.
 * ------------------------------------------------------------------ */

function contarLinhas(dirs) {
  let linhas = 0, arquivos = 0;
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts")) { arquivos++; linhas += readFileSync(p, "utf8").split("\n").length - 1; }
    }
  };
  for (const d of dirs) if (existsSync(d) && statSync(d).isDirectory()) walk(d);
  return { linhas, arquivos };
}

/* ------------------------------------------------------------------ *
 * Render do bloco.
 * ------------------------------------------------------------------ */

const T = {
  en: {
    head: "Generated by `node scripts/stats.mjs --write` — do not edit by hand.",
    col1: "Measurement", col2: "Value",
    tests: "Tests (`pnpm test`)",
    testsVal: (t) => t?.erro ? `not measured (${t.erro})`
      : t === undefined ? "not measured (`--no-tests`)"
      : `**${t.pass} passing** of ${t.total}${t.fail ? ` · ${t.fail} failing` : ""}`,
    corpus: "Corpus (`corpus/*.wasm`)",
    corpusVal: (c) => `**${c.contracts} mainnet contracts**, ${n(c.entrypoints)} entrypoints, ${c.parseFail} parse failures`,
    findings: "Findings",
    findingsVal: (c) => `**${c.findings}** total · **${(c.findings / c.contracts).toFixed(1)} per contract**`,
    classes: "By class",
    unsound: "`call_indirect` (analysis downgraded)",
    unsoundVal: (c) => `**${c.unsound} of ${c.contracts}** (${pct(c.unsound, c.contracts)})`,
    supr: "Declared suppressions",
    down: "Downgrades (reported, not suppressed)",
    sdk: "SDK version declared (`rssdkver`)",
    sdkVal: (c) => `**${c.sdkDeclared} of ${c.contracts}**`,
    cve: `In a ${CVE} affected range (High)`,
    cveVal: (c) => `**${c.sdkAffected} of ${c.sdkDeclared}** that declare a version`,
    lines: "Source lines (`src` + `test`)",
    linesVal: (l) => `${n(l.linhas)} in ${l.arquivos} files`,
    warn: (w) => `> ⚠ ${w}`,
  },
  pt: {
    head: "Gerado por `node scripts/stats.mjs --write` — não editar à mão.",
    col1: "Medida", col2: "Valor",
    tests: "Testes (`pnpm test`)",
    testsVal: (t) => t?.erro ? `não medido (${t.erro})`
      : t === undefined ? "não medido (`--no-tests`)"
      : `**${t.pass} passando** de ${t.total}${t.fail ? ` · ${t.fail} falhando` : ""}`,
    corpus: "Corpus (`corpus/*.wasm`)",
    corpusVal: (c) => `**${c.contracts} contratos de mainnet**, ${n(c.entrypoints)} entrypoints, ${c.parseFail} falhas de parse`,
    findings: "Achados",
    findingsVal: (c) => `**${c.findings}** no total · **${(c.findings / c.contracts).toFixed(1)} por contrato**`,
    classes: "Por classe",
    unsound: "`call_indirect` (análise rebaixada)",
    unsoundVal: (c) => `**${c.unsound} de ${c.contracts}** (${pct(c.unsound, c.contracts)})`,
    supr: "Supressões declaradas",
    down: "Rebaixamentos (reportados, não suprimidos)",
    sdk: "Versão de SDK declarada (`rssdkver`)",
    sdkVal: (c) => `**${c.sdkDeclared} de ${c.contracts}**`,
    cve: `Em faixa afetada pelo ${CVE} (High)`,
    cveVal: (c) => `**${c.sdkAffected} dos ${c.sdkDeclared}** que declaram versão`,
    lines: "Linhas (`src` + `test`)",
    linesVal: (l) => `${n(l.linhas)} em ${l.arquivos} arquivos`,
    warn: (w) => `> ⚠ ${w}`,
  },
};

const n = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
const pct = (a, b) => `${((a / b) * 100).toFixed(0)}%`;

function bloco(lang, d) {
  const t = T[lang];
  const classes = [...d.corpus.byClass].sort((a, b) => b[1] - a[1])
    .map(([c, k]) => `${k} \`${c}\``).join(" · ");
  // Um rebaixamento NÃO é uma supressão: o achado continua no documento, com a severidade
  // limitada. Somá-los inflaria a contagem de "o que a ferramenta deixou de reportar".
  const entradas = [...d.corpus.supr].sort((a, b) => b[1] - a[1]);
  const isDown = ([m]) => /^DOWNGRADED/.test(m);
  const suprLinhas = entradas.filter((e) => !isDown(e));
  const downLinhas = entradas.filter(isDown);
  const soma = (xs) => xs.reduce((a, [, k]) => a + k, 0);
  const fmt = (xs) => xs.map(([m, k]) => `${k} — ${m.replace(/^DOWNGRADED \(not suppressed\): /, "")}`).join("<br>");
  const supr = fmt(suprLinhas);
  const total = soma(suprLinhas);
  const l = [
    `<!-- ${t.head} -->`,
    "",
    `| ${t.col1} | ${t.col2} |`,
    "|---|---|",
    `| ${t.tests} | ${t.testsVal(d.tests)} |`,
    `| ${t.corpus} | ${t.corpusVal(d.corpus)} |`,
    `| ${t.findings} | ${t.findingsVal(d.corpus)} |`,
    `| ${t.classes} | ${classes} |`,
    `| ${t.unsound} | ${t.unsoundVal(d.corpus)} |`,
    `| ${t.supr} | **${total}**<br>${supr} |`,
    `| ${t.down} | **${soma(downLinhas)}**<br>${fmt(downLinhas)} |`,
    `| ${t.sdk} | ${t.sdkVal(d.corpus)} |`,
    `| ${t.cve} | ${t.cveVal(d.corpus)} |`,
    `| ${t.lines} | ${t.linesVal(d.lines)} |`,
  ];
  if (d.aviso) l.push("", t.warn(d.aviso));
  return l.join("\n");
}

const START = "<!-- stats:start -->";
const END = "<!-- stats:end -->";

function escrever(rel, lang, d) {
  const p = join(ROOT, rel);
  const src = readFileSync(p, "utf8");
  const i = src.indexOf(START), j = src.indexOf(END);
  if (i < 0 || j < 0 || j < i) {
    console.error(`  ✖ ${rel}: marcadores ${START} / ${END} ausentes ou fora de ordem — não escrito`);
    return false;
  }
  const novo = `${src.slice(0, i + START.length)}\n${bloco(lang, d)}\n${src.slice(j)}`;
  if (novo === src) { console.error(`  = ${rel} (sem mudança)`); return true; }
  writeFileSync(p, novo);
  console.error(`  ✔ ${rel} atualizado`);
  return true;
}

/* ------------------------------------------------------------------ */

const corpus = medirCorpus();
const d = {
  corpus,
  tests: medirTestes(),
  lines: contarLinhas([join(ROOT, "src"), join(ROOT, "test")]),
  aviso: conferirCalibracao(corpus),
};

if (WRITE) {
  const ok = [escrever("README.md", "en", d), escrever("docs/HANDOFF.md", "pt", d)];
  if (!ok.every(Boolean)) process.exitCode = 1;
} else {
  console.log(bloco("en", d));
}
if (d.tests && d.tests.ok === false) {
  console.error("  ⚠ a suíte de testes NÃO passou — o bloco reporta o que foi medido");
  process.exitCode = 1;
}
