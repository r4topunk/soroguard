/**
 * Guardas sobre `examples/` — os artefatos commitados que servem de vitrine.
 *
 * Eles são gerados por `scripts/regen-examples.mjs` e revisados a olho antes do
 * commit; este teste é a rede que impede que um `examples/` stale volte para o
 * repositório sem ninguém perceber. Não toca a rede: só lê os arquivos.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const DIR = new URL("../examples/", import.meta.url).pathname;

const arquivos = readdirSync(DIR)
  // README.md entra nas checagens de conteúdo (idioma, frases retratadas) e fica
  // de fora das estruturais: ele não é um artefato do template.
  .filter((f) => f.endsWith(".md"))
  .sort();

const planos = arquivos.filter((f) => f.endsWith("-monitoring-plan.md"));
const modelos = arquivos.filter((f) => f.endsWith("-threat-model.md"));

/** Cada exemplo é um par; um documento órfão é sinal de regeneração pela metade. */
test("examples/ tem pelo menos um par e todo par está completo", () => {
  assert.ok(planos.length >= 1, "nenhum monitoring plan em examples/");
  assert.equal(
    planos.length,
    modelos.length,
    `pares incompletos: ${planos.length} planos vs ${modelos.length} modelos`,
  );
  for (const p of planos) {
    const irmao = p.replace("-monitoring-plan.md", "-threat-model.md");
    assert.ok(modelos.includes(irmao), `${p} não tem o threat model irmão ${irmao}`);
  }
});

/**
 * A saída é em inglês desde o commit que trocou o default de `--lang`. Um
 * diacrítico português num arquivo de `examples/` significa render antigo.
 */
test("nenhum arquivo de examples/ carrega diacrítico português", () => {
  const diacriticos = /[çÇãÃõÕáÁâÂéÉêÊíÍóÓôÔúÚàÀ]/;
  for (const f of arquivos) {
    const txt = readFileSync(DIR + f, "utf8");
    const linhas = txt.split("\n");
    const achadas = linhas
      .map((l, i) => ({ l, n: i + 1 }))
      .filter(({ l }) => diacriticos.test(l))
      .slice(0, 5)
      .map(({ l, n }) => `${f}:${n}: ${l.trim().slice(0, 120)}`);
    assert.deepEqual(achadas, [], `texto em português em ${f}:\n${achadas.join("\n")}`);
  }
});

/**
 * Frases que o código já retirou. Se voltarem, é porque o arquivo foi gerado
 * por um binário velho — ou editado à mão, que é pior.
 *
 * - as duas primeiras afirmavam que o monitor era literalmente o filtro do
 *   `getEvents`, afirmação hoje hedgeada em `render/monitoring.ts`;
 * - `Last reviewed: 20…` afirmava revisão humana que nunca houve; o render
 *   atual escreve `never reviewed — generated on <data>`.
 */
test("nenhum arquivo de examples/ contém frase retratada", () => {
  const retratadas = ["são literalmente o filtro", "literally the filter", "Last reviewed: 20"];
  for (const f of arquivos) {
    const txt = readFileSync(DIR + f, "utf8");
    for (const frase of retratadas) {
      assert.ok(!txt.includes(frase), `${f} contém a frase retratada ${JSON.stringify(frase)}`);
    }
  }
});

test("todo threat model tem as quatro seções oficiais do template", () => {
  const secoes = [
    "What are we working on?",
    "What can go wrong?",
    "What are we going to do about it?",
    "Did we do a good job?",
  ];
  for (const f of modelos) {
    const txt = readFileSync(DIR + f, "utf8");
    for (const s of secoes) assert.ok(txt.includes(`## ${s}`), `${f} não tem a seção "${s}"`);
  }
});

test("todo monitoring plan tem as seis seções oficiais do template", () => {
  const secoes = [
    "What are we monitoring?",
    "What could go wrong?",
    "What does exploitation look like on-chain?",
    "What will we monitor for?",
    "What happens when an alert fires?",
    "Did we do a good job?",
  ];
  for (const f of planos) {
    const txt = readFileSync(DIR + f, "utf8");
    for (const s of secoes) assert.ok(txt.includes(`## ${s}`), `${f} não tem a seção "${s}"`);
  }
});

/**
 * O acoplamento por id é o que faz os dois documentos serem um par e não dois
 * textos soltos: o template exige que todo monitor derive de uma ameaça. Um
 * `Elevation.3.M.1` sem `Elevation.3` no threat model irmão é um monitor órfão.
 */
test("todo id de monitor referencia uma ameaça existente no threat model irmão", () => {
  // As seis letras do STRIDE como o render as escreve. Restringir a elas evita
  // que um `CAP-0058.1` qualquer entre como ameaça e afrouxe a checagem.
  const LETRAS = "Spoof|Tamper|Repudiate|Info|DoS|Elevation";
  const idMonitor = new RegExp(`\\b(${LETRAS})\\.(\\d+)\\.M\\.(\\d+)\\b`, "g");
  const idAmeaca = new RegExp(`\\b(${LETRAS})\\.(\\d+)\\b`, "g");
  for (const p of planos) {
    const plano = readFileSync(DIR + p, "utf8");
    const irmao = p.replace("-monitoring-plan.md", "-threat-model.md");
    const modelo = readFileSync(DIR + irmao, "utf8");

    const ameacas = new Set<string>();
    for (const m of modelo.matchAll(idAmeaca)) ameacas.add(`${m[1]}.${m[2]}`);

    const monitores = new Set<string>();
    for (const m of plano.matchAll(idMonitor)) monitores.add(`${m[1]}.${m[2]}.M.${m[3]}`);

    assert.ok(monitores.size > 0, `${p} não declara nenhum monitor`);
    const orfaos = [...monitores].filter((id) => !ameacas.has(id.replace(/\.M\.\d+$/, "")));
    assert.deepEqual(orfaos, [], `monitores sem ameaça correspondente em ${irmao}: ${orfaos.join(", ")}`);
  }
});
