// Valida a classe B.2 da TAXONOMIA-VALIDACAO.md (durabilidade de storage errada) e o
// primeiro termo da B.8 (coleção não-limitada em Instance -> DoS), medindo direto no
// bytecode do corpus. NÃO é um detector do produto: é o experimento que decide se vale
// virar um, no mesmo espírito de keys-sample.mjs -- imprime evidência crua para um humano
// conferir, e não esconde o que não conseguiu ler.
//
// RESULTADO DO EXPERIMENTO (corpus de 71 WASMs): B.2 NÃO vira linha de achado. As tres
// familias que dominam a escrita em Temporary sao corretas por desenho -- allowance
// SEP-41 (approve/transfer_from/burn_from), handoff de papel em dois passos, e estado
// transitorio de flash loan -- e Instance acende em 46/71 contratos, base rate alta
// demais para discriminar. A hipotese de que a governanca pendente em Temporary caia
// em B.12 (expiracao como prazo de seguranca) foi testada e NAO se sustentou: 8 dos 9
// entrypoints de governanca que escrevem Temporary leem um relogio (get_ledger_sequence
// ou get_ledger_timestamp) no proprio subgrafo, ou seja, gravam o prazo no valor.
// O que a medicao virou: `Entrypoint.durability` em src/analyze.ts e a coluna
// `durability` da tabela de superficie do threat model -- campo descritivo, nao achado.
// A cobertura de modulo deste script e a de `analyzeModule` foram conferidas
// contrato a contrato: 71/71 identicas.
//
// AVISO: imprime IDs de contrato do corpus. O corpus tem material sob embargo; a saída
// deste script é para leitura local, não para commit nem para publicação.
//
// O mecanismo, e por que ele é nível A:
//   put_contract_data(k: Val, v: Val, t: StorageType) -> Void       [l._]
//   get_contract_data(k: Val, t: StorageType) -> Val                [l.1]
//   has_contract_data(k: Val, t: StorageType) -> Bool               [l.0]
//   del_contract_data(k: Val, t: StorageType) -> Void               [l.2]
// Em todas as quatro, `StorageType` e o ULTIMO argumento, logo e o topo da pilha no
// momento do `call`. Um `i64.const` cujo `end` e exatamente o offset do `call` e, por
// construcao, esse argumento -- nao "uma constante por perto". `ConstSite.end` existe
// no parser justamente para permitir essa afirmacao de adjacencia.
//
// `extend_contract_data_ttl` (l.7) fica DE FORA: la o StorageType e o 2o de 4 argumentos,
// nao esta adjacente a chamada, e ler por adjacencia daria o argumento errado com cara
// de certeza. Medir errado e pior que nao medir.
//
// StorageType e #[repr(u64)] passado por marshalling direto. Os discriminantes abaixo
// foram CONFIRMADOS empiricamente no corpus antes de escrever este script (12 contratos,
// 96 sites literais, histograma {2,1,0} e nada fora disso) -- nao sao suposicao.
//
// VALIDACAO CONTRA DESASSEMBLADOR INDEPENDENTE (2026-09-17), em
// CAM7DY53G63XA4AJRS24Z6VFYAFSSF76C3RZ45BE5YU3FQS5255OOABP:
//   contagem de sites  -- wasm-dis: 5 put, 8 get  |  este script: 5 put, 8 get   OK
//   durabilidade 5/5   -- L273 (local.get)=?, L546=2, L571=2, L3579=0, L7713=2   OK
// O site L546 e o caso que separa adjacencia de proximidade: ele tem (i64.const 32)
// e (i64.const 4) ANINHADOS no 1o argumento. Um "const mais proximo" leria 4 (lixo);
// a regra de adjacencia le 2 (instance). Por isso o criterio e `const.end === call.offset`.
//
// DIVERGENCIA CONHECIDA com docs/TAXONOMIA-VALIDACAO.md: aquele documento reporta
// "208 call sites de put_contract_data, 190 literais (Instance 127 / Persistent 53 /
// Temporary 10)" sobre 75 WASMs. O corpus hoje tem 71 WASMs e este script mede 407
// sites de put (373 literais). Menos contratos e MAIS sites, entao nao e so o corpus
// ter mudado -- os dois numeros nao podem estar certos ao mesmo tempo. Este aqui esta
// conferido site a site contra wasm-dis; o outro nao foi reproduzido. Resolver antes
// de qualquer uma das duas contagens ser citada como `[medido]` num entregavel.
//
// Uso:
//   node scripts/durability.mjs                 # corpus inteiro
//   node scripts/durability.mjs --limit 12      # amostra
//   node scripts/durability.mjs a.wasm b.wasm   # arquivos avulsos
//   node scripts/durability.mjs --json          # saida para maquina

import { readdirSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import { parseModule } from "../src/wasm.ts";
import { exportSubgraphs } from "../src/analyze.ts";

/* ---------------- configuracao ---------------- */

const CORPUS = new URL("../corpus/", import.meta.url).pathname;

/** key do import -> rotulo curto. So funcoes cujo StorageType e o ultimo argumento. */
const ACESSOS = {
  "l._": { fn: "put_contract_data", curto: "put", escreve: true },
  "l.2": { fn: "del_contract_data", curto: "del", escreve: true },
  "l.1": { fn: "get_contract_data", curto: "get", escreve: false },
  "l.0": { fn: "has_contract_data", curto: "has", escreve: false },
};

/** StorageType, #[repr(u64)] -- confirmado no corpus, nao assumido. */
const DURABILIDADE = { 0: "temporary", 1: "persistent", 2: "instance" };
const ORDEM = ["temporary", "persistent", "instance", "?"];

/** Exports que o host recusa invocar diretamente (prefixo reservado, CAP-0058). */
const RESERVADO = /^__/;
/** Exports que o compilador gera e nao sao entrypoints -- mesmo criterio de analyze.ts. */
const NAO_ENTRYPOINT = /^(memory|__data_end|__heap_base|__rust_|_$)/;

/* ---------------- argumentos ---------------- */

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const JSON_OUT = flag("--json");
const iLim = argv.indexOf("--limit");
const LIMITE = iLim >= 0 ? Number(argv[iLim + 1]) : Infinity;
const avulsos = argv.filter((a) => a.endsWith(".wasm"));

const alvos = avulsos.length
  ? avulsos
  : readdirSync(CORPUS).filter((f) => f.endsWith(".wasm")).sort().slice(0, LIMITE)
      .map((f) => CORPUS + f);

/* ---------------- medicao ---------------- */

/**
 * Le um modulo e devolve um site por chamada de acesso a storage, com a durabilidade
 * quando ela e literal. `literal: false` nao vira "desconhecido silencioso": entra na
 * contagem de cobertura e aparece no relatorio.
 */
function medir(caminho) {
  const bytes = new Uint8Array(readFileSync(caminho));
  const mod = parseModule(bytes, { consts: true });

  // indice do import -> descricao do acesso
  const alvoPorIdx = new Map();
  mod.imports.forEach((imp, i) => {
    const a = ACESSOS[imp.key];
    if (a) alvoPorIdx.set(i, a);
  });

  // funcIdx -> entrypoints que o alcancam. Sobre-aproximacao, igual ao resto da
  // ferramenta: alcancar nao e executar. O relatorio rotula isso.
  const subgrafos = exportSubgraphs(mod);
  const epsPorFunc = new Map();
  for (const [nome, conjunto] of subgrafos) {
    if (NAO_ENTRYPOINT.test(nome)) continue;
    for (const idx of conjunto) {
      let s = epsPorFunc.get(idx);
      if (!s) epsPorFunc.set(idx, (s = new Set()));
      s.add(nome);
    }
  }

  const sites = [];
  let corposDegradados = 0;
  for (const body of mod.bodies) {
    if (body.degraded) corposDegradados++;
    const consts = body.consts ?? [];
    for (const call of body.calls) {
      const acesso = alvoPorIdx.get(call.target);
      if (!acesso) continue;
      // topo da pilha no `call` == ultimo argumento == StorageType
      const c = consts.find((x) => x.end === call.offset);
      const bruto = c ? Number(c.value) : undefined;
      const dur = c ? (DURABILIDADE[bruto] ?? "?") : "?";
      const eps = [...(epsPorFunc.get(body.funcIdx) ?? [])].sort();
      sites.push({
        fn: acesso.fn,
        curto: acesso.curto,
        escreve: acesso.escreve,
        durabilidade: dur,
        literal: Boolean(c),
        bruto,
        funcIdx: body.funcIdx,
        offset: call.offset,
        degradado: Boolean(body.degraded),
        eps,
        epsInvocaveis: eps.filter((n) => !RESERVADO.test(n)),
      });
    }
  }

  return {
    id: basename(caminho).replace(/\.wasm$/, ""),
    sites,
    corposDegradados,
    indireto: mod.bodies.some((b) => b.hasIndirectCall),
    incompleto: Boolean(mod.incomplete),
    incompletoPorque: mod.incompleteReason,
    entrypoints: [...subgrafos.keys()].filter((n) => !NAO_ENTRYPOINT.test(n) && !RESERVADO.test(n)).length,
  };
}

const contratos = [];
const falhas = [];
for (const caminho of alvos) {
  try { contratos.push(medir(caminho)); }
  catch (e) { falhas.push({ id: basename(caminho), erro: e.message }); }
}

/* ---------------- agregacao ---------------- */

const todosSites = contratos.flatMap((c) => c.sites.map((s) => ({ ...s, id: c.id })));
const escritas = todosSites.filter((s) => s.escreve);

const conta = (arr, chave) => {
  const m = new Map();
  for (const x of arr) m.set(chave(x), (m.get(chave(x)) ?? 0) + 1);
  return m;
};

const porFnDur = new Map();
for (const s of todosSites) {
  const k = s.curto;
  if (!porFnDur.has(k)) porFnDur.set(k, { temporary: 0, persistent: 0, instance: 0, "?": 0 });
  porFnDur.get(k)[s.durabilidade]++;
}

const literais = todosSites.filter((s) => s.literal).length;
const cobertura = todosSites.length ? literais / todosSites.length : 0;
const brutosEstranhos = conta(todosSites.filter((s) => s.literal && s.durabilidade === "?"), (s) => s.bruto);

/* ---------------- candidatos a achado ---------------- */

// B.2 -- escrita em Temporary. Red flag oficial: "funds-critical data in temporary()".
// Expiracao apaga permanentemente, sem restore (CAP-0066 nao cobre temporary).
const temp = escritas.filter((s) => s.durabilidade === "temporary" && s.epsInvocaveis.length);

// B.8 (1o termo) -- escrita em Instance. Uma unica ledger entry de 64 KiB, carregada
// inteira a cada invocacao. So e achado se a chave for derivada de parametro Address
// (colecao por usuario); esse 2o termo exige o dataflow de B.3 e NAO esta medido aqui.
const inst = escritas.filter((s) => s.durabilidade === "instance" && s.epsInvocaveis.length);

/** Agrupa sites por contrato para o relatorio de candidatos. */
function agrupar(sites) {
  const m = new Map();
  for (const s of sites) {
    if (!m.has(s.id)) m.set(s.id, []);
    m.get(s.id).push(s);
  }
  return [...m].sort((a, b) => b[1].length - a[1].length);
}

/* ---------------- saida ---------------- */

if (JSON_OUT) {
  console.log(JSON.stringify({
    contratos: contratos.length, falhas,
    sites: todosSites.length, literais, cobertura,
    porFnDur: Object.fromEntries([...porFnDur].map(([k, v]) => [k, v])),
    candidatos: {
      temporary: agrupar(temp).map(([id, ss]) => ({ id, sites: ss })),
      instance: agrupar(inst).map(([id, ss]) => ({ id, sites: ss })),
    },
  }, null, 1));
  process.exit(0);
}

const pct = (x) => `${(100 * x).toFixed(1)}%`;
const linha = (t) => console.log(`\n── ${t} ──`);

console.log(`${contratos.length} contratos lidos (${falhas.length} falhas de parse)`);
for (const f of falhas) console.log(`  PARSE FAIL ${f.id}: ${f.erro}`);

linha("cobertura da medicao");
console.log(`  call sites de storage:   ${todosSites.length}  (escritas: ${escritas.length})`);
console.log(`  com StorageType literal: ${literais}  (${pct(cobertura)})`);
console.log(`  argumento computado:     ${todosSites.length - literais}  -> analise degradada nesses sites`);
if (brutosEstranhos.size) {
  console.log(`  !! literais fora de {0,1,2}: ${[...brutosEstranhos].map(([v, n]) => `${v}x${n}`).join(" ")}`);
  console.log(`     (discriminante inesperado: conferir antes de confiar no mapeamento)`);
}
const comIndireto = contratos.filter((c) => c.indireto).length;
const comDegradado = contratos.filter((c) => c.corposDegradados > 0).length;
console.log(`  contratos com call_indirect: ${comIndireto}   com corpo degradado: ${comDegradado}`);
console.log(`  -> nesses, a atribuicao a entrypoint e indicacao, nao negativa solida`);

linha("durabilidade por funcao de acesso");
console.log(`  ${"fn".padEnd(6)}${ORDEM.map((d) => d.padStart(12)).join("")}${"total".padStart(9)}`);
for (const [fn, d] of porFnDur) {
  const tot = ORDEM.reduce((a, k) => a + d[k], 0);
  console.log(`  ${fn.padEnd(6)}${ORDEM.map((k) => String(d[k]).padStart(12)).join("")}${String(tot).padStart(9)}`);
}

linha("distribuicao das ESCRITAS por contrato");
console.log(`  ${"contrato".padEnd(16)}${"eps".padStart(5)}${"temp".padStart(7)}${"pers".padStart(7)}${"inst".padStart(7)}${"?".padStart(5)}`);
for (const c of contratos) {
  const w = c.sites.filter((s) => s.escreve);
  if (!w.length) continue;
  const d = conta(w, (s) => s.durabilidade);
  console.log(
    `  ${(c.id.slice(0, 14) + "…").padEnd(16)}` +
    `${String(c.entrypoints).padStart(5)}` +
    `${String(d.get("temporary") ?? 0).padStart(7)}` +
    `${String(d.get("persistent") ?? 0).padStart(7)}` +
    `${String(d.get("instance") ?? 0).padStart(7)}` +
    `${String(d.get("?") ?? 0).padStart(5)}`,
  );
}

linha(`B.2 candidatos — escrita em TEMPORARY (${temp.length} sites em ${agrupar(temp).length} contratos)`);
console.log(`  Red flag oficial: expiracao apaga permanentemente, sem restore. Se o dado for`);
console.log(`  critico ao fluxo, e achado; se for cache reproduzivel, e uso correto. Nivel C.`);
for (const [id, ss] of agrupar(temp)) {
  console.log(`\n  ${id.slice(0, 14)}…  ${ss.length} escrita(s) temporary`);
  for (const s of ss.slice(0, 6)) {
    const eps = s.epsInvocaveis;
    console.log(
      `     ${s.curto} @fn${s.funcIdx}+0x${s.offset.toString(16)}` +
      `  alcancado por ${eps.length} ep: ${eps.slice(0, 4).join(", ")}${eps.length > 4 ? ` +${eps.length - 4}` : ""}` +
      `${s.degradado ? "  [corpo degradado]" : ""}`,
    );
  }
  if (ss.length > 6) console.log(`     … +${ss.length - 6}`);
}

linha(`B.8 primeiro termo — escrita em INSTANCE (${inst.length} sites em ${agrupar(inst).length} contratos)`);
console.log(`  Instance = 1 ledger entry de 64 KiB carregada inteira a cada invocacao.`);
console.log(`  So vira achado com o 2o termo (chave derivada de parametro Address), que exige`);
console.log(`  o dataflow de B.3 e NAO esta medido aqui. Sozinho, o sinal tem base rate alta.`);
const topInst = agrupar(inst).slice(0, 10);
for (const [id, ss] of topInst) {
  const fanout = Math.max(...ss.map((s) => s.epsInvocaveis.length));
  console.log(`  ${(id.slice(0, 14) + "…").padEnd(16)} ${String(ss.length).padStart(3)} escritas instance   fanout max ${fanout} eps`);
}
if (agrupar(inst).length > 10) console.log(`  … +${agrupar(inst).length - 10} contratos`);

linha("leitura");
const nTemp = agrupar(temp).length, nInst = agrupar(inst).length;
console.log(`  ${nInst}/${contratos.length} contratos escrevem em Instance; ${nTemp}/${contratos.length} em Temporary.`);
console.log(`  Cobertura literal de ${pct(cobertura)} define o teto de recall de um detector B.2.`);
console.log(`\n  Conferir a mao (o wat do binaryen e folded: o StorageType e o ULTIMO filho`);
console.log(`  direto do (call ...), nao a constante textualmente mais proxima):`);
console.log(`    wasm-dis corpus/<id>.wasm -o /tmp/c.wat`);
console.log(`    grep -n '(import "l" "_"' /tmp/c.wat          # descobre o $fimport$N`);
console.log(`    grep -c '(call $fimport$N$' /tmp/c.wat        # confere a contagem de sites`);
console.log(`    awk 'NR>=<linha> { n=match($0,/[^ ]/); if (n<=<ind>) print NR, $0 }' /tmp/c.wat`);
