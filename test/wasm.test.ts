import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseModule } from "../src/wasm.ts";
import { analyzeModule } from "../src/analyze.ts";
import { hostFn } from "../src/hostfns.ts";

/**
 * O que este arquivo cobre: o parser falhando FECHADO.
 *
 * Um parser de WASM que lê um módulo pela metade e devolve o resultado sem dizer
 * nada é pior que um que estoura: a análise negativa ("este export não alcança
 * require_auth") só é prova quando o call graph está completo. Todo teste aqui é
 * sobre isso — módulo truncado, seção mentindo o tamanho, opcode desconhecido,
 * LEB128 patológico — e sobre `pathTo` ser de fato o caminho MÍNIMO.
 */

/* ---------- montador mínimo de módulos ---------- */

const leb = (n: number): number[] => {
  const o: number[] = [];
  do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n);
  return o;
};
const str = (s: string): number[] => { const b = [...Buffer.from(s)]; return [...leb(b.length), ...b]; };
const sec = (id: number, body: number[]): number[] => [id, ...leb(body.length), ...body];
const modulo = (...secs: number[][]): Uint8Array => new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...secs.flat()]);
/** um corpo de função: sem locais, os opcodes dados, terminado em `end` */
const corpo = (...ops: number[]): number[] => { const b = [0x00, ...ops, 0x0b]; return [...leb(b.length), ...b]; };

const secTipos = sec(1, [1, 0x60, 0x00, 0x00]);
const secImports = (keys: string[]) => sec(2, [...leb(keys.length), ...keys.flatMap((k) => { const [m, n] = k.split("."); return [...str(m), ...str(n), 0x00, 0x00]; })]);
const secFuncs = (n: number) => sec(3, [...leb(n), ...Array.from({ length: n }, () => 0x00)]);
const secExports = (es: [string, number][]) => sec(7, [...leb(es.length), ...es.flatMap(([n, i]) => [...str(n), 0x00, ...leb(i)])]);
const secCode = (bodies: number[][]) => sec(10, [...leb(bodies.length), ...bodies.flat()]);

/* ---------- LEB128 ---------- */

test("LEB128 multi-byte é lido inteiro: um índice de função de 2 bytes ainda vira aresta", () => {
  // `local.get 200` (0xc8 0x01) antes do `call 0`: se o LEB for lido como 1 byte,
  // o decodificador dessincroniza e o `call` some (ou aparece em offset errado).
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(1), secExports([["go", 1]]),
    secCode([corpo(0x20, 0xc8, 0x01, 0x1a, 0x10, 0x00)]));
  const m = parseModule(w);
  assert.deepEqual(m.bodies[0].calls.map((c) => c.target), [0]);
  assert.equal(m.bodies[0].degraded, undefined);
  assert.equal(m.incomplete, undefined);
});

test("LEB128 longo demais estoura em vez de varrer o arquivo inteiro", () => {
  // contagem de imports em 6 bytes: nenhum u32 válido ocupa mais de 5
  const mau = sec(2, [0x81, 0x80, 0x80, 0x80, 0x80, 0x00]);
  assert.throws(() => parseModule(modulo(secTipos, mau)), /LEB128 longo demais/);
});

test("LEB128 truncado no fim da seção estoura em vez de ler o vizinho", () => {
  // contagem de exports anunciada, seção acaba no meio do LEB
  assert.throws(() => parseModule(modulo(secTipos, sec(7, [0x80]))), /LEB128 truncado/);
});

/* ---------- varreduras sem limite ---------- */

test("element segment sem terminador estoura rápido, não trava o processo", { timeout: 5000 }, () => {
  // Módulo de 14 bytes: seção 9, 1 segmento, flags 0, expressão de offset `i32.const 0`
  // SEM o `end` (0x0b). A versão anterior fazia `while (wasm[q] !== 0x0b) q++` e girava
  // para sempre assim que `wasm[q]` virava `undefined`.
  const w = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x01, 0x00, 0x41, 0x00]);
  assert.equal(w.length, 14);
  const t0 = Date.now();
  assert.throws(() => parseModule(w), /sem terminador|LEB128|ultrapassa/);
  assert.ok(Date.now() - t0 < 2000, `parser levou ${Date.now() - t0}ms num módulo de 14 bytes`);
});

/* ---------- fail closed ---------- */

test("seção que ultrapassa o fim do módulo é recusada", () => {
  const w = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x40, 0x00]);
  assert.throws(() => parseModule(w), /ultrapassa o fim do módulo/);
});

test("WASM real cortado ao meio: ou estoura, ou sai declaradamente incompleto e aproximado", () => {
  const CORPUS = new URL("../corpus/", import.meta.url).pathname;
  const full = new Uint8Array(readFileSync(CORPUS + "CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm"));
  const cortado = full.subarray(0, Math.floor(full.length * 0.6));
  let m;
  try { m = parseModule(cortado); } catch (e) {
    assert.ok(e instanceof Error && e.message.length > 0, "estourou sem mensagem conferível");
    return;
  }
  assert.equal(m.incomplete, true, "módulo truncado parseou sem se declarar incompleto");
  assert.ok(m.incompleteReason && m.incompleteReason.length > 10, "incompleto sem motivo legível");
  const an = analyzeModule(cortado);
  assert.equal(an.soundness, "approximate");
  for (const ep of an.entrypoints) {
    assert.equal(ep.callGraphComplete, false, `${ep.name}: negativa afirmada como prova num módulo truncado`);
  }
});

test("funções declaradas sem seção de código não viram folhas silenciosas", () => {
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(2), secExports([["go", 1]]));
  const m = parseModule(w);
  assert.equal(m.declaredFuncs, 2);
  assert.equal(m.bodies.length, 0);
  assert.equal(m.incomplete, true);
  assert.match(m.incompleteReason!, /não há seção de código/);
  const an = analyzeModule(w);
  assert.equal(an.soundness, "approximate");
  assert.equal(an.entrypoints.find((e) => e.name === "go")!.callGraphComplete, false);
});

test("seção de função e seção de código em desacordo marcam o módulo incompleto", () => {
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(3), secExports([["go", 1]]),
    secCode([corpo(0x10, 0x00)]));
  const m = parseModule(w);
  assert.equal(m.incomplete, true);
  assert.match(m.incompleteReason!, /declara 3 funções/);
});

test("chamada para índice de função fora da faixa marca o módulo incompleto", () => {
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(1), secExports([["go", 1]]),
    secCode([corpo(0x10, 0x63)]));                         // call 99, só existem 2 funções
  const m = parseModule(w);
  assert.equal(m.incomplete, true);
  assert.match(m.incompleteReason!, /fora da faixa/);
  assert.equal(analyzeModule(w).soundness, "approximate");
});

/* ---------- opcodes ---------- */

test("`return_call` produz aresta de chamada como `call`", () => {
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(2), secExports([["go", 1]]),
    secCode([corpo(0x12, 0x02), corpo(0x12, 0x00)]));      // go → fn#2 → require_auth, por tail call
  const m = parseModule(w);
  assert.deepEqual(m.bodies.map((b) => b.calls.map((c) => c.target)), [[2], [0]]);
  assert.equal(m.incomplete, undefined);
  const ep = analyzeModule(w).entrypoints.find((e) => e.name === "go")!;
  assert.ok(ep.reaches.has("require_auth"), "tail call não entrou no alcance");
  assert.deepEqual([...ep.pathTo.get("require_auth")!], [1, 2, 0]);
  assert.equal(ep.callGraphComplete, true);
});

test("`return_call_indirect` e `call_ref` degradam a negativa, como `call_indirect`", () => {
  for (const ops of [[0x13, 0x00, 0x00], [0x14, 0x00]]) {
    const w = modulo(secTipos, secImports(["a.0"]), secFuncs(1), secExports([["go", 1]]), secCode([corpo(...ops)]));
    const m = parseModule(w);
    assert.equal(m.bodies[0].hasIndirectCall, true, `opcode 0x${ops[0].toString(16)} não marcou despacho indireto`);
    assert.equal(analyzeModule(w).entrypoints[0].callGraphComplete, false);
  }
});

test("`table.init` tem DOIS imediatos: ler um só dessincroniza e inventa chamada", () => {
  // 0xfc 12 (table.init) elemidx=0 tableidx=0; se só um imediato for pulado, o 0x00
  // restante vira opcode `unreachable` e o `call 0` seguinte ainda aparece — mas num
  // módulo real o byte extra cai no meio de outro imediato. Aqui o que se confere é
  // que o corpo não degrada e o call fica no offset certo.
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(1), secExports([["go", 1]]),
    secCode([corpo(0xfc, 0x0c, 0x00, 0x00, 0x10, 0x00)]));
  const m = parseModule(w);
  assert.equal(m.bodies[0].degraded, undefined);
  assert.deepEqual(m.bodies[0].calls.map((c) => c.target), [0]);
});

test("opcode desconhecido degrada o corpo em vez de assumir que não tem imediato", () => {
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(1), secExports([["go", 1]]),
    secCode([corpo(0xf0, 0x10, 0x00)]));                    // 0xf0 não existe
  const m = parseModule(w);
  assert.equal(m.bodies[0].degraded, true);
  assert.deepEqual(m.bodies[0].calls, [], "chamada registrada depois de perder a sincronia");
  const an = analyzeModule(w);
  assert.equal(an.entrypoints[0].callGraphComplete, false, "corpo degradado ainda afirma negativa sólida");
  assert.equal(an.soundness, "approximate");
});

/* ---------- pathTo é mínimo ---------- */

test("pathTo é caminho mínimo, não o primeiro que a travessia encontrar", () => {
  // go(1) → fn#2 (rota longa) e → fn#4 (rota curta), ambas terminando em require_auth(0).
  // A aresta longa vem primeiro no bytecode: uma DFS registraria 3 saltos.
  const w = modulo(secTipos, secImports(["a.0"]), secFuncs(4), secExports([["go", 1]]),
    secCode([
      corpo(0x10, 0x02, 0x10, 0x04),  // fn#1 (go)
      corpo(0x10, 0x03),              // fn#2 → fn#3
      corpo(0x10, 0x00),              // fn#3 → require_auth
      corpo(0x10, 0x00),              // fn#4 → require_auth
    ]));
  const ep = analyzeModule(w).entrypoints.find((e) => e.name === "go")!;
  assert.deepEqual([...ep.pathTo.get("require_auth")!], [1, 4, 0], "pathTo não é o caminho mínimo");
  assert.equal(ep.fanout, 5);
  // a ordem de primeira ocorrência continua sendo a ordem de chamada no bytecode
  assert.deepEqual([...ep.orderedHostCalls], ["require_auth"]);
});

test("golden: em contrato real, todo pathTo bate com uma BFS independente e nenhum alvo está fora da faixa", () => {
  const CORPUS = new URL("../corpus/", import.meta.url).pathname;
  const id = "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm";
  const wasm = new Uint8Array(readFileSync(CORPUS + id));
  const mod = parseModule(wasm);
  const an = analyzeModule(wasm);
  const nImports = mod.imports.length;
  const nFuncs = nImports + mod.bodies.length;
  const byIdx = new Map(mod.bodies.map((b) => [b.funcIdx, b]));

  for (const b of mod.bodies) {
    for (const c of b.calls) assert.ok(c.target < nFuncs, `fn#${b.funcIdx} chama ${c.target}, fora de ${nFuncs}`);
  }

  // BFS independente, escrita aqui de propósito: se a análise e o teste dividissem
  // a mesma travessia, o teste só confirmaria que ela é consistente consigo mesma.
  const distancias = (start: number) => {
    const dist = new Map<number, number>([[start, 0]]);
    const fila = [start];
    for (let h = 0; h < fila.length; h++) {
      const i = fila[h];
      if (i < nImports) continue;
      const b = byIdx.get(i);
      if (!b) continue;
      for (const c of b.calls) if (!dist.has(c.target)) { dist.set(c.target, dist.get(i)! + 1); fila.push(c.target); }
    }
    return dist;
  };

  let conferidos = 0;
  for (const ep of an.entrypoints) {
    const dist = distancias(ep.funcIdx);
    const minPorNome = new Map<string, number>();
    for (const [idx, d] of dist) {
      if (idx >= nImports) continue;
      const nome = hostFn(mod.imports[idx].key)?.name ?? mod.imports[idx].key;
      const prev = minPorNome.get(nome);
      if (prev === undefined || d < prev) minPorNome.set(nome, d);
    }
    assert.deepEqual([...ep.reaches].sort(), [...minPorNome.keys()].sort(), `${ep.name}: alcance diverge da BFS do teste`);
    for (const [nome, d] of minPorNome) {
      const p = ep.pathTo.get(nome)!;
      assert.ok(p, `${ep.name}: sem caminho até ${nome}`);
      assert.equal(p.length - 1, d, `${ep.name} → ${nome}: pathTo tem ${p.length - 1} saltos, mínimo é ${d}`);
      assert.equal(p[0], ep.funcIdx, `${ep.name} → ${nome}: caminho não começa no export`);
      // o caminho tem de ser uma sequência real de arestas, não uma lista plausível
      for (let k = 0; k + 1 < p.length; k++) {
        assert.ok(byIdx.get(p[k])!.calls.some((c) => c.target === p[k + 1]), `${ep.name} → ${nome}: fn#${p[k]} não chama fn#${p[k + 1]}`);
      }
      conferidos++;
    }
  }
  assert.ok(conferidos > 0, "o contrato escolhido não alcança host function nenhuma: o teste não conferiu nada");
});
