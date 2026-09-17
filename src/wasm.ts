/**
 * Parser mínimo de módulo WebAssembly — só o necessário para análise estática.
 * Sem dependência externa de propósito: a ferramenta precisa rodar sobre bytes
 * baixados da rede sem arrastar um runtime de WASM junto.
 *
 * Regra de ouro deste arquivo: **falhar fechado**. Um módulo que o parser não
 * consegue ler inteiro não pode sair daqui parecendo um módulo completo — a
 * análise negativa ("não alcança require_auth") só é prova quando o call graph
 * está completo, e o call graph só está completo quando TODO byte lido foi
 * entendido. Por isso: nenhum laço lê `wasm[i]` sem limite superior, nenhuma
 * seção pode ultrapassar o fim do arquivo, e opcode desconhecido marca o corpo
 * como `degraded` em vez de assumir "sem imediatos" e dessincronizar.
 */

export type ImportedFn = { module: string; name: string; key: string };
export type ExportedFn = { name: string; funcIdx: number };

/** Uma chamada direta encontrada no corpo, na ordem em que aparece no bytecode. */
export type CallSite = { target: number; offset: number; end: number };

/**
 * Um `i32.const`/`i64.const` literal. `end` é o offset do próximo opcode: é o que permite
 * afirmar *adjacência* (esta constante é imediatamente seguida por aquela chamada) em vez
 * de só proximidade — sem isso não dá para distinguir argumento de literal solto no meio.
 */
export type ConstSite = { bits: 32 | 64; value: bigint; offset: number; end: number };

export type FnBody = {
  /** índice global da função (imports ocupam os primeiros índices) */
  funcIdx: number;
  calls: CallSite[];
  /** `call_indirect` torna o call graph incompleto — a análise passa a ser aproximada */
  hasIndirectCall: boolean;
  /**
   * O scanner parou no meio do corpo (opcode desconhecido ou imediato ilegível).
   * A partir daí não há chamada registrada: quem alcança este corpo NÃO pode
   * afirmar negativa. Tratado como equivalente a `hasIndirectCall` pela análise.
   */
  degraded?: boolean;
  /** só preenchido com `{ consts: true }`: custa memória e quase nenhum consumidor precisa */
  consts?: ConstSite[];
};

export type WasmModule = {
  imports: ImportedFn[];
  exports: ExportedFn[];
  bodies: FnBody[];
  /** quantas funções a seção de função (id 3) declara — tem de bater com `bodies.length` */
  declaredFuncs: number;
  /** funções referenciadas por element segments ou `ref.func`: alvos possíveis de call_indirect */
  tableTargets: Set<number>;
  /** o módulo não pôde ser lido por inteiro: toda negativa derivada dele é fraca */
  incomplete?: boolean;
  /** por que está incompleto — vai literal para o laudo, nunca some silenciosamente */
  incompleteReason?: string;
  customSections: Map<string, Uint8Array>;
};

/* ---------- leitores LEB128, todos com limite superior ---------- */

/**
 * LEB128 sem sinal. `end` limita a leitura (fim de seção/corpo) e `max` limita o
 * número de bytes: sem os dois, um byte 0x80 repetido leva o parser a varrer o
 * arquivo inteiro — ou a girar para sempre quando `b[p]` vira `undefined`.
 */
function u32(b: Uint8Array, p: number, end: number = b.length, max = 5): [number, number] {
  let r = 0, s = 0, n = 0;
  for (;;) {
    if (p >= end) throw new Error(`LEB128 truncado em ${p}`);
    const x = b[p++];
    r |= (x & 0x7f) << s;
    if ((x & 0x80) === 0) return [r >>> 0, p];
    s += 7;
    if (++n >= max) throw new Error(`LEB128 longo demais em ${p} (>${max} bytes)`);
  }
}
/** Pula um LEB128 (com ou sem sinal) de até 10 bytes — u64 cabe em 10. */
function lebskip(b: Uint8Array, p: number, end: number): number {
  for (let n = 0; ; n++) {
    if (p >= end) throw new Error(`LEB128 truncado em ${p}`);
    const x = b[p++];
    if ((x & 0x80) === 0) return p;
    if (n >= 9) throw new Error(`LEB128 longo demais em ${p} (>10 bytes)`);
  }
}
/**
 * LEB128 com sinal, em BigInt. Devolve o valor já reinterpretado como padrão de bits sem
 * sinal de `bits` largura: um `Val` do Soroban é um u64 cujo bit 63 costuma estar ligado,
 * e o compilador o emite como sLEB negativo. Comparar tag em complemento de dois seria
 * uma fonte silenciosa de chave perdida.
 */
function sleb(b: Uint8Array, p: number, bits: 32 | 64, end: number = b.length): [bigint, number] {
  let r = 0n, s = 0n, x = 0, n = 0;
  do {
    if (p >= end) throw new Error(`LEB128 truncado em ${p}`);
    x = b[p++];
    r |= BigInt(x & 0x7f) << s;
    s += 7n;
    if (++n > 10) throw new Error(`LEB128 longo demais em ${p} (>10 bytes)`);
  } while (x & 0x80);
  if (s < BigInt(bits) && (x & 0x40)) r -= 1n << s;
  const mask = (1n << BigInt(bits)) - 1n;
  return [r & mask, p];
}
function name(b: Uint8Array, p: number, end: number): [string, number] {
  const [n, a] = u32(b, p, end);
  if (a + n > end) throw new Error(`nome ultrapassa o fim da seção em ${a}`);
  return [new TextDecoder().decode(b.subarray(a, a + n)), a + n];
}

/* ---------- scanner de corpo ---------- */

/** Opcodes sem imediato: se um opcode não está aqui nem no switch, o corpo é degradado. */
function noImmediate(op: number): boolean {
  return (
    op === 0x00 || op === 0x01 || op === 0x05 || op === 0x0b || op === 0x0f || // unreachable/nop/else/end/return
    op === 0x1a || op === 0x1b ||                                             // drop / select
    op === 0x19 ||                                                            // catch_all (EH legado)
    (op >= 0x45 && op <= 0xc4) ||                                             // toda a aritmética/comparação
    op === 0xd1 || op === 0xd3 || op === 0xd4                                 // ref.is_null / ref.eq / ref.as_non_null
  );
}

/** SIMD (0xfd): sub-ops de 0 a 275; o resto ainda não existe e degrada o corpo. */
function simdImmediates(sub: number): "none" | "memarg" | "memarg+lane" | "lane" | "b16" | "unknown" {
  if (sub <= 11) return "memarg";                       // v128.load*, load*_splat
  if (sub === 12 || sub === 13) return "b16";           // v128.const / i8x16.shuffle
  if (sub >= 21 && sub <= 34) return "lane";            // extract_lane / replace_lane
  if (sub >= 84 && sub <= 91) return "memarg+lane";     // load*_lane / store*_lane
  if (sub === 92 || sub === 93) return "memarg";        // load32_zero / load64_zero
  if (sub <= 275) return "none";                        // resto: swizzle, splat, aritmética, relaxed
  return "unknown";
}

/**
 * Percorre um corpo de função registrando apenas `call`/`return_call` e as formas
 * indiretas. Todo o resto é pulado — mas os imediatos precisam ser pulados
 * corretamente, senão o decodificador dessincroniza e passa a ler lixo como opcode.
 * Quando não dá para pular com certeza, o corpo para e sai marcado `degraded`.
 */
function scanBody(
  b: Uint8Array,
  start: number,
  end: number,
  wantConsts: boolean,
): { calls: CallSite[]; hasIndirectCall: boolean; degraded: boolean; refFuncs: number[]; consts?: ConstSite[] } {
  const calls: CallSite[] = [];
  const refFuncs: number[] = [];
  const consts: ConstSite[] | undefined = wantConsts ? [] : undefined;
  let hasIndirectCall = false;
  let degraded = false;
  let p = start;
  const memarg = (q: number) => { const [, a] = u32(b, q, end); const [, a2] = u32(b, a, end); return a2; };
  try {
    while (p < end) {
      const at = p;
      const op = b[p++];
      switch (op) {
        // chamadas diretas: `call` e `return_call` (tail call) são a mesma aresta
        case 0x10: case 0x12: { const [t, a] = u32(b, p, end); p = a; calls.push({ target: t, offset: at, end: p }); break; }
        // indiretas: call_indirect / return_call_indirect (typeidx + tableidx)
        case 0x11: case 0x13: { hasIndirectCall = true; const [, a] = u32(b, p, end); const [, a2] = u32(b, a, end); p = a2; break; }
        // call_ref / return_call_ref: chamada por referência, igualmente fora do call graph
        case 0x14: case 0x15: { hasIndirectCall = true; const [, a] = u32(b, p, end); p = a; break; }
        // blocktype: pode ser 0x40, um valtype, ou um índice de tipo em s33
        case 0x02: case 0x03: case 0x04: case 0x06: p = lebskip(b, p, end); break; // block/loop/if/try
        case 0x07: case 0x08: case 0x09: case 0x0a: case 0x18: // catch/throw/rethrow/delegate (EH legado)
        case 0x0c: case 0x0d:                                  // br / br_if
        case 0xd5: case 0xd6: { const [, a] = u32(b, p, end); p = a; break; } // br_on_null / br_on_non_null
        case 0x0e: { // br_table
          const [n, a] = u32(b, p, end); let q = a;
          for (let k = 0; k <= n; k++) { const [, r] = u32(b, q, end); q = r; }
          p = q; break;
        }
        case 0x1c: { // select t*
          const [n, a] = u32(b, p, end); p = a + n;
          if (p > end) throw new Error(`select t* ultrapassa o corpo em ${at}`);
          break;
        }
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26:
          { const [, a] = u32(b, p, end); p = a; break; }
        case 0xd2: { // ref.func: o índice vira alvo possível de chamada indireta
          const [f, a] = u32(b, p, end); p = a; refFuncs.push(f); break;
        }
        case 0xd0: p = lebskip(b, p, end); break; // ref.null <heaptype> (s33 no GC)
        case 0x41: { // i32.const (signed)
          if (consts) { const [v, a] = sleb(b, p, 32, end); p = a; consts.push({ bits: 32, value: v, offset: at, end: p }); }
          else p = lebskip(b, p, end);
          break;
        }
        case 0x42: { // i64.const (signed)
          if (consts) { const [v, a] = sleb(b, p, 64, end); p = a; consts.push({ bits: 64, value: v, offset: at, end: p }); }
          else p = lebskip(b, p, end);
          break;
        }
        case 0x43: p += 4; break;            // f32.const
        case 0x44: p += 8; break;            // f64.const
        case 0x3f: case 0x40: { const [, a] = u32(b, p, end); p = a; break; } // memory.size/grow (memidx)
        case 0xfc: { // prefixo: conversões saturadas / bulk memory / table
          const [sub, a] = u32(b, p, end); p = a;
          if (sub <= 7) break;                                     // trunc_sat: sem imediato
          if (sub > 17) { degraded = true; break; }
          // 8 memory.init(dataidx,0x00) · 10 memory.copy(0x00,0x00) · 12 table.init(elemidx,tableidx) · 14 table.copy(t,t)
          const dois = sub === 8 || sub === 10 || sub === 12 || sub === 14;
          { const [, r] = u32(b, p, end); p = r; }
          if (dois) { const [, r2] = u32(b, p, end); p = r2; }
          break;
        }
        case 0xfd: { // SIMD
          const [sub, a] = u32(b, p, end); p = a;
          switch (simdImmediates(sub)) {
            case "none": break;
            case "memarg": p = memarg(p); break;
            case "memarg+lane": p = memarg(p) + 1; break;
            case "lane": p += 1; break;
            case "b16": p += 16; break;
            default: degraded = true;
          }
          break;
        }
        case 0xfe: { // threads/atomics: `atomic.fence` tem 1 byte reservado, o resto é memarg
          const [sub, a] = u32(b, p, end); p = a;
          if (sub === 0x03) p += 1; else p = memarg(p);
          break;
        }
        default:
          if (op >= 0x28 && op <= 0x3e) { p = memarg(p); break; }  // load/store: memarg
          if (noImmediate(op)) break;
          // Opcode desconhecido: assumir "sem imediatos" é o que dessincroniza o
          // decodificador e faz o parser inventar chamadas. Para aqui e declara.
          degraded = true;
      }
      if (degraded) break;
      if (p > end) throw new Error(`imediato ultrapassa o fim do corpo em ${at}`);
    }
  } catch {
    // Corpo ilegível: melhor um subgrafo declaradamente incompleto que chamadas inventadas.
    degraded = true;
  }
  return { calls, hasIndirectCall, degraded, refFuncs, consts };
}

export type ParseOpts = {
  /** registra os imediatos `i32.const`/`i64.const` de cada corpo — ver `ConstSite` */
  consts?: boolean;
};

export function parseModule(wasm: Uint8Array, opts: ParseOpts = {}): WasmModule {
  if (wasm.length < 8) throw new Error("WASM curto demais");
  if (!(wasm[0] === 0x00 && wasm[1] === 0x61 && wasm[2] === 0x73 && wasm[3] === 0x6d)) {
    throw new Error("não é um módulo WASM (magic inválido)");
  }
  const imports: ImportedFn[] = [];
  const exports: ExportedFn[] = [];
  const bodies: FnBody[] = [];
  const tableTargets = new Set<number>();
  const customSections = new Map<string, Uint8Array>();
  let declaredFuncs = 0;
  let sawFuncSec = false;
  let sawCodeSec = false;

  let p = 8;
  while (p < wasm.length) {
    const id = wasm[p++];
    const [len, afterLen] = u32(wasm, p, wasm.length);
    p = afterLen;
    const end = p + len;
    // Fail closed: uma seção que ultrapassa o arquivo significa binário truncado.
    // Seguir lendo daria um call graph parcial com cara de completo.
    if (end > wasm.length) throw new Error(`seção ${id} ultrapassa o fim do módulo (${end} > ${wasm.length})`);
    let q = p;
    switch (id) {
      case 0: { const [nm, a] = name(wasm, q, end); customSections.set(nm, wasm.subarray(a, end)); break; }
      case 2: {
        const [n, a] = u32(wasm, q, end); q = a;
        for (let k = 0; k < n; k++) {
          let mod, nm;
          [mod, q] = name(wasm, q, end);
          [nm, q] = name(wasm, q, end);
          const kind = wasm[q++];
          if (kind === 0x00) { const [, a2] = u32(wasm, q, end); q = a2; imports.push({ module: mod, name: nm, key: `${mod}.${nm}` }); }
          else if (kind === 0x01) { q += 1; const [lim, a2] = u32(wasm, q, end); q = a2; const [, a3] = u32(wasm, q, end); q = a3; if (lim === 1) { const [, a4] = u32(wasm, q, end); q = a4; } }
          else if (kind === 0x02) { const [lim, a2] = u32(wasm, q, end); q = a2; const [, a3] = u32(wasm, q, end); q = a3; if (lim === 1) { const [, a4] = u32(wasm, q, end); q = a4; } }
          else if (kind === 0x03) { q += 2; }
          if (q > end) throw new Error("seção de import ultrapassa o fim da seção");
        }
        break;
      }
      case 3: { // seção de função: quantas funções o módulo DECLARA
        sawFuncSec = true;
        const [n, a] = u32(wasm, q, end); q = a;
        declaredFuncs = n;
        for (let k = 0; k < n; k++) { const [, a2] = u32(wasm, q, end); q = a2; }
        break;
      }
      case 7: {
        const [n, a] = u32(wasm, q, end); q = a;
        for (let k = 0; k < n; k++) {
          let nm;
          [nm, q] = name(wasm, q, end);
          const kind = wasm[q++];
          const [idx, a2] = u32(wasm, q, end); q = a2;
          if (kind === 0x00) exports.push({ name: nm, funcIdx: idx });
        }
        break;
      }
      case 9: { // element segments: quem pode ser alvo de call_indirect
        const [n, a] = u32(wasm, q, end); q = a;
        for (let k = 0; k < n; k++) {
          const [flags, a2] = u32(wasm, q, end); q = a2;
          if (flags === 0) {
            // expressão de offset: varre até `end` (0x0b) SEM ultrapassar a seção
            while (q < end && wasm[q] !== 0x0b) q++;
            if (q >= end) throw new Error("expressão de offset do element segment sem terminador dentro da seção");
            q++;
          } else if (flags === 1 || flags === 3) { q += 1; }
          else { break; }                                                // formas raras: aborta sem mentir
          const [cnt, a3] = u32(wasm, q, end); q = a3;
          for (let j = 0; j < cnt; j++) { const [f, a4] = u32(wasm, q, end); q = a4; tableTargets.add(f); }
        }
        break;
      }
      case 10: {
        sawCodeSec = true;
        const [n, a] = u32(wasm, q, end); q = a;
        for (let k = 0; k < n; k++) {
          const [size, a2] = u32(wasm, q, end); q = a2;
          const bodyEnd = q + size;
          if (bodyEnd > end) throw new Error(`corpo de função ${k} ultrapassa a seção de código`);
          const [nLocals, a3] = u32(wasm, q, bodyEnd); q = a3;
          for (let l = 0; l < nLocals; l++) { const [, a4] = u32(wasm, q, bodyEnd); q = a4 + 1; }
          const { calls, hasIndirectCall, degraded, refFuncs, consts } = scanBody(wasm, q, bodyEnd, opts.consts === true);
          bodies.push({ funcIdx: imports.length + k, calls, hasIndirectCall, ...(degraded ? { degraded } : {}), consts });
          for (const f of refFuncs) tableTargets.add(f);
          q = bodyEnd;
        }
        break;
      }
    }
    p = end;
  }

  // Coerência do call graph. Qualquer uma destas falhas transforma negativa em palpite.
  const nFuncs = imports.length + bodies.length;
  let incompleteReason: string | undefined;
  if (sawFuncSec && bodies.length !== declaredFuncs) {
    incompleteReason = sawCodeSec
      ? `seção de função declara ${declaredFuncs} funções, seção de código traz ${bodies.length} corpos`
      : `seção de função declara ${declaredFuncs} funções e não há seção de código`;
  } else if (!sawFuncSec && bodies.length > 0) {
    incompleteReason = "seção de código presente sem seção de função: contagem de funções não conferível";
  } else {
    for (const b of bodies) {
      const fora = b.calls.find((c) => c.target >= nFuncs);
      if (fora) { incompleteReason = `chamada para índice de função fora da faixa (${fora.target} >= ${nFuncs}) em fn#${b.funcIdx}`; break; }
    }
  }

  return {
    imports,
    exports,
    bodies,
    declaredFuncs: sawFuncSec ? declaredFuncs : bodies.length,
    tableTargets,
    ...(incompleteReason ? { incomplete: true, incompleteReason } : {}),
    customSections,
  };
}

/** Atalho para quem só quer uma custom section e não o módulo inteiro. */
export function customSection(wasm: Uint8Array, name: string): Uint8Array | undefined {
  return parseModule(wasm).customSections.get(name);
}
