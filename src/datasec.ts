/**
 * Seção de dados (id 11) — a memória linear inicial do módulo.
 *
 * Existe separada de `wasm.ts` porque tem uma natureza diferente: `wasm.ts` responde
 * "quem chama quem"; aqui respondemos "o que estava escrito na memória no instante 0".
 * As duas se cruzam num ponto só — `symbol_new_from_linear_memory(ptr, len)` — e é esse
 * cruzamento que transforma um ponteiro em string legível.
 *
 * Só segmentos ativos com offset constante entram. Segmento passivo (`memory.init`) ou
 * offset vindo de `global.get` não têm endereço estático conhecível; incluí-los com um
 * endereço chutado produziria string lida do lugar errado — pior que lacuna.
 */

export type DataSegment = { addr: number; bytes: Uint8Array };

export type DataSection = {
  segments: DataSegment[];
  /** segmentos descartados por não terem endereço estático — a leitura fica incompleta */
  skipped: number;
};

function u32(b: Uint8Array, p: number): [number, number] {
  let r = 0, s = 0;
  for (;;) {
    const x = b[p++];
    if (x === undefined) throw new Error("LEB128 truncado");
    r |= (x & 0x7f) << s;
    if ((x & 0x80) === 0) return [r >>> 0, p];
    s += 7;
    if (s > 35) throw new Error("LEB128 longo demais");
  }
}

function sleb32(b: Uint8Array, p: number): [number, number] {
  let r = 0, s = 0, x = 0;
  do { x = b[p++]; r |= (x & 0x7f) << s; s += 7; } while (x & 0x80);
  if (s < 32 && (x & 0x40)) r |= -(1 << s);
  return [r, p];
}

/**
 * Init expr de offset. Aceita apenas a forma que o LLVM emite de fato:
 * `i32.const N end`. Qualquer outra (global.get, aritmética de const) devolve undefined,
 * e o segmento é contado em `skipped`.
 */
function constOffset(b: Uint8Array, p: number): [number | undefined, number] {
  const op = b[p];
  if (op === 0x41) {
    const [v, a] = sleb32(b, p + 1);
    if (b[a] === 0x0b) return [v >>> 0, a + 1];
  }
  // pula até o `end` do expr para não dessincronizar o resto da seção
  let q = p;
  while (q < b.length && b[q] !== 0x0b) q++;
  return [undefined, q + 1];
}

export function parseDataSection(wasm: Uint8Array): DataSection {
  const segments: DataSegment[] = [];
  let skipped = 0;
  let p = 8;
  while (p + 1 < wasm.length) {
    const id = wasm[p++];
    const [len, afterLen] = u32(wasm, p);
    p = afterLen;
    const end = p + len;
    if (id === 11) {
      try {
        let q = p;
        const [n, a] = u32(wasm, q); q = a;
        for (let k = 0; k < n && q < end; k++) {
          const [flags, a2] = u32(wasm, q); q = a2;
          let addr: number | undefined;
          if (flags === 0) { [addr, q] = constOffset(wasm, q); }
          else if (flags === 2) { const [, a3] = u32(wasm, q); q = a3; [addr, q] = constOffset(wasm, q); }
          else if (flags === 1) { addr = undefined; }          // passivo: sem endereço estático
          else break;                                           // forma desconhecida: para sem inventar
          const [size, a4] = u32(wasm, q); q = a4;
          if (addr === undefined) skipped++;
          else segments.push({ addr, bytes: wasm.subarray(q, q + size) });
          q += size;
        }
      } catch { /* seção ilegível: fica o que deu para ler, readMemory devolve undefined no resto */ }
    }
    p = end;
  }
  segments.sort((x, y) => x.addr - y.addr);
  return { segments, skipped };
}

/**
 * Leitor de memória linear estática. Devolve `undefined` — nunca bytes parciais ou zeros —
 * quando o intervalo não está inteiramente dentro de um único segmento. Um intervalo que
 * cruza a borda de dois segmentos ou cai em `.bss` não tem conteúdo conhecido no binário;
 * completar com zero produziria uma "chave" que não existe.
 */
export function makeReadMemory(ds: DataSection): (addr: number, len: number) => Uint8Array | undefined {
  const { segments } = ds;
  return (addr, len) => {
    if (len <= 0 || !Number.isSafeInteger(addr) || !Number.isSafeInteger(len)) return undefined;
    // busca binária pelo último segmento que começa em ou antes de addr
    let lo = 0, hi = segments.length - 1, found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (segments[mid].addr <= addr) { found = mid; lo = mid + 1; } else hi = mid - 1;
    }
    if (found < 0) return undefined;
    const s = segments[found];
    const off = addr - s.addr;
    if (off + len > s.bytes.length) return undefined;
    return s.bytes.subarray(off, off + len);
  };
}

/** Atalho para quem só quer ler memória e não se importa com a estrutura dos segmentos. */
export function readMemoryOf(wasm: Uint8Array): (addr: number, len: number) => Uint8Array | undefined {
  return makeReadMemory(parseDataSection(wasm));
}
