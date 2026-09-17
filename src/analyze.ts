import { parseModule, type WasmModule } from "./wasm.ts";
import { hostFn, AUTH_FNS, AUTH_DELEGATE_FNS, STORAGE_WRITE_FNS, STORAGE_READ_FNS, EVENT_FNS, UPGRADE_FNS, DEPLOY_FNS, CROSS_CALL_FNS, TTL_EXTEND_FNS } from "./hostfns.ts";

/**
 * Assimetria de solidez — é o que torna o detector confiável, e precisa ficar explícito:
 *
 *   NÃO alcança require_auth  →  PROVA de que nunca chama (se o call graph estiver completo)
 *   alcança require_auth      →  NÃO prova que chama em todo caminho
 *
 * Ou seja: a afirmação negativa é sólida, a positiva é apenas possível. Todo detector
 * construído aqui se apoia na negativa. Quando há `call_indirect` alcançável, nem a
 * negativa se sustenta — e o resultado é rebaixado para aproximado.
 */
export type Soundness = "sound" | "approximate";

/** As três durabilidades de storage do Soroban, com semânticas irreconciliáveis. */
export type Durability = "temporary" | "persistent" | "instance";

/**
 * Durabilidades que um entrypoint toca, e o quanto disso foi de fato lido.
 *
 * `sites`/`literal` não são decoração: a durabilidade só é legível quando chega ao
 * call site como literal. Quando o contrato acessa storage por um helper genérico que
 * recebe a durabilidade por parâmetro, o argumento é computado e não há o que ler.
 * Publicar `writes` sem publicar a cobertura transformaria "não consegui ler" em
 * "não usa", que é a inversão que este projeto existe para não cometer.
 */
export type DurabilityUse = {
  /** durabilidades tocadas por `put`/`del` no subgrafo deste entrypoint */
  writes: ReadonlySet<Durability>;
  /** durabilidades tocadas por `get`/`has` */
  reads: ReadonlySet<Durability>;
  /** call sites de acesso a storage no subgrafo */
  sites: number;
  /** quantos desses tinham a durabilidade como literal adjacente à chamada */
  literal: number;
};

/**
 * ATENÇÃO — a assimetria acima só vale para a NEGATIVA. A positiva é super-aproximada:
 * "alcança put_contract_data" NÃO significa "escreve". Calibração em corpus real mostrou
 * `estimate_swap` (read-only) alcançando escrita através de um helper compartilhado que
 * ela nunca executa. Por isso toda afirmação positiva precisa vir com o CAMINHO, para que
 * o revisor confirme ou descarte. Afirmar "escreve" sem o caminho seria slop.
 */

export type Entrypoint = {
  name: string;
  funcIdx: number;
  /** nomes canônicos de host functions alcançáveis a partir deste export */
  reaches: ReadonlySet<string>;
  /** primeira ocorrência de cada host function numa travessia que preserva ordem de chamada */
  orderedHostCalls: readonly string[];
  /** funções internas visitadas — proxy do tamanho do subgrafo */
  fanout: number;
  /**
   * Caminho MAIS CURTO (em saltos de índice de função) do export até cada host
   * function alcançada. É BFS de propósito: a contagem de saltos é usada como
   * proxy de "passa por helper compartilhado" (detect.ts rebaixa acima de 2), e
   * uma DFS devolveria o primeiro caminho encontrado, não o menor — o que
   * rebaixaria achados por acidente da ordem das arestas.
   */
  pathTo: ReadonlyMap<string, readonly number[]>;
  /**
   * Host functions alcançáveis pelos alvos da tabela (element segments / `ref.func`)
   * quando há `call_indirect` no subgrafo deste export. NÃO é união com `reaches`:
   * `reaches` continua sendo o que o call graph direto prova; isto é o que PODERIA
   * ser alcançado pelo despacho indireto — é o conteúdo concreto do "aproximado".
   */
  reachesViaTable: ReadonlySet<string>;
  /**
   * false quando há `call_indirect`/`call_ref`, corpo degradado no subgrafo, ou o
   * módulo inteiro é incompleto: negativas deixam de ser prova.
   */
  callGraphComplete: boolean;
  /** durabilidade de storage tocada neste subgrafo — ver `DurabilityUse` */
  durability: DurabilityUse;
};

/** Ordem entre autorização e escrita DENTRO de um mesmo corpo — o único caso conferível. */
export type OrderEvidence = {
  bodyFuncIdx: number;
  authOffset: number;
  writeOffset: number;
  authFn: string;
  writeFn: string;
};

export type ModuleAnalysis = {
  entrypoints: Entrypoint[];
  imports: { key: string; name: string | undefined }[];
  /** host functions importadas mas não alcançáveis de nenhum export */
  unreachableImports: string[];
  hasIndirectAnywhere: boolean;
  /** prefixo hex bruto de `contractenvmetav0` — mantido por compatibilidade */
  interfaceVersion?: string;
  /** `contractenvmetav0` decodificado: XDR ScEnvMetaEntry(0) + u64 (protocol<<32 | pre-release) */
  envInterface?: { protocol: number; preRelease: number };
  soundness: Soundness;
  /** preenchido quando o parser não conseguiu ler o módulo inteiro — ver `WasmModule.incomplete` */
  incompleteReason?: string;
  /** por entrypoint: corpos onde escrita precede autorização */
  writeBeforeAuth: Map<string, OrderEvidence[]>;
  /**
   * Cobertura da leitura de durabilidade no MÓDULO, cada call site contado uma vez.
   * A soma dos `DurabilityUse` por entrypoint não serve para isso: um helper de storage
   * compartilhado por 20 exports entraria 20 vezes, e o número publicado deixaria de
   * ser "call sites deste módulo" sem que o texto mudasse.
   */
  durabilityCoverage: { sites: number; literal: number };
};

/** Exports que o compilador gera e que não são entrypoints do contrato. */
const NOT_ENTRYPOINTS = /^(memory|__data_end|__heap_base|__rust_|_$)/;

export function analyzeModule(wasm: Uint8Array): ModuleAnalysis {
  const mod = parseModule(wasm, { consts: true });
  const nImports = mod.imports.length;
  const bodyByIdx = new Map(mod.bodies.map((b) => [b.funcIdx, b]));

  const hostNameOf = (funcIdx: number): string | undefined =>
    funcIdx < nImports ? hostFn(mod.imports[funcIdx].key)?.name ?? mod.imports[funcIdx].key : undefined;

  /* ---------- durabilidade de storage, por corpo ---------- */

  /**
   * As QUATRO host functions em que `StorageType` é o ÚLTIMO argumento:
   *   put_contract_data(k, v, t) · del_contract_data(k, t)
   *   get_contract_data(k, t)    · has_contract_data(k, t)
   * Sendo o último argumento, ele é o topo da pilha no `call`, logo um `i64.const`
   * cujo `end` é exatamente o offset da chamada É esse argumento — por construção,
   * não por proximidade. É o que `ConstSite.end` existe para permitir afirmar.
   *
   * `extend_contract_data_ttl` fica DE FORA de propósito: lá o `StorageType` é o 2º
   * de 4 argumentos e não está adjacente à chamada. Ler por adjacência devolveria o
   * argumento errado com cara de certeza, que é pior do que não medir.
   */
  const DURABILITY_FNS = new Map<string, "write" | "read">([
    ["put_contract_data", "write"],
    ["del_contract_data", "write"],
    ["get_contract_data", "read"],
    ["has_contract_data", "read"],
  ]);
  /** `StorageType` é `#[repr(u64)]` passada por marshalling direto. */
  const DUR_BY_CODE: Record<number, Durability> = { 0: "temporary", 1: "persistent", 2: "instance" };

  type DurSite = { kind: "write" | "read"; dur?: Durability };
  const durSitesByFunc = new Map<number, DurSite[]>();
  for (const body of mod.bodies) {
    const consts = body.consts ?? [];
    let sites: DurSite[] | undefined;
    for (const c of body.calls) {
      const n = hostNameOf(c.target);
      if (!n) continue;
      const kind = DURABILITY_FNS.get(n);
      if (!kind) continue;
      const lit = consts.find((x) => x.end === c.offset);
      // discriminante fora de {0,1,2}: não inventa durabilidade, conta como não lido
      const dur = lit ? DUR_BY_CODE[Number(lit.value)] : undefined;
      (sites ??= []).push({ kind, dur });
    }
    if (sites) durSitesByFunc.set(body.funcIdx, sites);
  }

  const durabilityCoverage = ((): { sites: number; literal: number } => {
    let sites = 0, literal = 0;
    for (const ss of durSitesByFunc.values()) for (const s of ss) { sites++; if (s.dur) literal++; }
    return { sites, literal };
  })();

  /**
   * BFS a partir do export: distância em saltos + ponteiros de pai.
   * O primeiro import de um dado nome canônico a sair da fila está, por
   * construção, à menor distância possível — daí `pathTo` ser mínimo.
   */
  function bfs(start: number) {
    const reaches = new Set<string>();
    const pathTo = new Map<string, number[]>();
    const dist = new Map<number, number>([[start, 0]]);
    const parent = new Map<number, number>();
    let hasIndirect = false;
    let degraded = false;
    // Durabilidade sai DESTA travessia, e não de uma segunda: duas travessias
    // divergentes produziriam dois laudos diferentes para o mesmo binário.
    const durWrites = new Set<Durability>();
    const durReads = new Set<Durability>();
    let durSites = 0;
    let durLiteral = 0;

    const caminhoAte = (idx: number): number[] => {
      const out: number[] = [];
      for (let cur: number | undefined = idx; cur !== undefined; cur = parent.get(cur)) out.push(cur);
      return out.reverse();
    };

    const fila: number[] = [start];
    for (let h = 0; h < fila.length; h++) {
      const idx = fila[h];
      if (idx < nImports) {
        const n = hostNameOf(idx)!;
        reaches.add(n);
        if (!pathTo.has(n)) pathTo.set(n, caminhoAte(idx));
        continue;
      }
      const body = bodyByIdx.get(idx);
      // função declarada sem corpo: o parser já marcou o módulo como incompleto
      if (!body) continue;
      if (body.hasIndirectCall) hasIndirect = true;
      if (body.degraded) degraded = true;
      // a fila só admite cada função uma vez, então nenhum corpo é contado em duplicidade
      for (const s of durSitesByFunc.get(idx) ?? []) {
        durSites++;
        if (!s.dur) continue;
        durLiteral++;
        (s.kind === "write" ? durWrites : durReads).add(s.dur);
      }
      const d = dist.get(idx)!;
      for (const c of body.calls) {
        if (dist.has(c.target)) continue;
        dist.set(c.target, d + 1);
        parent.set(c.target, idx);
        fila.push(c.target);
      }
    }
    return {
      reaches, pathTo, fanout: dist.size, hasIndirect, degraded,
      durability: { writes: durWrites, reads: durReads, sites: durSites, literal: durLiteral },
    };
  }

  /**
   * DFS separada, só para `orderedHostCalls`: a ordem de primeira ocorrência tem de
   * seguir a ordem das chamadas no bytecode, e BFS por camada destruiria isso.
   * Nenhuma outra resposta sai daqui — alcance, caminho e fanout vêm da BFS.
   */
  function ordemDeChamada(start: number): string[] {
    const ordered: string[] = [];
    const visited = new Set<number>();
    const rec = (idx: number): void => {
      if (visited.has(idx)) return;
      visited.add(idx);
      if (idx < nImports) {
        const n = hostNameOf(idx)!;
        if (!ordered.includes(n)) ordered.push(n);
        return;
      }
      const body = bodyByIdx.get(idx);
      if (body) for (const c of body.calls) rec(c.target);
    };
    rec(start);
    return ordered;
  }

  /**
   * Alcance a partir de TODOS os alvos de tabela, computado uma vez: é o mesmo
   * conjunto para qualquer export com despacho indireto, já que não dá para saber
   * qual entrada da tabela cada `call_indirect` seleciona.
   */
  const tableReach = ((): ReadonlySet<string> => {
    if (mod.tableTargets.size === 0) return new Set<string>();
    const out = new Set<string>();
    const seen = new Set<number>();
    const fila = [...mod.tableTargets];
    for (const t of fila) seen.add(t);
    for (let h = 0; h < fila.length; h++) {
      const idx = fila[h];
      if (idx < nImports) { out.add(hostNameOf(idx)!); continue; }
      const body = bodyByIdx.get(idx);
      if (!body) continue;
      for (const c of body.calls) if (!seen.has(c.target)) { seen.add(c.target); fila.push(c.target); }
    }
    return out;
  })();

  const VAZIO: ReadonlySet<string> = new Set<string>();
  const entrypoints: Entrypoint[] = [];
  for (const e of mod.exports) {
    if (NOT_ENTRYPOINTS.test(e.name)) continue;
    const { reaches, pathTo, fanout, hasIndirect, degraded, durability } = bfs(e.funcIdx);
    entrypoints.push({
      name: e.name,
      funcIdx: e.funcIdx,
      reaches,
      orderedHostCalls: ordemDeChamada(e.funcIdx),
      fanout,
      callGraphComplete: !hasIndirect && !degraded && mod.incomplete !== true,
      pathTo,
      reachesViaTable: hasIndirect ? tableReach : VAZIO,
      durability,
    });
  }

  const allReached = new Set<string>();
  for (const ep of entrypoints) for (const r of ep.reaches) allReached.add(r);
  const imports = mod.imports.map((i) => ({ key: i.key, name: hostFn(i.key)?.name }));
  const unreachableImports = imports.map((i) => i.name ?? i.key).filter((n) => !allReached.has(n));

  /*
   * Ordem auth × escrita.
   * A versão anterior comparava a ordem linearizada de uma DFS entre funções — o que
   * mistura ramos exclusivos e produz afirmação que ninguém consegue conferir.
   * Aqui só olhamos DENTRO de um mesmo corpo, comparando offsets de bytecode: se no
   * mesmo corpo a escrita aparece antes da autorização, isso é local e verificável.
   * Casos entre funções ficam indeterminados e não viram achado.
   */
  const writeBeforeAuth = new Map<string, OrderEvidence[]>();
  for (const ep of entrypoints) {
    const evid: OrderEvidence[] = [];
    const visited = new Set<number>();
    const stack = [ep.funcIdx];
    while (stack.length) {
      const idx = stack.pop()!;
      if (idx < nImports || visited.has(idx)) continue;
      visited.add(idx);
      const body = bodyByIdx.get(idx);
      if (!body) continue;
      let firstAuth: { off: number; fn: string } | undefined;
      let firstWrite: { off: number; fn: string } | undefined;
      for (const c of body.calls) {
        const n = hostNameOf(c.target);
        if (!n) { stack.push(c.target); continue; }
        if (!firstAuth && AUTH_FNS.has(n)) firstAuth = { off: c.offset, fn: n };
        if (!firstWrite && STORAGE_WRITE_FNS.has(n)) firstWrite = { off: c.offset, fn: n };
      }
      if (firstAuth && firstWrite && firstWrite.off < firstAuth.off) {
        evid.push({ bodyFuncIdx: idx, authOffset: firstAuth.off, writeOffset: firstWrite.off, authFn: firstAuth.fn, writeFn: firstWrite.fn });
      }
    }
    if (evid.length) writeBeforeAuth.set(ep.name, evid);
  }

  const envMeta = mod.customSections.get("contractenvmetav0");
  const hasIndirectAnywhere = mod.bodies.some((b) => b.hasIndirectCall);
  const hasDegraded = mod.bodies.some((b) => b.degraded);

  return {
    entrypoints,
    imports,
    unreachableImports,
    hasIndirectAnywhere,
    interfaceVersion: envMeta ? Buffer.from(envMeta).toString("hex").slice(0, 32) : undefined,
    envInterface: envMeta ? decodeEnvMeta(envMeta) : undefined,
    soundness: hasIndirectAnywhere || hasDegraded || mod.incomplete === true ? "approximate" : "sound",
    incompleteReason: mod.incompleteReason,
    writeBeforeAuth,
    durabilityCoverage,
  };
}

/**
 * `contractenvmetav0` é XDR: união `ScEnvMetaEntry` com discriminante u32 big-endian
 * (0 = interfaceVersion) seguido de um `uint64`. Em rs-soroban-env (`meta.rs`) esse u64
 * é `protocol << 32 | pre_release`. Guardar só o prefixo hex, como antes, não dizia nada
 * a ninguém — e é justamente o número que decide quais host functions existem.
 */
function decodeEnvMeta(b: Uint8Array): { protocol: number; preRelease: number } | undefined {
  if (b.length < 12) return undefined;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (dv.getUint32(0, false) !== 0) return undefined; // outro discriminante: não é interfaceVersion
  return { protocol: dv.getUint32(4, false), preRelease: dv.getUint32(8, false) };
}

/* ---------- consultas que os detectores usam ---------- */

const any = (s: ReadonlySet<string>, set: ReadonlySet<string>) => [...set].some((n) => s.has(n));

/** Ordem canônica: da mais volátil para a mais compartilhada. */
export const DURABILITY_ORDER = ["temporary", "persistent", "instance"] as const;

/** Durabilidades de ESCRITA do entrypoint, em ordem canônica. Vazio = nenhuma lida. */
export const writeDurabilities = (ep: Entrypoint): Durability[] =>
  DURABILITY_ORDER.filter((d) => ep.durability.writes.has(d));

export const requiresAuth = (ep: Entrypoint) => any(ep.reaches, AUTH_FNS);
export const writesStorage = (ep: Entrypoint) => any(ep.reaches, STORAGE_WRITE_FNS);
export const readsStorage = (ep: Entrypoint) => any(ep.reaches, STORAGE_READ_FNS);
export const emitsEvent = (ep: Entrypoint) => any(ep.reaches, EVENT_FNS);
/** Troca o código que ESTE contrato roda — inclui o segundo caminho do protocol 28. */
export const canUpgradeSelf = (ep: Entrypoint) => any(ep.reaches, UPGRADE_FNS);
/** Publica ou instancia outro código. Factory legítima cai aqui, não em upgrade. */
export const canDeploy = (ep: Entrypoint) => any(ep.reaches, DEPLOY_FNS);
/** Empresta a identidade do contrato em vez de verificar autorização. */
export const delegatesAuth = (ep: Entrypoint) => any(ep.reaches, AUTH_DELEGATE_FNS);
export const callsOut = (ep: Entrypoint) => any(ep.reaches, CROSS_CALL_FNS);
export const extendsTtl = (ep: Entrypoint) => any(ep.reaches, TTL_EXTEND_FNS);



/**
 * Menor número de saltos do export até QUALQUER host function do conjunto, ou
 * `undefined` se nenhuma é alcançada. Existe porque cada consumidor estava
 * escolhendo "a primeira do Set que tiver caminho" — o que depende da ordem de
 * iteração do conjunto, não do binário, e produz contagens diferentes para o
 * mesmo contrato conforme quem pergunta.
 */
export function minHops(ep: Entrypoint, fnNames: Iterable<string>): number | undefined {
  let best: number | undefined;
  for (const n of fnNames) {
    const p = ep.pathTo.get(n);
    if (!p) continue;
    const h = p.length - 1;
    if (best === undefined || h < best) best = h;
  }
  return best;
}

/** Caminho legível do export até a host function — é o que torna a afirmação conferível. */
export function caminho(ep: Entrypoint, hostFnName: string, nImports: number): string | undefined {
  const p = ep.pathTo.get(hostFnName);
  if (!p) return undefined;
  const hops = p.map((i) => (i < nImports ? hostFnName : `fn#${i}`));
  return hops.length > 6 ? `${hops.slice(0, 3).join(" → ")} → … (${hops.length - 4} saltos) → ${hops.at(-1)}` : hops.join(" → ");
}

/**
 * Subgrafo alcançável de cada entrypoint exportado, em índices de função.
 *
 * Existe para que outros analisadores atribuam um fato *local* (uma constante num corpo,
 * um offset de bytecode) aos entrypoints que o alcançam, sem reimplementar a travessia —
 * duas travessias divergentes produziriam dois laudos diferentes para o mesmo binário.
 */
export function exportSubgraphs(mod: WasmModule): Map<string, Set<number>> {
  const nImports = mod.imports.length;
  const bodyByIdx = new Map(mod.bodies.map((b) => [b.funcIdx, b]));
  const out = new Map<string, Set<number>>();
  for (const e of mod.exports) {
    if (NOT_ENTRYPOINTS.test(e.name)) continue;
    const seen = new Set<number>();
    const stack = [e.funcIdx];
    while (stack.length) {
      const idx = stack.pop()!;
      if (seen.has(idx) || idx < nImports) continue;
      seen.add(idx);
      const body = bodyByIdx.get(idx);
      if (body) for (const c of body.calls) stack.push(c.target);
    }
    // um mesmo nome exportado duas vezes é patológico, mas a união não mente
    const prev = out.get(e.name);
    if (prev) for (const i of seen) prev.add(i);
    else out.set(e.name, seen);
  }
  return out;
}
