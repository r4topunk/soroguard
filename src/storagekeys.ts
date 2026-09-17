/**
 * Quais chaves de storage o contrato usa — lidas do WASM deployado.
 *
 * Alimenta os "data stores" do data-flow diagram e o inventário de componentes do
 * monitoring plan. Por isso a régua aqui é precisão, não cobertura: uma chave errada
 * num artefato de segurança derruba o documento inteiro; uma chave faltando só o deixa
 * incompleto — e a lacuna é declarável.
 *
 * ── Como o Soroban constrói símbolo, medido em 75 contratos de mainnet ──
 *
 * O enunciado óbvio ("procure `symbol_new_from_linear_memory` com dois `i32.const` antes")
 * quase nunca casa direto: em 1.612 de 1.614 sítios o compilador emite um *wrapper* fino
 * `fn(ptr: i32, len: i32) -> Symbol` que faz a codificação de 6 bits inline e só cai na
 * host function quando o símbolo passa de 9 caracteres. Os dois `i32.const` ficam no
 * chamador do wrapper, não no chamador da host function. Daí `SYMBOL_CTORS`.
 *
 * Símbolo de até 9 caracteres também aparece como `SymbolSmall`: um `i64.const` cujo byte
 * baixo é a tag 14 e cujos 54 bits restantes são 9 códigos de 6 bits. Esse caminho não
 * toca a seção de dados — quem procurar só na memória linear perde a maioria das chaves.
 *
 * ── Por que nem todo símbolo é chave ──
 *
 * Varrer todos os símbolos do módulo dá ~909 strings limpas, mas mistura tópico de evento
 * (`transfer`, `role_granted`), nome de função de contrato chamado (`balance_of`) e variante
 * de enum do próprio SDK (`CreateContractHostFn`, `Wasm`). Publicar isso como "chaves de
 * storage" seria exatamente o slop descrito em `docs/CALIBRACAO.md`. Então a chave só entra
 * quando o bytecode mostra que ela **é o argumento `k`** de uma host function de storage.
 */

import { parseModule, type WasmModule, type CallSite, type ConstSite } from "./wasm.ts";
import { readMemoryOf } from "./datasec.ts";
import { hostFn } from "./hostfns.ts";
import { exportSubgraphs } from "./analyze.ts";

export type KeyConfidence = "certain" | "likely";

export type StorageKeySite = {
  key: string;
  confidence: KeyConfidence;
  /** host function de storage que consome a chave */
  via: string;
  /** corpo onde o símbolo é construído — é o que liga a chave a um entrypoint */
  builtIn: number;
  /** offset da chamada de storage no bytecode: torna a afirmação conferível */
  offset: number;
};

export type StorageKeyFinding = {
  key: string;
  confidence: KeyConfidence;
  /** entrypoints exportados cujo subgrafo alcança a construção do símbolo */
  foundIn: string[];
};

/**
 * Aridade das host functions de storage e posição do argumento `k` (sempre a primeira).
 * `typeArg` é a distância, a partir do fim, do argumento `StorageType` — que o guest passa
 * como i64 cru 0/1/2 (Temporary/Persistent/Instance), NÃO como `U32Val`. Exigir esse
 * literal no lugar certo é o que impede casar com uma sequência qualquer de constantes.
 */
const STORAGE_SINKS: Record<string, { arity: number; typeArg: number }> = {
  has_contract_data: { arity: 2, typeArg: 1 },
  get_contract_data: { arity: 2, typeArg: 1 },
  del_contract_data: { arity: 2, typeArg: 1 },
  put_contract_data: { arity: 3, typeArg: 1 },
  extend_contract_data_ttl: { arity: 4, typeArg: 3 },
};

/** Charset e tamanho de `soroban_sdk::Symbol`. Filtro barato contra ponteiro mal resolvido. */
const SYMBOL_RE = /^[A-Za-z0-9_]{1,32}$/;

/** Código de 6 bits → caractere, conforme `SymbolSmall` de `rs-soroban-env`. */
const SMALL_CODE: readonly (string | undefined)[] = (() => {
  const t: (string | undefined)[] = new Array(64).fill(undefined);
  t[1] = "_";
  for (let i = 0; i < 10; i++) t[2 + i] = String.fromCharCode(0x30 + i);
  for (let i = 0; i < 26; i++) t[12 + i] = String.fromCharCode(0x41 + i);
  for (let i = 0; i < 26; i++) t[38 + i] = String.fromCharCode(0x61 + i);
  return t;
})();

/**
 * Decodifica um `Val` de tag 14. Devolve undefined para qualquer coisa que não seja um
 * símbolo válido — inclusive o símbolo vazio, porque `i64.const 14` é indistinguível do
 * inteiro 14 e aceitá-lo encheria o resultado de chaves `""`.
 */
export function decodeSymbolSmall(val: bigint): string | undefined {
  if ((val & 0xffn) !== 14n) return undefined;
  let body = val >> 8n;
  if (body === 0n || body >> 54n) return undefined;
  let out = "";
  while (body > 0n) {
    const ch = SMALL_CODE[Number(body & 63n)];
    if (ch === undefined) return undefined;
    out = ch + out;
    body >>= 6n;
  }
  return out;
}

/** Um `Val` de tag 4 carrega o u32 nos 32 bits altos. */
const asU32 = (v: bigint): number | undefined => ((v & 0xffn) === 4n ? Number(v >> 32n) : undefined);

type Item = ({ kind: "const" } & ConstSite) | ({ kind: "call" } & CallSite);

/**
 * Coleta as chaves e os sítios que as provam. Separado de `inferStorageKeys` porque o
 * artefato precisa citar offset e função — afirmação de nível A sem caminho não é conferível.
 */
export function storageKeySites(mod: WasmModule, read: (a: number, l: number) => Uint8Array | undefined): StorageKeySite[] {
  const nImports = mod.imports.length;
  const bodyByIdx = new Map(mod.bodies.map((b) => [b.funcIdx, b]));
  const hostNameOf = (i: number) => (i < nImports ? hostFn(mod.imports[i].key)?.name : undefined);

  /* Host functions alcançáveis a partir de cada função — usado só para classificar
     construtor de símbolo e key-builder, não para afirmar nada sobre o entrypoint. */
  const reachMemo = new Map<number, Set<string>>();
  const reach = (idx: number): Set<string> => {
    if (idx < nImports) return new Set([mod.imports[idx].key]);
    const hit = reachMemo.get(idx);
    if (hit) return hit;
    const out = new Set<string>();
    reachMemo.set(idx, out); // publicado antes da recursão: fecha ciclo sem estourar a pilha
    const body = bodyByIdx.get(idx);
    if (body) for (const c of body.calls) for (const k of reach(c.target)) out.add(k);
    return out;
  };
  for (const b of mod.bodies) reach(b.funcIdx);

  /*
   * Construtor de símbolo: o import `symbol_new_from_linear_memory` e qualquer função cuja
   * ÚNICA host function alcançável seja ele. A exclusividade é o que garante que um par
   * (ptr, len) passado ali só pode ser lido como símbolo — um wrapper que também alcance
   * `string_new_from_linear_memory` ou `bytes_new_from_linear_memory` tornaria a leitura
   * um chute sobre qual dos três o compilador quis.
   */
  const SYMBOL_CTORS = new Set<number>();
  for (let i = 0; i < nImports; i++) if (hostNameOf(i) === "symbol_new_from_linear_memory") SYMBOL_CTORS.add(i);
  const ctorKeys = new Set([...SYMBOL_CTORS].map((i) => mod.imports[i].key));
  for (const b of mod.bodies) {
    const r = reach(b.funcIdx);
    if (r.size === 1 && [...r].every((k) => ctorKeys.has(k))) SYMBOL_CTORS.add(b.funcIdx);
  }

  /* Instrução indexada pelo offset em que TERMINA: é assim que se testa adjacência. */
  const itemsByEnd = new Map<number, Map<number, Item>>();
  for (const b of mod.bodies) {
    const m = new Map<number, Item>();
    for (const c of b.consts ?? []) m.set(c.end, { kind: "const", ...c });
    for (const c of b.calls) m.set(c.end, { kind: "call", ...c });
    itemsByEnd.set(b.funcIdx, m);
  }

  /** Resolve `(i32.const ptr, i32.const len) call <ctor>` — ou a mesma dupla em `U32Val`. */
  function ctorString(hostIdx: number, call: CallSite): string | undefined {
    const m = itemsByEnd.get(hostIdx);
    const lenArg = m?.get(call.offset);
    const ptrArg = lenArg && m?.get(lenArg.offset);
    if (!ptrArg || !lenArg || ptrArg.kind !== "const" || lenArg.kind !== "const") return undefined;
    let ptr: number | undefined, len: number | undefined;
    if (ptrArg.bits === 32 && lenArg.bits === 32) { ptr = Number(ptrArg.value); len = Number(lenArg.value); }
    else if (ptrArg.bits === 64 && lenArg.bits === 64) { ptr = asU32(ptrArg.value); len = asU32(lenArg.value); }
    if (ptr === undefined || len === undefined) return undefined;
    const bytes = read(ptr, len);
    if (!bytes) return undefined;
    const s = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return SYMBOL_RE.test(s) ? s : undefined;
  }

  /**
   * Símbolos montados no CORPO PRÓPRIO de um key-builder. Sem recursão de propósito: descer
   * nas funções chamadas traz as variantes dos enums aninhados dentro do payload da chave
   * (`Default`, `CallContract`), que não nomeiam storage nenhum.
   */
  const ownSymbols = (idx: number): string[] => {
    const body = bodyByIdx.get(idx);
    if (!body) return [];
    const out = new Set<string>();
    for (const c of body.calls) {
      if (!SYMBOL_CTORS.has(c.target)) continue;
      const s = ctorString(idx, c);
      if (s) out.add(s);
    }
    for (const c of body.consts ?? []) {
      if (c.bits !== 64) continue;
      const s = decodeSymbolSmall(c.value);
      if (s) out.add(s);
    }
    return [...out];
  };

  /*
   * Key-builder "limpo": função sem nenhum efeito colateral alcançável. Se a função que
   * produz `k` pudesse ela mesma gravar, emitir evento ou chamar outro contrato, ela não
   * seria um construtor de chave e sim lógica de negócio — e os símbolos lá dentro não
   * teriam relação com a chave deste sítio.
   */
  const IMPURE = new Set([
    "put_contract_data", "get_contract_data", "has_contract_data", "del_contract_data",
    "extend_contract_data_ttl", "extend_contract_data_ttl_v2",
    "contract_event", "call", "try_call",
    "require_auth", "require_auth_for_args", "authorize_as_curr_contract",
    "update_current_contract_wasm", "create_contract", "upload_wasm", "fail_with_error",
  ]);
  const isPure = (idx: number) => ![...reach(idx)].some((k) => IMPURE.has(hostFn(k)?.name ?? k));

  const sites: StorageKeySite[] = [];
  for (const body of mod.bodies) {
    const m = itemsByEnd.get(body.funcIdx)!;
    for (const call of body.calls) {
      const sink = STORAGE_SINKS[hostNameOf(call.target) ?? ""];
      if (!sink) continue;

      /* Recua argumento a argumento exigindo adjacência estrita. Sem isso, um `local.get`
         no meio faria a busca pegar a chamada anterior — que não produziu a chave. */
      let cur: Item | undefined = m.get(call.offset);
      let typeOk = false;
      for (let back = 1; back < sink.arity && cur; back++) {
        if (back === sink.typeArg) typeOk = cur.kind === "const" && cur.bits === 64 && cur.value <= 2n;
        cur = m.get(cur.offset);
      }
      if (!cur || !typeOk) continue;

      const via = hostNameOf(call.target)!;
      // k literal: `i64.const <SymbolSmall>` colado na chamada
      if (cur.kind === "const") {
        const s = cur.bits === 64 ? decodeSymbolSmall(cur.value) : undefined;
        if (s) sites.push({ key: s, confidence: "certain", via, builtIn: body.funcIdx, offset: call.offset });
        continue;
      }
      // k é `Symbol::new(env, "…")` colado na chamada
      if (SYMBOL_CTORS.has(cur.target)) {
        const s = ctorString(body.funcIdx, cur);
        if (s) sites.push({ key: s, confidence: "certain", via, builtIn: body.funcIdx, offset: call.offset });
        continue;
      }
      // k é o retorno de um key-builder puro: sabemos que a chave sai dali, não qual variante
      if (cur.target >= nImports && isPure(cur.target)) {
        for (const s of ownSymbols(cur.target)) {
          sites.push({ key: s, confidence: "likely", via, builtIn: cur.target, offset: call.offset });
        }
      }
    }
  }
  return sites;
}

/**
 * Chaves de storage do módulo, com o nível de confiança e os entrypoints que as alcançam.
 *
 * `certain` — o símbolo é literalmente o argumento `k` da host function de storage,
 *   adjacência provada no bytecode. Fato de nível A.
 * `likely`  — o `k` vem de uma função construtora sem efeito colateral, e este é um dos
 *   símbolos que ela monta. Que a função nomeia storage é fato; qual variante cada sítio
 *   usa, não. Sobre-aproxima dentro de um conjunto conhecido, e vai rotulada.
 */
export function inferStorageKeys(wasm: Uint8Array): StorageKeyFinding[] {
  const mod = parseModule(wasm, { consts: true });
  const sites = storageKeySites(mod, readMemoryOf(wasm));
  if (!sites.length) return [];

  const subgraphs = exportSubgraphs(mod);
  const byKey = new Map<string, { confidence: KeyConfidence; builders: Set<number> }>();
  for (const s of sites) {
    const e = byKey.get(s.key) ?? { confidence: "likely" as KeyConfidence, builders: new Set<number>() };
    // basta um sítio provado para a chave inteira subir de nível
    if (s.confidence === "certain") e.confidence = "certain";
    e.builders.add(s.builtIn);
    byKey.set(s.key, e);
  }

  const out: StorageKeyFinding[] = [];
  for (const [key, { confidence, builders }] of byKey) {
    const foundIn: string[] = [];
    for (const [name, sub] of subgraphs) if ([...builders].some((b) => sub.has(b))) foundIn.push(name);
    out.push({ key, confidence, foundIn: foundIn.sort() });
  }
  // certain primeiro: é a ordem em que o revisor deve ler
  return out.sort((a, b) =>
    a.confidence === b.confidence ? a.key.localeCompare(b.key) : a.confidence === "certain" ? -1 : 1,
  );
}
