import { rpc, xdr } from "@stellar/stellar-sdk";
import { customSection } from "./wasm.ts";
import type { ContractModel, ErrEnum, EventDecl, Fn, FnTrait, Param } from "./model.ts";

/**
 * Endpoints padrão. `mainnet.sorobanrpc.com` é um RPC **público da comunidade**, com rate
 * limit e sem garantia de disponibilidade — serve de fallback, não de infraestrutura. Para
 * uso sério aponte `-n <url>` ou a variável de ambiente `SOROGUARD_RPC_URL` para um nó seu.
 */
export const NETWORKS: Record<string, string> = {
  mainnet: "https://mainnet.sorobanrpc.com",
  testnet: "https://soroban-testnet.stellar.org",
};

/** Decodifica a custom section `contractspecv0` numa lista de entradas XDR. */
export function parseSpecEntries(wasm: Uint8Array): unknown[] {
  const section = customSection(wasm, "contractspecv0");
  if (!section) return [];
  // O buffer é uma sequência de ScSpecEntry concatenadas, sem contagem prefixada.
  return (xdr as any).decodeStream(xdr.ScSpecEntry, Buffer.from(section), "raw") as unknown[];
}

/* ------------------------------------------------------------------ *
 * Adaptadores de forma.
 * decodeStream(..., "raw") devolve objetos XDR planos ({ type, functionV0 })
 * enquanto a API de união do SDK expõe métodos (.switch(), .functionV0()).
 * Lemos as duas formas para não quebrar entre versões do SDK.
 * ------------------------------------------------------------------ */
const call = (o: any, k: string): any => (typeof o?.[k] === "function" ? o[k]() : o?.[k]);
const kindOf = (e: any): string => {
  const k = typeof e?.switch === "function" ? e.switch() : (e?.type ?? e?.kind);
  return typeof k === "string" ? k : (k?.name ?? String(k));
};
const sym = (v: any): string => {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v)) return v.toString();
  if (v.bytes) return Buffer.from(v.bytes).toString(); // XdrString
  if (typeof v.name === "string") return v.name;       // enum XDR
  return String(v);
};

function typeName(t: any): string {
  const raw = typeof t?.switch === "function" ? t.switch().name : (t?.type ?? t?._switch?.name ?? t);
  return String(raw).replace(/^scSpecType/, "").replace(/^./, (c) => c.toLowerCase());
}

const RE: Record<string, RegExp> = {
  admin: /admin|owner|ownership|authority|manager|operator|governor|add_signer|remove_signer|set_authorized/i,
  upgrade: /upgrade|migrate|set_wasm|update_code/i,
  pause: /pause|freeze|halt|emergency|kill/i,
  // "transfer" só conta como movimento de valor se não for transferência de papel/controle.
  moves_funds: /(?!transfer_(ownership|owner|team|admin|authority|role|manager))(^|_)(transfer|withdraw|deposit|claim|swap|send|payout|sweep|liquidat|redeem|borrow|repay|settle)/i,
  mint_burn: /^mint|^burn|issue|clawback/i,
  config: /^set_|^update_|^configure|^add$|^add_|^remove|^register|^init/i,
};

const MUTATING: FnTrait[] = ["admin", "upgrade", "pause", "moves_funds", "mint_burn", "config"];

function traitsFor(name: string, params: Param[], returns: string): FnTrait[] {
  const t = new Set<FnTrait>();
  if (/^__constructor$|^initialize$|^init$/i.test(name)) t.add("constructor");
  for (const [trait, re] of Object.entries(RE)) {
    if (re.test(name)) t.add(trait as FnTrait);
  }
  // transferir um papel não é mover fundos
  if (/transfer_(ownership|owner|team|admin|authority|role|manager)/i.test(name)) t.delete("moves_funds");
  if (params.some((p) => p.type === "address")) t.add("takes_address");
  // um parâmetro chamado new_admin/new_owner delata mudança de controle mesmo se o nome da fn não delatar
  if (params.some((p) => /admin|owner|authority|manager|operator|governor/i.test(p.name))) t.add("admin");
  if (params.some((p) => /^[iu](32|64|128)$/.test(p.type) && /amount|value|qty|quantity|shares|tokens/i.test(p.name))) {
    t.add("takes_amount");
  }
  if (/^(get_|is_|has_|query_|view_|balance|decimals|name$|symbol$)/i.test(name) && returns !== "void") {
    // getter não muda estado: descarta os traços de mutação para não poluir o STRIDE
    for (const m of MUTATING) t.delete(m);
    t.add("read_only");
  }
  return [...t];
}

export function modelFromEntries(entries: unknown[]): Pick<ContractModel, "fns" | "errors" | "events" | "specEntryCounts"> {
  const fns: Fn[] = [];
  const errors: ErrEnum[] = [];
  const events: EventDecl[] = [];
  const specEntryCounts: Record<string, number> = {};

  for (const e of entries as any[]) {
    const kind = kindOf(e);
    specEntryCounts[kind] = (specEntryCounts[kind] ?? 0) + 1;
    switch (kind) {
      case "scSpecEntryFunctionV0": {
        const f = call(e, "functionV0");
        const params: Param[] = (call(f, "inputs") ?? []).map((i: any) => ({
          name: sym(call(i, "name")),
          type: typeName(call(i, "type")),
        }));
        const outs = call(f, "outputs") ?? [];
        const returns = outs.length ? typeName(outs[0]) : "void";
        const name = sym(call(f, "name"));
        fns.push({ name, params, returns, doc: sym(call(f, "doc")), traits: traitsFor(name, params, returns) });
        break;
      }
      case "scSpecEntryUdtErrorEnumV0": {
        const en = call(e, "udtErrorEnumV0");
        errors.push({
          name: sym(call(en, "name")),
          cases: (call(en, "cases") ?? []).map((c: any) => ({ name: sym(call(c, "name")), value: Number(call(c, "value")) })),
        });
        break;
      }
      case "scSpecEntryEventV0": {
        const ev = call(e, "eventV0");
        events.push({
          name: sym(call(ev, "name")),
          prefixTopics: (call(ev, "prefixTopics") ?? []).map(sym),
          dataFormat: sym(call(ev, "dataFormat")).replace(/^scSpecEventDataFormat/, ""),
          params: (call(ev, "params") ?? []).map((p: any) => ({
            name: sym(call(p, "name")),
            type: typeName(call(p, "type")),
            location: sym(call(p, "location")).replace(/^scSpecEventParamLocation/, ""),
          })),
          source: "spec",
        });
        break;
      }
    }
  }
  return { fns, errors, events, specEntryCounts };
}

export async function fetchWasm(contractId: string, network: string): Promise<{ wasm: Uint8Array; wasmHash?: string }> {
  const url = NETWORKS[network] ?? network;
  const server = new rpc.Server(url);
  const wasm = await server.getContractWasmByContractId(contractId);
  let wasmHash: string | undefined;
  try {
    const inst = await server.getContractInstance(contractId);
    const exe = (inst as any)?.executable;
    // Medido contra o SDK 17: `executable.wasmHash` é um `xdr.Hash`, não um Buffer — ele não
    // tem `.toString("hex")` (estoura com ERR_INVALID_ARG_TYPE, engolido pelo catch), e por
    // isso TODO alvo por contract id saía com "hash do WASM não capturado". O hash é o
    // baseline dos monitores de upgrade e o que prende o documento ao binário que está no ar.
    // As três formas conhecidas ficam cobertas: string hex, bytes e wrapper XDR.
    const bruto = exe?.wasmHash ?? exe?.wasm ?? exe?.wasm_hash;
    const hex =
      typeof bruto === "string" ? bruto
      : Buffer.isBuffer(bruto) || bruto instanceof Uint8Array ? Buffer.from(bruto).toString("hex")
      : bruto?.value ? Buffer.from(bruto.value).toString("hex")
      : bruto != null ? String(bruto)
      : undefined;
    if (hex && /^[0-9a-f]{64}$/i.test(hex)) wasmHash = hex.toLowerCase();
  } catch { /* instância pode não expor o hash; não é fatal */ }
  return { wasm, wasmHash };
}
