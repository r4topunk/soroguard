/**
 * Catálogo de host functions do Soroban — a ponte entre os imports do WASM (`a.0`, `l.6`)
 * e os nomes canônicos em que a taxonomia de ameaças é escrita.
 *
 * O JSON vendorizado ao lado é cópia aparada de `rs-soroban-env/soroban-env-common/env.json`.
 * Vendorizamos em vez de buscar em runtime porque a análise de nível A precisa ser
 * redeterminística: o mesmo binário tem que produzir o mesmo laudo daqui a um ano.
 */

import catalog from "./hostfns.json" with { type: "json" };

/**
 * A granularidade aqui não é cosmética — cada categoria que existe separada existe porque
 * fundi-la com outra produziria falso positivo em algum detector de `docs/PROBLEMA.md`:
 *
 *   auth / auth-delegate / auth-introspect
 *     `require_auth*` EXIGE autorização; `authorize_as_curr_contract` CONCEDE (o contrato
 *     empresta a própria identidade a uma sub-invocação); `get_delegated_signers_*` só LÊ o
 *     contexto do check corrente. Tratar as três como "auth" faria um entrypoint que apenas
 *     delega privilégio passar por entrypoint protegido — inversão de sentido, não imprecisão.
 *
 *   upgrade / deploy
 *     `update_current_contract_wasm` troca o código QUE ESTE CONTRATO EXECUTA; `create_contract`
 *     instancia OUTRO código. A primeira é "Upgrade sem controle" na taxonomia; a segunda é
 *     padrão factory, legítimo e comum. Fundidas, toda factory viraria achado de upgrade.
 *
 * Subconjuntos que são recorte e não inversão de sentido (verificação de assinatura dentro de
 * `crypto`, por exemplo) ficam como Set nomeado, sem categoria própria.
 */
export type HostCategory =
  | "auth"
  | "auth-delegate"
  | "auth-introspect"
  | "address"
  | "storage-read"
  | "storage-write"
  | "ttl"
  | "upgrade"
  | "deploy"
  | "ledger"
  | "event"
  | "cross-call"
  | "context"
  | "crypto"
  | "prng"
  | "int"
  | "map"
  | "vec"
  | "buf"
  | "test";

export type HostFn = {
  /** `<módulo>.<função>` exatamente como aparece no import do WASM */
  key: string;
  name: string;
  module: string;
  category: HostCategory;
};

type RawFn = { name: string; module: string; category: string; since?: number; until?: number };

const RAW = catalog.fns as Record<string, RawFn>;

const BY_KEY = new Map<string, HostFn>();
const BY_NAME = new Map<string, HostFn>();
for (const [key, raw] of Object.entries(RAW)) {
  const fn: HostFn = { key, name: raw.name, module: raw.module, category: raw.category as HostCategory };
  BY_KEY.set(key, fn);
  BY_NAME.set(raw.name, fn);
}

export const CATALOG_META: { source: string; fetchedAt: string; count: number } = {
  source: catalog.source,
  fetchedAt: catalog.fetchedAt,
  count: BY_KEY.size,
};

/** Resolve um import do WASM (`"a.0"`) para a host function canônica. */
export function hostFn(key: string): HostFn | undefined {
  return BY_KEY.get(key);
}

export function categoryOf(name: string): HostCategory | undefined {
  return BY_NAME.get(name)?.category;
}

/** Todas as host functions, para quem precisa varrer o catálogo inteiro. */
export function allHostFns(): readonly HostFn[] {
  return [...BY_KEY.values()];
}

/* ------------------------------------------------------------------ *
 * Conjuntos de que a taxonomia depende.
 *
 * Os derivados de categoria saem do próprio catálogo — assim um nome novo no upstream
 * (ex.: um `extend_*_ttl` de protocolo futuro) entra no Set sozinho, sem editar código.
 * Os recortes manuais passam por `named()`, que estoura na carga do módulo se um nome não
 * existir: um Set vazio por typo seria pior que um erro, porque viraria falso negativo
 * silencioso num laudo que se apresenta como fato de bytecode.
 * ------------------------------------------------------------------ */

function byCategory(...cats: HostCategory[]): ReadonlySet<string> {
  const want = new Set<HostCategory>(cats);
  return new Set([...BY_KEY.values()].filter((f) => want.has(f.category)).map((f) => f.name));
}

function named(...names: string[]): ReadonlySet<string> {
  const missing = names.filter((n) => !BY_NAME.has(n));
  if (missing.length) throw new Error(`hostfns: nomes ausentes do catálogo: ${missing.join(", ")}`);
  return new Set(names);
}

/** Exige autorização de um Address. A ausência destes num entrypoint é o sinal primário. */
export const AUTH_FNS = byCategory("auth");

/** Concede a identidade do contrato a uma sub-invocação. NÃO conta como checagem de auth. */
export const AUTH_DELEGATE_FNS = byCategory("auth-delegate");

/** Lê o contexto do check de auth corrente — típico de `__check_auth` de smart account. */
export const AUTH_INTROSPECT_FNS = byCategory("auth-introspect");

/** `del_contract_data` entra aqui: apagar estado é mutação, e a classe de ameaça é a mesma. */
export const STORAGE_WRITE_FNS = byCategory("storage-write");
export const STORAGE_READ_FNS = byCategory("storage-read");

/**
 * Só `contract_event`. `log_from_linear_memory` emite evento de diagnóstico, que não entra
 * no stream que o monitoring plan filtra via getEvents — contá-lo mascararia mutação silenciosa.
 */
export const EVENT_FNS = byCategory("event");

/** Substituição do próprio código. Inclui o caminho por executable ref (protocolo 28). */
export const UPGRADE_FNS = byCategory("upgrade");

/** Publicação/instanciação de OUTRO código. `upload_wasm` entra por ser a mesma superfície de supply chain. */
export const DEPLOY_FNS = byCategory("deploy");

/** União, para quem quer "mexe em código" sem se importar com de quem é o código. */
export const CODE_MUTATION_FNS = byCategory("upgrade", "deploy");

export const CROSS_CALL_FNS = byCategory("cross-call");

export const TTL_EXTEND_FNS = byCategory("ttl");

/**
 * Verificação/recuperação de assinatura. Recorte de `crypto`: são as que indicam auth
 * artesanal (smart account, permit assinado) em vez de aritmética de curva.
 */
export const CRYPTO_VERIFY_FNS = named(
  "verify_sig_ed25519",
  "verify_sig_ecdsa_secp256r1",
  "recover_key_ecdsa_secp256k1",
);

/**
 * Verificação de assinatura MAIS os hashes de domínio/mensagem. É o conjunto que indica
 * um verificador artesanal (EIP-712-like, permit assinado, smart account): quem checa
 * assinatura no contrato quase sempre também monta o digest com `compute_hash_*`.
 * Separado de `CRYPTO_VERIFY_FNS` porque hash sozinho não é verificação — aqui o conjunto
 * é o GATILHO de uma leitura de spec, não a afirmação de que há verificação.
 */
export const SIG_SCHEME_FNS = named(
  "verify_sig_ed25519",
  "verify_sig_ecdsa_secp256r1",
  "recover_key_ecdsa_secp256k1",
  "compute_hash_sha256",
  "compute_hash_keccak256",
);

export const PRNG_FNS = byCategory("prng");
