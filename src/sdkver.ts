import { parseModule } from "./wasm.ts";
import { allHostFns, hostFn } from "./hostfns.ts";
import { msgs } from "./i18n.ts";

/**
 * A versão do soroban-sdk usada na compilação fica gravada na custom section
 * `contractmetav0`, sob a chave `rssdkver`. Isso é observável APENAS no artefato
 * deployado. O fonte mostra o padrão de código que um advisory exige (ex.: colisão de
 * nomes trait/inerente); o que só o artefato mostra é qual SDK compilou o binário que está
 * no ledger — o repositório pode ter sido atualizado depois do deploy.
 */
export type SdkInfo = {
  version?: string;
  commit?: string;
  raw: Record<string, string>;
  /** o módulo tem ao menos uma custom section `contractmetav0` */
  present?: boolean;
  /**
   * a decodificação parou antes do fim de alguma seção. Com isto `raw` é PARCIAL: a ausência
   * de `rssdkver` deixa de ser "não declarado" e vira "não lido" — estados diferentes.
   */
  partial?: boolean;
  /** offset (em bytes, dentro da seção) da entrada malformada que interrompeu a leitura */
  partialAt?: number;
};

/**
 * Faixa afetada. O limite superior precisa distinguir `<=` de `<` porque os dois advisories
 * usam as duas formas: a versão anterior codificava `< 25.3.0` como `25.2.999`, um número que
 * não existe — se algum dia existir um `25.2.1000`, a faixa passa a mentir. `maxInclusive`
 * elimina o truque e mantém a faixa idêntica ao texto do advisory.
 */
export type Range = { min: string; max: string; maxInclusive: boolean };

export type Advisory = {
  id: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  title: string;
  /** faixas afetadas, com limite inferior sempre inclusivo */
  affected: Range[];
  patched: string[];
  url: string;
  /**
   * Condição de disparo descrita pelo advisory. Vai para a evidência nível C: é o que a
   * revisão manual precisa confirmar, e o bytecode não mostra.
   */
  trigger: string;
  /**
   * Filtro heurístico opcional: só reportar se o WASM importar ao menos uma destas host
   * functions (nomes canônicos de `env.json`). Ausência de import NÃO prova ausência do tipo
   * afetado — é um corte de ruído, e a evidência C do achado diz isso.
   */
  requiresHostFn?: ReadonlySet<string>;
};

/**
 * Host functions de BLS12-381 e BN254 (módulo `crypto`, import `c.*`), derivadas do catálogo
 * vendorizado de `rs-soroban-env/soroban-env-common/env.json`: BLS12-381 desde o protocolo 22
 * (c.4–c.l, c.x, c.y), BN254 desde o 25 (c.m–c.o) e 26 (c.r–c.w, c.z).
 */
export const PAIRING_CURVE_FNS: ReadonlySet<string> = new Set(
  allHostFns().filter((f) => /^(bls12_381|bn254)_/.test(f.name)).map((f) => f.name),
);

/**
 * Texto dos advisories que chega ao revisor. `id`, `url`, `severity` e as faixas são dado,
 * não texto: ficam fora daqui e idênticos nos dois idiomas.
 */
const M = msgs({
  en: {
    adv1Title: "soroban-sdk-macros: authorization bypass",
    adv1Trigger:
      "Only triggers if the contract has `impl Trait for C` with #[contractimpl] AND `impl C` with a function of the same name: " +
      "the macro exports the inherent function instead of the trait one. The source shows that collision; the bytecode does not.",
    adv2Title: "Fr equality without modular reduction — may lead to an incorrect authorization decision",
    adv2Trigger:
      "Only affects contracts that take `Fr` (BN254/BLS12-381) as input and compare it with ==/!=/assert_eq! without modular reduction.",
    cmpNaoParseavel: (v: string) => `cmp: version not parseable: ${v}`,
    metaParcial: (off: number) =>
      `⟨contractmetav0 could not be decoded past byte ${off}; rssdkver was not read⟩`,
    faixaNaoParseavel: (min: string, max: string) => `advisory range not parseable: ${min}..${max}`,
  },
  pt: {
    adv1Title: "soroban-sdk-macros: bypass de autorização",
    adv1Trigger:
      "Só dispara se o contrato tiver `impl Trait for C` com #[contractimpl] E `impl C` com função de mesmo nome: " +
      "o macro exporta a função inerente em vez da do trait. O fonte mostra essa colisão; o bytecode não.",
    adv2Title: "igualdade de Fr sem redução modular — pode levar a decisão de autorização incorreta",
    adv2Trigger:
      "Só afeta contratos que recebem `Fr` (BN254/BLS12-381) de entrada e o comparam com ==/!=/assert_eq! sem redução modular.",
    cmpNaoParseavel: (v: string) => `cmp: versão não parseável: ${v}`,
    metaParcial: (off: number) =>
      `⟨contractmetav0 não pôde ser decodificada além do byte ${off}; rssdkver não foi lido⟩`,
    faixaNaoParseavel: (min: string, max: string) => `faixa de advisory não parseável: ${min}..${max}`,
  },
});

/**
 * Advisories conhecidos contra soroban-sdk. Lista curada manualmente e datada:
 * a ferramenta não busca advisory em runtime, então esta tabela envelhece —
 * `ADVISORIES_AS_OF` existe para que o relatório declare a data em vez de fingir atualidade.
 */
export const ADVISORIES_AS_OF = "2026-09-16";

export const ADVISORIES: Advisory[] = [
  {
    id: "CVE-2026-26267 / GHSA-4chv-4c6w-w254",
    severity: "High",
    get title() { return M.adv1Title; },
    // GHSA: <= 22.0.9, >= 23.0.0 <= 23.5.1, >= 25.0.0 <= 25.1.0 (pacote soroban-sdk-macros,
    // versionado junto com soroban-sdk — por isso `rssdkver` serve de proxy).
    affected: [
      { min: "0.0.0", max: "22.0.9", maxInclusive: true },
      { min: "23.0.0", max: "23.5.1", maxInclusive: true },
      { min: "25.0.0", max: "25.1.0", maxInclusive: true },
    ],
    patched: ["22.0.10", "23.5.2", "25.1.1"],
    url: "https://github.com/advisories/GHSA-4chv-4c6w-w254",
    get trigger() { return M.adv1Trigger; },
  },
  {
    id: "GHSA-x2hw-px52-wp4m",
    severity: "Medium",
    get title() { return M.adv2Title; },
    // GHSA: < 22.0.11, >= 23.0.0 < 23.5.3, >= 25.0.0 < 25.3.0. O piso é 22.0.0 e não 0.0.0:
    // `crypto::bls12_381::Fr` aparece em soroban-sdk v22.0.0 (ausente em v21.7.7) e
    // `crypto::bn254::Fr` em v25.0.0. Antes disso o tipo afetado não existe.
    affected: [
      { min: "22.0.0", max: "22.0.11", maxInclusive: false },
      { min: "23.0.0", max: "23.5.3", maxInclusive: false },
      { min: "25.0.0", max: "25.3.0", maxInclusive: false },
    ],
    patched: ["22.0.11", "23.5.3", "25.3.0"],
    url: "https://github.com/advisories/GHSA-x2hw-px52-wp4m",
    get trigger() { return M.adv2Trigger; },
    requiresHostFn: PAIRING_CURVE_FNS,
  },
];

/**
 * Parse ESTRITO de versão. A versão anterior fazia `split(".").map(Number)`, e `Number("main")`
 * é NaN — com NaN toda subtração vira NaN, `cmp` devolvia 0 e QUALQUER string não numérica
 * (`main`, `v26.0.0`, um commit) caía dentro de toda faixa afetada. Um achado High por causa de
 * um parse silencioso é exatamente o falso positivo que derruba o documento inteiro.
 */
const VERSION_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/;
const PRERELEASE_RE = /^v?\d+\.\d+\.\d+-/;

export type ParsedVersion = { major: number; minor: number; patch: number; prerelease: boolean };

export function parseVersion(raw: string): ParsedVersion | undefined {
  const s = raw.trim();
  const m = VERSION_RE.exec(s);
  if (!m) return undefined;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    // `22.0.10-rc.1` é ANTES de `22.0.10`: o pré-release não contém o patch que corrige.
    prerelease: PRERELEASE_RE.test(s),
  };
}

/**
 * Compara duas versões. -1 | 0 | 1. **Estoura** em entrada não parseável, em vez de devolver 0:
 * comparar o incomparável é pior que falhar, porque o erro vira afirmação de nível A.
 */
function cmpParsed(a: ParsedVersion, b: ParsedVersion): number {
  for (const k of ["major", "minor", "patch"] as const) {
    const d = a[k] - b[k];
    if (d) return d > 0 ? 1 : -1;
  }
  if (a.prerelease === b.prerelease) return 0;
  return a.prerelease ? -1 : 1;
}

export function cmp(a: string, b: string): number {
  const pa = parseVersion(a), pb = parseVersion(b);
  if (!pa) throw new Error(M.cmpNaoParseavel(JSON.stringify(a)));
  if (!pb) throw new Error(M.cmpNaoParseavel(JSON.stringify(b)));
  return cmpParsed(pa, pb);
}

/**
 * Pertinência a uma faixa, com pré-release tratado como "imediatamente antes" da release.
 * Um limite superior inclusivo `<= M` é lido como o meio-aberto `< próximo(M)`, porque é isso
 * que o advisory quer dizer: `<= 22.0.9` é "antes do patch 22.0.10". Sem essa leitura,
 * `22.0.10-rc.1` — que não contém a correção — escaparia da faixa.
 */
export function inRange(v: ParsedVersion, r: Range): boolean {
  const min = parseVersion(r.min), max = parseVersion(r.max);
  if (!min || !max) throw new Error(M.faixaNaoParseavel(r.min, r.max));
  if (cmpParsed(v, min) < 0) return false;
  const upper = r.maxInclusive ? { ...max, patch: max.patch + 1, prerelease: false } : max;
  return cmpParsed(v, upper) < 0;
}

/**
 * TODAS as custom sections `contractmetav0` do módulo, na ordem em que aparecem.
 *
 * `parseModule` guarda as custom sections num `Map` por nome, e o formato WASM permite
 * repetir o nome: a toolchain grava uma segunda `contractmetav0` (com `cliver`,
 * `source_repo`) depois da que o `soroban-sdk` gravou (com `rsver`, `rssdkver`), e o Map
 * ficava só com a última. Medido sobre os 25 code hashes mais invocados da mainnet: 11
 * deles saíam como "SDK não declarado" por causa disso, perdendo 6 achados `vulnerable-sdk`.
 *
 * O walker aqui é deliberadamente raso — só o cabeçalho de seção — e tolerante: um módulo
 * que ele não consegue varrer devolve o que já coletou, e o chamador marca `partial`.
 */
function metaSections(wasm: Uint8Array): { sections: Uint8Array[]; truncated: boolean } {
  const sections: Uint8Array[] = [];
  const leb = (p: number): [number, number] => {
    let r = 0, s = 0;
    for (let n = 0; n < 5; n++) {
      if (p >= wasm.length) throw new Error("LEB128 truncado");
      const x = wasm[p++];
      r |= (x & 0x7f) << s;
      if (!(x & 0x80)) return [r >>> 0, p];
      s += 7;
    }
    throw new Error("LEB128 longo demais");
  };
  try {
    let p = 8; // pula magic + version; `parseModule` já validou o magic para os consumidores
    while (p < wasm.length) {
      const id = wasm[p++];
      let len: number;
      [len, p] = leb(p);
      const end = p + len;
      if (end > wasm.length) throw new Error("seção ultrapassa o fim do módulo");
      if (id === 0) {
        let nameLen: number, q: number;
        [nameLen, q] = leb(p);
        const nome = Buffer.from(wasm.subarray(q, q + nameLen)).toString();
        if (nome === "contractmetav0") sections.push(wasm.subarray(q + nameLen, end));
      }
      p = end;
    }
  } catch {
    return { sections, truncated: true };
  }
  return { sections, truncated: false };
}

/**
 * Leitor tolerante de `ScMetaEntry`, entrada por entrada, sobre os bytes crus.
 *
 * XDR: u32 de discriminante (0 = `ScMetaV0`), depois `ScMetaV0 { key: string, val: string }`,
 * e uma string XDR é u32 de tamanho + bytes + padding até múltiplo de 4.
 *
 * A versão anterior usava `xdr.decodeStream(...)` dentro de um `try/catch` que engolia o erro
 * e devolvia o mapa parcial SEM dizer que era parcial — uma entrada estranha no meio fazia o
 * `rssdkver` que vinha depois sumir, e o relatório dizia "nenhum SDK declarado". Aqui uma
 * entrada malformada interrompe a leitura da seção e fica REGISTRADA (`partial` + offset).
 */
function decodeMetaEntries(sec: Uint8Array, raw: Record<string, string>): { partial: boolean; partialAt?: number } {
  const buf = Buffer.from(sec);
  let off = 0;
  const u32 = (): number => {
    if (off + 4 > buf.length) throw new Error("u32 truncado");
    const v = buf.readUInt32BE(off);
    off += 4;
    return v;
  };
  const str = (): string => {
    const len = u32();
    const pad = (4 - (len % 4)) % 4;
    if (len > buf.length - off || off + len + pad > buf.length) throw new Error("string XDR truncada");
    const s = buf.subarray(off, off + len).toString("utf8");
    off += len + pad;
    return s;
  };
  while (off < buf.length) {
    const inicio = off;
    try {
      const disc = u32();
      if (disc !== 0) throw new Error(`discriminante desconhecido: ${disc}`);
      const key = str();
      const val = str();
      raw[key] = val;
    } catch {
      return { partial: true, partialAt: inicio };
    }
  }
  return { partial: false };
}

export function readSdkMeta(wasm: Uint8Array): SdkInfo {
  // `parseModule` valida o magic e falha fechado em módulo truncado; mantê-lo no caminho
  // preserva esse contrato para quem chama `readSdkMeta` com bytes arbitrários.
  parseModule(wasm);
  const { sections, truncated } = metaSections(wasm);
  const raw: Record<string, string> = {};
  let partial = truncated;
  let partialAt: number | undefined;
  for (const sec of sections) {
    const r = decodeMetaEntries(sec, raw);
    if (r.partial && !partial) { partial = true; partialAt = r.partialAt; }
  }
  // `rssdkver` costuma vir como "22.0.8#<commit>"
  const rssdkver = raw["rssdkver"];
  const [version, commit] = rssdkver ? rssdkver.split("#") : [undefined, undefined];
  return { version, commit, raw, present: sections.length > 0, partial, partialAt };
}

/**
 * Avaliação da versão gravada no WASM. Três resultados DISTINTOS, porque "não sabemos" não é
 * "não afetado": ausente, presente-mas-não-parseável (lacuna declarada) e avaliada.
 */
export type VersionEval =
  | { status: "ausente" }
  | { status: "nao-parseavel"; raw: string }
  | { status: "avaliada"; parsed: ParsedVersion; advisories: Advisory[] };

export function evaluateVersion(v: string | undefined | SdkInfo): VersionEval {
  const meta = typeof v === "object" && v !== null ? v : undefined;
  const version = meta ? meta.version : (v as string | undefined);
  // Ausência de `rssdkver` num mapa que SABEMOS estar incompleto não é "não declarado":
  // é "não lido". Sem esta distinção o documento afirma ausência de exposição a partir de
  // uma falha nossa de parse — que é exatamente como 6 achados de advisory se perderam.
  if (!version && meta?.partial) {
    return { status: "nao-parseavel", raw: M.metaParcial(meta.partialAt ?? 0) };
  }
  if (!version) return { status: "ausente" };
  const parsed = parseVersion(version);
  if (!parsed) return { status: "nao-parseavel", raw: version };
  const advisories = ADVISORIES.filter((a) => a.affected.some((r) => inRange(parsed, r)));
  return { status: "avaliada", parsed, advisories };
}

/** Advisories que se aplicam à versão gravada no WASM. Versão ilegível ⇒ nenhum advisory. */
export function advisoriesFor(version: string | undefined): Advisory[] {
  const ev = evaluateVersion(version);
  return ev.status === "avaliada" ? ev.advisories : [];
}

/** Nomes canônicos das host functions importadas pelo módulo (imports fora do catálogo ficam de fora). */
export function importedHostFns(wasm: Uint8Array): Set<string> {
  const out = new Set<string>();
  for (const i of parseModule(wasm).imports) {
    const n = hostFn(i.key)?.name;
    if (n) out.add(n);
  }
  return out;
}

export type AdvisoryHit = { advisory: Advisory; gateHits: string[] };

/**
 * Advisories aplicáveis a um binário: faixa de versão (fato A) e, quando o advisory tem
 * `requiresHostFn`, o filtro de imports (heurístico — ver `Advisory.requiresHostFn`).
 */
export function advisoriesForWasm(wasm: Uint8Array, sdk: SdkInfo = readSdkMeta(wasm)): AdvisoryHit[] {
  const byVersion = advisoriesFor(sdk.version);
  if (!byVersion.length) return [];
  const imported = importedHostFns(wasm);
  const hits: AdvisoryHit[] = [];
  for (const a of byVersion) {
    if (!a.requiresHostFn) { hits.push({ advisory: a, gateHits: [] }); continue; }
    const gateHits = [...a.requiresHostFn].filter((n) => imported.has(n)).sort();
    if (gateHits.length) hits.push({ advisory: a, gateHits });
  }
  return hits;
}
