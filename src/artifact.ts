/**
 * CONTRATO CONGELADO entre os módulos que geram os dois artefatos do tranche #2.
 * Nenhum módulo deve alterar este arquivo — implementem contra ele.
 */
import type { ModuleAnalysis, Entrypoint } from "./analyze.ts";
import type { Finding, Stride, Tier } from "./detect.ts";
import type { ContractModel } from "./model.ts";
import type { Lang } from "./i18n.ts";

/** Nível B — fato observado on-chain. Única origem legítima de baseline. */
export type ObservedEvent = {
  /** primeiro topic, decodificado. Casa com `prefixTopics` do spec quando houver. */
  topic: string;
  count: number;
  firstLedger: number;
  lastLedger: number;
  /** eventos por hora na janela observada */
  ratePerHour: number;
};

export type ObservationWindow = {
  fromLedger: number;
  toLedger: number;
  ledgers: number;
  /** ~5s por ledger; usado para converter contagem em taxa */
  approxHours: number;
  /** true quando a janela foi curta demais para um baseline honesto */
  insufficient: boolean;
};

export type Observations = {
  window: ObservationWindow;
  events: ObservedEvent[];
  /** topics declarados no spec que nunca foram observados na janela */
  declaredButUnseen: string[];
};

/* ---------- data-flow diagram ---------- */

export type DfdNode =
  | { kind: "external"; id: string; label: string }
  | { kind: "process"; id: string; label: string; entrypoint: string }
  | { kind: "store"; id: string; label: string }
  | { kind: "contract"; id: string; label: string };

export type DfdEdge = { from: string; to: string; label: string; crossesBoundary: boolean };

export type Dfd = {
  nodes: DfdNode[];
  edges: DfdEdge[];
  /** cada fronteira agrupa nós sob uma mesma suposição de confiança */
  boundaries: { id: string; label: string; contains: string[] }[];
  mermaid: string;
};

/* ---------- monitoring plan ---------- */

export type Monitor = {
  /** `<ThreatID>.M.<n>` — o template exige que derive do id da ameaça */
  id: string;
  threatId: string;
  /** o que dá para observar on-chain */
  observable: string;
  /** condição de disparo, em linguagem executável */
  trigger: string;
  /** baseline vindo de observação (nível B) ou declarado ausente */
  baseline: string;
  baselineTier: Tier | "none";
  severity: Finding["severity"];
  response: string;
  status: "Active" | "Tuning" | "Planned";
};

/** Monitor executável: o filtro que vai numa chamada real de getEvents. */
export type ExecutableMonitor = {
  monitorId: string;
  contractId: string;
  filter: { type: "contract"; contractIds: string[]; topics?: string[][] };
  condition: { kind: "any-occurrence" | "rate-above" | "absence"; threshold?: number; windowHours?: number };
  note: string;
};

/* ---------- contexto que os renderizadores recebem ---------- */

export type ArtifactContext = {
  contractId: string;
  network: string;
  /** data ISO — injetada de fora; os renderizadores não leem relógio */
  generatedAt: string;
  spec: ContractModel;
  analysis: ModuleAnalysis;
  findings: Finding[];
  /** letras do STRIDE sem achado derivável — vão declaradas, nunca preenchidas */
  gaps: Stride[];
  observations?: Observations;
  /**
   * Motivo pelo qual a coleta de nível B FALHOU (erro de RPC etc.). Distinto de
   * `observations` ausente por `--offline` ou por alvo `.wasm`: "janela não coletada
   * porque a chamada falhou" e "janela coletada, zero ocorrências" são afirmações
   * diferentes e os documentos precisam distingui-las.
   */
  observationError?: string;
  /** true quando a coleta de nível B foi pulada de propósito (`--offline` ou alvo .wasm) */
  offline?: boolean;
  /** idioma da saída; padrão `en`. Os renderizadores chamam `setLang(ctx.lang)`. */
  lang?: Lang;
  /** chaves de storage inferidas, quando disponíveis */
  storageKeys?: { key: string; confidence: "certain" | "likely" }[];
  dfd?: Dfd;
  monitors?: Monitor[];
};

/* ---------- validação dos checklists oficiais ---------- */

export type ChecklistItem = {
  question: string;
  status: "ok" | "gap" | "n/a";
  detail: string;
};

export type ValidationReport = {
  document: "threat-model" | "monitoring-plan";
  items: ChecklistItem[];
  /** o documento está completo o suficiente para submissão? */
  submittable: boolean;
  blockers: string[];
};

/* ---------- helpers compartilhados ---------- */

/** Rótulo de nível de evidência, como aparece nos documentos (por idioma; ver i18n.ts). */
export const tierLabels: Record<Lang, Record<Tier, string>> = {
  en: { A: "bytecode fact", B: "fact observed on-chain", C: "inference — requires human review" },
  pt: { A: "fato de bytecode", B: "fato observado on-chain", C: "inferência — requer revisão humana" },
};
/** @deprecated use `tierLabels[lang()]`. Mantido enquanto os renderizadores migram. */
export const tierLabel: Record<Tier, string> = tierLabels.pt;

export const isMutating = (ep: Entrypoint, an: ModuleAnalysis): boolean =>
  an.writeBeforeAuth.has(ep.name) || ep.reaches.has("put_contract_data") || ep.reaches.has("del_contract_data");
