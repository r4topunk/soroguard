/** Modelo intermediário: tudo que conseguimos saber sobre um contrato antes de raciocinar sobre ameaças. */

import type { ProbeResult } from "./probe.ts";

export type Param = { name: string; type: string };

export type Fn = {
  name: string;
  params: Param[];
  returns: string;
  doc: string;
  /** Heurísticas derivadas do nome/assinatura — cada uma vira evidência rastreável numa ameaça. */
  traits: FnTrait[];
};

export type FnTrait =
  | "constructor"
  | "admin"        // muda quem manda
  | "upgrade"      // troca código
  | "pause"        // liga/desliga o sistema
  | "moves_funds"  // move valor
  | "mint_burn"    // muda supply
  | "config"       // muda parâmetro econômico/operacional
  | "read_only"    // getter
  | "takes_address" // recebe Address (candidato a require_auth)
  | "takes_amount";

export type ErrEnum = { name: string; cases: { name: string; value: number }[] };

export type EventDecl = {
  name: string;
  /** Tópicos-prefixo emitidos on-chain. É por AQUI que uma regra de monitoramento filtra no getEvents. */
  prefixTopics: string[];
  dataFormat: string;
  /** params, com indicação de topicList vs data */
  params: { name: string; type: string; location: string }[];
  source: "spec" | "observed";
};

export type ObservedEvent = {
  /** primeiro topic legível, quando decodificável */
  topic: string;
  count: number;
  firstLedger: number;
  lastLedger: number;
};

/**
 * O que FECHOU a janela de observação. Sem isto o documento apresenta 32 h e 375 h com a
 * mesma cara, e o revisor lê a janela curta como "contrato parado" em vez de "contrato
 * denso demais para o orçamento de paginação" — que é o caso exatamente nos contratos
 * mais movimentados (docs/PRECISION-TOP25.md).
 *
 *  - `retention`: pedimos tudo que o RPC retém e varremos até o topo. O limite é o RPC.
 *  - `request-budget`: o orçamento de requisições acabou antes do range pedido.
 *  - `none`: a janela pedida coube inteira; ninguém cortou nada.
 */
export type WindowLimitedBy = "retention" | "request-budget" | "none";

export type ContractModel = {
  contractId: string;
  network: string;
  /** caminho do `.wasm` analisado, quando o alvo foi um arquivo local em vez de um id */
  analyzedFile?: string;
  wasmHash?: string;
  wasmBytes?: number;
  fns: Fn[];
  errors: ErrEnum[];
  events: EventDecl[];
  observed: ObservedEvent[];
  observedWindow?: { fromLedger: number; toLedger: number; ledgers: number };
  /**
   * Campos aditivos que NÃO cabem em `artifact.ts` (contrato congelado). `ObservationWindow`
   * e `Observations` são tipos congelados lá; carregá-los aqui, no modelo que já viaja em
   * `ctx.spec`, é a rota menos invasiva — nenhum consumidor existente precisa mudar e
   * nenhum estado ambiente (WeakMap por ctx) entra no caminho, o que manteria a saída
   * dependente de identidade de objeto e não do dado.
   */
  windowLimitedBy?: WindowLimitedBy;
  /** páginas de `getEvents` efetivamente gastas na coleta (prova do orçamento) */
  windowPagesUsed?: number;
  /**
   * Sondagens de nível B por id de achado (`Elevation.1` → resultado). Mesma justificativa
   * dos campos acima: `ArtifactContext` é congelado, `ContractModel` é aditivo.
   */
  probes?: Record<string, ProbeResult>;
  specEntryCounts: Record<string, number>;
  warnings: string[];
};
