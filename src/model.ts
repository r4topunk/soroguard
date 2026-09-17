/** Modelo intermediário: tudo que conseguimos saber sobre um contrato antes de raciocinar sobre ameaças. */

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
  specEntryCounts: Record<string, number>;
  warnings: string[];
};
