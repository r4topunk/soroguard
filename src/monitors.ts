/**
 * Derivação de monitores a partir das ameaças.
 *
 * A ponte técnica que torna isto possível: o contract spec grava `prefixTopics` por evento
 * (`EventDecl` em model.ts) e esses símbolos são o filtro de tópicos de uma chamada
 * `getEvents` — cada segmento vai no transporte como ScVal símbolo em base64, não como a
 * string crua. Um monitor executável é esse filtro mais uma condição.
 *
 * Medido contra o RPC de mainnet, e é o que decide o desenho abaixo: o filtro casa pelo
 * COMPRIMENTO EXATO da lista de tópicos do evento. `[deposit_for_burn, *, *, *]` devolveu 20
 * eventos no mesmo intervalo em que `[deposit_for_burn]` e `[deposit_for_burn, *]` devolveram
 * ZERO. Errar o número de segmentos não dá erro: dá silêncio — o modo de falha mais caro num
 * plano de monitoramento. Por isso só se emite filtro de tópicos quando o número de segmentos
 * vem do spec; quando não vem, o filtro fica só no contractId e a triagem do tópico é
 * declarada como pós-filtro.
 *
 * Três regras herdadas de docs/PROBLEMA.md, e são elas que separam isto de um gerador de texto:
 *
 *  1. Ameaça sem observável on-chain NÃO ganha monitor. Ela sai do conjunto de monitores e
 *     aparece no plano como exigindo controle fora da chain. Fabricar um monitor para fechar
 *     a coluna é pior que declarar que não há como observar.
 *  2. Baseline só vem de `ctx.observations` (nível B). Sem janela, `baselineTier: "none"` e o
 *     texto diz o que falta — nunca um número plausível.
 *  3. A ligação evento↔entrypoint é feita por nome e por isso é nível C. O que é fato de
 *     bytecode (nível A) é outra coisa: que o entrypoint alcança `contract_event`. Sem esse
 *     fato A, nenhuma correspondência de nome vira monitor de evento.
 *
 * Todo texto que sai deste módulo passa pela tabela `M`.
 */

import type { ArtifactContext, ExecutableMonitor, Monitor, ObservedEvent } from "./artifact.ts";
import type { Finding, Tier } from "./detect.ts";
import { emitsEvent, writesStorage } from "./analyze.ts";
import { EVENT_FNS, UPGRADE_FNS } from "./hostfns.ts";
import { plural } from "./text.ts";

const M = {
  LACUNA: "⟨to be defined — not derivable from the binary⟩",
  /** separador entre filtros de tópicos alternativos */
  ou: " or ",
  semTrafego:
    " ⚠ No event of any topic was observed for this contract during the window — absence of traffic, not a traffic profile",
  coletaFalhou: (e: string) =>
    `tier B collection FAILED: ${e} — the baseline is missing because the RPC call did not complete, not because the contract is idle`,
  coletaPulada: "tier B collection not run (offline / local target)",
  semJanela: "no observation window was collected for this contract",
  baselinePorHash: (h: string) =>
    `instance wasm hash when this plan was generated: \`${h}\`. Any different value is a code change.`,
  /**
   * Caso (c) do SHIP-05: a janela pode até existir — este monitor não passa pelo stream de
   * eventos, então o baseline dele não é observação nenhuma, é um valor a registrar.
   */
  baselineFillIn: (oque: string, l: string) =>
    `this monitor is not event-based; its baseline is the current on-chain value (${oque}), to be recorded at plan approval — ${l}. This is a fill-in, not an observation gap: no \`getEvents\` window would produce it.`,
  valorHash: "current instance wasm hash",
  valorChaves: "current value of the storage keys, read via getLedgerEntries",
  valorTx: "current invocation profile of the entrypoint, read by transaction inspection",
  hashAPreencher: "⟨to be filled: current instance wasm hash⟩",
  baselineNaoEstabelecido: (motivo: string) => `baseline not established: ${motivo}.`,
  janelaInsuficiente: (n: number, h: string) =>
    `insufficient window: ${n} ledgers (~${h} h) observed — too short for an honest baseline.`,
  janela: (n: number, h: string, de: number, ate: number) => `window of ${n} ledgers (~${h} h, ledgers ${de}–${ate})`,
  zeroEmissoes: (rot: string, janela: string, confirmado: boolean) =>
    `0 emissions of ${rot} in the ${janela}${confirmado ? " — topic declared in the spec and confirmed as never observed" : ""}. ` +
    "An observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold.",
  emissoes: (n: number, rot: string, janela: string, taxa: string, chaves: number) =>
    `${n} emissions of ${rot} in the ${janela} ⇒ ${taxa}/h` +
    (chaves > 1 ? ` (sum of the ${chaves} candidate topics — the attribution is not unique)` : "") + ".",
  alcance: (ep: string, saltos: string) => `(A) \`${ep}\` reaches contract_event in ${saltos} hop(s)`,
  viaHelper: (ep: string) =>
    `. (C) ⚠ the path is longer than 2 hops and probably goes through a shared helper: the emission may sit on a branch \`${ep}\` never executes — an event monitor here may never fire, by design. Confirm before switching it on.`,
  eventoTexto: (como: string, rot: string) => `${como} — event with topics ${rot}`,
  ambiguo: (n: number, nomes: string) =>
    ` (attribution ambiguous between ${n} spec events: ${nomes} — the filter covers all of them)`,
  avisoHelperCurto: " ⚠ emission reached through a shared helper, may never occur along this path",
  atribuicaoSpec: (alcance: string, nomes: string, ambiguo: boolean, n: number) =>
    `${alcance} The topics and the segment count come from the \`contractspecv0\` section of the WASM itself. ` +
    `(C) the event↔entrypoint link is by name (${nomes})` +
    (ambiguo
      ? ` — AMBIGUOUS ATTRIBUTION between ${n} events, all included as alternative filters; confirm by hand which one belongs to the entrypoint.`
      : "."),
  eventoObservadoTexto: (como: string, rot: string) =>
    `${como} — event with topics ${rot} (topic arity not derivable: see the filter note)`,
  atribuicaoObservada: (alcance: string, l: string) =>
    `${alcance} (B) the topic is not in the spec; it was read from the on-chain stream. ` +
    `(C) the link to the entrypoint is by name. ${l}: how many segments the event has — ` +
    "the observed stream only preserved the first one, and `getEvents` matches on the exact list length.",
  invocacaoTexto: (ep: string, motivo: string) =>
    `invocation of \`${ep}\` ${motivo} — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream`,
  invocacaoAtribuicao:
    "(A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.",
  /* observáveis por classe */
  comoInit: "initialization executed",
  motivoInit: "by an address that is not the deployer",
  comoMutacao: "state mutation executed",
  motivoMutacao: (l: string) =>
    `by an address outside the operational allowlist (the allowlist is not derivable from the binary: ${l})`,
  upgradeLedgerTexto:
    "wasm hash change on the contract instance executable (ContractData/ContractInstance ledger entry, read via getLedgerEntries — not through getEvents)",
  upgradeAtribuicao: (ep: string, saltos: string) =>
    `(A) \`${ep}\` reaches the self-code-replacement family in ${saltos} hop(s); the effect is the hash change on the instance.`,
  comoUpgrade: "upgrade announced",
  delegacaoTexto: (ep: string) =>
    `sub-invocation receiving the contract's identity from \`${ep}\` — visible in the transaction's authorization tree (SorobanAuthorizationEntry), read by transaction inspection`,
  delegacaoAtribuicao: (ep: string) =>
    `(A) \`${ep}\` reaches authorize_as_curr_contract, which grants authorization instead of checking it.`,
  comoDelegacao: "delegation accompanied by an event",
  archivalTexto:
    "`liveUntilLedger` of the contract's persistent/instance entries approaching the current ledger (read via getLedgerEntries)",
  archivalAtribuicao: "(A) no entrypoint of the contract reaches the extend_*_ttl family; the TTL only decreases.",
  cessacaoTexto: (topic: string) =>
    `the flow of [${topic}] stopping, which today is continuous — archived state leaves the contract inoperable`,
  cessacaoAtribuicao:
    "(B) rate measured in the observed window; the absence is measurable precisely because there is measured flow.",
  comoPrng: "drawn result published",
  motivoPrng: "together with the ledger it was submitted in",
  sdkTexto: "instance wasm hash staying equal to the vulnerable binary (read via getLedgerEntries)",
  sdkAtribuicao:
    "(A) the SDK version is recorded in this binary's `contractmetav0` custom section; it only changes with an upgrade.",
  silenciosaTexto: (n: number, chaves: string, mudos: string[]) =>
    `diff of the ${n} ${plural(n, "key", "keys")} inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (${chaves}) across ledgers (getLedgerEntries) — ` +
    `with no event, the state diff is the only possible reading${mudos.length ? `; silent entrypoints: ${mudos.join(", ")}` : ""}`,
  silenciosaAtribuicao: (mudos: string[], l: string) =>
    `(A) ${mudos.length ? `${mudos.join(", ")} ${plural(mudos.length, "reaches", "reach")}` : "the entrypoints in the finding reach"} put_contract_data and ${mudos.length === 1 ? "does" : "do"} not reach contract_event. ` +
    "(A) the keys were extracted from the bytecode as arguments of storage host functions, with `certain` confidence. " +
    `(C) which of those keys each silent entrypoint writes is NOT derivable from this context — the monitor covers the whole set and may alert on changes from other paths. ${l}: the durability of each entry, which is a runtime argument and decides the ledger key to query.`,
  comoFallback: "execution of the affected entrypoint",
  motivoFallback: "whose execution is what materializes this threat",
  /* respostas */
  respInit: (ep: string) =>
    `Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether ${ep} is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard.`,
  respMutacao: (ep: string) =>
    `Identify the caller of ${ep} and the state it changed; if it is not a known operator, trigger the contract pause if one exists and freeze integrations that read that state.`,
  respWriteBeforeAuth: "Informational alert: review the body flagged in the finding before acting. No automated response.",
  respUpgrade:
    "Compare the new wasm hash against the expected release. A divergence is unauthorized code replacement and subsumes every other control — escalate immediately.",
  respDelegacao: (ep: string) =>
    `Open the transaction's authorization tree and check which sub-invocation ${ep} lent the contract's identity to; confirm the scope is the one the design intends.`,
  respArchival:
    "Renew the TTL of the entries before the threshold. Archival is unavailability, not loss: restoration is possible, but the contract stays inoperable until then.",
  respSdk:
    "Confirm in the source whether the advisory's trigger condition (evidence C of the finding) exists in this contract; if it does, recompile with the fixed version and run the upgrade.",
  respPrng: (ep: string) =>
    `Compare the submission ledger of the ${ep} invocations against the drawn results: concentration in a single ledger, or repetition by the same address within it, indicates ledger picking. If the PRNG use is cosmetic, the finding closes and the monitor goes away.`,
  respSilenciosa:
    "Reconcile the observed state against what the backend expects. The right response is a design change, not an on-call one: add events to the entrypoints listed.",
  respPadrao: (classe: string, ep: string, l: string) =>
    `Open the ${classe} finding on ${ep} and the transaction that fired the alert before taking any action. Specific procedure: ${l}`,
  /* gatilhos */
  gatilhoHash: (ref: string) =>
    `Periodic check (getLedgerEntries): the wasm hash of the instance executable differs from the hash recorded at plan approval — ${ref}. ` +
    "While it stays equal, the state described in the finding still holds; when it changes, the new binary needs to be re-analyzed.",
  alvoLinha: "of the observable on this row",
  alvoTopicos: (rot: string) => `of ${rot}`,
  gatilhoTaxa: (limiar: number, horas: number, alvo: string) =>
    `More than ${limiar} ${plural(limiar, "occurrence", "occurrences")} ${alvo} in ${horas} h (3× the rate measured in the observed window).`,
  gatilhoAusencia: (horas: number, alvo: string) => `No occurrence ${alvo} for ${horas} h in a row.`,
  gatilhoQualquerB: (alvo: string, nunca: boolean) =>
    `Any occurrence ${alvo}${nunca ? ", which never happened in the observed window" : ""}.`,
  gatilhoQualquerSemBaseline: (alvo: string, base: string) =>
    `Any occurrence ${alvo}. No numeric threshold can be set — ${base}`,
  /**
   * O diff de estado só vira consulta real quando a durabilidade é conhecida: ela é
   * argumento de runtime e entra na chave de ledger. Sem ela não há o que consultar, e o
   * gatilho tem de dizer isso na própria linha — o blocker de baseline já diz o mesmo.
   */
  gatilhoDurabilidade:
    " Durability ⟨to be filled: temporary / persistent / instance⟩ — needed to build the ledger key.",
  /* nota do filtro executável */
  notaSpec:
    "Topics read from `contractspecv0` in the WASM itself, with one `*` per parameter declared in TopicList. " +
    "On the wire each segment goes as a base64 ScVal symbol — the raw string is rejected with `invalid parameters`; " +
    "`*` matches exactly one segment and the list must have the same length as the event's (measured on mainnet). ",
  notaSemSpec: (chaves: string, l: string) =>
    `No topic filter ON PURPOSE: the topic [${chaves}] was read from the on-chain stream and is not in the spec, ` +
    `so the event's segment count is not derivable (${l}) — and a filter of the wrong length silently returns zero. ` +
    `Filter by contractId and drop client-side everything whose first topic is not [${chaves}]. `,
  notaAlternativos: (n: number) =>
    `${n} alternative filters: the event↔entrypoint attribution is by name and is not unique — confirm which one before switching it on. `,
  notaBaseline: (tier: string, texto: string) => `Baseline (${tier}): ${texto}`,
};

/**
 * Marcador único para tudo que a ferramenta honestamente não sabe. O renderizador o conta.
 * É função, não constante: o idioma é escolhido em runtime pelo CLI e um `const` congelaria
 * o texto no momento do import.
 */
export const lacuna = (): string => M.LACUNA;

/**
 * Observável on-chain de uma ameaça. `kind` decide se o monitor é executável:
 * só `event` vira chamada de `getEvents`; os outros dois exigem, respectivamente,
 * leitura de ledger entry e introspecção da transação, que não passam por esse endpoint.
 */
/**
 * Um filtro de tópicos completo, de UM evento. Nunca se misturam dois eventos no mesmo
 * conjunto: o RPC casa segmento a segmento, então `[a, b]` significa "topic[0]=a E topic[1]=b".
 * Concatenar dois eventos ali produz um filtro que não casa com nenhum dos dois.
 */
type TopicSet = {
  /** segmentos na ordem do transporte; `*` casa exatamente um segmento */
  segments: string[];
  /** primeiro segmento — é o que `ObservedEvent.topic` carrega, e a chave do baseline */
  key: string;
  /** evento do spec que originou este conjunto */
  nome?: string;
  /** quantos `*` o conjunto carrega — um por parâmetro declarado em TopicList no spec */
  wildcards?: number;
};

type Observavel = {
  kind: "event" | "ledger-entry" | "tx-introspection";
  texto: string;
  /** conjuntos alternativos de tópicos (OR no `getEvents`) — um por evento candidato */
  topicos?: TopicSet[];
  /** o nº de segmentos do filtro é conhecido E a atribuição é única */
  filtroCompleto?: boolean;
  fonteTopic?: "spec" | "observed";
  /** por que atribuímos este observável a esta ameaça — sempre nível C quando é por nome */
  atribuicao?: string;
  /** dica de condição quando o baseline não manda (ex.: ausência de fluxo) */
  forcarCond?: ExecutableMonitor["condition"]["kind"];
  janelaHoras?: number;
  /** o observável é a executável da instância: o hash lido on-chain serve de baseline */
  baselinePorHash?: true;
  /** a chave de ledger só se monta com a durabilidade, que não está no binário */
  durabilidadeAPreencher?: true;
};

type Baseline = { texto: string; tier: Tier | "none"; contagem?: number; taxaHora?: number };

/** Como os conjuntos aparecem no documento. Alternativas ficam separadas por "ou"/"or". */
const rotulo = (ts: TopicSet[]): string => ts.map((t) => `[${t.segments.join(", ")}]`).join(M.ou);

/** Monitor + o que o produziu. Interno: `Monitor` é contrato congelado e não carrega o filtro. */
type Derivado = { monitor: Monitor; obs: Observavel; base: Baseline };

/* ------------------------------------------------------------------ *
 * Atribuição evento ↔ entrypoint
 * ------------------------------------------------------------------ */

/** Sufixos/prefixos que só embrulham o nome do evento e atrapalhariam o casamento. */
const RUIDO = new Set(["evt", "event", "ev", "e"]);

/** `MilestoneApproved` / `tw_ms_approve` → tokens comparáveis com `approve_milestone`. */
function tokens(s: string): string[] {
  return s
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 1 && !RUIDO.has(t));
}

/** Casa `init` com `initialize`: o spec abrevia o tópico e a função não. O piso de 4 caracteres impede que `ms` case com `msg`. */
function casa(x: string, y: string): boolean {
  if (x === y) return true;
  const [curto, longo] = x.length < y.length ? [x, y] : [y, x];
  return curto.length >= 4 && longo.startsWith(curto);
}

/**
 * Peso de um token, inverso ao número de entrypoints em que ele aparece.
 *
 * Existe por causa de um falso positivo medido: num escrow, `initialize_escrow` foi atribuído
 * a `tw_dispute` porque o evento se chama `EscrowDisputed` e "escrow" casa. Só que "escrow"
 * aparece em 6 dos 15 entrypoints — é o substantivo do domínio, não o identificador da ação.
 * "init" aparece em um só. Quem atribui é o token raro; o token comum não atribui nada.
 */
function pesos(ctx: ArtifactContext): Map<string, number> {
  const df = new Map<string, number>();
  for (const e of ctx.analysis.entrypoints) {
    for (const t of new Set(tokens(e.name))) df.set(t, (df.get(t) ?? 0) + 1);
  }
  return new Map([...df].map(([t, n]) => [t, 1 / n]));
}

/** Abaixo disto o único token em comum é substantivo de domínio, e atribuir seria chute. */
const PISO_ATRIBUICAO = 0.4;

function score(ep: string, ladoEvento: string[], w: Map<string, number>): number {
  let s = 0;
  for (const x of new Set(tokens(ep))) {
    if (ladoEvento.some((y) => casa(x, y))) s += w.get(x) ?? 1;
  }
  return s;
}

/** Eventos do spec cujo nome/tópicos melhor casam com o entrypoint. Vazio quando nada casa. */
function eventosDoEntrypoint(ep: string, ctx: ArtifactContext): { topics: string[]; wildcards: number; nome: string }[] {
  const w = pesos(ctx);
  let melhor = PISO_ATRIBUICAO;
  const cand: { topics: string[]; wildcards: number; nome: string; s: number }[] = [];
  for (const ev of ctx.spec.events) {
    const s = score(ep, [...tokens(ev.name), ...ev.prefixTopics.flatMap(tokens)], w);
    if (s < PISO_ATRIBUICAO) continue;
    // Parâmetros que vão na lista de tópicos ocupam segmentos do filtro e viram curinga.
    const wildcards = ev.params.filter((p) => /topic/i.test(p.location)).length;
    cand.push({ topics: ev.prefixTopics, wildcards, nome: ev.name, s });
    melhor = Math.max(melhor, s);
  }
  // Comparação com folga: dois eventos empatados em ponto flutuante são ambiguidade real.
  return cand.filter((c) => c.s >= melhor - 1e-9).map(({ topics, wildcards, nome }) => ({ topics, wildcards, nome }));
}

/** Tópicos realmente vistos on-chain que casam com o entrypoint. Usado quando o spec não declara eventos. */
function observadosDoEntrypoint(ep: string, ctx: ArtifactContext): ObservedEvent[] {
  if (!ctx.observations) return [];
  const w = pesos(ctx);
  let melhor = PISO_ATRIBUICAO;
  const cand: { e: ObservedEvent; s: number }[] = [];
  for (const e of ctx.observations.events) {
    const s = score(ep, tokens(e.topic), w);
    if (s < PISO_ATRIBUICAO) continue;
    cand.push({ e, s });
    melhor = Math.max(melhor, s);
  }
  return cand.filter((c) => c.s >= melhor - 1e-9).map((c) => c.e);
}

/* ------------------------------------------------------------------ *
 * Baseline — nível B ou nada
 * ------------------------------------------------------------------ */

const h1 = (n: number) => (n >= 10 ? n.toFixed(0) : n.toFixed(2));

/**
 * Por que não há janela de observação. São três afirmações diferentes e o documento
 * inteiro depende de não confundi-las (SHIP-05):
 *
 *  (a) a coleta foi pulada de propósito — `--offline` ou alvo `.wasm` local;
 *  (b) a coleta foi TENTADA e falhou — a ausência de baseline é nossa, não do contrato;
 *  (c) a coleta rodou — aí existe janela e este texto não é usado.
 *
 * Escrever (b) com o texto de (a) afirma "não coletamos" quando o certo é "não
 * conseguimos" — e leva o leitor a concluir que o contrato está parado.
 */
export function motivoSemObservacao(ctx: ArtifactContext): string {
  if (ctx.observationError) return M.coletaFalhou(ctx.observationError);
  if (ctx.offline) return M.coletaPulada;
  return M.semJanela;
}

/**
 * Qualificador para a janela em que o contrato não emitiu evento NENHUM (AQ-1).
 * "0 emissões de X" numa janela onde outros tópicos apareceram é perfil de tráfego;
 * numa janela sem nenhum evento é ausência de tráfego — as duas sustentam limiares
 * diferentes, e a contagem medida não distingue as duas sozinha.
 */
export const qualificadorSemTrafego = (): string => M.semTrafego;

/** A janela existe, é suficiente, e não registrou evento de tópico algum. */
export function janelaSemTrafego(ctx: ArtifactContext): boolean {
  const o = ctx.observations;
  return !!o && !!o.window.ledgers && !o.window.insufficient && o.events.length === 0;
}

function baselineDe(obs: Observavel, ctx: ArtifactContext): Baseline {
  // Upgrade e SDK: o observável é a executável da instância. O hash lido on-chain é
  // fato de verdade, então serve de baseline — não é evento, mas é nível B.
  if (obs.baselinePorHash && ctx.spec.wasmHash) {
    return { texto: M.baselinePorHash(ctx.spec.wasmHash), tier: "B" };
  }
  // Monitor que não passa por `getEvents` não tem baseline observado NEM quando existe janela:
  // o baseline dele é o valor on-chain corrente, que se registra na aprovação do plano. Dizer
  // "não há janela" aqui contradiz o próprio documento quando a janela está impressa acima.
  if (obs.kind !== "event" || !obs.topicos?.length) {
    const oque = obs.baselinePorHash ? M.valorHash : obs.kind === "ledger-entry" ? M.valorChaves : M.valorTx;
    return { texto: M.baselineFillIn(oque, M.LACUNA), tier: "none" };
  }
  const w = ctx.observations?.window;
  if (!w) return { texto: M.baselineNaoEstabelecido(motivoSemObservacao(ctx)), tier: "none" };
  if (w.insufficient) {
    return { texto: M.janelaInsuficiente(w.ledgers, h1(w.approxHours)), tier: "none" };
  }
  // O casamento é pelo PRIMEIRO segmento: é o único que `ObservedEvent` carrega.
  const chaves = [...new Set(obs.topicos.map((t) => t.key))];
  const vistos = chaves
    .map((t) => ctx.observations!.events.find((e) => e.topic === t))
    .filter((e): e is ObservedEvent => !!e);
  const janela = M.janela(w.ledgers, h1(w.approxHours), w.fromLedger, w.toLedger);
  if (!vistos.length) {
    // Zero observado numa janela suficiente É um baseline, e dos mais fortes: o evento
    // privilegiado que nunca disparou é exatamente o que "qualquer ocorrência" quer pegar.
    const confirmado = chaves.every((t) => ctx.observations!.declaredButUnseen.includes(t));
    return {
      texto: M.zeroEmissoes(rotulo(obs.topicos), janela, confirmado) + (janelaSemTrafego(ctx) ? M.semTrafego + "." : ""),
      tier: "B",
      contagem: 0,
      taxaHora: 0,
    };
  }
  const contagem = vistos.reduce((s, e) => s + e.count, 0);
  const taxa = vistos.reduce((s, e) => s + e.ratePerHour, 0);
  return {
    texto: M.emissoes(contagem, rotulo(obs.topicos), janela, h1(taxa), chaves.length),
    tier: "B",
    contagem,
    taxaHora: taxa,
  };
}

/* ------------------------------------------------------------------ *
 * Observáveis por classe de ameaça
 * ------------------------------------------------------------------ */

/**
 * Observável de evento para um entrypoint — só existe se o bytecode disser que ele emite.
 * Sem esse fato A, correspondência de nome é só coincidência de string e não vira monitor.
 */
function eventoDe(ep: string, ctx: ArtifactContext, comoExploracao: string): Observavel | undefined {
  const e = ctx.analysis.entrypoints.find((x) => x.name === ep);
  if (!e || !emitsEvent(e)) return undefined;
  // A positiva de alcançabilidade é super-aproximada (docs/CALIBRACAO.md): sai sempre com o
  // número de saltos, e com aviso explícito quando o caminho atravessa helper compartilhado.
  const saltos = Math.min(
    ...[...EVENT_FNS].map((n) => e.pathTo.get(n)?.length).filter((n): n is number => !!n).map((n) => n - 1),
  );
  const viaHelper = Number.isFinite(saltos) && saltos > 2;
  const alcance = M.alcance(ep, Number.isFinite(saltos) ? String(saltos) : "?") + (viaHelper ? M.viaHelper(ep) : ".");

  const doSpec = eventosDoEntrypoint(ep, ctx);
  if (doSpec.length) {
    // Um conjunto por evento: cada um com os SEUS curingas. `*` ocupa os segmentos que o
    // spec declara como parâmetro em TopicList.
    const topicos: TopicSet[] = doSpec.map((d) => ({
      segments: [...d.topics, ...Array.from({ length: d.wildcards }, () => "*")],
      key: d.topics[0] ?? "",
      nome: d.nome,
      wildcards: d.wildcards,
    }));
    const ambiguo = doSpec.length > 1;
    const nomes = doSpec.map((d) => d.nome).join(", ");
    return {
      kind: "event",
      texto:
        M.eventoTexto(comoExploracao, rotulo(topicos)) +
        (ambiguo ? M.ambiguo(doSpec.length, nomes) : "") +
        (viaHelper ? M.avisoHelperCurto : ""),
      topicos,
      filtroCompleto: !ambiguo && !viaHelper,
      fonteTopic: "spec",
      atribuicao: M.atribuicaoSpec(alcance, nomes, ambiguo, doSpec.length),
    };
  }

  const vistos = observadosDoEntrypoint(ep, ctx);
  if (vistos.length) {
    // Do stream só chega o PRIMEIRO tópico (`ObservedEvent.topic`). Quantos segmentos o
    // evento tem de fato não está no contexto — e o RPC casa pelo comprimento exato. Por
    // isso o filtro sai com um segmento só e a limitação vai declarada, em vez de um
    // curinga inventado que faria o filtro casar com nada se o evento tiver outra aridade.
    const topicos: TopicSet[] = vistos.map((v) => ({ segments: [v.topic], key: v.topic }));
    return {
      kind: "event",
      texto: M.eventoObservadoTexto(comoExploracao, rotulo(topicos)) + (viaHelper ? M.avisoHelperCurto : ""),
      topicos,
      filtroCompleto: false,
      fonteTopic: "observed",
      atribuicao: M.atribuicaoObservada(alcance, M.LACUNA),
    };
  }
  return undefined;
}

/**
 * Saltos do export até a host function mais próxima do conjunto. A positiva de
 * alcançabilidade é super-aproximada (docs/CALIBRACAO.md): sem o nº de saltos o revisor
 * não tem como julgar se o caminho é direto ou atravessa helper compartilhado.
 */
function saltosAte(ep: string, ctx: ArtifactContext, fns: ReadonlySet<string>): string {
  const e = ctx.analysis.entrypoints.find((x) => x.name === ep);
  const n = Math.min(
    ...[...fns].map((f) => e?.pathTo.get(f)?.length).filter((x): x is number => !!x).map((x) => x - 1),
  );
  return Number.isFinite(n) ? String(n) : "?";
}

/** Fallback sempre válido: a invocação em si é visível na transação, ainda que não em getEvents. */
function invocacaoDe(ep: string, motivo: string): Observavel {
  return {
    kind: "tx-introspection",
    texto: M.invocacaoTexto(ep, motivo),
    atribuicao: M.invocacaoAtribuicao,
  };
}

function observaveis(f: Finding, ctx: ArtifactContext): Observavel[] {
  const ep = f.entrypoint;
  const out: Observavel[] = [];

  switch (f.class) {
    case "initialization-front-running": {
      const e = eventoDe(ep, ctx, M.comoInit);
      out.push(e ?? invocacaoDe(ep, M.motivoInit));
      break;
    }
    case "unauthenticated-state-mutation":
    case "write-before-auth": {
      const e = eventoDe(ep, ctx, M.comoMutacao);
      out.push(e ?? invocacaoDe(ep, M.motivoMutacao(M.LACUNA)));
      break;
    }
    case "unguarded-upgrade": {
      // A executável da instância é o observável definitivo: o upgrade muda o ledger entry
      // mesmo que o contrato não emita nada. O evento, se houver, é confirmação secundária.
      out.push({
        kind: "ledger-entry",
        texto: M.upgradeLedgerTexto,
        baselinePorHash: true,
        atribuicao: M.upgradeAtribuicao(ep, saltosAte(ep, ctx, UPGRADE_FNS)),
      });
      const e = eventoDe(ep, ctx, M.comoUpgrade);
      if (e) out.push(e);
      break;
    }
    case "privilege-delegation": {
      out.push({
        kind: "tx-introspection",
        texto: M.delegacaoTexto(ep),
        atribuicao: M.delegacaoAtribuicao(ep),
      });
      const e = eventoDe(ep, ctx, M.comoDelegacao);
      if (e) out.push(e);
      break;
    }
    case "archival-risk": {
      out.push({
        kind: "ledger-entry",
        // Sem baseline por hash: o TTL corrente não está no binário, e inventar um limiar de
        // ledgers restantes seria exatamente o número plausível que este módulo se recusa a dar.
        texto: M.archivalTexto,
        atribuicao: M.archivalAtribuicao,
      });
      // Um contrato arquivado para de produzir eventos. Isso só vira monitor se existir
      // fluxo medido: sem taxa observada, "parou de emitir" não tem como ser aferido.
      const recorrente = [...(ctx.observations?.events ?? [])]
        .filter((e) => e.count >= 10 && e.ratePerHour >= 0.5)
        .sort((a, b) => b.count - a.count)[0];
      if (recorrente && !ctx.observations!.window.insufficient) {
        out.push({
          kind: "event",
          texto: M.cessacaoTexto(recorrente.topic),
          topicos: [{ segments: [recorrente.topic], key: recorrente.topic }],
          filtroCompleto: false,
          fonteTopic: "observed",
          forcarCond: "absence",
          janelaHoras: Math.max(1, Math.ceil(3 / recorrente.ratePerHour)),
          atribuicao: M.cessacaoAtribuicao,
        });
      }
      break;
    }
    case "host-prng-in-value-path": {
      // O que denuncia manipulação não é a invocação isolada: é o par invocação×ledger,
      // porque o PRNG do host é determinístico dentro do ledger.
      const e = eventoDe(ep, ctx, M.comoPrng);
      out.push(e ?? invocacaoDe(ep, M.motivoPrng));
      break;
    }
    case "vulnerable-sdk": {
      // A exposição só termina com uma troca de código. O monitor é a confirmação de que ela ocorreu.
      out.push({
        kind: "ledger-entry",
        texto: M.sdkTexto,
        baselinePorHash: true,
        atribuicao: M.sdkAtribuicao,
      });
      break;
    }
    case "silent-mutation": {
      // Nível A diz que estes entrypoints NÃO alcançam contract_event. Inventar um monitor de
      // evento aqui contradiria a própria evidência do achado. Só há observável se soubermos
      // as chaves de storage com certeza — aí o diff de estado é aferível.
      const certas = (ctx.storageKeys ?? []).filter((k) => k.confidence === "certain");
      if (certas.length) {
        const mudos = ctx.analysis.entrypoints
          .filter((e) => !e.name.startsWith("__") && writesStorage(e) && !emitsEvent(e))
          .map((e) => `\`${e.name}\``);
        out.push({
          kind: "ledger-entry",
          // As chaves são as do CONTRATO, não as destes entrypoints: `ArtifactContext.storageKeys`
          // não carrega o vínculo chave↔entrypoint. Dizer "as chaves que eles escrevem" seria
          // vender inferência como fato — o diff cobre o conjunto inteiro, e isso vai dito.
          texto: M.silenciosaTexto(certas.length, certas.map((k) => `\`${k.key}\``).join(", "), mudos),
          // A durabilidade decide a chave de ledger e não está no binário: o gatilho declara
          // o preenchimento na própria linha, para não afirmar uma consulta que não se monta.
          durabilidadeAPreencher: true,
          atribuicao: M.silenciosaAtribuicao(mudos, M.LACUNA),
        });
      }
      break;
    }
    default: {
      // Classe que este módulo não conhece — detectores novos entram por aqui. Um entrypoint
      // exportado sempre tem ao menos a própria invocação como efeito observável, então o
      // fallback é fato, não invenção. Achado de escopo de contrato não tem esse piso.
      if (ep === "<contrato>") break;
      const e = eventoDe(ep, ctx, M.comoFallback);
      out.push(e ?? invocacaoDe(ep, M.motivoFallback));
      break;
    }
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Resposta por classe — nível C, e sempre citando a função específica
 * ------------------------------------------------------------------ */

function respostaDe(f: Finding): string {
  const ep = `\`${f.entrypoint}\``;
  switch (f.class) {
    case "initialization-front-running":
      return M.respInit(ep);
    case "unauthenticated-state-mutation":
      return M.respMutacao(ep);
    case "write-before-auth":
      return M.respWriteBeforeAuth;
    case "unguarded-upgrade":
      return M.respUpgrade;
    case "privilege-delegation":
      return M.respDelegacao(ep);
    case "archival-risk":
      return M.respArchival;
    case "vulnerable-sdk":
      return M.respSdk;
    case "host-prng-in-value-path":
      return M.respPrng(ep);
    case "silent-mutation":
      return M.respSilenciosa;
    default:
      // Classe sem resposta escrita à mão: melhor apontar para o achado do que sugerir um
      // procedimento genérico que ninguém pode executar.
      return M.respPadrao(f.class, ep, M.LACUNA);
  }
}

/* ------------------------------------------------------------------ *
 * Derivação
 * ------------------------------------------------------------------ */

function derivar(ctx: ArtifactContext): Derivado[] {
  const out: Derivado[] = [];
  for (const f of ctx.findings) {
    // Sem id não há como formar `<ThreatID>.M.<n>`, e um monitor sem rastro até a ameaça é
    // exatamente o monitor órfão que este módulo existe para não produzir.
    if (!f.id) continue;
    const obs = observaveis(f, ctx);
    obs.forEach((o, i) => {
      const base = baselineDe(o, ctx);
      const cond = condicaoDe(o, base);
      const gatilho = gatilhoDe(o, base, cond, ctx);
      out.push({
        obs: o,
        base,
        monitor: {
          id: `${f.id}.M.${i + 1}`,
          threatId: f.id!,
          observable: o.texto,
          trigger: gatilho,
          baseline: base.texto,
          baselineTier: base.tier,
          severity: f.severity,
          response: respostaDe(f),
          // Nenhum monitor nasce "Active": este documento é o plano, não a implantação.
          // "Tuning" = totalmente especificado, pronto para ligar; "Planned" = falta dado.
          // Filtro com atribuição ambígua, aridade desconhecida ou emissão alcançada via
          // helper não está pronto — fica "Planned" com o motivo no texto.
          status: o.kind === "event" && o.topicos?.length && base.tier === "B" && o.filtroCompleto ? "Tuning" : "Planned",
        },
      });
    });
  }
  return out;
}

function condicaoDe(o: Observavel, b: Baseline): ExecutableMonitor["condition"] {
  if (o.forcarCond === "absence") return { kind: "absence", windowHours: o.janelaHoras ?? 24 };
  // O baseline é quem escolhe a condição. Evento rotineiro alertado "a cada ocorrência" é
  // ruído garantido; evento privilegiado que nunca disparou pede exatamente isso.
  if (b.tier === "B" && (b.contagem ?? 0) >= 20 && (b.taxaHora ?? 0) > 0) {
    return { kind: "rate-above", threshold: Math.ceil(b.taxaHora! * 3), windowHours: 1 };
  }
  return { kind: "any-occurrence" };
}

function gatilhoDe(o: Observavel, b: Baseline, c: ExecutableMonitor["condition"], ctx: ArtifactContext): string {
  // Observável de hash não é "ocorrência": é uma comparação periódica contra o baseline.
  // Escrever "qualquer ocorrência de o hash permanecendo igual" invertia o sentido do alerta.
  // A referência é o hash lido on-chain quando ele existe no contexto (alvo por contract id);
  // sem ele, a linha declara o que precisa ser preenchido, em vez de citar um baseline
  // "registrado nesta linha" que a própria linha não registra.
  if (o.baselinePorHash) {
    return M.gatilhoHash(ctx.spec.wasmHash ? `\`${ctx.spec.wasmHash}\`` : M.hashAPreencher);
  }
  // Repetir o observável inteiro aqui dobrava a frase na célula da §4: o leitor lia a mesma
  // descrição duas vezes na mesma linha. Sem tópicos, o gatilho aponta para a própria linha.
  const alvo = o.topicos?.length ? M.alvoTopicos(rotulo(o.topicos)) : M.alvoLinha;
  const durabilidade = o.durabilidadeAPreencher ? M.gatilhoDurabilidade : "";
  switch (c.kind) {
    case "rate-above":
      return M.gatilhoTaxa(c.threshold!, c.windowHours!, alvo) + durabilidade;
    case "absence":
      return M.gatilhoAusencia(c.windowHours!, alvo) + durabilidade;
    default:
      return (
        b.tier === "B"
          ? M.gatilhoQualquerB(alvo, (b.contagem ?? -1) === 0)
          : M.gatilhoQualquerSemBaseline(alvo, b.texto)
      ) + durabilidade;
  }
}

/** Monitores derivados das ameaças de `ctx.findings`. Todo monitor rastreia até um `threatId`. */
export function deriveMonitors(ctx: ArtifactContext): Monitor[] {
  return derivar(ctx).map((d) => d.monitor);
}

/** Ameaças que não têm nenhum observável on-chain — vão ao plano como controle fora da chain. */
export function threatsSemObservavel(ctx: ArtifactContext): Finding[] {
  const comMonitor = new Set(derivar(ctx).map((d) => d.monitor.threatId));
  return ctx.findings.filter((f) => f.id && !comMonitor.has(f.id));
}

/**
 * Traduz o monitor no filtro real de uma chamada `getEvents`. `undefined` quando o
 * observável não passa por esse endpoint (ledger entry, árvore de autorização) — o monitor
 * continua válido no plano, só não é executável por aqui.
 *
 * Rederiva em vez de guardar o filtro no `Monitor`: o tipo é contrato congelado e não tem
 * campo para isso, e um cache por identidade de objeto quebraria no primeiro round-trip JSON.
 */
export function toExecutable(m: Monitor, ctx: ArtifactContext): ExecutableMonitor | undefined {
  const d = derivar(ctx).find((x) => x.monitor.id === m.id);
  if (!d || d.obs.kind !== "event" || !d.obs.topicos?.length) return undefined;

  // O RPC casa segmento a segmento e exige o MESMO comprimento da lista de tópicos do evento
  // (medido: ver nota no topo). Cada conjunto é um filtro alternativo (OR); juntar dois eventos
  // numa lista só produziria "topic[0]=a E topic[1]=b", que não casa com nenhum dos dois.
  //
  // Sem o spec não se sabe quantos segmentos o evento tem, e filtro com comprimento errado
  // devolve zero em silêncio. Nesse caso o filtro sai só por contractId — mais ruidoso, porém
  // nunca silenciosamente vazio — e a triagem pelo tópico vira pós-filtro declarado.
  const comSpec = d.obs.fonteTopic === "spec";
  const topics = comSpec ? d.obs.topicos.map((t) => t.segments) : undefined;
  const chaves = [...new Set(d.obs.topicos.map((t) => t.key))];

  return {
    monitorId: m.id,
    contractId: ctx.contractId,
    filter: { type: "contract", contractIds: [ctx.contractId], ...(topics ? { topics } : {}) },
    condition: condicaoDe(d.obs, d.base),
    note:
      (comSpec ? M.notaSpec : M.notaSemSpec(chaves.join(", "), M.LACUNA)) +
      (topics && topics.length > 1 ? M.notaAlternativos(topics.length) : "") +
      M.notaBaseline(d.base.tier, d.base.texto),
  };
}

/**
 * Evidência de como o observável foi atribuído à ameaça, com os níveis explícitos.
 * Existe porque `Monitor` é contrato congelado e não tem campo para isto — e sem ela o
 * documento apresentaria uma ligação por nome (nível C) como se fosse fato de bytecode.
 */
export function monitorAttribution(m: Monitor, ctx: ArtifactContext): string | undefined {
  return derivar(ctx).find((x) => x.monitor.id === m.id)?.obs.atribuicao;
}

/**
 * Quantos `*` o filtro deste monitor carrega, POR EVENTO do spec — e de onde o número veio.
 *
 * O comprimento da lista de tópicos é o que decide entre casar e devolver zero em silêncio
 * (ver a nota do topo). O número não é escolha do renderizador: é a contagem de parâmetros
 * que o spec declara em `TopicList`. Sem isto o documento imprime `[["init"]]` e o leitor
 * não tem como saber se a ausência de `*` foi medida ou esquecida.
 */
export function monitorFilterArity(m: Monitor, ctx: ArtifactContext): { nome: string; wildcards: number }[] {
  const d = derivar(ctx).find((x) => x.monitor.id === m.id);
  if (!d || d.obs.fonteTopic !== "spec" || !d.obs.topicos?.length) return [];
  return d.obs.topicos
    .filter((t): t is TopicSet & { nome: string } => typeof t.nome === "string")
    .map((t) => ({ nome: t.nome, wildcards: t.wildcards ?? 0 }));
}
