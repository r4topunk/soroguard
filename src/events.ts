/**
 * Nível B — o que o contrato REALMENTE emitiu on-chain.
 *
 * Este módulo é a única origem legítima de baseline nos dois artefatos. Por isso ele
 * responde a uma pergunta antes de responder "qual a taxa?": **que janela eu de fato
 * consegui observar?** Um número de eventos/hora sem a janela que o sustenta é
 * exatamente o "baseline inventado" que `docs/PROBLEMA.md` lista como risco 3.
 *
 * Fatos do RPC público que foram MEDIDOS contra mainnet (não lidos em doc) e que
 * mudam o desenho:
 *
 * 1. **Retenção ~7 dias, e ela anda.** `oldestLedger` avança ~1 ledger a cada ~5,55s.
 *    Usar o `oldestLedger` de uma sondagem como `startLedger` da chamada seguinte já
 *    devolve `startLedger must be within the ledger range` — aconteceu conosco em série.
 *    Daí a margem de segurança e o reajuste ao parsear o erro.
 *
 * 2. **Cada chamada varre no máximo ~10.000 ledgers**, independente do range pedido.
 *    Remedido nesta revisão: `startLedger=64343543`, contrato sem eventos, cursor
 *    devolvido = `64353542` = start+9.999. Ou seja: **página curta NÃO significa fim do
 *    range.** Quem interpretar assim calcula a taxa dividindo por uma janela ~40% maior
 *    do que a varrida, e subestima o baseline. É um erro silencioso — o pior tipo.
 *
 * 3. **O cursor é a prova de cobertura.** O `cursor` devolvido codifica um TOID cujo
 *    ledger é (a) o do último evento, quando a página encheu, ou (b) o fim do bloco
 *    varrido, quando a página veio curta. É isso que transforma "não vi nada" em
 *    "**não houve nada** neste intervalo, e eu sei porque ele foi varrido".
 *
 * 4. **Em contrato denso o orçamento de requisições, não a retenção, é o limite — e a
 *    paginação só anda para a frente.** Medido em CBBMQBNH (AMM): pedindo a retenção
 *    inteira, as 24 requisições cobriam 45.671 ledgers e a janela **terminava 74.988
 *    ledgers (~115,7 h) antes do topo da cadeia**. A taxa era verdadeira para o trecho,
 *    mas o documento a apresentava como baseline corrente sem dizer que era de 5 dias
 *    atrás — um baseline velho apresentado como atual, e a taxa que ele afirmava (112/h)
 *    era menos da metade da corrente. Por isso uma sondagem de densidade no topo escolhe
 *    o `startLedger` (ver `anchorRecent`). No mesmo contrato, depois da correção:
 *    20.757 ledgers ~32,0 h terminando **4.575 ledgers (~7,1 h) antes do topo**, com
 *    248/h. Janela mais curta, mas do período que o monitor vai vigiar.
 *
 * A janela reportada nunca é a pedida: é a coberta, derivada do cursor. O resíduo de
 * defasagem acima continua existindo e NÃO cabe em `ObservationWindow`, que é tipo
 * congelado em `artifact.ts`: quem renderiza só consegue vê-lo comparando `toLedger` com
 * o ledger corrente. Está declarado aqui para não passar por janela "até agora".
 *
 * **Fronteira do módulo, para não virar afirmação que não sustenta:** a contagem é
 * agrupada pelo PRIMEIRO topic do evento. Um evento declarado com `prefixTopics`
 * multi-nível (`["config","hub"]`) só é observável aqui pelo grupo `config`. Por isso
 * `declaredButUnseen` lista **primeiros topics**, nunca sub-topics: afirmar "0 emissões
 * de `hub`" quando o módulo nem conta `hub` seria inferência vendida como observação.
 */

import { rpc, scValToNative } from "@stellar/stellar-sdk";
import { endpointDe, fetchWasm, modelFromEntries, parseSpecEntries } from "./spec.ts";
import type { Observations, ObservationWindow, ObservedEvent } from "./artifact.ts";
import type { WindowLimitedBy } from "./model.ts";
import { plural } from "./text.ts";

export type { WindowLimitedBy } from "./model.ts";

/**
 * O que `observe` devolve de fato: `Observations` (tipo congelado em `artifact.ts`) MAIS a
 * declaração de o que fechou a janela. O campo não cabe em `ObservationWindow` sem
 * descongelar o contrato, e ele é a diferença entre um revisor ler "32 h" como contrato
 * parado e ler como contrato denso demais para o orçamento de paginação.
 */
export type ObserveResult = Observations & {
  limitedBy: WindowLimitedBy;
  /** páginas de `getEvents` gastas na paginação (sem contar sondagens) */
  pagesUsed: number;
};

/** Ledgers varridos por chamada de getEvents — medido no RPC público da mainnet. */
export const LEDGER_SCAN_CHUNK = 10_000;

/**
 * Horas mínimas para chamar uma taxa de "baseline". Abaixo de um ciclo diário completo
 * a taxa carrega o horário em que rodamos, não o comportamento do contrato — e o
 * checklist oficial pede baseline "grounded, not guesswork".
 */
export const MIN_BASELINE_HOURS = 24;

/** Folga contra o avanço da retenção entre a sondagem e a primeira página. */
const RETENTION_MARGIN_LEDGERS = 300;

/** Só usado se a rede não devolver tempos de fechamento coerentes. */
const SECONDS_PER_LEDGER_FALLBACK = 5;

/**
 * Reserva na ancoragem. A densidade NÃO é estável dentro da retenção: medido em CBBMQBNH,
 * 112 eventos/h na ponta antiga contra ~300/h perto do topo, e ~2,2× de diferença entre
 * duas sub-janelas separadas por um dia. Um alvo calculado com a densidade sondada no topo
 * e sem reserva estoura o orçamento antes de chegar ao topo — que é exatamente o defeito
 * a corrigir. Os dois erros não custam o mesmo: subestimar encurta a janela (e o piso
 * abaixo garante que ela ainda cubra `MIN_BASELINE_HOURS`), superestimar devolve um
 * baseline vencido com cara de corrente. Daí metade do orçamento ficar de reserva.
 */
const ANCHOR_RESERVE = 0.5;

/**
 * Multiplicador do orçamento quando o contrato é DENSO — quando a primeira página volta
 * cheia, cada requisição cobre pouquíssimos ledgers e o orçamento nominal produz uma janela
 * de ~32 h justamente nos contratos com mais tráfego (docs/PRECISION-TOP25.md). Dobrar é
 * modesto de propósito: o orçamento existe porque o RPC público devolve 429 sob rajada.
 */
const DENSE_BUDGET_FACTOR = 2;

export type ObserveOptions = {
  /** janela desejada em ledgers; o default é a retenção inteira do RPC */
  ledgers?: number;
  /** teto de chamadas de paginação — o RPC público devolve 429 sob rajada */
  maxRequests?: number;
  /** eventos por página */
  pageLimit?: number;
  /**
   * `prefixTopics` de cada evento declarado no spec, como vêm do `ContractModel` — uma
   * lista por evento, NÃO achatada. Passar aqui evita rebaixar o WASM de novo.
   * O achatamento é justamente o que produzia absência fabricada: ver nota de fronteira
   * no topo do arquivo.
   */
  declaredPrefixTopics?: string[][];
  /** pausa entre páginas */
  pauseMs?: number;
  /**
   * Reancorar o início quando o orçamento de requisições não cobrir o range pedido, para
   * que a janela termine no topo da cadeia em vez de na ponta antiga da retenção.
   * Default `true`. `false` reproduz a varredura crua a partir do início pedido.
   */
  anchorRecent?: boolean;
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Falhas que somem sozinhas: limite de taxa e soluços de rede. Erro de domínio, não. */
const RETRYABLE = /\b429\b|too many requests|rate limit|ECONNRESET|ETIMEDOUT|socket hang up|EAI_AGAIN|\b50[234]\b/i;

/** `startLedger must be within the ledger range: A - B` — o RPC diz onde está a janela. */
const LEDGER_RANGE = /ledger range:\s*(\d+)\s*-\s*(\d+)/;

async function withRetry<T>(fn: () => Promise<T>, tries = 4, base = 1200): Promise<T> {
  let last: unknown;
  for (let t = 0; t < tries; t++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (!RETRYABLE.test(String((e as Error)?.message ?? e))) throw e;
      await sleep(base * 2 ** t);
    }
  }
  throw last;
}

/**
 * Ledger codificado no cursor (TOID: ledger nos 32 bits altos).
 * É o fim comprovado da varredura — ver nota 3 no topo.
 */
export function ledgerFromCursor(cursor: string | undefined): number | undefined {
  if (!cursor) return undefined;
  const head = cursor.split("-")[0];
  if (!/^\d+$/.test(head)) return undefined;
  const led = Number(BigInt(head) >> 32n);
  return Number.isSafeInteger(led) && led > 0 ? led : undefined;
}

/**
 * Rótulos de tópico irrecusável. Só o texto muda entre idiomas: o `<` de abertura é o que
 * garante que um rótulo nunca se disfarce de topic real (símbolo Soroban é `[A-Za-z0-9_]`).
 */
const M = {
  vazio: "<empty>",
  indecodificavel: (tag: string) => `<${tag}:undecodable>`,
  ambiguo: (tag: string) => `<${tag}:ambiguous>`,
  longo: (tag: string, n: number) => `<${tag}:long:${n}>`,
  naoImprimivel: (tag: string) => `<${tag}:non-printable>`,
};

/**
 * Primeiro topic em forma legível — é ele que casa com `prefixTopics[0]` do contract spec.
 *
 * O que não serve como chave de filtro vira um rótulo entre `<>`. Um símbolo Soroban só
 * aceita `[A-Za-z0-9_]`, então o `<` garante que um rótulo nunca se disfarça de topic
 * real numa regra de monitoramento. O rótulo diz o motivo REAL da recusa: chamar de
 * "não-imprimível" uma string longa mas perfeitamente legível seria afirmar no documento
 * algo que o dado não sustenta.
 */
export function decodeTopic(v: unknown): string {
  const tag = String((v as { type?: unknown })?.type ?? "scv").replace(/^scv/, "").toLowerCase() || "scv";
  if (v == null) return M.vazio;
  let native: unknown;
  try {
    native = scValToNative(v as never);
  } catch {
    return M.indecodificavel(tag);
  }
  if (typeof native === "string") {
    // ASCII imprimível e curto: é nome de evento ou endereço, serve como chave de filtro.
    if (/^[\x20-\x7E]+$/.test(native)) {
      if (native.startsWith("<")) return M.ambiguo(tag); // colidiria com os rótulos daqui
      if (native.length > 64) return M.longo(tag, native.length);
      return native;
    }
    return M.naoImprimivel(tag);
  }
  if (native instanceof Uint8Array) return `<bytes:0x${Buffer.from(native).toString("hex").slice(0, 16)}>`;
  if (typeof native === "bigint" || typeof native === "number" || typeof native === "boolean") {
    return `<${tag}:${String(native)}>`;
  }
  return `<${tag}>`;
}

/** Tempo real por ledger, medido pelos dois extremos da retenção em vez de assumido. */
function secondsPerLedger(r: { latestLedger: number; oldestLedger: number; latestLedgerCloseTime: string; oldestLedgerCloseTime: string }): number {
  const toEpoch = (s: string): number => (/^\d+$/.test(s) ? Number(s) : Date.parse(s) / 1000);
  const dt = toEpoch(r.latestLedgerCloseTime) - toEpoch(r.oldestLedgerCloseTime);
  const dl = r.latestLedger - r.oldestLedger;
  const spl = dl > 0 ? dt / dl : NaN;
  // Fora dessa faixa o dado está corrompido; um divisor errado contamina toda a taxa.
  return Number.isFinite(spl) && spl >= 1 && spl <= 30 ? spl : SECONDS_PER_LEDGER_FALLBACK;
}

/**
 * Primeiro topic de cada evento declarado, deduplicado. É a ÚNICA projeção do spec que
 * este módulo consegue confrontar com a observação, porque só o primeiro topic é contado.
 */
export const declaredFirstTopics = (prefixTopics: string[][]): string[] =>
  [...new Set(prefixTopics.map((t) => t?.[0]).filter((t): t is string => typeof t === "string" && t.length > 0))];

/** Topics declarados no spec do WASM. Falha aqui é lacuna, não erro: devolve vazio. */
async function declaredTopicsOf(contractId: string, endpoint: string): Promise<string[]> {
  try {
    const { wasm } = await withRetry(() => fetchWasm(contractId, endpoint));
    const { events } = modelFromEntries(parseSpecEntries(wasm));
    return declaredFirstTopics(events.map((e) => e.prefixTopics));
  } catch {
    return [];
  }
}

/**
 * Lê os eventos emitidos pelo contrato na maior janela recente que o RPC permitir,
 * e devolve a janela **coberta** junto com as contagens.
 *
 * Lança apenas quando nem a janela dá para estabelecer (RPC inacessível): aí não existe
 * observação nenhuma a reportar, e devolver um objeto vazio faria um contrato inalcançável
 * parecer um contrato parado. Falha parcial de paginação NÃO lança — vira janela menor.
 */
export async function observe(contractId: string, endpoint: string, opts: ObserveOptions = {}): Promise<ObserveResult> {
  // `endpoint` é o RPC — nome conhecido ou URL, e a URL pode carregar API key. Ele fica
  // nesta função e nas chamadas de rede: nada dele entra em `Observations`, que vai para o
  // documento. O rótulo de rede que o documento mostra vem de `ctx.network`, separado.
  const url = endpointDe(endpoint);
  const server = new rpc.Server(url);
  const pageLimit = opts.pageLimit ?? 1000;
  const maxRequests = opts.maxRequests ?? 24;
  const pauseMs = opts.pauseMs ?? 350;
  const anchorRecent = opts.anchorRecent !== false;
  /** Orçamento efetivo: sobe para `DENSE_BUDGET_FACTOR ×` quando a primeira página vem cheia. */
  let budget = maxRequests;
  let denso = false;
  const filters = [{ type: "contract" as const, contractIds: [contractId] }];

  // Sondagem: uma chamada mínima que devolve o estado de retenção (latest/oldest + tempos).
  // O índice de eventos pode estar atrás do `getLatestLedger` do mesmo nó; nesse caso o RPC
  // diz qual é o range válido e a sondagem é refeita com ele. Sem isso, um atraso de dois
  // ledgers derruba a observação inteira — e o pipeline engole a exceção, deixando o
  // contrato sem nível B nenhum.
  const latest = (await withRetry(() => server.getLatestLedger())).sequence;
  const probeAt = async (at: number) => withRetry(() => server.getEvents({ startLedger: at, filters, limit: 1 }));
  let probe: rpc.Api.GetEventsResponse;
  try {
    probe = await probeAt(latest);
  } catch (e) {
    const m = LEDGER_RANGE.exec(String((e as Error)?.message ?? e));
    if (!m) throw e;
    probe = await probeAt(Number(m[2]));
  }
  const spl = secondsPerLedger(probe);
  const retention = probe.latestLedger - probe.oldestLedger;
  const floorLedger = probe.oldestLedger + RETENTION_MARGIN_LEDGERS;

  const desired = Math.max(1, Math.min(opts.ledgers ?? retention, retention));

  // Ancoragem (nota 4 no topo). Uma sondagem de densidade NO TOPO diz quantos ledgers
  // cabem numa página para este contrato ali. Se o orçamento não alcança o range pedido,
  // varrer a partir do início pedido produz uma janela que termina dias atrás — baseline
  // vencido, indistinguível de um corrente no documento. Ancorar no topo troca "as 70 h
  // que começam 7,75 dias atrás" por "as ~N h até agora".
  //
  // Piso: nunca trocar uma janela que sustenta baseline por uma mais recente e curta
  // demais. Como o piso já é o mínimo, um pedido menor que ele nunca muda de lugar — e aí
  // a sondagem é pura queima de requisição, então nem acontece.
  const floorSpan = Math.ceil((MIN_BASELINE_HOURS * 3600) / spl);
  /**
   * Teto ABSOLUTO do orçamento: cada requisição varre no máximo `LEDGER_SCAN_CHUNK`
   * ledgers (nota 2 no topo), então `budget × chunk` é o range que nenhuma coleta
   * ultrapassa — sem sondar nada.
   *
   * Medido em CCR2CH4G num RPC com retenção longa (1.036.799 ledgers, ~67 dias): a
   * sondagem de densidade não dispara em contrato esparso (página curta), `reachable`
   * ficava infinito, a varredura começava na ponta ANTIGA e a janela de 375 h terminava
   * ~52 dias antes do topo. Baseline vencido com cara de corrente — o mesmo defeito da
   * nota 4, pelo caminho oposto. O teto corrige sem custar uma requisição.
   */
  const tetoDoOrcamento = () => Math.max(floorSpan, budget * LEDGER_SCAN_CHUNK);
  let reachable = anchorRecent ? tetoDoOrcamento() : Number.POSITIVE_INFINITY;
  if (anchorRecent && desired > floorSpan) {
    const dStart = Math.max(floorLedger, probe.latestLedger - LEDGER_SCAN_CHUNK + 1);
    try {
      const d = await withRetry(() => server.getEvents({ startLedger: dStart, filters, limit: pageLimit }));
      const dEnd = ledgerFromCursor(d.cursor) ?? d.events.at(-1)?.ledger;
      // Página curta = o chunk de 10k ledgers, não a densidade, é o limite: nada a ancorar.
      if (d.events.length >= pageLimit && dEnd !== undefined && dEnd >= dStart) {
        // Página cheia na sondagem = contrato denso: o orçamento sobe, e o alcance é
        // calculado com o orçamento que de fato vai ser gasto.
        denso = true;
        budget = maxRequests * DENSE_BUDGET_FACTOR;
        reachable = Math.max(
          floorSpan,
          Math.min(tetoDoOrcamento(), Math.floor((dEnd - dStart + 1) * budget * ANCHOR_RESERVE)),
        );
      }
    } catch {
      /* a sondagem de densidade é otimização de recorte; falhar nela não invalida nada */
    }
  }

  // Se nem o piso couber no orçamento, a janela trunca e sai menor — honesta nos dois
  // casos, porque quem manda no `toLedger` continua sendo o cursor, nunca o range pedido.
  let start = Math.max(probe.latestLedger - Math.min(desired, reachable), floorLedger);

  const counts = new Map<string, { count: number; firstLedger: number; lastLedger: number }>();
  let covered = 0; // último ledger com cobertura COMPROVADA pelo cursor
  let cursor: string | undefined;

  let pagesUsed = 0;
  let orcamentoEstourado = false;
  for (let page = 0; page < budget; page++) {
    pagesUsed++;
    let res: rpc.Api.GetEventsResponse;
    try {
      res = await withRetry(() =>
        cursor
          ? server.getEvents({ cursor, filters, limit: pageLimit })
          : server.getEvents({ startLedger: start, filters, limit: pageLimit }),
      );
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      // A retenção andou entre a sondagem e agora: reajusta o piso e tenta de novo.
      const range = LEDGER_RANGE.exec(msg);
      if (range && !cursor && Number(range[1]) > start) {
        start = Number(range[1]) + RETENTION_MARGIN_LEDGERS;
        continue;
      }
      // Qualquer outra falha encerra a coleta: reportamos a janela coberta até aqui,
      // que é menor, mas verdadeira. Parar não estraga o dado; extrapolar estragaria.
      break;
    }

    for (const ev of res.events) {
      // Evento de chamada revertida não é comportamento do contrato, é tentativa.
      if (ev.inSuccessfulContractCall === false) continue;
      const topic = decodeTopic(ev.topic?.[0]);
      const cur = counts.get(topic);
      if (!cur) counts.set(topic, { count: 1, firstLedger: ev.ledger, lastLedger: ev.ledger });
      else {
        cur.count++;
        if (ev.ledger < cur.firstLedger) cur.firstLedger = ev.ledger;
        if (ev.ledger > cur.lastLedger) cur.lastLedger = ev.ledger;
      }
    }

    // A primeira página cheia é o mesmo sinal de densidade da sondagem, para quando ela
    // não aconteceu (janela pedida ≤ piso) ou falhou.
    if (res.events.length >= pageLimit) {
      if (!denso) {
        denso = true;
        budget = maxRequests * DENSE_BUDGET_FACTOR;
      }
    }

    const mark = ledgerFromCursor(res.cursor) ?? res.events.at(-1)?.ledger;
    if (mark === undefined) break; // sem cursor não há prova de cobertura; melhor parar
    covered = Math.max(covered, mark);
    cursor = res.cursor;
    if (!cursor || covered >= probe.latestLedger) break;
    if (page === budget - 1) orcamentoEstourado = true;
    await sleep(pauseMs);
  }

  const ledgers = covered > start ? covered - start + 1 : 0;
  const approxHours = (ledgers * spl) / 3600;
  const window: ObservationWindow = {
    fromLedger: start,
    toLedger: ledgers ? covered : start,
    ledgers,
    approxHours: Math.round(approxHours * 100) / 100,
    insufficient: approxHours < MIN_BASELINE_HOURS,
  };

  // Quem fechou a janela. `request-budget` quando a paginação parou antes do topo por falta
  // de requisições OU quando a ancoragem já recortou o range pedido por causa do orçamento;
  // `retention` quando pedimos tudo que o RPC retém e a varredura chegou ao fim;
  // `none` quando a janela pedida coube inteira.
  //
  // Materialidade: parar a um punhado de ledgers do topo não é "o orçamento me cortou" —
  // medido em CCR2CH4G, a varredura cobriu 239.977 dos ~240.000 ledgers da retenção e
  // ainda assim terminou com cursor antes do tip. Chamar aquilo de limite de orçamento
  // trocaria uma verdade (é a retenção do RPC) por outra afirmação, igualmente checável e
  // errada. O corte é uma varredura de página (10k ledgers, ~15 h).
  const alcancouOPedido = ledgers >= desired - LEDGER_SCAN_CHUNK;
  const limitedBy: WindowLimitedBy =
    !alcancouOPedido && (orcamentoEstourado || reachable < desired) ? "request-budget"
    : desired >= retention ? "retention"
    : "none";

  const events: ObservedEvent[] = [...counts.entries()]
    .map(([topic, c]) => ({
      topic,
      count: c.count,
      firstLedger: c.firstLedger,
      lastLedger: c.lastLedger,
      ratePerHour: approxHours > 0 ? Math.round((c.count / approxHours) * 1000) / 1000 : 0,
    }))
    .sort((a, b) => b.count - a.count);

  // `declaredButUnseen` só vale como sinal ("código morto ou caminho raro") se a janela
  // sustenta a ausência. Numa janela curta demais, ausência é falta de tempo de observação:
  // listar os topics ali seria fabricar um achado a partir do nosso próprio limite.
  // E só primeiros topics entram: ver a nota de fronteira no topo do arquivo.
  let declaredButUnseen: string[] = [];
  if (!window.insufficient) {
    const declared = opts.declaredPrefixTopics
      ? declaredFirstTopics(opts.declaredPrefixTopics)
      : await declaredTopicsOf(contractId, endpoint);
    const seen = new Set(counts.keys());
    declaredButUnseen = declared.filter((t) => !seen.has(t));
  }

  return { window, events, declaredButUnseen, limitedBy, pagesUsed };
}

/**
 * A declaração de janela, como sai nos DOIS documentos.
 *
 * Existe porque os dois documentos precisam dizer a mesma coisa sobre o mesmo dado, e
 * porque o número sozinho engana: 32 h e 375 h têm a mesma cara na página, e o caso curto
 * é sistematicamente o do contrato MAIS movimentado — aquele em que o baseline mais
 * importa. Sem esta linha o revisor lê a janela curta como falta de tráfego.
 */
export function declaracaoDeJanela(ledgers: number, horas: number, limitedBy: WindowLimitedBy): string {
  const h = horas >= 10 ? horas.toFixed(0) : horas.toFixed(2);
  return W.declaracao(ledgers, h, limitedBy);
}

const W = {
  declaracao: (n: number, h: string, por: WindowLimitedBy) =>
    `window of ${n} ${plural(n, "ledger", "ledgers")} (~${h} h) — ` +
    (por === "request-budget"
      ? "limited by the RPC request budget, not by retention: the collector could not page the whole " +
        "retained range in the time allowed, and the contracts that emit most events hit this first; " +
        "baselines are rates over the observed slice, not totals."
      : por === "retention"
        ? "limited by RPC retention."
        : "bounded by the requested window: neither RPC retention nor the request budget cut it short."),
};
