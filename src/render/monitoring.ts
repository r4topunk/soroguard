/**
 * Renderiza o On-Chain Monitoring Plan no template oficial da Stellar
 * (developers.stellar.org/docs/build/security-docs/monitoring/monitoring-template-builders):
 * seis seções, nesta ordem, com as colunas que o template pede.
 *
 * Os títulos das seções e os cabeçalhos de coluna do template ficam no inglês original —
 * são a interface do documento com o revisor do SCF, e traduzi-los quebraria o
 * reconhecimento do template.
 *
 * O acoplamento por ID é o valor central: toda linha da seção 4 tem um `<ThreatID>.M.<n>` que
 * aparece na seção 2, e todo baseline ou vem de observação (nível B) ou declara a lacuna.
 * Nenhuma célula é preenchida com genérico para fechar tabela.
 *
 * §6 NÃO É CALCULADA AQUI. O checklist vem inteiro de `validateMonitoringPlan` (src/validate.ts),
 * que é a fonte única: antes havia duas implementações da mesma pergunta — uma aqui, outra lá —
 * e elas divergiram, de modo que o documento afirmava uma coisa e o veredito do CLI, outra.
 * A ordem é: renderizar o corpo, passar esse corpo ao validador, imprimir os itens que ele
 * devolve. Não há ciclo de import (validate.ts nunca importa renderizador) e o relatório é o
 * MESMO que o CLI imprime, porque o validador corta o documento no título da §6 antes de lê-lo.
 */

import type { ArtifactContext } from "../artifact.ts";
import { tierLabel } from "../artifact.ts";
import type { Finding } from "../detect.ts";
import { deriveMonitors, toExecutable, threatsSemObservavel, monitorAttribution, monitorFilterArity, lacuna } from "../monitors.ts";
import { validateMonitoringPlan } from "../validate.ts";
import { requiresAuth, writesStorage, emitsEvent, callsOut } from "../analyze.ts";
import { declaracaoDeJanela } from "../events.ts";
import { plural } from "../text.ts";

const M = {
  colFuncao: "Function",
  titulo: (id: string) => `# On-Chain Monitoring Plan — \`${id}\``,
  cabecalho: (rede: string, data: string, hash?: string) =>
    `**Network:** ${rede} · **Generated:** ${data} (UTC) · **Source:** deployed WASM${hash ? `, hash \`${hash}\`` : ""}`,
  interno:
    "> **Keep this document internal.** A filled-in monitoring plan is the map of what is and what is not being watched.",
  /**
   * A frase acima é do time para o time. Sem a de baixo, um leitor externo lê este arquivo
   * como laudo revisado sobre um contrato de terceiros — que é o que ele não é: o alvo é
   * bytecode público, ninguém do lado do contrato viu isto, e nada aqui foi confirmado
   * como explorável.
   */
  naoRevisado:
    "> This draft was generated from public mainnet bytecode by a tool and has not been reviewed by the contract's owners; it is not a vulnerability report.",
  comoLer: "**How to read the evidence marks.** No claim here is worth more than the evidence behind it:",
  colMarca: "Marker",
  colSignificado: "Meaning",
  colQuemConfere: "Who can check it",
  confereA: "anyone, by re-running the analysis over the same binary",
  confereB: "anyone, over RPC in the same window",
  confereC: "human review only",
  lacunaSignificado: "the tool does not have this data and does not invent it",
  lacunaQuem: "whoever operates the protocol has to fill it in",
  rascunho:
    "This plan was derived automatically from the bytecode by soroguard. It is a defensible draft, not a deployment: no monitor is born with status `Active`.",
  /* §1 */
  resumo: (
    id: string, rede: string, bytes: string, fns: number, evs: number,
    eps: number, inv: number, mut: number, auth: number, emite: number, completo: boolean, contaCustom: boolean,
  ) =>
    `Contract \`${id}\` on ${rede}${bytes ? `, a ${bytes}-byte binary` : ""}. ` +
    `The spec declares ${fns} ${plural(fns, "function", "functions")} and ${evs} ${plural(evs, "event", "events")}. ` +
    `The bytecode analysis found ${eps} exported, ${inv} invocable (\`__*\` reserved exports excluded, CAP-0058); ` +
    `of the ${inv} invocable ${plural(inv, "entrypoint", "entrypoints")}, ${mut} reach a storage write, ` +
    `${auth} reach \`require_auth*\` and ${emite} reach \`contract_event\`. ` +
    `Call graph ${completo
      ? "complete — a negative claim here is a sound negative for this module's call graph (authorization enforced in a called contract or in `__check_auth` is not visible here)"
      : "**incomplete** (`call_indirect` present) — the negative claims are downgraded"}.` +
    (contaCustom
      ? " This module exports `__check_auth`: it is a custom account, so authorization is implemented there instead of by a `require_auth` call in each entrypoint — read every negative about `require_auth*` with that in mind."
      : ""),
  objetoAnalisado: (caminho: string) =>
    `**Analyzed object:** local file \`${caminho}\`. The addresses below come from the file name when it is a contract id; otherwise they come out marked as not derivable — a file path in an address cell is a filter that matches nothing.`,
  descricaoProtocolo: (l: string) =>
    `Description of the protocol, the value it custodies and its operational context: ${l} — none of that is in the binary.`,
  linhaInstancia: "Contract instance",
  instanciaFuncao: (hash: string) => `Executable ${hash}; target of every filter in this plan`,
  linhaEntrypoint: (nome: string) => `Entrypoint \`${nome}\``,
  assinaturaAusente: "not declared in the spec (export with no function entry)",
  linhaExternos: "External contracts invoked",
  externosFuncao: (eps: string, extra: string) =>
    `The destination address of \`call\`/\`try_call\` is a runtime argument and is not in the bytecode. Reaching cross-call: ${eps}${extra}`,
  avisoEndereco:
    "> A stale address is the most common cause of a monitor that silently stops working. The addresses above hold for the binary identified in the header; re-check after any upgrade.",
  /* §2 */
  severityReminders: "### Severity reminders",
  colSeverity: "Severity",
  colMeaning: "Meaning",
  sevCritical: "Direct, large-scale loss of funds or of control; requires an immediate response.",
  sevHigh: "Serious impact on funds, users or availability; requires a fast response.",
  sevMedium: "Limited or workaround-able impact; the response can be scheduled.",
  sevLow: "Minor or informational; monitored for awareness.",
  threatRegister: "### Threat register",
  colThreatId: "Threat ID",
  colThreat: "Threat (from threat model)",
  colComponente: "Affected component",
  rebaixada: " ⚠ evidence downgraded: `call_indirect` in the subgraph",
  semAmeaca: "No threat derivable from this contract's bytecode.",
  letrasSemAmeaca: (letras: string) => `**STRIDE letters with no derivable threat:** ${letras}.`,
  explicacaoLacunas: (estruturais: string, demais: string) =>
    "The template asks for at least one issue per letter. These are declared instead of filled in. " +
    (estruturais
      ? `${estruturais} depend on identity and on data exposure, which do not exist in a contract's bytecode — that is a limit of the tool, not of this binary. `
      : "") +
    (demais ? `For ${demais}, no detector found a signal in this binary — which does not prove absence. ` : "") +
    "All of them require manual analysis of the off-chain flow; filling them with generic text would give an impression of coverage that does not exist.",
  /* §1 — atividade observada (nível B) */
  e: " and ",
  janelaObservada: (n: number, h: string, de: number, ate: number) =>
    `window of ${n} ${plural(n, "ledger", "ledgers")} (~${h} h, ledgers ${de}–${ate})`,
  tituloObservado: (janela: string) => `**Observed activity (B)** — ${janela}:`,
  colTopic: "Topic",
  colOcorrencias: "Occurrences",
  colTaxa: "Rate/h",
  colDeclarado: "Declared in spec",
  sim: "yes",
  nao: "no",
  observadoMais: (n: number) => `… (+${n} more ${plural(n, "topic", "topics")})`,
  notaObservado: (naoDeclarados: number, total: number) =>
    `${naoDeclarados} of the ${total} observed ${plural(total, "topic", "topics")} ${plural(naoDeclarados, "is", "are")} not declared in this contract's spec: undeclared topics come from the SDK's own events (token \`transfer\`/\`approve\`, TTL) or from contracts invoked underneath this one. ` +
    "They are still usable as a monitor observable — what they do not carry is the segment count, which only the spec gives, so their filter goes by contractId with the topic triaged client-side.",
  semObservado: (janela: string) => `**Observed activity (B)** — ${janela}: no event of any topic. Absence of traffic is not a traffic profile.`,
  /* §3 */
  colCenario: "Exploitation scenario",
  colEfeito: "Observable on-chain effect(s)",
  semEfeito: "**No observable on-chain effect derivable from this analysis** — see §5.",
  notaSemObservavel:
    "> Threats with no observable effect were neither dismissed nor handed a for-show monitor: they are in section 5, with the control they require off-chain.",
  /* §4 */
  semBaselineMarca: "⚠ no baseline",
  intencao: (classe: string, componente: string, threat: string) =>
    `Alert on ${classe} in ${componente}, tracing back to threat ${threat}.`,
  intencaoSemAchado: (threat: string) => `Alert on threat ${threat}.`,
  celulaBaselineEmbutido: (gatilho: string, marca: string) => `${gatilho} **Baseline: ${marca}**`,
  celulaBaseline: (gatilho: string, marca: string, base: string) => `${gatilho} **Baseline ${marca}:** ${base}`,
  semMonitorLinha: "No on-chain observable derivable for this contract's threats.",
  emUmaLinha: "One line each:",
  umaLinha: (id: string, threat: string, componente: string, observavel: string, endereco: string) =>
    `- **${id}** — We address **${threat}** in **${componente}** by monitoring **${observavel}** at address **\`${endereco}\`**.`,
  comoAtribuido:
    "**How each observable was attributed to its threat.** The tier holds per claim: (A) is a bytecode fact, (C) is an inference that still needs human review.",
  demaisMonitores: (l: string) => `- Remaining monitors: the attribution could not be recomputed from this context — ${l}.`,
  filtrosExecutaveis: "### Executable filters",
  semExecutaveis: (n: number, estranhos: number, l: string) =>
    (n === 1 ? "The only monitor is not directly executable through \`getEvents\`. " : `None of the ${n} monitors is directly executable through \`getEvents\`. `) +
    (estranhos
      ? `${estranhos} of them were not derived from this context and therefore have no recomputable filter here — ${l}. `
      : "That is not a flaw in the plan: the observables derived here are ledger entries and the authorization tree, which are read through " +
        "`getLedgerEntries` and by inspecting the transaction. ") +
    "A topic filter requires the contract to emit an event attributable to the threat.",
  comExecutaveis: (n: number, total: number) =>
    `${n} of ${total} ${plural(total, "monitor", "monitors")} ${plural(n, "turns", "turn")} into an RPC call with no manual translation. ` +
    "The topics below come from `prefixTopics` in the contract spec recorded in the WASM itself. On the wire each segment goes as a " +
    "base64 ScVal symbol (the raw string is rejected with `invalid parameters`) and the list must have the same length as the event's " +
    "topic list — a filter that is too short does not error, it returns zero.",
  /**
   * O nº de `*` não é escolha do renderizador: é a contagem de parâmetros que o spec
   * declara em TopicList. Sem dizer isso, um filtro sem `*` se lê como esquecimento —
   * e errar o comprimento devolve zero em silêncio, o modo de falha mais caro do plano.
   */
  aridadeSpec: (nome: string, n: number) =>
    `\`${nome}\` declares ${n} topic ${plural(n, "parameter", "parameters")} in the spec, so the filter ` +
    (n === 0 ? "has no `*`" : `carries ${n} \`*\``) + ".",
  /* §5 */
  revisao: (data: string) => `never reviewed — generated on ${data}`,
  colResposta: "Response / action",
  colOwner: "Owner",
  colStatus: "Status",
  colRevisao: "Last reviewed",
  canalEAcao: (resposta: string, l: string) => `${resposta} Channel and automated action: ${l}`,
  statusValues:
    "**Status values:** _Active_ (live, alerting), _Tuning_ (live, thresholds being adjusted), _Planned_ (agreed, not implemented yet).",
  explicacaoStatus:
    "No monitor leaves this document as `Active`: this is the plan, not the deployment. " +
    "`Tuning` marks what is fully specified — topic attributed and baseline observed — and can be switched on as is. " +
    "`Planned` marks what still depends on data the tool does not have.",
  donoECanal: (n: number) =>
    `Owner and channel do not appear in the binary: ${n} ${plural(n, "row awaits", "rows await")} that information, and section 6 counts it as a submission blocker.`,
  tituloForaDaChain: "### Threats that require an off-chain control",
  colPorQue: "Why there is no on-chain observable",
  colControle: "Required control",
  motivoSilenciosa:
    "(A) the listed entrypoints reach `put_contract_data` and do not reach `contract_event`: by construction they produce nothing in the event stream. With no storage keys known for certain, not even the state diff is addressable.",
  motivoGenerico: "No observable effect was derived for this class from the bytecode.",
  controleSilenciosa:
    "Periodic reconciliation between the state read from the contract and the state the backend expects; and, as a design fix, emit an event in the entrypoints listed in the finding.",
  /* §6 */
  colPergunta: "Checklist question",
  colSituacao: "Status",
  colDetalhe: "Detail",
  ok: "✔ ok",
  gap: "⚠ gap",
  submetivel:
    "**Ready to submit:** every monitor traces back to a threat, every baseline either comes from observation or declares the gap, and no field was filled with generic text.",
  naoSubmeter: "**Do not submit without closing these points:**",
  tituloInput: "### Input the team must provide before submitting",
  documentoVivo:
    "Treat this plan as a living document: review it whenever the contracts, the addresses or the threat model change.",
};

/**
 * Junção de lista em prosa: "Tamper", "Tamper and DoS", "Tamper, DoS and Repudiate".
 * Existe porque `join(", ")` produzia "For Tamper, DoS, no detector found a signal" — uma
 * enumeração sem conjunção que o leitor lê como aposto e não como lista.
 */
const juntar = (xs: readonly string[]): string =>
  xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")}${M.e}${xs[xs.length - 1]}`;

/** Pipe dentro de célula quebra a tabela inteira; quebra de linha idem. */
const cel = (s: string): string => s.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ").trim();

const linha = (...cols: string[]): string => `| ${cols.map(cel).join(" | ")} |`;

/** Componente afetado: achados de escopo de contrato não têm entrypoint. */
const componente = (f: Finding, ctx: ArtifactContext): string =>
  f.entrypoint === "<contrato>" ? `Whole contract (${ctx.contractId})` : `\`${f.entrypoint}\``;

/** Só as inferências do achado — é o que a coluna "cenário de exploração" pede. */
const cenario = (f: Finding): string =>
  f.evidence.filter((e) => e.tier === "C").map((e) => e.claim).join(" ") || lacuna();

export function renderMonitoringPlan(ctx: ArtifactContext): string {
  const monitors = ctx.monitors?.length ? ctx.monitors : deriveMonitors(ctx);
  const semObs = threatsSemObservavel(ctx);
  const porAmeaca = new Map<string, typeof monitors>();
  for (const m of monitors) porAmeaca.set(m.threatId, [...(porAmeaca.get(m.threatId) ?? []), m]);
  const achadoPorId = new Map(ctx.findings.filter((f) => f.id).map((f) => [f.id!, f]));
  const L = lacuna();
  const tier = tierLabel;

  const o: string[] = [];
  const p = (s = "") => o.push(s);

  /* ---------- cabeçalho ---------- */
  p(M.titulo(ctx.contractId));
  p();
  p(M.cabecalho(ctx.network, ctx.generatedAt, ctx.spec.wasmHash));
  p();
  p(M.interno);
  p(M.naoRevisado);
  p();
  p(M.comoLer);
  p();
  p(linha(M.colMarca, M.colSignificado, M.colQuemConfere));
  p("|---|---|---|");
  p(linha("(A)", tier.A, M.confereA));
  p(linha("(B)", tier.B, M.confereB));
  p(linha("(C)", tier.C, M.confereC));
  p(linha(L, M.lacunaSignificado, M.lacunaQuem));
  p();
  p(M.rascunho);
  p();

  /* ---------- 1 ---------- */
  p("## What are we monitoring?");
  p();
  const eps = ctx.analysis.entrypoints;
  // `__constructor`, `__check_auth` e afins são exports reservados do protocolo (CAP-0058):
  // ninguém os invoca por InvokeHostFunction. Contá-los no mesmo número que os entrypoints
  // invocáveis fazia o plano e o threat model divergirem no denominador do mesmo contrato.
  const invocaveis = eps.filter((e) => !e.name.startsWith("__"));
  const mutadores = invocaveis.filter((e) => writesStorage(e));
  p(
    M.resumo(
      ctx.contractId,
      ctx.network,
      ctx.spec.wasmBytes ? ctx.spec.wasmBytes.toLocaleString("en-US") : "",
      ctx.spec.fns.length,
      ctx.spec.events.length,
      eps.length,
      invocaveis.length,
      mutadores.length,
      invocaveis.filter((e) => requiresAuth(e)).length,
      invocaveis.filter((e) => emitsEvent(e)).length,
      ctx.analysis.soundness === "sound",
      eps.some((e) => e.name === "__check_auth"),
    ),
  );
  p();
  if (ctx.spec.analyzedFile) {
    // O alvo foi um arquivo: o caminho é metadado da análise, nunca endereço on-chain.
    p(M.objetoAnalisado(cel(ctx.spec.analyzedFile)));
    p();
  }
  p(M.descricaoProtocolo(L));
  p();
  p(linha("Component", "On-chain address", M.colFuncao));
  p("|---|---|---|");
  p(linha(M.linhaInstancia, `\`${ctx.contractId}\``, M.instanciaFuncao(ctx.spec.wasmHash ? `\`${ctx.spec.wasmHash.slice(0, 16)}…\`` : L)));
  // Um componente por entrypoint que carrega ameaça: é a granularidade em que o plano opera.
  const ameacados = [...new Set(ctx.findings.map((f) => f.entrypoint))].filter((n) => n !== "<contrato>").sort();
  for (const nome of ameacados) {
    const fn = ctx.spec.fns.find((f) => f.name === nome);
    const assinatura = fn ? `${fn.name}(${fn.params.map((x) => `${x.name}: ${x.type}`).join(", ")}) → ${fn.returns}` : M.assinaturaAusente;
    p(linha(M.linhaEntrypoint(nome), `\`${ctx.contractId}\``, assinatura));
  }
  const saem = eps.filter((e) => callsOut(e));
  if (saem.length) {
    p(linha(
      M.linhaExternos,
      L,
      M.externosFuncao(saem.slice(0, 8).map((e) => `\`${e.name}\``).join(", "), saem.length > 8 ? ` (+${saem.length - 8})` : ""),
    ));
  }
  p();
  p(M.avisoEndereco);
  p();

  /* ---------- 1b — o que a janela observada mediu (nível B) ----------
   * A janela já sustentava os baselines da §4, mas as contagens por tópico nunca chegavam
   * ao documento: o revisor lia "0 emissões de [init]" sem saber que o contrato emitiu
   * 12.853 eventos de outros 9 tópicos na MESMA janela. Sem esta tabela o plano parece
   * descrever um contrato parado, e um tópico observado fora do spec — que é observável de
   * monitor perfeitamente válido — ficava invisível.
   */
  if (ctx.observations) {
    const w = ctx.observations.window;
    const janela = M.janelaObservada(w.ledgers, w.approxHours >= 10 ? w.approxHours.toFixed(0) : w.approxHours.toFixed(2), w.fromLedger, w.toLedger);
    // O número sozinho engana: 32 h e 375 h têm a mesma cara, e a janela curta é
    // sistematicamente a do contrato MAIS movimentado — aquele em que o baseline mais
    // importa. Declarar QUEM fechou a janela é o que impede ler "32 h" como "parado".
    if (ctx.spec.windowLimitedBy) {
      p(declaracaoDeJanela(w.ledgers, w.approxHours, ctx.spec.windowLimitedBy));
      p();
    }
    const declarados = new Set(ctx.spec.events.map((e) => e.prefixTopics[0]).filter(Boolean));
    const vistos = [...ctx.observations.events].sort((a, b) => b.count - a.count);
    if (!vistos.length) {
      p(M.semObservado(janela));
      p();
    } else {
      p(M.tituloObservado(janela));
      p();
      p(linha(M.colTopic, M.colOcorrencias, M.colTaxa, M.colDeclarado));
      p("|---|---|---|---|");
      for (const e of vistos.slice(0, 12)) {
        p(linha(
          `\`${e.topic}\``,
          e.count.toLocaleString("en-US"),
          e.ratePerHour >= 10 ? e.ratePerHour.toFixed(0) : e.ratePerHour.toFixed(2),
          declarados.has(e.topic) ? M.sim : M.nao,
        ));
      }
      if (vistos.length > 12) p(linha(M.observadoMais(vistos.length - 12), "—", "—", "—"));
      p();
      const naoDeclarados = vistos.filter((e) => !declarados.has(e.topic)).length;
      if (naoDeclarados) {
        p(M.notaObservado(naoDeclarados, vistos.length));
        p();
      }
    }
  }

  /* ---------- 2 ---------- */
  p("## What could go wrong?");
  p();
  p(M.severityReminders);
  p();
  p(linha(M.colSeverity, M.colMeaning));
  p("|---|---|");
  p(linha("**Critical**", M.sevCritical));
  p(linha("**High**", M.sevHigh));
  p(linha("**Medium**", M.sevMedium));
  p(linha("**Low**", M.sevLow));
  p();
  p(M.threatRegister);
  p();
  p(linha(M.colThreatId, M.colThreat, M.colComponente, M.colSeverity));
  p("|---|---|---|---|");
  for (const f of ctx.findings) {
    if (!f.id) continue;
    p(linha(f.id, `${f.title}${f.sound ? "" : M.rebaixada}`, componente(f, ctx), f.severity));
  }
  if (!ctx.findings.length) p(linha("—", M.semAmeaca, "—", "—"));
  p();
  if (ctx.gaps.length) {
    p(M.letrasSemAmeaca(ctx.gaps.join(", ")));
    p();
    // Spoof e Info têm um motivo estrutural, medido em 75 contratos de mainnet: zero achados.
    // As demais letras podem simplesmente não ocorrer neste binário, e dizer o contrário seria
    // atribuir à ferramenta um limite que ela não tem.
    const estruturais: string[] = ctx.gaps.filter((g) => g === "Spoof" || g === "Info");
    p(
      M.explicacaoLacunas(
        juntar(estruturais),
        juntar(ctx.gaps.filter((g) => !estruturais.includes(g))),
      ),
    );
    p();
  }

  /* ---------- 3 ---------- */
  p("## What does exploitation look like on-chain?");
  p();
  p(linha(M.colThreatId, M.colCenario, M.colEfeito));
  p("|---|---|---|");
  for (const f of ctx.findings) {
    if (!f.id) continue;
    const ms = porAmeaca.get(f.id) ?? [];
    const efeito = ms.length ? ms.map((m) => `${m.id}: ${m.observable}`).join(" · ") : M.semEfeito;
    p(linha(f.id, `(C) ${cenario(f)}`, efeito));
  }
  p();
  if (semObs.length) {
    p(M.notaSemObservavel);
    p();
  }

  /* ---------- 4 ---------- */
  p("## What will we monitor for?");
  p();
  p("| Monitor ID | Observable on-chain effect | Trigger condition & baseline | Monitoring rule (plain-language intent) |");
  p("|---|---|---|---|");
  for (const m of monitors) {
    const f = achadoPorId.get(m.threatId);
    const marca = m.baselineTier === "none" ? M.semBaselineMarca : `(${m.baselineTier})`;
    const intencao = f
      ? M.intencao(f.class.replace(/-/g, " "), componente(f, ctx), m.threatId)
      : M.intencaoSemAchado(m.threatId);
    // O gatilho composto em monitors.ts já embute o texto do baseline quando ele falta.
    // Repetir aqui dobrava a frase na célula — o leitor lia duas vezes a mesma ressalva.
    const jaTemBaseline = m.baseline.length > 12 && m.trigger.includes(m.baseline.slice(0, 40));
    const celula = jaTemBaseline ? M.celulaBaselineEmbutido(m.trigger, marca) : M.celulaBaseline(m.trigger, marca, m.baseline);
    p(linha(m.id, m.observable, celula, intencao));
  }
  if (!monitors.length) p(linha("—", M.semMonitorLinha, "—", "—"));
  p();
  if (monitors.length) {
    p(M.emUmaLinha);
    p();
    for (const m of monitors) {
      const f = achadoPorId.get(m.threatId);
      p(M.umaLinha(m.id, m.threatId, f ? componente(f, ctx) : L, cel(m.observable), ctx.contractId));
    }
    p();
    // Sem isto o documento apresentaria a ligação evento↔entrypoint — que é por nome, nível C —
    // com a mesma força de um fato de bytecode. É a regra que docs/PROBLEMA.md não deixa quebrar.
    const atribuicoes = monitors.map((m) => [m.id, monitorAttribution(m, ctx)] as const).filter(([, a]) => !!a);
    if (atribuicoes.length) {
      p(M.comoAtribuido);
      p();
      for (const [id, a] of atribuicoes) p(`- **${id}** — ${cel(a!)}`);
      if (atribuicoes.length < monitors.length) p(M.demaisMonitores(L));
      p();
    }
  }

  /* ---------- 4b — o filtro literal ---------- */
  const executaveis = monitors.map((m) => toExecutable(m, ctx)).filter((x) => x !== undefined);
  p(M.filtrosExecutaveis);
  p();
  if (!executaveis.length) {
    // O motivo só pode ser afirmado para monitores que ESTE contexto rederiva. Um `ctx.monitors`
    // vindo de outra análise sairia daqui como "não é executável" sem que isso tenha sido medido.
    const derivados = new Set(deriveMonitors(ctx).map((m) => m.id));
    const estranhos = monitors.filter((m) => !derivados.has(m.id)).length;
    p(M.semExecutaveis(monitors.length, estranhos, L));
    p();
  } else {
    p(M.comExecutaveis(executaveis.length, monitors.length));
    p();
    // De onde saiu o número de `*` de cada filtro: do spec, por evento. Um por nome de evento,
    // sem repetir quando dois monitores compartilham o mesmo evento.
    const aridades = [
      ...new Map(
        monitors.filter((m) => toExecutable(m, ctx)).flatMap((m) => monitorFilterArity(m, ctx)).map((a) => [a.nome, a]),
      ).values(),
    ];
    if (aridades.length) {
      p(aridades.map((a) => M.aridadeSpec(a.nome, a.wildcards)).join(" "));
      p();
    }
    p("```json");
    p(JSON.stringify(executaveis, null, 2));
    p("```");
    p();
  }

  /* ---------- 5 ---------- */
  p("## What happens when an alert fires?");
  p();
  // Gerado ≠ revisado. Estampar a data da geração nesta coluna afirmaria uma revisão humana
  // que não aconteceu — e é exatamente o campo que o revisor do SCF usa para medir a operação.
  const revisao = M.revisao(ctx.generatedAt.slice(0, 10));
  p(linha("Monitor ID", M.colSeverity, M.colResposta, M.colOwner, M.colStatus, M.colRevisao));
  p("|---|---|---|---|---|---|");
  for (const m of monitors) {
    p(linha(m.id, m.severity, M.canalEAcao(m.response, L), L, m.status, revisao));
  }
  if (!monitors.length) p(linha("—", "—", "—", "—", "—", revisao));
  p();
  p(M.statusValues);
  p();
  p(M.explicacaoStatus);
  p();
  p(M.donoECanal(monitors.length));
  p();

  if (semObs.length) {
    p(M.tituloForaDaChain);
    p();
    p(linha(M.colThreatId, M.colPorQue, M.colControle));
    p("|---|---|---|");
    for (const f of semObs) {
      const motivo = f.class === "silent-mutation" ? M.motivoSilenciosa : M.motivoGenerico;
      const controle = f.class === "silent-mutation" ? M.controleSilenciosa : L;
      p(linha(f.id!, motivo, controle));
    }
    p();
  }

  /* ---------- 6 ---------- *
   * O corpo pronto vira a entrada do validador: a §6 é a saída dele, e não pode ser
   * calculada aqui sob pena de divergir do veredito que o CLI imprime (ver nota do topo).
   * O validador corta o documento neste mesmo título, então acrescentar a tabela depois
   * não muda nenhum item — é o que garante que os dois relatórios sejam iguais.
   */
  const rel = validateMonitoringPlan(ctx, o.join("\n"), monitors);
  p("## Did we do a good job?");
  p();
  p(linha(M.colPergunta, M.colSituacao, M.colDetalhe));
  p("|---|---|---|");
  for (const it of rel.items) p(linha(it.question, it.status === "ok" ? M.ok : it.status === "gap" ? M.gap : "n/a", it.detail));
  p();
  const input = rel.needsInput ?? [];
  if (rel.verdict === "submittable" || (rel.verdict === undefined && rel.submittable)) {
    p(M.submetivel);
  } else if (rel.blockers.length) {
    p(M.naoSubmeter);
    p();
    for (const b of rel.blockers) p(`- ${b}`);
  }
  if (input.length) {
    p();
    p(M.tituloInput);
    p();
    input.forEach((b, i) => p(`${i + 1}. ${b}`));
  }
  p();
  p(M.documentoVivo);
  p();

  return o.join("\n");
}
