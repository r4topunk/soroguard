/**
 * Validadores dos dois checklists oficiais "Did we do a good job?" do tranche #2.
 *
 * O módulo existe para APONTAR LACUNA, não para carimbar completude: nenhum item devolve `ok`
 * por ausência de evidência contrária — cada `ok` exige um fato positivo.
 *
 * DESENHO: CADA DECISÃO SAI DO DADO, NÃO DA PROSA.
 *   ctx / monitores → toda pergunta de conteúdo. Os renderizadores escrevem o que o `ctx`
 *                     sustenta, então o que eles escreveram é derivável de onde eles leram.
 *   markdown        → só a conferência ESTRUTURAL: títulos oficiais presentes; todo id de
 *                     achado, de remediação (`X.n.R.m`) e de monitor que o relatório espera
 *                     aparece ao menos uma vez; documento não vazio e com a cerca do DFD.
 *
 * A versão anterior lia o documento com ~15 regex bilíngues e crescia uma regex por frase nova
 * do renderizador: a regex respondia sobre o TEXTO e não sobre o documento (um `[A]` de tabela
 * agregada virava "nível inflado" num documento correto), e reescrever prosa virava lacuna
 * fantasma no checklist. O que ela inferia da prosa é o que o renderizador derivou do `ctx`:
 * "remediação genérica?" é "existe template escrito para esta classe?"; "nível inflado?" é
 * "esta ameaça tem evidência A/B ou só C?"; "baseline inventado?" é "tier B sem observação".
 * Três perguntas não saem de dado nenhum e ficam com checagem textual mínima, marcada no ponto
 * de uso: a §1 do template (só a equipe a escreve), a cerca do mermaid e os títulos oficiais.
 *
 * Duas decisões que continuam valendo: (1) `render/monitoring.ts` renderiza a §6 a partir do
 * relatório que esta função devolve — quem passa o markdown é o chamador, não há ciclo de
 * import; (2) o markdown é cortado no título "Did we do a good job?" antes da leitura, que é o
 * que faz o relatório da §6 e o do CLI serem o mesmo objeto.
 *
 * A saída é só em inglês: os templates da Stellar e os revisores do SCF são em inglês.
 */

import type { ArtifactContext, ChecklistItem, DfdNode, Monitor, ValidationReport } from "./artifact.ts";
import type { Finding, Stride } from "./detect.ts";
import { callsOut, emitsEvent } from "./analyze.ts";
import {
  deriveMonitors, janelaSemTrafego, lacuna, motivoSemObservacao, threatsSemObservavel, toExecutable,
} from "./monitors.ts";
import { plural } from "./text.ts";

const LETRAS: readonly Stride[] = ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"];

/* ===== o que os renderizadores derivam da classe do achado ===== */
/**
 * Classes para as quais `render/threatmodel.ts` tem remediação ESCRITA (o `switch` de
 * `remediacoes()`). Fora desta lista ele emite a lacuna declarada — texto certo segundo o
 * PROBLEMA.md (campo honestamente vazio > enchimento), e por isso não é blocker; é dito no
 * detalhe, para o revisor saber que aquela ameaça espera remediação humana.
 *
 * Substitui o antigo `citaIdentificador()`: perguntar ao TEXTO se a remediação citava um
 * identificador aprovava "aplicar `controles de acesso` adequados" (medido) e reprovava prosa
 * boa por acaso de crase. A pergunta real é qual template o renderizador escolheu.
 */
const CLASSES_COM_REMEDIACAO: ReadonlySet<string> = new Set([
  "unauthenticated-state-mutation", "initialization-front-running", "unguarded-upgrade", "write-before-auth",
  "silent-mutation", "archival-risk", "host-prng-in-value-path", "vulnerable-sdk",
]);

/** Classes cujo achado é questão de DESENHO do sistema, não relistagem de superfície. */
const CLASSES_ESTRUTURAIS: ReadonlySet<string> = new Set([
  "silent-mutation", "archival-risk", "write-before-auth", "unguarded-upgrade", "vulnerable-sdk",
  "initialization-front-running",
]);

/**
 * Ameaça sem monitor cujo CONTROLE SUBSTITUTO o `render/monitoring.ts` nomeia na §5: só
 * `silent-mutation` tem controle escrito; nas demais a célula sai `⟨a preencher⟩`. "Não dá
 * para monitorar on-chain" só cobre a ameaça quando o substituto está nomeado.
 */
const CLASSES_COM_CONTROLE_OFFCHAIN: ReadonlySet<string> = new Set(["silent-mutation"]);

/* ===== marcas que leem DADO (nunca o documento) ===== */
/** Evidência que o detector marcou para revisão. Roda sobre `evidence.claim`, texto gerado. */
const EVIDENCIA_REVISAR = /REVIEW|super-approx|helper/i;
/** Preenchimento em aberto num CAMPO de monitor (`observable`, `trigger`, `baseline`). */
const PLACEHOLDER = /⟨|⟩|to\s+be\s+(defined|filled|recorded)|not\s+derivable|to\s+fill/i;
/** Baseline que declara a própria lacuna em vez de apresentar número. Campo do monitor. */
const BASELINE_LACUNA = /insufficient|not\s+derivable|no\s+baseline|not\s+observ|⟨/i;
/** Resposta que não é resposta: um verbo solto no lugar de um procedimento. */
const RESPOSTA_OCA =
  /^\s*(tbd|to\s+be\s+defined|investigate|monitor|review|verify|alert|follow\s*up|check|n\/?a|—|-)\s*\.?\s*$/i;
/** Mecanismo de leitura que não é `getEvents`, declarado no observável/gatilho do monitor. */
const MECANISMO_ALTERNATIVO =
  /diff|snapshot|getLedgerEntries|ledger\s*entr|wasm\s*hash|transaction\s+inspection|InvokeHostFunction|SorobanAuthorizationEntry|authorization\s+tree|state|simulation\s+output|invariant/i;
/** Texto que só um monitor de evento produz — fallback para monitor que este ctx não rederiva. */
const MARCA_EVENTO = /getEvents|event\s+with\s+topics|topic\s+filter/i;
/** Gatilho que fixa um limiar numérico de taxa (em vez de "qualquer ocorrência"). */
const MARCA_LIMIAR_TAXA = /more\s+than\s+\d/i;
/** Pendência no DETALHE de um item — varredura sobre a saída deste módulo, não sobre o documento. */
const PENDENCIA_NA_LINHA = /\bhas\s+to\b|\bmust\b|\bneeds?\s+to\b|to\s+be\s+(filled|defined|written|recorded)|⟨|⟩/i;

/* ===== conferência estrutural do documento ===== */
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** `Elevation.1` não pode casar dentro de `Elevation.10` nem de `Elevation.1.M.1`. */
const reId = (id: string) => new RegExp(`(?<![\\w.])${esc(id)}(?![\\w.])`);
/** ID de remediação no padrão do template: `Elevation.1.R.1`. */
const reRem = (id: string) => new RegExp(`(?<![\\w.])${esc(id)}\\.R\\.\\d+(?![\\w.])`);
/** Título oficial presente? É o que "estrutural" quer dizer. */
const temTitulo = (md: string, t: string) => new RegExp(`^[ \\t]{0,3}#{1,6}[ \\t]*${esc(t)}`, "m").test(md);

/** Tudo a partir deste título é saída DESTE módulo e não conta como documento. */
const TITULO_CHECKLIST = /^[ \t]{0,3}#{1,6}[ \t]*Did we do a good job\?/m;
function semChecklist(md: string): string {
  const m = TITULO_CHECKLIST.exec(md);
  return m ? md.slice(0, m.index) : md;
}

/**
 * Títulos exigidos. A §4/§6 ("Did we do a good job?") fica FORA de propósito: o renderizador
 * valida o corpo antes de escrevê-la e o CLI valida o documento inteiro — exigi-la faria os
 * dois relatórios divergirem sobre o mesmo contrato.
 */
const TITULOS_TM = ["What are we working on?", "What can go wrong?", "What are we going to do about it?"] as const;
const TITULOS_MP = [
  "What are we monitoring?", "What could go wrong?", "What does exploitation look like on-chain?",
  "What will we monitor for?", "What happens when an alert fires?",
] as const;

/* ===== mensagens ===== */
/** O motivo da ausência de janela depende do `ctx`; entra por substituição no blocker. */
const motivoPlaceholder = "%MOTIVO%";
const comMotivo = (s: string, motivo: string) => s.replace(motivoPlaceholder, motivo);

const M = {
  docVazio: "Empty document: there is no rendered markdown to validate.",
  tituloAusenteBlocker: (t: string) => `Section "${t}" missing from the document: the official template requires it, and the checklist answers refer to it.`,
  /** §1: única pergunta sem resposta no binário — por isso `needsInput`, nunca blocker. */
  inputSecao1:
    'Write section 1, "What are we working on?": what the protocol does, who the actors are, what value ' +
    "it holds in custody and which trust assumptions live off-chain. Worksheet: the *Analyzed object* " +
    "table and the measured surface right below the gap notice in section 1 — the bytecode records none " +
    "of that, so no analysis closes this one.",
  /* --- threat model --- */
  tmSemAmeaca:
    "No threat derived from the bytecode: the document does not contain a single threat, and all six STRIDE letters would come out as gaps. This is not a submittable threat model — it is the report that the automated analysis did not cover this contract and that it needs manual modelling.",
  qDfd: "Was the data-flow diagram derived from the analysis (processes = entrypoints, data stores = storage keys, boundaries = auth and cross-call)?",
  dfdAusenteBlocker: "No data-flow diagram in the context: the template requires the DFD as section 2.",
  dfdAusenteDetalhe: "ctx.dfd missing. With no DFD the checklist questions that depend on it cannot be answered.",
  dfdSemProcesso: "no process (entrypoint) in the diagram",
  dfdSemStore: "no data store: the storage keys never reached the diagram",
  dfdSemFronteira: "no trust boundary declared",
  dfdSemNo: (eps: string) => `entrypoints with a finding and no node in the DFD: ${eps}`,
  dfdSemTravessia: (n: number) => `${n} entrypoints reach call/try_call but no edge is marked as crossing a boundary`,
  dfdDetalheGap: (p: number, s: number, b: number, faltas: string) => `${p} processes, ${s} stores, ${b} boundaries. Problems: ${faltas}.`,
  dfdDetalheOk: (p: number, s: number, b: number, cruzam: number) => `${p} processes tied to real entrypoints, ${s} data stores, ${b} boundaries, ${cruzam} edges crossing a boundary.`,
  qDfdRef: "Was the data-flow diagram referenced after it was created?",
  dfdSemBloco: "The DFD was derived but the ```mermaid block does not appear in the document.",
  dfdSemBlocoDetalhe: "The diagram is not in the document, so there is nothing to reference.",
  dfdRefOk: (n: number, citados: string) => `${n} nameable DFD elements (nodes and boundaries) the threat sections resolve against: ${citados}. What was checked is that the diagram carries the anchors the reasoning uses; whether a human reasoned with it, only the review says.`,
  dfdRefGap:
    "The diagram has no node id and no boundary name to cite: a DFD with nothing nameable cannot be referenced, and repeating the entrypoint name in the threat table is not referencing it.",
  qDesign: "Did STRIDE reveal a new design issue?",
  designOk: (n: number, achados: string) => `${n} structural findings (not merely "this function is missing require_auth"): ${achados}. The tool cannot know what was NEW to the team — it shows what the exercise derived.`,
  designSoEntrypoint: (n: number) => `All ${n} findings are per-entrypoint; none touches system design (order of operations, storage lifecycle, audit trail, upgrade). If the human review raised a design issue, it has to be recorded here by hand.`,
  designSemAchado:
    "No finding derived from the bytecode. A threat model with no issue raised is not a finished threat model: either the analysis did not run, or the contract needs a manual review on record.",
  qRemediacao: "Do the remediations address the issues raised?",
  remSemBloco: (id: string) => `Threat ${id} exists in the analysis but does not appear in the document.`,
  remSemRemediacao: (id: string) => `Threat ${id} has no remediation in the document.`,
  remSemAmeaca:
    "No threat was derived from the bytecode, so there is no remediation to assess. That does not mean the contract is safe: the classes this tool covers did not fire, and the letters declared as gaps still require manual analysis.",
  remAusentes: (ids: string) => `missing from the document: ${ids}`,
  remSem: (ids: string) => `without remediation: ${ids}`,
  remLacunaDeClasse: (ids: string, classes: string) => `declared gap instead of a derived remediation, because no remediation is written for their class (${classes}): ${ids} — honest output, and still a remediation a human writes`,
  remOk: (n: number) => `${n} threats, each with the remediation its class derives — anchored to this contract (export, storage key or host function) and present in the document by id. What was checked is the anchoring, not whether the fix is the RIGHT one.`,
  qLetras: "Does every STRIDE letter have an entry — a finding with evidence, or an explicitly declared gap?",
  letraSemAchadoNoDoc: (l: string, ids: string) => `${l}: has a finding in the analysis (${ids}) and none appears in the document`,
  letraSemAchadoBlocker: (l: string, ids: string) => `Letter ${l}: none of the findings ${ids} appears in the document.`,
  letraComAchado: (l: string) => `${l} (finding)`,
  letraComLacuna: (l: string) => `${l} (declared gap)`,
  letraSemIssue: (l: string) => `${l}: declared gap, no issue (the template requires at least one)`,
  letraSemIssueBlocker: (l: string) => `STRIDE letter ${l} has no issue — the template requires at least one; fill it from the worksheet in the ${l} gap section (it lists the concrete surface to review).`,
  letrasPreenchidas: (n: number) => `${n} of 6 letters filled.`,
  letrasResumo: (com: string, sem: string) => `derived from the bytecode: ${com || "none"}; with no derivable finding: ${sem || "none"}.`,
  letrasProblemas: (p: string) => `Problems: ${p}.`,
  letrasTodas: (ok: string) => `All six covered: ${ok}.`,
  letrasDivergentes: (d: string) => `⚠ ctx.gaps lists ${d} as a gap, but there are findings for those letters — inconsistent context.`,
  qNivel: "Does every claim carry its evidence tier (A/B/C) and a citable anchor?",
  semEvidenciaBlocker: (id: string) => `Threat ${id} has no evidence at all.`,
  soInferenciaBlocker: (id: string) => `Threat ${id} is supported only by inference (tier C), with no bytecode fact and no on-chain observation. Presenting it as a derived threat gives an inference the force of a bytecode fact, which is the one rule this project does not break (PROBLEMA.md, "never present C as A").`,
  nivelContagem: (a: number, b: number, c: number) => `${a} tier A claims, ${b} tier B, ${c} tier C in the context.`,
  nivelPorAmeaca: (ok: number, presentes: number, faltando: number, total: number) => `Checked per threat: ${ok}/${presentes} present in the document with at least one tier A or B claim behind the inference${faltando ? ` (${faltando} of ${total} do not appear in the document)` : ""}.`,
  nivelSemAmeaca: "No threat in the context: there is no claim whose tier to check, and a document with no threat is not a threat model.",
  nivelSemEvidencia: (ids: string) => `without evidence: ${ids}.`,
  nivelSoC: (ids: string) => `tier C only: ${ids}.`,
  qLimites: "Are the analysis limits declared in the document (incomplete call graph, over-approximate positive)?",
  limitesNA: (s: string) => `Call graph complete (soundness=${s}) and no finding depends on a path through a helper: there is no imprecision to declare.`,
  limitesOk: (s: string, n: number, ids: string, motivo?: string) => `Declared. soundness=${s}${motivo ? `, reason: ${motivo}` : ""}${n ? `, ${n} findings flagged for review because of a path through a helper: ${ids}` : ""}. The declaration rides on the same fields this item reads, so document and analysis cannot disagree about it.`,
  qPosterior: "Did additional issues surface after the exercise?",
  posteriorOk: (lacunas: string, confirmar: number) => `What the exercise left open is on record: ${lacunas || "no STRIDE gap"}${confirmar ? `, and ${confirmar} ${plural(confirmar, "finding", "findings")} flagged for confirmation in the source` : ""}. Only the human review answers this one; the record above is where it starts.`,
  posteriorAusente:
    "Nothing on record about what the exercise left open: no declared STRIDE gap and no finding flagged for confirmation. This describes the outcome of a human review that has not happened yet, and the team has to fill it in before submitting.",
  qInventario: "Does the inventory identify the analyzed artifact (contract id, network, WASM hash)?",
  invSemIdBlocker: (id: string) => `Contract id ${id || "(empty)"} missing from the document: the inventory does not identify what was analyzed.`,
  invIdOk: (id: string) => `contract id present (${id})`,
  invIdFalta: (id: string) => `contract id MISSING (${id || "empty in the context"})`,
  invRedeOk: (n: string) => `network present (${n})`,
  invRedeFalta: "network missing from the context",
  invHashOk: "WASM hash present",
  invHashNA: "WASM hash not available in the context — without it the report is not reproducible against the exact binary",
  /* --- monitoring plan --- */
  mpSemMonitor: "No monitor in the plan. A monitoring plan with no monitor is not submittable.",
  semMonitorDetalhe:
    "No monitor was derived for this contract, so there is nothing to assess here. This is a gap, not an approval: the plan has no active coverage and monitoring has to be defined by hand before submitting.",
  qCobertura: "Does every threat in the threat model have a monitor, or a documented reason it cannot be monitored?",
  cobJustificadaSemDono: (id: string, sev: string) => `Threat ${id} (${sev}) has no monitor, and the document justifies the lack of an on-chain observable with a named off-chain control. What is missing is that control's owner: a ${sev} threat with no active coverage and no owner is not submittable.`,
  cobControleAberto: (id: string, sev: string) => `Threat ${id} (${sev}) has no monitor. The document says there is no on-chain observable, but leaves the substitute control as a gap — saying it cannot be monitored is not covering the threat.`,
  cobSemJustificativa: (id: string, sev: string) => `Threat ${id} (${sev}) with no monitor and no non-monitorability justification in the document.`,
  cobSemAmeacas: "There are no threats in the context to cover — the plan has no traceable origin.",
  cobComMonitor: (n: number, total: number) => `${n}/${total} threats with a monitor`,
  cobJustificadas: (n: number, ids: string) => `${n} declared non-monitorable with a named off-chain control: ${ids}`,
  cobDescobertas: (ids: string) => `no monitor and no named substitute control: ${ids}`,
  cobSemEvento: (n: number, total: number) => `${n} of ${total} invocable ${plural(total, "entrypoint", "entrypoints")} ${plural(n, "does", "do")} not reach contract_event (\`__*\` reserved exports excluded, CAP-0058) — for ${plural(n, "it", "those")}, monitoring through getEvents is impossible`,
  qRastreio: "Does every monitor trace back to an existing threat, with an ID derived from it?",
  orfaoBlocker: (id: string, threat: string) => `Monitor ${id} points at threat ${threat}, which does not exist in the threat model.`,
  monitorAusenteBlocker: (id: string) => `Monitor ${id} is in the plan's data and does not appear in the document: a monitor nobody can read is not monitoring.`,
  rastreioSemMonitor:
    "No monitor was derived, so there is no traceability to check. This is a gap, not an approval: either the contract has no threat with an on-chain observable, or the observables were not derived.",
  rastreioOrfaos: (ids: string) => `orphans (nonexistent threat): ${ids}`,
  rastreioOk: (n: number) => n === 1 ? "the single monitor is anchored to a threat in the document" : `${n} monitors, all anchored to a threat in the document`,
  rastreioForaDoPadrao: (ids: string) => `ID outside the <ThreatID>.M.<n> pattern: ${ids}`,
  qBaseline: "Is the baseline grounded in observation, not guesswork?",
  baseSemBaselineBlocker: (id: string) => `Monitor ${id} has no baseline (baselineTier="none"): there is no defensible threshold, and the template requires a baseline in section 4. No observation window: ${motivoPlaceholder}. Collect a \`getEvents\` window before fixing any threshold — the tool refuses to invent the number.`,
  /** (b) a janela EXISTE e foi coletada; o que falta é ela ser longa o bastante. */
  baseJanelaInsuficienteBlocker: (id: string, ledgers: number) => `Monitor ${id} has no baseline: a window of ${ledgers} ${plural(ledgers, "ledger", "ledgers")} was observed, but it is declared insufficient for an honest baseline. The window was collected — widen it; do not read this as "no observation was made".`,
  /** (b) zero observado é medição — só não sustenta limiar de taxa. */
  baseZeroComLimiarBlocker: (id: string, ledgers: number, topics: string) => `Monitor ${id}: window of ${ledgers} ${plural(ledgers, "ledger", "ledgers")} observed; 0 occurrences of ${topics} — an observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold. Either switch the trigger to any-occurrence or collect a window in which the topic actually fires.`,
  /** (c) monitor que não passa por getEvents: o campo é preenchimento, não lacuna de observação. */
  baseFillInBlocker: (id: string) => `Monitor ${id} has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no \`getEvents\` window would produce it.`,
  baseInventadoBlocker: (id: string) => `Monitor ${id} declares a tier B baseline with no on-chain observation in the context — a baseline asserted as observed without data is exactly the slop this document must not have.`,
  baseJanelaCurtaBlocker: (id: string, ledgers: number) => `Monitor ${id} presents a numeric baseline over a window declared insufficient (${ledgers} ledgers). The field should say "insufficient window", not a plausible number.`,
  baseDivergeBlocker: (d: string) => `Tier B baseline that does not match the observation: ${d}. A number presented as measured without coming from the measurement is an inference wearing the badge of a fact.`,
  baseTopicoFantasmaBlocker: (t: string) => `Tier B baseline over a topic the observed window does not contain: ${t}. A baseline is only tier B for what was actually observed.`,
  baseSemTrafegoBlocker: (ledgers: number) => `The observed window of ${ledgers} ledgers recorded no event of any topic for this contract: that is absence of traffic, not a traffic profile. The counts are real and still cannot support a threshold — widen the window, or state that the thresholds are provisional, before submitting.`,
  baseSemTrafegoDetalhe: (ledgers: number) => `⚠ gap: the window of ${ledgers} ledgers was collected and holds no event of any topic — absence of traffic, not a traffic profile.`,
  baseJanela: (ledgers: number, horas: number, topics: number, insuficiente: boolean) => `observed window: ${ledgers} ledgers (~${horas}h), ${topics} distinct ${plural(topics, "topic", "topics")}${insuficiente ? ", DECLARED INSUFFICIENT" : ""}`,
  baseSemJanela: (motivo: string) => `no on-chain observation in the context (${motivo})`,
  baseSemBaseline: (ids: string) => `without a baseline: ${ids}`,
  baseInventado: (ids: string) => `tier B baseline with no data: ${ids}`,
  baseJanelaCurta: (ids: string) => `plausible number over an insufficient window: ${ids}`,
  baseDiverge: (d: string) => `count that does not match the window: ${d}`,
  baseTopicoFantasma: (t: string) => `unobserved topic presented as a baseline: ${t}`,
  baseZeroComLimiar: (d: string) => `observed zero carrying a rate threshold, which it cannot support: ${d}`,
  baseInferido: (ids: string) => `inferred baseline (tier C, not observed): ${ids}`,
  baseConferidos: (n: number) => `${n} ${plural(n, "baseline", "baselines")} with the count checked against the window`,
  /** Zero de tópico one-shot é medição — e não é conferência: nada precisava cair na janela. */
  baseZeroObservado: (n: number, ids: string) => `${n} ${plural(n, "baseline is", "baselines are")} an observed zero (measurement) and ${plural(n, "does", "do")} not count as checked against the window — for an any-occurrence trigger the only legitimate occurrence may predate the window: ${ids}`,
  qResposta: "Does every monitor have a defined response?",
  respSemBlocker: (id: string) => `Monitor ${id} has no defined response: an alert with no procedure is not monitoring, it is noise.`,
  respSem: (ids: string) => `without a response: ${ids}`,
  respComResposta: (n: number) => `${n} ${plural(n, "monitor", "monitors")} with a response`,
  respOca: (exemplo: string, ids: string) => `generic response, no procedure ("${exemplo}"): ${ids}`,
  qDono: "Does every monitor have a named owner?",
  donoBlocker: (n: number) => `Assign an owner and a notification channel to ${n} ${plural(n, "row", "rows")} of §5; neither is derivable from the binary, and a monitor with no owner has no one to fire at.`,
  donoGap: (n: number) => `0/${n} monitors with a named owner: the Monitor type has no owner field and the §5 column is a fill-in on every row. The information is neither in the bytecode nor on-chain, and the team provides it before submitting.`,
  qPrecisao: "Have the alerts been historically accurate?",
  /** §5 afirma que nenhum monitor sai daqui `Active`; chamar `Tuning` de ativo contradiz a §5. */
  precSemAtivos: (conferidos: number, total: number) =>
    `No monitor is Active yet (${total ? `${total} in the plan, all \`Tuning\` or \`Planned\`` : "there is no monitor in the plan"}); ` +
    `${conferidos} ${plural(conferidos, "carries", "carry")} an observed baseline that was checked against the window, but none has alert history. ` +
    "Accuracy is only answerable after the monitors run: there is no alert yet to be right or wrong about.",
  precSemJanela:
    "There is no observed window in the context, so no monitor was checked against real data: how many times each trigger would have fired is unknown. On a first issue this is expected — the field has to say so and be reassessed after operating.",
  precOk: (ativos: number, ledgers: number) => `${ativos === 1 ? "The single active monitor has" : `The ${ativos} active monitors have`} the baseline count checked against the ${ledgers}-ledger window. That is a backtest over the window, not an operating history.`,
  precParcial: (com: number, ativos: number, ledgers: number, insuficiente: boolean, naoVistos: number, ids: string) => `${com}/${ativos} active monitors with the count checked against the observed window (${ledgers} ledgers)${insuficiente ? ", which is declared insufficient" : ""}. Without checking, there is no way to state a false-positive rate${naoVistos ? `; ${naoVistos} topics declared in the spec were never observed: ${ids}` : ""}.`,
  qEnderecos: "Is the on-chain address inventory present and up to date?",
  endSemIdBlocker: (id: string) => `Contract id ${id || "(empty)"} missing from the document: with no address in the inventory no monitor is executable.`,
  endSemHashBlocker: "Record the instance's wasm hash: without it the plan cannot be re-checked against what is deployed.",
  endOk: (id: string, rede: string) => `contract id ${id} present in the document (network ${rede}).`,
  endGap: (id: string) => `contract id ${id || "empty in the context"} does not appear in the document. It is the only address the tool knows for certain, and it is the filter of any getEvents call.`,
  endHashOk: (hash: string, data: string) => ` Analysis run over wasm hash \`${hash}\` on ${data}; a different hash on the instance means this plan describes code that is no longer live.`,
  endHashFalta: (l: string) => ` The WASM hash was not captured at generation time — without it there is no way to state that the plan still describes the code that is live. ${l}`,
  qFronteiras: "Are the external boundaries (contracts called) in the inventory?",
  frontNA: "No entrypoint reaches call/try_call: the contract crosses no boundary, there is no external address to inventory.",
  frontGap: (n: number, eps: string) => `${n} entrypoints reach call/try_call (${eps}). The destination addresses are runtime arguments: not derivable from the bytecode, and the tool does not invent them. The inventory has to be completed by hand, or the monitoring covers only half the flow.`,
  qOffchain: "Have off-chain threats been identified and declared out of on-chain scope?",
  offOk: (ancoradas: string) => `The document ties the off-chain boundary to what was left out of the on-chain analysis: ${ancoradas}.`,
  offSemAncora: "there is no letter without a finding and no threat without a monitor in this contract",
  offAusente: (ancoras: string) => `The analysis left ${ancoras} outside on-chain coverage and the context declares no STRIDE gap and no off-chain control for them: nothing ties that boundary to anything. A plan that does not declare it gives the impression of covering what it does not.`,
  qSinal: "Does every monitor have a concrete observable signal and an executable trigger?",
  sinalBlocker: (id: string, oque: string) => `Monitor ${id} without ${oque}: it can be neither executed nor checked.`,
  sinalObservavel: "an observable signal",
  sinalGatilho: "a trigger",
  sinalSemObservavel: (ids: string) => `without an observable: ${ids}`,
  sinalSemGatilho: (ids: string) => `without a trigger: ${ids}`,
  sinalMudo: (n: number, ids: string) => `${n} ${plural(n, "monitor has", "monitors have")} no executable getEvents filter and ${plural(n, "declares", "declare")} no alternative mechanism (getLedgerEntries, state diff, wasm hash, transaction inspection) — there is no endpoint on which ${plural(n, "it could", "they could")} fire: ${ids}`,
  sinalSemTopic: (n: number, total: number, topics: string, ids: string) => `${n} event-based ${plural(n, "monitor cites", "monitors cite")} none of the ${total} ${plural(total, "topic", "topics")} declared in the spec (${topics}) — with no topic the getEvents filter sweeps everything: ${ids}`,
  /** Linha que não sai ✔ enquanto a chave de ledger não se montar: o mesmo preenchimento é blocker. */
  sinalIncompleto: (n: number, ids: string) => `${n} ${plural(n, "monitor is", "monitors are")} neither executable through getEvents nor fully specified — the query cannot be built while the fill-in on the row is open (durability of the entry, address or hash): ${ids}`,
  sinalComTopic: "every event-based monitor cites a topic declared in the spec",
  sinalSemEventBased:
    "no monitor is event-based, so the topic check does not apply: the observables derived here are ledger entries and the transaction, read through getLedgerEntries and by inspecting it",
  sinalSemSpec: "the spec declares no events, so the filter can only be by contractId and the plan depends on a state diff",
  sinalExecutaveis: (n: number, total: number) => `${n} of ${total} ${plural(total, "monitor", "monitors")} ${plural(n, "turns", "turn")} into an RPC call with no manual translation (topic filter from the contract spec)` + (n < total ? "; the rest need getLedgerEntries or transaction introspection" : ""),
};

/* ===== utilidades ===== */
const lista = (xs: readonly string[], n = 6) =>
  xs.length <= n ? xs.join(", ") : `${xs.slice(0, n).join(", ")} … (+${xs.length - n})`;

const idDe = (f: Finding) => f.id ?? `${f.stride}.?`;
const grave = (f: Finding) => f.severity === "Critical" || f.severity === "High";

/** Tópicos citados num baseline: símbolos dentro de `[...]`. Roda sobre `monitor.baseline`. */
function topicosCitados(txt: string): string[] {
  const out: string[] = [];
  for (const m of txt.matchAll(/\[([^\]\n]+)\]/g)) {
    for (const bruto of m[1].split(",")) {
      const t = bruto.trim().replace(/^`|`$/g, "");
      if (t.length >= 2 && !/\s/.test(t)) out.push(t);
    }
  }
  return [...new Set(out)];
}

/** Número inteiro que precede imediatamente um termo (`7 emissions`, `17280 ledgers`). */
function numeroAntesDe(txt: string, termo: RegExp): number | undefined {
  const re = new RegExp(`(\\d[\\d.,]*)\\s*(?:${termo.source})`, termo.flags.replace("g", ""));
  const m = re.exec(txt);
  if (!m) return undefined;
  const n = Number(m[1].replace(/[.,]/g, ""));
  return Number.isFinite(n) ? n : undefined;
}

/**
 * O veredito de três estados. `submittable: false` num documento cujo único pendente é "a
 * equipe precisa nomear o dono do alerta" diz ao time que a ferramenta falhou; `true` só
 * chegaria apagando o pendente. O terceiro estado separa o que a FERRAMENTA deveria ter
 * cumprido (`blockers`) do que só um humano fecha (`needsInput`) — e um blocker da ferramenta
 * nunca é encoberto por um preenchimento.
 */
function veredito(blockers: readonly string[], needsInput: readonly string[]): NonNullable<ValidationReport["verdict"]> {
  if (blockers.length) return "not-submittable";
  return needsInput.length ? "needs-input" : "submittable";
}

function relatorio(
  document: ValidationReport["document"],
  items: ChecklistItem[],
  blockers: string[],
  needsInput: string[],
): ValidationReport {
  const v = veredito(blockers, needsInput);
  return { document, items, submittable: v === "submittable", blockers, verdict: v, needsInput };
}

/* ================= threat model ================= */

export function validateThreatModel(ctx: ArtifactContext, markdown: string): ValidationReport {
  const md = markdown ?? "";
  const items: ChecklistItem[] = [];
  const blockers: string[] = [];
  /** Pendências que nenhuma análise fecha — ver `veredito`. */
  const needsInput: string[] = [];
  const add = (question: string, status: ChecklistItem["status"], detail: string) =>
    items.push({ question, status, detail });

  /* ---------- conferência estrutural ---------- */
  if (!md.trim()) blockers.push(M.docVazio);
  else for (const t of TITULOS_TM) if (!temTitulo(md, t)) blockers.push(M.tituloAusenteBlocker(t));

  /**
   * Checagem TEXTUAL mínima, e deliberada: a §1 é escrita pela equipe DENTRO do arquivo, e o
   * aviso de lacuna do renderizador é o único sinal de que ela ainda não foi escrita. Não há
   * campo em `ctx` que a responda — propósito, atores e custódia não estão no binário.
   */
  if (md.trim() && /Gap to be filled by the team/i.test(md)) needsInput.push(M.inputSecao1);

  /** Ids que o relatório espera ver no documento: presença é conferência estrutural. */
  const noDocumento = (id: string) => reId(id).test(md);

  /*
   * Zero ameaças não é "contrato limpo": é a análise não tendo produzido documento. As seis
   * letras cairiam como lacuna declarada e o checklist passaria verde num arquivo sem um único
   * threat — o resultado mais enganoso que este módulo pode dar. Medido: 9 dos 75 do corpus.
   */
  if (!ctx.findings.length) blockers.push(M.tmSemAmeaca);

  /* 1 — o DFD saiu da análise ou é desenho decorativo? */
  const dfd = ctx.dfd;
  if (!dfd) {
    blockers.push(M.dfdAusenteBlocker);
    add(M.qDfd, "gap", M.dfdAusenteDetalhe);
  } else {
    type NoProcesso = Extract<DfdNode, { kind: "process" }>;
    const processos = dfd.nodes.filter((n): n is NoProcesso => n.kind === "process");
    const stores = dfd.nodes.filter((n) => n.kind === "store");
    const nomesProc = new Set(processos.map((p) => p.entrypoint));
    const epsDeAchado = [...new Set(ctx.findings.map((f) => f.entrypoint).filter((e) => e !== "<contrato>"))];
    const semNo = epsDeAchado.filter((e) => !nomesProc.has(e));
    const cruzamDfd = ctx.analysis.entrypoints.filter((e) => callsOut(e)).length;
    const arestasQueCruzam = dfd.edges.filter((e) => e.crossesBoundary).length;
    const faltas: string[] = [];
    if (!processos.length) faltas.push(M.dfdSemProcesso);
    if (!stores.length) faltas.push(M.dfdSemStore);
    if (!dfd.boundaries.length) faltas.push(M.dfdSemFronteira);
    if (semNo.length) faltas.push(M.dfdSemNo(lista(semNo)));
    if (cruzamDfd && !arestasQueCruzam) faltas.push(M.dfdSemTravessia(cruzamDfd));
    add(
      M.qDfd,
      faltas.length ? "gap" : "ok",
      faltas.length
        ? M.dfdDetalheGap(processos.length, stores.length, dfd.boundaries.length, faltas.join("; "))
        : M.dfdDetalheOk(processos.length, stores.length, dfd.boundaries.length, arestasQueCruzam),
    );

    /*
     * 2 — o diagrama foi USADO, ou desenhado e esquecido? A cerca ```mermaid é a única parte
     * textual (conferência estrutural: o diagrama chegou ao arquivo); o resto é dado — quais
     * nós e fronteiras existem para serem citados. Ler o texto depois do diagrama media
     * casamento de substring: um nó `s1` casa dentro de qualquer palavra.
     */
    const temCerca = /^\s*(```+|~~~+)\s*mermaid/im.test(md);
    const citaveis = [
      ...dfd.nodes.map((n) => n.id), ...dfd.boundaries.map((b) => b.id), ...dfd.boundaries.map((b) => b.label),
    ].filter((a) => a && a.length >= 2);
    if (!temCerca) {
      blockers.push(M.dfdSemBloco);
      add(M.qDfdRef, "gap", M.dfdSemBlocoDetalhe);
    } else {
      add(M.qDfdRef, citaveis.length ? "ok" : "gap", citaveis.length ? M.dfdRefOk(citaveis.length, lista(citaveis)) : M.dfdRefGap);
    }
  }

  /* 3 — o exercício produziu questão de DESENHO, ou só relistou a superfície? */
  const estruturais = ctx.findings.filter((f) => CLASSES_ESTRUTURAIS.has(f.class) && noDocumento(idDe(f)));
  add(
    M.qDesign,
    estruturais.length ? "ok" : "gap",
    estruturais.length
      ? M.designOk(estruturais.length, lista(estruturais.map((f) => `${idDe(f)} ${f.class}`)))
      : ctx.findings.length ? M.designSoEntrypoint(ctx.findings.length) : M.designSemAchado,
  );

  /*
   * 4 — remediação presente E específica. "Presente" é estrutural: o id `X.n.R.m` do template
   * tem de aparecer. "Específica" é dado: o renderizador escolhe o template pela CLASSE, e só
   * `CLASSES_COM_REMEDIACAO` tem remediação escrita; as demais recebem a lacuna declarada,
   * que é honesta e ainda assim não é remediação.
   */
  const semBloco: string[] = [];
  const semRemediacao: string[] = [];
  const semTemplate: Finding[] = [];
  for (const f of ctx.findings) {
    const id = idDe(f);
    if (!noDocumento(id)) { semBloco.push(id); continue; }
    if (!reRem(id).test(md)) { semRemediacao.push(id); continue; }
    if (!CLASSES_COM_REMEDIACAO.has(f.class)) semTemplate.push(f);
  }
  for (const id of semBloco) blockers.push(M.remSemBloco(id));
  for (const id of semRemediacao) blockers.push(M.remSemRemediacao(id));
  add(
    M.qRemediacao,
    semBloco.length || semRemediacao.length ? "gap" : ctx.findings.length ? "ok" : "gap",
    !ctx.findings.length
      ? M.remSemAmeaca
      : [
          semBloco.length ? M.remAusentes(lista(semBloco)) : "",
          semRemediacao.length ? M.remSem(lista(semRemediacao)) : "",
          semTemplate.length
            ? M.remLacunaDeClasse(lista(semTemplate.map(idDe)), lista([...new Set(semTemplate.map((f) => f.class))], 3))
            : "",
        ].filter(Boolean).join("; ") || M.remOk(ctx.findings.length),
  );

  /*
   * 5 — as seis letras, com achado ou com lacuna declarada. Letra com achado: basta um id dela
   * no documento (estrutural). Letra sem achado: o renderizador escreve a lacuna declarada por
   * construção; o que resta é a pendência do template, que pede ≥1 issue por letra e que
   * ninguém além da equipe fecha.
   */
  const comAchado = new Set(ctx.findings.map((f) => f.stride));
  const semAchado = LETRAS.filter((l) => !comAchado.has(l));
  const divergentes = ctx.gaps.filter((g) => comAchado.has(g));
  const okLetras: string[] = [];
  const problemas: string[] = [];
  let preenchidas = 0;
  for (const l of LETRAS) {
    if (comAchado.has(l)) {
      const seus = ctx.findings.filter((f) => f.stride === l).map(idDe);
      if (seus.some(noDocumento)) { okLetras.push(M.letraComAchado(l)); preenchidas++; }
      else {
        problemas.push(M.letraSemAchadoNoDoc(l, lista(seus)));
        blockers.push(M.letraSemAchadoBlocker(l, lista(seus)));
      }
      continue;
    }
    // Lacuna declarada é o texto CERTO (campo honestamente vazio > enchimento) e continua
    // listada como cobertura declarada. O template exige ≥1 issue por letra, então a letra
    // vazia barra a submissão — como PREENCHIMENTO, não como falha da ferramenta.
    okLetras.push(M.letraComLacuna(l));
    problemas.push(M.letraSemIssue(l));
    needsInput.push(M.letraSemIssueBlocker(l));
  }
  add(
    M.qLetras,
    problemas.length || divergentes.length ? "gap" : "ok",
    [
      M.letrasPreenchidas(preenchidas),
      M.letrasResumo([...comAchado].join(", "), semAchado.join(", ")),
      problemas.length ? M.letrasProblemas(problemas.join("; ")) : M.letrasTodas(okLetras.join(", ")),
      divergentes.length ? M.letrasDivergentes(divergentes.join(", ")) : "",
    ].filter(Boolean).join(" "),
  );

  /*
   * 6 — evidência citável e nível marcado. O renderizador IMPRIME o nível que a evidência
   * carrega (`evidence[].tier`), então "o documento marcou A onde só há C" só acontece se a
   * própria evidência for só C. Contar tokens `[A]` no bloco media outra coisa — uma tabela
   * agregada com `[A]+[C]` por linha somava marcas de irmãos e acusava inflação onde não há
   * (medido: CDZQL342…, Elevation.1, "4 claims marked (A) for 3 evidences").
   */
  const semEvidencia = ctx.findings.filter((f) => !f.evidence.length).map(idDe);
  const semFato = ctx.findings
    .filter((f) => f.evidence.length && !f.evidence.some((e) => (e.tier === "A" || e.tier === "B") && e.claim.trim()))
    .map(idDe);
  for (const id of semEvidencia) blockers.push(M.semEvidenciaBlocker(id));
  for (const id of semFato) blockers.push(M.soInferenciaBlocker(id));
  const evidencias = ctx.findings.flatMap((f) => f.evidence);
  const nA = evidencias.filter((e) => e.tier === "A").length;
  const nB = evidencias.filter((e) => e.tier === "B").length;
  const nC = evidencias.filter((e) => e.tier === "C").length;
  const presentes = ctx.findings.filter((f) => noDocumento(idDe(f))).length;
  add(
    M.qNivel,
    semEvidencia.length || semFato.length || !presentes ? "gap" : "ok",
    [
      M.nivelContagem(nA, nB, nC),
      ctx.findings.length
        ? M.nivelPorAmeaca(presentes - semEvidencia.length - semFato.length, presentes, ctx.findings.length - presentes, ctx.findings.length)
        : M.nivelSemAmeaca,
      semEvidencia.length ? M.nivelSemEvidencia(lista(semEvidencia)) : "",
      semFato.length ? M.nivelSoC(lista(semFato)) : "",
    ].filter(Boolean).join(" "),
  );

  /*
   * 7 — limites da análise ditos em voz alta. A declaração no documento sai dos MESMOS campos
   * que este item lê (`soundness`, `incompleteReason`, evidências marcadas para revisão):
   * procurar o vocabulário no texto media a redação, não o fato.
   */
  const viaHelper = ctx.findings
    .filter((f) => f.evidence.some((e) => e.tier === "C" && EVIDENCIA_REVISAR.test(e.claim)))
    .map(idDe);
  const precisaDeclarar = ctx.analysis.soundness !== "sound" || viaHelper.length > 0;
  add(
    M.qLimites,
    !precisaDeclarar ? "n/a" : "ok",
    !precisaDeclarar
      ? M.limitesNA(ctx.analysis.soundness)
      : M.limitesOk(ctx.analysis.soundness, viaHelper.length, lista(viaHelper), ctx.analysis.incompleteReason),
  );

  /*
   * 8 — o que surgiu DEPOIS do exercício. Nenhuma análise responde isto: descreve revisão
   * humana que ainda não aconteceu. O que a ferramenta tem é o que o exercício deixou em
   * aberto — letras em lacuna e achados marcados para confirmação —, de onde a revisão parte.
   */
  const emAberto = ctx.gaps.length || viaHelper.length;
  add(M.qPosterior, emAberto ? "ok" : "gap", emAberto ? M.posteriorOk(ctx.gaps.join(", "), viaHelper.length) : M.posteriorAusente);

  /* 9 — inventário do artefato analisado */
  const temIdTm = ctx.contractId ? noDocumento(ctx.contractId) : false;
  const hashTm = ctx.spec?.wasmHash;
  if (!temIdTm) blockers.push(M.invSemIdBlocker(ctx.contractId));
  add(
    M.qInventario,
    temIdTm && !!ctx.network && !!hashTm ? "ok" : "gap",
    [
      temIdTm ? M.invIdOk(ctx.contractId) : M.invIdFalta(ctx.contractId),
      ctx.network ? M.invRedeOk(ctx.network) : M.invRedeFalta,
      hashTm ? M.invHashOk : M.invHashNA,
    ].join("; ") + ".",
  );

  return relatorio("threat-model", items, blockers, needsInput);
}

/* ================= monitoring plan ================= */

/**
 * Fonte única do checklist do plano. `render/monitoring.ts` chama esta função com o documento
 * renderizado ATÉ a §6 e imprime os `items`: o relatório do documento e o do CLI são o mesmo
 * objeto porque o texto da §6 é cortado antes da leitura.
 */
export function validateMonitoringPlan(ctx: ArtifactContext, markdown: string, monitors: Monitor[]): ValidationReport {
  const md = semChecklist(markdown ?? "");
  const mons = monitors ?? [];
  const items: ChecklistItem[] = [];
  const blockers: string[] = [];
  /** Pendências que nenhuma análise fecha — ver `veredito`. */
  const needsInput: string[] = [];
  const add = (question: string, status: ChecklistItem["status"], detail: string) =>
    items.push({ question, status, detail });

  /* ---------- conferência estrutural ---------- */
  if (!md.trim()) blockers.push(M.docVazio);
  else for (const t of TITULOS_MP) if (!temTitulo(md, t)) blockers.push(M.tituloAusenteBlocker(t));
  if (!mons.length) blockers.push(M.mpSemMonitor);

  const noDocumento = (id: string) => reId(id).test(md);
  for (const m of mons) if (!noDocumento(m.id)) blockers.push(M.monitorAusenteBlocker(m.id));

  const idsAmeaca = new Set(ctx.findings.map(idDe));
  const obs = ctx.observations;

  /*
   * "É monitor de evento?" é pergunta ESTRUTURAL: o monitor é de evento se, e somente se, ele
   * vira um filtro executável de `getEvents` (`toExecutable`). Monitor que ESTE contexto não
   * rederiva não tem filtro a inspecionar; só nesse caso se lê o que os campos afirmam.
   */
  const rederivaveis = new Set(deriveMonitors(ctx).map((m) => m.id));
  const ehEvento = (m: Monitor): boolean =>
    rederivaveis.has(m.id) ? !!toExecutable(m, ctx) : MARCA_EVENTO.test(`${m.observable} ${m.trigger}`);

  /*
   * 1 — cobertura do threat model. O template aceita "não monitorável on-chain" — desde que o
   * controle substituto esteja NOMEADO. Quem decide as duas coisas é o renderizador, a partir
   * do dado: a §5 ganha uma linha por ameaça sem observável (`threatsSemObservavel`) e a
   * coluna "Required control" só sai preenchida para `silent-mutation`.
   */
  const comMonitor = new Set(mons.map((m) => m.threatId));
  const semObservavel = new Set(threatsSemObservavel(ctx).map((f) => f.id));
  const descobertas: string[] = [];
  const justificadas: string[] = [];
  for (const f of ctx.findings) {
    const id = idDe(f);
    if (comMonitor.has(id)) continue;
    const temLinhaOffchain = semObservavel.has(id);
    if (temLinhaOffchain && CLASSES_COM_CONTROLE_OFFCHAIN.has(f.class)) {
      justificadas.push(id);
      // Justificada continua sendo ameaça grave sem cobertura ativa: o que muda é o que falta.
      if (grave(f)) blockers.push(M.cobJustificadaSemDono(id, f.severity));
      continue;
    }
    descobertas.push(id);
    if (grave(f)) blockers.push(temLinhaOffchain ? M.cobControleAberto(id, f.severity) : M.cobSemJustificativa(id, f.severity));
  }
  // Denominador = entrypoints INVOCÁVEIS. `__constructor`/`__check_auth` são exports reservados
  // (CAP-0058) e não são chamáveis por InvokeHostFunction; contá-los dava um "42 de 57" que não
  // batia com o "56 invocáveis" do threat model do mesmo binário.
  const invocaveis = ctx.analysis.entrypoints.filter((e) => !e.name.startsWith("__"));
  const semEvento = invocaveis.filter((e) => !emitsEvent(e)).length;
  add(
    M.qCobertura,
    descobertas.length ? "gap" : ctx.findings.length ? "ok" : "gap",
    !ctx.findings.length
      ? M.cobSemAmeacas
      : [
          M.cobComMonitor(ctx.findings.length - descobertas.length - justificadas.length, ctx.findings.length),
          justificadas.length ? M.cobJustificadas(justificadas.length, lista(justificadas)) : "",
          descobertas.length ? M.cobDescobertas(lista(descobertas)) : "",
          M.cobSemEvento(semEvento, invocaveis.length),
        ].filter(Boolean).join("; ") + ".",
  );

  /* 2 — todo monitor rastreia a uma ameaça real */
  const orfaos = mons.filter((m) => !idsAmeaca.has(m.threatId));
  const idForaDoPadrao = mons.filter((m) => !new RegExp(`^${esc(m.threatId)}\\.M\\.\\d+$`).test(m.id));
  for (const m of orfaos) blockers.push(M.orfaoBlocker(m.id, m.threatId));
  add(
    M.qRastreio,
    orfaos.length || idForaDoPadrao.length ? "gap" : mons.length ? "ok" : "gap",
    !mons.length
      ? M.rastreioSemMonitor
      : [
          orfaos.length ? M.rastreioOrfaos(lista(orfaos.map((m) => `${m.id}→${m.threatId}`))) : M.rastreioOk(mons.length),
          idForaDoPadrao.length ? M.rastreioForaDoPadrao(lista(idForaDoPadrao.map((m) => m.id))) : "",
        ].filter(Boolean).join("; ") + ".",
  );

  /* 3 — baseline observado, não chutado. Tudo aqui sai de `monitor.*` e de `ctx.observations`. */
  const semBaseline = mons.filter((m) => m.baselineTier === "none");
  const inventado = mons.filter((m) => m.baselineTier === "B" && !obs);
  const janelaCurta = obs?.window.insufficient
    ? mons.filter((m) => m.baselineTier === "B" && /\d/.test(m.baseline) && !BASELINE_LACUNA.test(m.baseline))
    : [];
  const inferido = mons.filter((m) => m.baselineTier === "C");
  /*
   * AQ-1: uma janela coletada em que NENHUM evento de NENHUM tópico apareceu mede ausência de
   * tráfego, não perfil de tráfego. A contagem (0) é real e não sustenta limiar — "3× a taxa
   * medida" sobre taxa zero é limiar sem base.
   */
  const semTrafego = janelaSemTrafego(ctx);
  /*
   * Conferência do NÚMERO contra `ctx.observations`, não só do tier: sem isto o validador
   * aceitava "412 emissões de [deposit]" com a observação dizendo 7 — medido.
   */
  const conferidos = new Set<string>();
  const divergem: string[] = [];
  const topicoFantasma: string[] = [];
  /** `id|[topics]` — zero medido sustentando um limiar de taxa, que ele não sustenta. */
  const zeroComLimiar: string[] = [];
  /**
   * Zero observado num gatilho de qualquer-ocorrência: medição honesta, conferência nenhuma.
   * O caso real é um `init` de um pool inicializado ANTES da janela — o zero sairia zero
   * qualquer que fosse o comportamento do contrato dentro dela.
   */
  const zeroMedido: string[] = [];
  if (obs) {
    const conhecidos = new Set([...obs.events.map((e) => e.topic), ...obs.declaredButUnseen]);
    for (const m of mons) {
      if (m.baselineTier !== "B") continue;
      const tops = topicosCitados(m.baseline);
      const fantasmas = tops.filter((t) => !conhecidos.has(t));
      if (fantasmas.length) { topicoFantasma.push(`${m.id} → [${fantasmas.join(", ")}]`); continue; }
      const ledgersDitos = numeroAntesDe(m.baseline, /ledgers/i);
      if (ledgersDitos !== undefined && ledgersDitos !== obs.window.ledgers) {
        divergem.push(`${m.id}: ${ledgersDitos} ledgers ≠ ${obs.window.ledgers}`);
        continue;
      }
      const dito = numeroAntesDe(m.baseline, /(emiss|occurr|event|firing)/i);
      if (dito === undefined || !tops.length) continue; // baseline sem contagem (ex.: hash da instância)
      const esperado = tops.reduce((s, t) => s + (obs.events.find((e) => e.topic === t)?.count ?? 0), 0);
      if (dito !== esperado) { divergem.push(`${m.id}: ${dito} ≠ ${esperado} [${tops.join(", ")}]`); continue; }
      // Zero numa janela suficiente É medição, e sustenta "qualquer ocorrência"; o que ele não
      // sustenta é limiar de taxa, que seria "3× zero". Só esse par vira blocker.
      if (esperado === 0 && !obs.window.insufficient && MARCA_LIMIAR_TAXA.test(m.trigger ?? "")) {
        zeroComLimiar.push(`${m.id}|[${tops.join(", ")}]`);
      } else if (esperado === 0) {
        zeroMedido.push(m.id);
      }
      if (esperado === 0) continue;
      if (!obs.window.insufficient && !semTrafego) conferidos.add(m.id);
    }
  }
  const motivo = motivoSemObservacao(ctx);
  /*
   * SHIP-05, POR MONITOR: "sem baseline" tem três causas e o documento afirmava a primeira nas
   * três. (a) nenhuma janela foi coletada; (b) a janela existe e é curta demais; (c) o monitor
   * não passa por getEvents, e aí nenhuma janela produziria o baseline dele: o campo é
   * preenchimento na aprovação do plano, não coleta que a ferramenta deixou de fazer.
   */
  for (const m of semBaseline) {
    if (!ehEvento(m)) needsInput.push(M.baseFillInBlocker(m.id));
    else if (obs?.window && obs.window.insufficient) blockers.push(M.baseJanelaInsuficienteBlocker(m.id, obs.window.ledgers));
    else blockers.push(comMotivo(M.baseSemBaselineBlocker(m.id), motivo));
  }
  for (const z of zeroComLimiar) {
    const [id, tops] = z.split("|");
    blockers.push(M.baseZeroComLimiarBlocker(id, obs!.window.ledgers, tops));
  }
  for (const m of inventado) blockers.push(M.baseInventadoBlocker(m.id));
  for (const m of janelaCurta) blockers.push(M.baseJanelaCurtaBlocker(m.id, obs?.window.ledgers ?? 0));
  for (const d of divergem) blockers.push(M.baseDivergeBlocker(d));
  for (const t of topicoFantasma) blockers.push(M.baseTopicoFantasmaBlocker(t));
  if (semTrafego) blockers.push(M.baseSemTrafegoBlocker(obs!.window.ledgers));
  add(
    M.qBaseline,
    semBaseline.length || inventado.length || janelaCurta.length || inferido.length || divergem.length
      || topicoFantasma.length || semTrafego || zeroComLimiar.length
      ? "gap"
      : mons.length ? "ok" : "gap",
    [
      obs ? M.baseJanela(obs.window.ledgers, obs.window.approxHours, obs.events.length, obs.window.insufficient) : M.baseSemJanela(motivo),
      semTrafego ? M.baseSemTrafegoDetalhe(obs!.window.ledgers) : "",
      semBaseline.length ? M.baseSemBaseline(lista(semBaseline.map((m) => m.id))) : "",
      inventado.length ? M.baseInventado(lista(inventado.map((m) => m.id))) : "",
      janelaCurta.length ? M.baseJanelaCurta(lista(janelaCurta.map((m) => m.id))) : "",
      divergem.length ? M.baseDiverge(lista(divergem, 3)) : "",
      topicoFantasma.length ? M.baseTopicoFantasma(lista(topicoFantasma, 3)) : "",
      zeroComLimiar.length ? M.baseZeroComLimiar(lista(zeroComLimiar.map((z) => z.replace("|", " ")), 3)) : "",
      zeroMedido.length ? M.baseZeroObservado(zeroMedido.length, lista(zeroMedido)) : "",
      inferido.length ? M.baseInferido(lista(inferido.map((m) => m.id))) : "",
      obs ? M.baseConferidos(conferidos.size) : "",
    ].filter(Boolean).join("; ") + ".",
  );

  /* 4 — resposta definida */
  const semResposta = mons.filter((m) => !m.response || !m.response.trim());
  const respostaOca = mons.filter((m) => m.response?.trim() && (RESPOSTA_OCA.test(m.response) || m.response.trim().length < 20));
  for (const m of semResposta) blockers.push(M.respSemBlocker(m.id));
  add(
    M.qResposta,
    semResposta.length || respostaOca.length ? "gap" : mons.length ? "ok" : "gap",
    [
      semResposta.length ? M.respSem(lista(semResposta.map((m) => m.id))) : M.respComResposta(mons.length),
      respostaOca.length ? M.respOca(respostaOca[0].response.trim(), lista(respostaOca.map((m) => m.id))) : "",
    ].filter(Boolean).join("; ") + ".",
  );

  /*
   * 5 — dono nomeado. Não há campo de dono no tipo `Monitor` nem fonte on-chain para ele: a
   * coluna Owner da §5 sai `⟨a preencher⟩` em toda linha, por construção. A resposta é sempre
   * a mesma e não depende do documento. Continua `needsInput`: alerta sem destinatário barra
   * a submissão, e ninguém além da equipe o fecha.
   */
  if (mons.length) needsInput.push(M.donoBlocker(mons.length));
  add(M.qDono, "gap", mons.length ? M.donoGap(mons.length) : M.semMonitorDetalhe);

  /*
   * 6 — precisão histórica. "Ativo" é `status === "Active"`, e só: a §5 do mesmo documento diz
   * que nenhum monitor sai daqui `Active`, e contar `Tuning` como ativo dava ✔ a uma pergunta
   * sobre alertas que nunca existiram. Conferido é só o monitor cuja contagem bateu com a
   * janela (`conferidos`, do item 3): "tem número e existe janela" não é conferência.
   */
  const ativos = mons.filter((m) => m.status === "Active");
  const comBacktest = ativos.filter((m) => conferidos.has(m.id));
  add(
    M.qPrecisao,
    !mons.length ? "gap" : !ativos.length ? "n/a" : comBacktest.length === ativos.length ? "ok" : "gap",
    !mons.length
      ? M.semMonitorDetalhe
      : !ativos.length
        ? M.precSemAtivos(conferidos.size, mons.length)
        : !obs
          ? M.precSemJanela
          : comBacktest.length === ativos.length
            ? M.precOk(ativos.length, obs.window.ledgers)
            : M.precParcial(comBacktest.length, ativos.length, obs.window.ledgers, obs.window.insufficient, obs.declaredButUnseen.length, lista(obs.declaredButUnseen)),
  );

  /* 7 — inventário de endereços, e o hash que prende o plano ao binário no ar */
  const temId = ctx.contractId ? noDocumento(ctx.contractId) : false;
  const hash = ctx.spec?.wasmHash;
  if (!temId) blockers.push(M.endSemIdBlocker(ctx.contractId));
  // O hash da instância se lê do ledger na aprovação do plano: é registro, não análise.
  if (!hash) needsInput.push(M.endSemHashBlocker);
  add(
    M.qEnderecos,
    temId && hash ? "ok" : "gap",
    (temId ? M.endOk(ctx.contractId, ctx.network) : M.endGap(ctx.contractId)) +
      (hash ? M.endHashOk(hash, ctx.generatedAt) : M.endHashFalta(lacuna())),
  );

  /* 8 — fronteiras externas: endereços que o bytecode não revela */
  const cruzam = ctx.analysis.entrypoints.filter((e) => callsOut(e));
  add(M.qFronteiras, !cruzam.length ? "n/a" : "gap", !cruzam.length ? M.frontNA : M.frontGap(cruzam.length, lista(cruzam.map((e) => e.name))));

  /*
   * 9 — ameaças off-chain. A palavra "off-chain" no texto nunca bastou: um documento de quatro
   * linhas contendo só "infraestrutura" ganhava ✔ por casamento de palavra. O que importa é a
   * ÂNCORA — o que a análise deixou de fora — e onde o documento a prende: a explicação das
   * letras em lacuna sai de `ctx.gaps`, a tabela de controle fora da chain de `threatsSemObservavel`.
   */
  const ancoras = [...ctx.gaps, ...ctx.findings.map(idDe).filter((id) => !comMonitor.has(id))];
  const ancoradas = [
    ...ctx.gaps,
    ...ctx.findings.filter((f) => !comMonitor.has(idDe(f)) && semObservavel.has(idDe(f))).map(idDe),
  ];
  const offOk = !ancoras.length || ancoradas.length > 0;
  add(M.qOffchain, offOk ? "ok" : "gap", offOk ? M.offOk(ancoras.length ? lista(ancoradas) : M.offSemAncora) : M.offAusente(lista(ancoras)));

  /* 10 — sinal observável e gatilho executável */
  const semSinal = mons.filter((m) => !m.observable?.trim());
  const semGatilho = mons.filter((m) => !m.trigger?.trim());
  const topicsSpec = ctx.spec?.events?.flatMap((e) => e.prefixTopics) ?? [];
  // Cobrar topic de um monitor de ledger entry é cobrar campo do endpoint errado: a cobertura
  // de tópicos só se aplica a quem usa `getEvents`.
  const deEvento = mons.filter(ehEvento);
  const semTopic = topicsSpec.length
    ? deEvento.filter((m) => !topicsSpec.some((t) => `${m.observable} ${m.trigger}`.includes(t)))
    : [];
  // Monitor sem filtro executável precisa dizer por qual outro mecanismo o sinal chega. Só
  // quando nem filtro nem mecanismo valem o monitor é decorativo — caso comum no corpus: a
  // maioria dos contratos mainnet não emite evento nos entrypoints que mudam estado.
  const epPorAmeaca = new Map(ctx.findings.map((f) => [idDe(f), f.entrypoint]));
  const semSinalReal = mons.filter((m) => !ehEvento(m) && !MECANISMO_ALTERNATIVO.test(`${m.observable} ${m.trigger}`));
  // Executável por `getEvents` OU completamente especificado: enquanto a durabilidade (ou o
  // endereço, ou o hash) for `⟨a preencher⟩` a consulta não se monta, e o mesmo preenchimento
  // já é bloqueio na §6 — uma linha não sai ✔ apontando para um bloqueio aberto do documento.
  const naoEspecificados = mons.filter((m) => !toExecutable(m, ctx) && PLACEHOLDER.test(`${m.observable} ${m.trigger}`));
  const executaveis = mons.filter((m) => toExecutable(m, ctx)).length;
  for (const m of [...semSinal, ...semGatilho]) {
    blockers.push(M.sinalBlocker(m.id, !m.observable?.trim() ? M.sinalObservavel : M.sinalGatilho));
  }
  add(
    M.qSinal,
    semSinal.length || semGatilho.length || semTopic.length || semSinalReal.length || naoEspecificados.length
      ? "gap"
      : mons.length ? "ok" : "gap",
    !mons.length
      ? M.semMonitorDetalhe
      : [
          semSinal.length ? M.sinalSemObservavel(lista(semSinal.map((m) => m.id))) : "",
          semGatilho.length ? M.sinalSemGatilho(lista(semGatilho.map((m) => m.id))) : "",
          semSinalReal.length ? M.sinalMudo(semSinalReal.length, lista(semSinalReal.map((m) => `${m.id}→${epPorAmeaca.get(m.threatId)}`))) : "",
          naoEspecificados.length ? M.sinalIncompleto(naoEspecificados.length, lista(naoEspecificados.map((m) => m.id))) : "",
          !deEvento.length
            ? M.sinalSemEventBased
            : topicsSpec.length
              ? semTopic.length
                ? M.sinalSemTopic(semTopic.length, topicsSpec.length, lista(topicsSpec), lista(semTopic.map((m) => m.id)))
                : M.sinalComTopic
              : M.sinalSemSpec,
          M.sinalExecutaveis(executaveis, mons.length),
        ].filter(Boolean).join("; ") + ".",
  );

  /*
   * Varredura final: uma linha ✔ cujo detalhe carrega uma pendência é contradição dentro da
   * própria célula. Quem lê o checklist lê a coluna Situação; graduar um pendente como
   * aprovado é o modo mais barato de o documento perder o revisor.
   */
  for (const it of items) {
    if (it.status === "ok" && PENDENCIA_NA_LINHA.test(it.detail)) it.status = "gap";
  }

  return relatorio("monitoring-plan", items, blockers, needsInput);
}
