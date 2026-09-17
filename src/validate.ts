/**
 * Validadores dos dois checklists oficiais "Did we do a good job?" do tranche #2.
 *
 * O módulo existe para APONTAR LACUNA, não para carimbar completude. Um validador que
 * devolve tudo verde é pior que inútil: dá ao time a impressão de que pode submeter, e
 * quem descobre o buraco vira o revisor do SCF. Por isso nenhum item aqui devolve `ok`
 * por ausência de evidência contrária — cada `ok` exige um fato positivo.
 *
 * O desenho não óbvio é a dupla fonte, e é dela que sai o poder de detecção:
 *
 *   ctx      → o que a análise SABE  (achados, lacunas, DFD, observações, monitores)
 *   markdown → o que o documento DIZ (o texto que o revisor vai ler)
 *
 * Um item só passa quando as duas concordam. Achado que existe no ctx e não aparece no
 * documento é omissão; prosa no documento sem âncora no ctx é enchimento. Validar só o
 * ctx aprovaria um renderizador quebrado; validar só o markdown aprovaria texto bonito
 * sem lastro. As duas falhas são o mesmo slop visto de lados opostos.
 *
 * Duas decisões de desenho desta revisão:
 *
 *  1. FONTE ÚNICA DA §6 DO MONITORING PLAN. `validateMonitoringPlan` daqui é o único
 *     validador do plano; `render/monitoring.ts` renderiza a §6 a partir do relatório que
 *     esta função devolve. Não há ciclo de import: este módulo importa `monitors.ts` e
 *     `analyze.ts`, nunca os renderizadores — quem passa o markdown é o chamador.
 *  2. O TEXTO DA §6 NÃO É EVIDÊNCIA SOBRE O DOCUMENTO. O markdown é cortado no título
 *     "Did we do a good job?" antes de ser lido. Sem o corte o validador leria a própria
 *     saída como prosa do documento — o detalhe de um item contém "off-chain", "owner",
 *     "gap" — e se auto-aprovaria por casamento de palavra, que é exatamente o slop que
 *     este módulo existe para barrar. O corte também é o que faz o relatório da §6 e o
 *     relatório que o CLI imprime serem o MESMO objeto: o texto acrescentado depois do
 *     corte não pode mudar nenhum item.
 *
 * Todo texto que sai daqui passa pela tabela `M` (ver i18n.ts). As perguntas em inglês são
 * as do template oficial; o português é a tradução com a glosa que os documentos já usavam.
 * Os detectores de marca (as regex abaixo) precisam casar nos DOIS idiomas: o documento pode
 * ter sido gerado em `pt` e validado em `en`, e um marcador que só casa num idioma
 * transforma honestidade do renderizador em lacuna no checklist.
 */

import type { ArtifactContext, ChecklistItem, DfdNode, Monitor, ValidationReport } from "./artifact.ts";
import type { Finding, Stride } from "./detect.ts";
import { callsOut, emitsEvent } from "./analyze.ts";
import { deriveMonitors, janelaSemTrafego, lacuna, motivoSemObservacao, toExecutable } from "./monitors.ts";
import { msgs, plural } from "./i18n.ts";

const LETRAS: readonly Stride[] = ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"];

/* ================= marcas: precisam casar em pt e en ================= */

/**
 * Lacuna DECLARADA. A regra do PROBLEMA.md é que uma letra do STRIDE sem evidência saia
 * dita como lacuna; sem um destes termos por perto, prosa sobre a letra é enchimento —
 * e enchimento numa seção obrigatória é o que faz um revisor competente descartar o
 * documento inteiro em vez de só aquela linha.
 */
const MARCA_LACUNA =
  /lacuna|n[ãa]o\s+(é\s+)?deriv|nenhum[ao]\s+(amea[çc]a|achado|evid[êe]ncia|sinal|monitor)|requer\s+an[áa]lise\s+manual|exige\s+an[áa]lise\s+manual|an[áa]lise\s+manual\s+do\s+fluxo|fora\s+do\s+(alcance|escopo)|n[ãa]o\s+observ[áa]vel|n[ãa]o\s+determin[áa]vel|janela\s+insuficiente|n[ãa]o\s+suportad|\bgaps?\b|not\s+derivable|no\s+(threat|finding|evidence|signal|monitor|observable)\b|manual\s+(review|analysis)|requires?\s+manual|out\s+of\s+(scope|reach)|not\s+observable|not\s+determinable|insufficient|not\s+supported/i;

const MARCA_REMEDIACAO =
  /remedia|mitiga|corre[çc][ãa]o|corrigir|recomend|contramedida|remediation|mitigation|recommend|countermeasure|\bfix\b/i;
/** Cabeçalho de coluna de dono numa tabela — a forma que o template oficial usa. */
const MARCA_DONO = /\bdonos?\b|respons[áa]ve(l|is)|\bowners?\b|on-?call|plant[ãa]o|responsible/i;
/**
 * Atribuição de dono, não menção. A palavra solta casa dentro de uma resposta
 * ("escalar para o dono do contrato"), e foi assim que este validador aprovou um documento
 * sem nenhum responsável nomeado na primeira rodada contra o corpus. Ou há `Dono: <alguém>`,
 * ou há célula preenchida numa coluna de dono — menção em prosa não conta.
 */
const MARCA_DONO_ATRIB = /(dono|respons[áa]ve(l|is)|owner|responsible|on-?call)\s*[:=]\s*\S/i;
/**
 * Célula que finge preencher. Inclui a marca `⟨a definir — não derivável do binário⟩` /
 * `⟨to be defined — not derivable from the binary⟩` que os renderizadores usam: é uma lacuna
 * honesta no documento, e contá-la como preenchida transformaria a honestidade do
 * renderizador em verde no checklist.
 */
const CELULA_OCA = /^\s*(—|–|-{1,2}|n\/?a|tbd|\?|)\s*$/i;
const PLACEHOLDER =
  /⟨|⟩|a\s+definir|n[ãa]o\s+deriv[áa]ve|por\s+preencher|preencher|to\s+be\s+(defined|filled)|not\s+derivable|to\s+fill/i;
const celulaVazia = (c: string) => CELULA_OCA.test(c) || PLACEHOLDER.test(c);
/**
 * Afirmação de NÃO-monitorabilidade. Precisa cobrir as formas que os documentos reais usam:
 * medido contra o renderizador, "**Nenhum efeito observável on-chain derivável desta análise**"
 * e "não alcançam `contract_event`" ficavam de fora, e o validador acusava "sem justificativa
 * no documento" sobre um documento que justificava a lacuna em três lugares e com evidência de
 * nível A. Um blocker que afirma algo falso sobre o texto é tão descartável quanto o slop.
 */
const MARCA_SEM_MONITOR =
  /n[ãa]o\s+monitor[áa]vel|sem\s+sinal\s+on-chain|n[ãa]o\s+observ[áa]vel|sem\s+evento\s+correspondente|n[ãa]o\s+emite\s+evento|nenhum\s+(efeito\s+)?observ[áa]vel|sem\s+observ[áa]vel|n[ãa]o\s+alcan[çc]am?\s+`?contract_event|not\s+monitorable|no\s+on-chain\s+signal|not\s+observable|no\s+corresponding\s+event|do(es)?\s+not\s+emit\s+(an\s+)?event|no\s+(derivable\s+)?observable|do(es)?\s+not\s+reach\s+`?contract_event/i;
const MARCA_OFFCHAIN =
  /off-?chain|fora\s+da\s+chain|fluxo\s+off|governan[çc]a|chave\s+privada|processo\s+operacional|infraestrutura|governance|private\s+key|operational\s+process|infrastructure/i;
const MARCA_POSTERIOR =
  /quest[õo]es\s+adicionais|surgir(am|em)\s+depois|ap[óo]s\s+a\s+revis[ãa]o|itens?\s+em\s+aberto|follow-?up|open\s+issues|pend[êe]ncias\s+da\s+revis[ãa]o|additional\s+(issues|questions)|surfaced?\s+(after|later)|after\s+the\s+review/i;
/**
 * A lacuna da §1 do template, como os renderizadores a escrevem nos dois idiomas. Enquanto ela
 * estiver no documento, a primeira pergunta do template ("What are we working on?") está sem
 * resposta — e nenhuma análise de bytecode a responde: propósito de negócio, atores e custódia
 * não estão no binário. Some do documento quando a equipe escreve o parágrafo, e é por isso que
 * ela é lida no texto em vez de assumida: o validador mede o documento, não a intenção.
 */
const MARCA_LACUNA_EQUIPE = /Gap to be filled by the team|Lacuna a preencher pela equipe/i;

const MARCA_NIVEL = /n[íi]vel\s+[ABC]\b|\(\s*[ABC]\s*\)|\[\s*[ABC]\s*\]|tier\s+[ABC]\b/;
/**
 * MARCA por afirmação — `[A]`, `(B)`. Não casa com prosa ("níveis A+C", "nível de evidência"),
 * e é essa diferença que importa: um título dizendo "(nível A)" em algum ponto do documento
 * satisfazia `MARCA_NIVEL` e deixava passar um documento com TODAS as afirmações sem marca.
 * Medido: apagar as marcas por afirmação do threat model real mantinha o item verde.
 */
const TOKEN_NIVEL = /\[\s*([ABC])\s*\]|\(\s*([ABC])\s*\)/g;
/**
 * Imprecisão declarada. Cobre as duas origens: `call_indirect` no módulo e módulo lido de
 * forma incompleta/degradada (`ctx.analysis.incompleteReason`) — as duas rebaixam a
 * afirmação negativa, e o documento precisa dizer qual delas ocorreu.
 */
const MARCA_APROXIMADO =
  /call_indirect|aproximad|rebaixad|negativa\s+n[ãa]o\s+s[óo]lida|incompleto|degradad|approximate|over-approx|downgraded|incomplete|degraded|unsound/i;

/**
 * Âncora concreta: crase, nome de host function ou identificador. Uma remediação que não
 * cita nenhum destes não endereça ameaça nenhuma — é a linha de checklist genérica que o
 * PROBLEMA.md lista como risco #5 de slop.
 */
const MARCA_CONCRETA =
  /require_auth|put_contract_data|del_contract_data|get_contract_data|contract_event|update_current_contract_wasm|extend_\w*ttl|authorize_as_curr_contract|getLedgerEntries|getEvents|__constructor|__check_auth/i;

/**
 * Crase NÃO é evidência de concretude por si só — era, e isso reabria o buraco que o
 * `trechoRemediacao()` tinha fechado: "Aplicar `controles de acesso` adequados e seguir as
 * `boas práticas`" passava como remediação concreta e o threat model inteiro saía submetível.
 * Medido. O que conta é crase em volta de algo com FORMA de código: um identificador com `_`,
 * com `::` ou com `()`. Nome de export e chave de storage continuam valendo por `nomes`,
 * comparados contra o que a análise leu do binário.
 */
const CRASE_CODIGO = /`([^`\s]{3,})`/g;
/**
 * Forma de código, não de palavra: um separador (`_`, `-`, `::`, `.`, `#`, `()`), um dígito ou
 * uma maiúscula no meio. `soroban-sdk`, `require_auth()` e `contractmetav0` passam; `controles`
 * e `práticas` não. É régua de forma, de propósito: nome de export e chave de storage são
 * conferidos à parte, contra o que a análise leu do binário.
 */
const ehCodigo = (t: string): boolean => /[_\-:.#()0-9]/.test(t) || /[a-z][A-Z]/.test(t);

/** Resposta que não é resposta: um verbo solto no lugar de um procedimento. */
const RESPOSTA_OCA =
  /^\s*(tbd|a\s+definir|to\s+be\s+defined|investigar|investigate|monitorar|monitor|revisar|review|verificar|verify|alertar|alert|acompanhar|follow\s*up|checar|check|n\/?a|—|-)\s*\.?\s*$/i;

/** Evidência que o próprio detector marcou para revisão humana (`REVISAR` / `REVIEW`). */
const MARCA_REVISAR = /REVISAR|REVIEW|super-aproxim|super-approx|helper/i;

/**
 * Mecanismo de leitura que não é `getEvents`. Sem citar um destes, um monitor que não vira
 * filtro de `getEvents` é decorativo — com um deles, ele é um monitor legítimo de outro
 * endpoint, e acusá-lo de "getEvents nunca vai disparar" contradiz a própria §4 do plano,
 * que diz qual é o mecanismo. As formas cobertas são as que os observáveis realmente usam:
 * getLedgerEntries, diff de estado, wasm hash e inspeção da transação.
 */
const MECANISMO_ALTERNATIVO =
  /diff|snapshot|getLedgerEntries|ledger\s*entr|wasm\s*hash|hash\s+da\s+inst|transaction\s+inspection|inspe[cç][ãa]o\s+da\s+transa|InvokeHostFunction|SorobanAuthorizationEntry|authorization\s+tree|[áa]rvore\s+de\s+autoriza|estado|state|sa[íi]da\s+da\s+simula|simulation\s+output|invariante|invariant/i;

/**
 * Texto que só um monitor de evento produz. Serve de fallback para monitores que ESTE
 * contexto não rederiva (`ctx.monitors` vindo de outra análise): sem rederivação não há
 * filtro para inspecionar, e a alternativa honesta é ler o que o documento afirma.
 */
const MARCA_EVENTO = /getEvents|event\s+with\s+topics|evento\s+com\s+t[óo]picos|topic\s+filter|filtro\s+de\s+t[óo]picos/i;

/** Gatilho que fixa um limiar numérico de taxa (em vez de "qualquer ocorrência"). */
const MARCA_LIMIAR_TAXA = /(more\s+than|mais\s+de)\s+\d/i;

/**
 * Tarefa em aberto dentro do detalhe de um item do checklist, nos dois idiomas. Serve à
 * varredura final de `validateMonitoringPlan`: nenhum item graduado `ok` pode conter uma.
 */
const PENDENCIA_NA_LINHA =
  /\bhas\s+to\b|\bmust\b|\bneeds?\s+to\b|to\s+be\s+(filled|defined|written|recorded)|⟨|⟩|\bprecisa\b|\bprecisam\b|\bdeve\b|\bdevem\b|\btem\s+que\b|a\s+preencher|a\s+definir|a\s+registrar/i;

/**
 * Título da seção de checklist — igual nos dois idiomas, porque é o título do template
 * oficial. Tudo a partir dele é saída DESTE módulo e não conta como evidência sobre o
 * documento (ver a nota de desenho no topo).
 */
const TITULO_CHECKLIST = /^[ \t]{0,3}#{1,6}[ \t]*Did we do a good job\?/m;

function semChecklist(md: string): string {
  const m = TITULO_CHECKLIST.exec(md);
  return m ? md.slice(0, m.index) : md;
}

/* ================= mensagens ================= */

/**
 * O motivo da ausência de janela entra no blocker de baseline. Fica como placeholder na
 * tabela porque depende do `ctx` — `baseSemBaselineBlocker` o recebe por substituição.
 */
const motivoPlaceholder = "%MOTIVO%";
const comMotivo = (s: string, motivo: string) => s.replace(motivoPlaceholder, motivo);

const M = msgs({
  en: {
    /* comuns */
    docVazio: "Empty document: there is no rendered markdown to validate.",
    /**
     * §1 do template. É a única pergunta do documento cuja resposta não está no binário em
     * nenhuma forma — por isso ela é `needsInput`, nunca blocker: não há nada que a ferramenta
     * pudesse ter feito e não fez.
     */
    inputSecao1:
      'Write section 1, "What are we working on?": what the protocol does, who the actors are, what value ' +
      "it holds in custody and which trust assumptions live off-chain. Worksheet: the *Analyzed object* " +
      "table and the measured surface right below the gap notice in section 1 — the bytecode records none " +
      "of that, so no analysis closes this one.",
    /* threat model */
    tmSemAmeaca:
      "No threat derived from the bytecode: the document does not contain a single threat, and all six STRIDE letters would come out as gaps. This is not a submittable threat model — it is the report that the automated analysis did not cover this contract and that it needs manual modelling.",
    qDfd: "Was the data-flow diagram derived from the analysis (processes = entrypoints, data stores = storage keys, boundaries = auth and cross-call)?",
    dfdAusenteBlocker: "No data-flow diagram in the context: the template requires the DFD as section 2.",
    dfdAusenteDetalhe:
      "ctx.dfd missing. With no DFD there is no way to answer the following checklist questions, which depend on it.",
    dfdSemProcesso: "no process (entrypoint) in the diagram",
    dfdSemStore: "no data store: the storage keys never reached the diagram",
    dfdSemFronteira: "no trust boundary declared",
    dfdSemNo: (eps: string) => `entrypoints with a finding and no node in the DFD: ${eps}`,
    dfdSemTravessia: (n: number) =>
      `${n} entrypoints reach call/try_call but no edge is marked as crossing a boundary`,
    dfdDetalheGap: (p: number, s: number, b: number, faltas: string) =>
      `${p} processes, ${s} stores, ${b} boundaries. Problems: ${faltas}.`,
    dfdDetalheOk: (p: number, s: number, b: number, cruzam: number) =>
      `${p} processes tied to real entrypoints, ${s} data stores, ${b} boundaries, ${cruzam} edges crossing a boundary.`,
    qDfdRef: "Was the data-flow diagram referenced after it was created?",
    dfdSemBloco: "The DFD was derived but the ```mermaid block does not appear in the document.",
    dfdSemBlocoDetalhe: "The diagram is not in the document, so there is nothing to reference.",
    dfdRefOk: (n: number, citados: string) => `${n} DFD elements cited in the text after the diagram: ${citados}.`,
    dfdRefGap:
      "No DFD node id or boundary name appears in the text after the diagram. Repeating the entrypoint name in the threat table does not count: the checklist asks whether the diagram was used to reason, and naming the boundary a threat crosses is the evidence of that.",
    qDesign: "Did STRIDE reveal a new design issue?",
    designOk: (n: number, achados: string) =>
      `${n} structural findings (not merely "this function is missing require_auth"): ${achados}. The tool cannot know what was NEW to the team — it shows what the exercise derived; marking what was already known is the reviewer's job.`,
    designSoEntrypoint: (n: number) =>
      `All ${n} findings are per-entrypoint; none touches system design (order of operations, storage lifecycle, audit trail, upgrade). The tool has no way to know what the team already knew — if the human review raised a design issue, it has to be recorded here by hand.`,
    designSemAchado:
      "No finding derived from the bytecode. A threat model with no issue raised is not a finished threat model: either the analysis did not run, or the contract needs a manual review on record.",
    qRemediacao: "Do the remediations address the issues raised?",
    remSemBloco: (id: string) => `Threat ${id} exists in the analysis but does not appear in the document.`,
    remSemRemediacao: (id: string) => `Threat ${id} has no remediation in the document.`,
    remGenerica: (id: string) =>
      `The remediation for ${id} does not cite a single identifier of this contract (exported function, storage key or host function). A remediation copied from a checklist does not address the threat — it is slop risk #5 in PROBLEMA.md, and a reviewer knocks it down in one line.`,
    remSemAmeaca:
      "No threat was derived from the bytecode, so there is no remediation to assess. That does not mean the contract is safe: it means the classes this tool covers did not fire. The letters declared as gaps still require manual analysis.",
    remAusentes: (ids: string) => `missing from the document: ${ids}`,
    remSem: (ids: string) => `without remediation: ${ids}`,
    remGenericas: (ids: string) => `generic remediation (cites neither the function nor the host function involved): ${ids}`,
    remOk: (n: number) =>
      `${n} threats, all with a remediation that cites an identifier of this contract (export, storage key or host function). What was checked is the anchoring, not the correctness: whether the remediation is the RIGHT fix, only human review answers.`,
    qLetras: "Does every STRIDE letter have an entry — a finding with evidence, or an explicitly declared gap?",
    letraSemAchadoNoDoc: (l: string, ids: string) =>
      `${l}: has a finding in the analysis (${ids}) and none of them appears in the document`,
    letraSemAchadoBlocker: (l: string, ids: string) =>
      `Letter ${l}: none of the findings ${ids} appears in the document.`,
    letraAusente: (l: string) => `${l}: missing from the document`,
    letraAusenteBlocker: (l: string) =>
      `Letter ${l} does not appear in the document. The template requires ≥1 entry per STRIDE letter — a finding or a declared gap.`,
    letraEnchimento: (l: string, n: number) => `${l}: ${n} words without declaring a gap`,
    letraEnchimentoBlocker: (l: string, n: number) =>
      `Letter ${l} has no finding derivable from the bytecode, and the document filled it with ${n} words of prose without declaring the gap. Generic text in a mandatory section is what makes a reviewer discard the whole document.`,
    letraVaziaBlocker: (l: string) => `Letter ${l} appears in the document with no content and no declared gap.`,
    letraComAchado: (l: string) => `${l} (finding)`,
    letraComLacuna: (l: string) => `${l} (declared gap)`,
    /**
     * Lacuna honesta continua sendo a saída certa do RENDERIZADOR — o que não pode continuar é o
     * veredito chamar de submetível um documento com letra vazia. O template oficial pede ≥1 issue
     * por letra; a lacuna descreve o trabalho, não o cumpre.
     */
    letraSemIssue: (l: string) => `${l}: declared gap, no issue (the template requires at least one)`,
    letraSemIssueBlocker: (l: string) =>
      `STRIDE letter ${l} has no issue — the template requires at least one; fill it from the worksheet in the ${l} gap section (it lists the concrete surface to review).`,
    letrasPreenchidas: (n: number) => `${n} of 6 letters filled.`,
    letrasResumo: (com: string, sem: string) =>
      `derived from the bytecode: ${com || "none"}; with no derivable finding: ${sem || "none"}.`,
    letrasProblemas: (p: string) => `Problems: ${p}.`,
    letrasTodas: (ok: string) => `All six covered: ${ok}.`,
    letrasDivergentes: (d: string) =>
      `⚠ ctx.gaps lists ${d} as a gap, but there are findings for those letters — inconsistent context.`,
    qNivel: "Does every claim carry its evidence tier (A/B/C) and a citable anchor?",
    semEvidenciaBlocker: (id: string) => `Threat ${id} has no evidence at all.`,
    soInferenciaBlocker: (id: string) =>
      `Threat ${id} is supported only by inference (tier C), with no bytecode fact and no on-chain observation.`,
    semMarcaBlocker: (id: string) =>
      `Threat ${id} appears in the document with no evidence tier (A/B/C) on its claims: the reader cannot tell a bytecode fact from an inference.`,
    infladoBlocker: (d: string) =>
      `Inflated evidence tier — ${d}. Presenting an inference with the force of a bytecode fact or an on-chain observation is the one rule this project does not break (PROBLEMA.md, "never present C as A").`,
    infladoA: (id: string, doc: number, ev: number) =>
      `${id}: ${doc} claims marked (A) for ${ev} bytecode ${plural(ev, "evidence", "evidences")}`,
    infladoB: (id: string, doc: number, ev: number, semJanela: boolean) =>
      `${id}: ${doc} claims marked (B) for ${ev} on-chain ${plural(ev, "observation", "observations")}${semJanela ? " — and there is no observed window in the context at all" : ""}`,
    nivelContagem: (a: number, b: number, c: number) => `${a} tier A claims, ${b} tier B, ${c} tier C in the context.`,
    nivelPorAmeaca: (ok: number, presentes: number, faltando: number, total: number) =>
      `Checked per threat: ${ok}/${presentes} threats present in the document with a per-claim tier and no tier inflation${faltando ? ` (${faltando} of ${total} do not appear in the document and could not be checked)` : ""}.`,
    nivelSemAmeaca:
      "No threat in the context: there is no claim whose tier to check, and a document with no threat is not a threat model.",
    nivelSemEvidencia: (ids: string) => `without evidence: ${ids}.`,
    nivelSoC: (ids: string) => `tier C only: ${ids}.`,
    nivelSemMarca: (ids: string) => `without a per-claim tier: ${ids}.`,
    nivelInflado: (d: string) => `inflated tier: ${d}.`,
    nivelSemNotacao:
      "The document never explains nor uses the tier notation — without it the reader cannot tell a bytecode fact from an opinion.",
    qLimites: "Are the analysis limits declared in the document (incomplete call graph, over-approximate positive)?",
    limitesNA: (soundness: string) =>
      `Call graph complete (soundness=${soundness}) and no finding depends on a path through a helper: there is no imprecision to declare.`,
    limitesOk: (soundness: string, n: number, ids: string, motivo?: string) =>
      `Declared. soundness=${soundness}${motivo ? `, reason: ${motivo}` : ""}${n ? `, ${n} findings flagged for review because of a path through a helper: ${ids}` : ""}.`,
    limitesGap: (soundness: string, n: number, ids: string, motivo?: string) =>
      `soundness=${soundness}${motivo ? ` (${motivo})` : ""}${n ? ` and ${n} findings with a long path to the write (${ids})` : ""}, and the document does not mention the imprecision. Claiming reachability without saying the positive is over-approximate presents C with the force of A.`,
    qPosterior: "Did additional issues surface after the exercise?",
    posteriorOk: (n: number) => `Section present with ${n} lines of content.`,
    posteriorVazia:
      "The section exists but is empty. If nothing surfaced during the review, record that explicitly with the date and who reviewed.",
    posteriorAusente:
      "There is no section recording what surfaced after the exercise. This is the one checklist question the tool cannot answer by itself: it describes the outcome of a human review that has not happened yet. The team has to fill it in before submitting.",
    qInventario: "Does the inventory identify the analyzed artifact (contract id, network, WASM hash)?",
    invSemIdBlocker: (id: string) =>
      `Contract id ${id || "(empty)"} missing from the document: the inventory does not identify what was analyzed.`,
    invIdOk: (id: string) => `contract id present (${id})`,
    invIdFalta: (id: string) => `contract id MISSING (${id || "empty in the context"})`,
    invRedeOk: (n: string) => `network present (${n})`,
    invRedeFalta: (n: string) => `network missing (${n || "empty in the context"})`,
    invHashOk: "WASM hash present",
    invHashFalta: (h: string) =>
      `WASM hash missing (${h}…) — without it the report is not reproducible against the exact binary`,
    invHashNA: "WASM hash not available in the context",

    /* monitoring plan */
    mpSemMonitor: "No monitor in the plan. A monitoring plan with no monitor is not submittable.",
    semMonitorDetalhe:
      "No monitor was derived for this contract, so there is nothing to assess here. This is a gap, not an approval: the plan has no active coverage and the team has to define monitoring by hand before submitting.",
    qCobertura: "Does every threat in the threat model have a monitor, or a documented reason it cannot be monitored?",
    cobJustificadaSemDono: (id: string, sev: string) =>
      `Threat ${id} (${sev}) has no monitor, and the document justifies the lack of an on-chain observable with a named off-chain control. What is missing is that control's owner: a ${sev} threat with no active coverage and no owner is not submittable.`,
    cobControleAberto: (id: string, sev: string) =>
      `Threat ${id} (${sev}) has no monitor. The document says there is no on-chain observable, but leaves the substitute control as a gap — saying it cannot be monitored is not covering the threat.`,
    cobSemJustificativa: (id: string, sev: string) =>
      `Threat ${id} (${sev}) with no monitor and no non-monitorability justification in the document.`,
    cobSemAmeacas: "There are no threats in the context to cover — the plan has no traceable origin.",
    cobComMonitor: (n: number, total: number) => `${n}/${total} threats with a monitor`,
    cobJustificadas: (n: number, ids: string) => `${n} declared non-monitorable: ${ids}`,
    cobDescobertas: (ids: string) => `no monitor and no justification: ${ids}`,
    /**
     * Fato, sem tarefa embutida. A frase antiga terminava em "a justificativa precisa estar
     * escrita" — uma pendência dentro do detalhe de uma linha graduada `✔ ok`. Se a
     * justificativa falta, quem diz isso são `cobDescobertas`/`cobControleAberto`, que
     * rebaixam a linha; enunciar a tarefa aqui graduava um pendente como aprovado.
     */
    cobSemEvento: (n: number, total: number) =>
      `${n} of ${total} invocable ${plural(total, "entrypoint", "entrypoints")} ${plural(n, "does", "do")} not reach contract_event (\`__*\` reserved exports excluded, CAP-0058) — for ${plural(n, "it", "those")}, monitoring through getEvents is impossible`,
    qRastreio: "Does every monitor trace back to an existing threat, with an ID derived from it?",
    orfaoBlocker: (id: string, threat: string) =>
      `Monitor ${id} points at threat ${threat}, which does not exist in the threat model.`,
    rastreioSemMonitor:
      "No monitor was derived, so there is no traceability to check. This is a gap, not an approval: either the contract has no threat with an on-chain observable, or the observables were not derived — the plan has no active coverage and needs monitoring defined by hand.",
    rastreioOrfaos: (ids: string) => `orphans (nonexistent threat): ${ids}`,
    rastreioOk: (n: number) =>
      n === 1 ? "the single monitor is anchored to a threat in the document" : `${n} monitors, all anchored to a threat in the document`,
    rastreioForaDoPadrao: (ids: string) => `ID outside the <ThreatID>.M.<n> pattern: ${ids}`,
    qBaseline: "Is the baseline grounded in observation, not guesswork?",
    baseSemBaselineBlocker: (id: string) =>
      `Monitor ${id} has no baseline (baselineTier="none"): there is no defensible threshold, and the template requires a baseline in section 4. No observation window: ${motivoPlaceholder}. Collect a \`getEvents\` window before fixing any threshold — the tool refuses to invent the number.`,
    /** (b) a janela EXISTE e foi coletada; o que falta é ela ser longa o bastante. */
    baseJanelaInsuficienteBlocker: (id: string, ledgers: number) =>
      `Monitor ${id} has no baseline: a window of ${ledgers} ${plural(ledgers, "ledger", "ledgers")} was observed, but it is declared insufficient for an honest baseline. The window was collected — widen it; do not read this as "no observation was made".`,
    /** (b) zero observado é medição — só não sustenta limiar de taxa. */
    baseZeroComLimiarBlocker: (id: string, ledgers: number, topics: string) =>
      `Monitor ${id}: window of ${ledgers} ${plural(ledgers, "ledger", "ledgers")} observed; 0 occurrences of ${topics} — an observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold. Either switch the trigger to any-occurrence or collect a window in which the topic actually fires.`,
    /** (c) monitor que não passa por getEvents: o campo é preenchimento, não lacuna de observação. */
    baseFillInBlocker: (id: string) =>
      `Monitor ${id} has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no \`getEvents\` window would produce it.`,
    baseInventadoBlocker: (id: string) =>
      `Monitor ${id} declares a tier B baseline with no on-chain observation in the context — a baseline asserted as observed without data is exactly the slop this document must not have.`,
    baseJanelaCurtaBlocker: (id: string, ledgers: number) =>
      `Monitor ${id} presents a numeric baseline over a window declared insufficient (${ledgers} ledgers). The field should say "insufficient window", not a plausible number.`,
    baseDivergeBlocker: (d: string) =>
      `Tier B baseline that does not match the observation: ${d}. A number presented as measured without coming from the measurement is an inference wearing the badge of a fact.`,
    baseTopicoFantasmaBlocker: (t: string) =>
      `Tier B baseline over a topic the observed window does not contain: ${t}. A baseline is only tier B for what was actually observed.`,
    baseSemTrafegoBlocker: (ledgers: number) =>
      `The observed window of ${ledgers} ledgers recorded no event of any topic for this contract: that is absence of traffic, not a traffic profile. The counts are real and still cannot support a threshold — widen the window, or state that the thresholds are provisional, before submitting.`,
    baseSemTrafegoDetalhe: (ledgers: number) =>
      `⚠ gap: the window of ${ledgers} ledgers was collected and holds no event of any topic — absence of traffic, not a traffic profile.`,
    baseJanela: (ledgers: number, horas: number, topics: number, insuficiente: boolean) =>
      `observed window: ${ledgers} ledgers (~${horas}h), ${topics} distinct ${plural(topics, "topic", "topics")}${insuficiente ? ", DECLARED INSUFFICIENT" : ""}`,
    baseSemJanela: (motivo: string) => `no on-chain observation in the context (${motivo})`,
    baseSemBaseline: (ids: string) => `without a baseline: ${ids}`,
    baseInventado: (ids: string) => `tier B baseline with no data: ${ids}`,
    baseJanelaCurta: (ids: string) => `plausible number over an insufficient window: ${ids}`,
    baseDiverge: (d: string) => `count that does not match the window: ${d}`,
    baseTopicoFantasma: (t: string) => `unobserved topic presented as a baseline: ${t}`,
    baseZeroComLimiar: (d: string) => `observed zero carrying a rate threshold, which it cannot support: ${d}`,
    baseInferido: (ids: string) => `inferred baseline (tier C, not observed): ${ids}`,
    baseConferidos: (n: number) => `${n} ${plural(n, "baseline", "baselines")} with the count checked against the window`,
    /**
     * Zero observado de um tópico one-shot (um `init` cuja única ocorrência legítima é
     * anterior à janela) É medição — e não é conferência: nada do que o gatilho pegaria
     * precisava cair dentro da janela para o número dar zero.
     */
    baseZeroObservado: (n: number, ids: string) =>
      `${n} ${plural(n, "baseline is", "baselines are")} an observed zero (measurement) and ${plural(n, "does", "do")} not count as checked against the window — for an any-occurrence trigger the only legitimate occurrence may predate the window: ${ids}`,
    qResposta: "Does every monitor have a defined response?",
    respSemBlocker: (id: string) =>
      `Monitor ${id} has no defined response: an alert with no procedure is not monitoring, it is noise.`,
    respSem: (ids: string) => `without a response: ${ids}`,
    respComResposta: (n: number) => `${n} ${plural(n, "monitor", "monitors")} with a response`,
    respOca: (exemplo: string, ids: string) => `generic response, no procedure ("${exemplo}"): ${ids}`,
    qDono: "Does every monitor have a named owner?",
    donoBlocker: (n: number) =>
      `Assign an owner and a notification channel to ${n} ${plural(n, "row", "rows")} of §5; neither is derivable from the binary, and a monitor with no owner has no one to fire at.`,
    donoGap: (com: number, total: number, ids: string, mencao: boolean) =>
      `${com}/${total} monitors with an owner in the document; without an owner: ${ids}. ${mencao ? "There is a mention of someone responsible elsewhere in the document, but not per monitor." : "The document does not name anyone responsible."} The tool does not have this information — it is neither in the bytecode nor on-chain, and the team has to fill it in before submitting.`,
    donoOk: (n: number) =>
      n === 1 ? "The single monitor has a named owner in the document." : `All ${n} monitors have a named owner in the document.`,
    qPrecisao: "Have the alerts been historically accurate?",
    /**
     * §5 diz que nenhum monitor sai deste documento como `Active`. Chamar de "ativo" um
     * monitor em `Tuning`/`Planned` — como esta linha fazia — contradizia a §5 do MESMO
     * documento e graduava como ✔ uma pergunta sobre alertas que nunca dispararam.
     */
    precSemAtivos: (conferidos: number, total: number) =>
      `No monitor is Active yet (${total ? `${total} in the plan, all \`Tuning\` or \`Planned\`` : "there is no monitor in the plan"}); ` +
      `${conferidos} ${plural(conferidos, "carries", "carry")} an observed baseline that was checked against the window, but none has alert history. ` +
      "Accuracy is only answerable after the monitors run: there is no alert yet to be right or wrong about.",
    precSemJanela:
      "There is no observed window in the context, so no monitor was checked against real data: how many times each trigger would have fired is unknown. On a first issue this is expected — the field has to say so and be reassessed after operating, not left implicit.",
    precOk: (ativos: number, ledgers: number) =>
      `${ativos === 1 ? "The single active monitor has" : `The ${ativos} active monitors have`} the baseline count checked against the ${ledgers}-ledger window. That is a backtest over the window, not an operating history: it says how many times the trigger would have fired, not how many alerts were useful.`,
    precParcial: (com: number, ativos: number, ledgers: number, insuficiente: boolean, naoVistos: number, ids: string) =>
      `${com}/${ativos} active monitors with the count checked against the observed window (${ledgers} ledgers)${insuficiente ? ", which is declared insufficient" : ""}. Without checking, there is no way to state a false-positive rate${naoVistos ? `; ${naoVistos} topics declared in the spec were never observed: ${ids}` : ""}.`,
    qEnderecos: "Is the on-chain address inventory present and up to date?",
    endSemIdBlocker: (id: string) =>
      `Contract id ${id || "(empty)"} missing from the document: with no address in the inventory no monitor is executable.`,
    endSemHashBlocker:
      "Record the instance's wasm hash: without it the plan cannot be re-checked against what is deployed.",
    endOk: (id: string, rede: string) => `contract id ${id} present in the document (network ${rede}).`,
    endGap: (id: string) =>
      `contract id ${id || "empty in the context"} does not appear in the document. It is the only address the tool knows for certain, and it is the filter of any getEvents call.`,
    endHashOk: (hash: string, data: string) =>
      ` Analysis run over wasm hash \`${hash}\` on ${data}; a different hash on the instance means this plan describes code that is no longer live.`,
    endHashFalta: (l: string) =>
      ` The WASM hash was not captured at generation time — without it there is no way to state that the plan still describes the code that is live. ${l}`,
    qFronteiras: "Are the external boundaries (contracts called) in the inventory?",
    frontNA: "No entrypoint reaches call/try_call: the contract crosses no boundary, there is no external address to inventory.",
    frontGap: (n: number, eps: string) =>
      `${n} entrypoints reach call/try_call (${eps}). The destination addresses are runtime arguments: they are not derivable from the bytecode and the tool does not invent them. The inventory has to be completed by hand, or the monitoring covers only half the flow.`,
    qOffchain: "Have off-chain threats been identified and declared out of on-chain scope?",
    offOk: (ancoradas: string) =>
      `The document ties the off-chain boundary to what was left out of the on-chain analysis: ${ancoradas}.`,
    offSemAncora: "there is no letter without a finding and no threat without a monitor in this contract",
    offSolta: (ancoras: string) =>
      `The document mentions what is off-chain, but without tying the mention to anything the analysis left out (${ancoras}). A loose mention does not identify a threat: it only says the category exists.`,
    offAusente: (lacunas: string) =>
      `Nothing in the document about off-chain threats.${lacunas ? ` The letters ${lacunas} have no finding derivable from the bytecode precisely because they depend on identity, keys and process — which live off-chain and are not monitorable through getEvents.` : ""} A plan that does not declare that boundary gives the impression of covering what it does not.`,
    qSinal: "Does every monitor have a concrete observable signal and an executable trigger?",
    sinalBlocker: (id: string, oque: string) => `Monitor ${id} without ${oque}: it can be neither executed nor checked.`,
    sinalObservavel: "an observable signal",
    sinalGatilho: "a trigger",
    sinalSemObservavel: (ids: string) => `without an observable: ${ids}`,
    sinalSemGatilho: (ids: string) => `without a trigger: ${ids}`,
    sinalMudo: (n: number, ids: string) =>
      `${n} ${plural(n, "monitor has", "monitors have")} no executable getEvents filter and ${plural(n, "declares", "declare")} no alternative mechanism (getLedgerEntries, state diff, wasm hash, transaction inspection) — there is no endpoint on which ${plural(n, "it could", "they could")} fire: ${ids}`,
    sinalSemTopic: (n: number, total: number, topics: string, ids: string) =>
      `${n} event-based ${plural(n, "monitor cites", "monitors cite")} none of the ${total} ${plural(total, "topic", "topics")} declared in the spec (${topics}) — with no topic the getEvents filter sweeps everything: ${ids}`,
    /**
     * Linha que não pode sair ✔ enquanto um monitor não for nem executável por `getEvents`
     * nem completamente especificado: sem a durabilidade (ou o endereço, ou o hash) a chave
     * de ledger não se monta, e o mesmo preenchimento é blocker de submissão na §6.
     */
    sinalIncompleto: (n: number, ids: string) =>
      `${n} ${plural(n, "monitor is", "monitors are")} neither executable through getEvents nor fully specified — the query cannot be built while the fill-in on the row is open (durability of the entry, address or hash): ${ids}`,
    sinalComTopic: "every event-based monitor cites a topic declared in the spec",
    sinalSemEventBased:
      "no monitor is event-based, so the topic check does not apply: the observables derived here are ledger entries and the transaction, read through getLedgerEntries and by inspecting it",
    sinalSemSpec: "the spec declares no events, so the filter can only be by contractId and the plan depends on a state diff",
    sinalExecutaveis: (n: number, total: number) =>
      `${n} of ${total} ${plural(total, "monitor", "monitors")} ${plural(n, "turns", "turn")} into an RPC call with no manual translation (topic filter from the contract spec)` +
      (n < total ? "; the rest need getLedgerEntries or transaction introspection" : ""),
  },
  pt: {
    docVazio: "Documento vazio: não há markdown renderizado para validar.",
    inputSecao1:
      'Escrever a seção 1, "What are we working on?": o que o protocolo faz, quem são os atores, que valor ' +
      "ele custodia e quais suposições de confiança vivem fora da cadeia. Planilha: a tabela *Objeto " +
      "analisado* e a superfície medida logo abaixo do aviso de lacuna da seção 1 — o bytecode não registra " +
      "nada disso, então nenhuma análise fecha esta.",
    tmSemAmeaca:
      "Nenhuma ameaça derivada do bytecode: o documento não contém um único threat, e as seis letras do STRIDE sairiam como lacuna. Isso não é um threat model submetível — é o laudo de que a análise automática não cobriu este contrato e ele precisa de modelagem manual.",
    qDfd: "O data-flow diagram foi derivado da análise (processos = entrypoints, data stores = chaves de storage, fronteiras = auth e cross-call)?",
    dfdAusenteBlocker: "Nenhum data-flow diagram no contexto: o template exige o DFD como seção 2.",
    dfdAusenteDetalhe:
      "ctx.dfd ausente. Sem DFD não há como responder as perguntas seguintes do checklist, que dependem dele.",
    dfdSemProcesso: "nenhum processo (entrypoint) no diagrama",
    dfdSemStore: "nenhum data store: as chaves de storage não chegaram ao diagrama",
    dfdSemFronteira: "nenhuma fronteira de confiança declarada",
    dfdSemNo: (eps: string) => `entrypoints com achado e sem nó no DFD: ${eps}`,
    dfdSemTravessia: (n: number) =>
      `${n} entrypoints alcançam call/try_call mas nenhuma aresta está marcada como travessia de fronteira`,
    dfdDetalheGap: (p: number, s: number, b: number, faltas: string) =>
      `${p} processos, ${s} stores, ${b} fronteiras. Problemas: ${faltas}.`,
    dfdDetalheOk: (p: number, s: number, b: number, cruzam: number) =>
      `${p} processos ligados a entrypoints reais, ${s} data stores, ${b} fronteiras, ${cruzam} arestas cruzando fronteira.`,
    qDfdRef: "O data-flow diagram foi referenciado depois de criado? (Was the data-flow diagram referenced after it was created?)",
    dfdSemBloco: "O DFD foi derivado mas o bloco ```mermaid não aparece no documento.",
    dfdSemBlocoDetalhe: "O diagrama não está no documento, logo não há o que referenciar.",
    dfdRefOk: (n: number, citados: string) => `${n} elementos do DFD citados no texto depois do diagrama: ${citados}.`,
    dfdRefGap:
      "Nenhum id de nó ou nome de fronteira do DFD aparece no texto após o diagrama. Repetir o nome do entrypoint na tabela de ameaças não conta: o checklist pergunta se o diagrama foi usado para raciocinar, e citar a fronteira que a ameaça atravessa é a evidência disso.",
    qDesign: "O exercício de STRIDE revelou alguma questão de design nova? (Did STRIDE reveal a new design issue?)",
    designOk: (n: number, achados: string) =>
      `${n} achados de natureza estrutural (não são só "falta require_auth nesta função"): ${achados}. A ferramenta não sabe o que era NOVO para o time — ela mostra o que o exercício derivou; marcar o que já era conhecido é do revisor.`,
    designSoEntrypoint: (n: number) =>
      `Os ${n} achados são todos por entrypoint; nenhum toca desenho do sistema (ordem de operações, ciclo de vida do storage, trilha de auditoria, upgrade). A ferramenta não tem como saber o que o time já sabia — se a revisão humana levantou uma questão de desenho, ela precisa ser registrada aqui à mão.`,
    designSemAchado:
      "Nenhum achado derivado do bytecode. Um threat model sem nenhuma questão levantada não é um threat model concluído: ou a análise não rodou, ou o contrato precisa de revisão manual registrada.",
    qRemediacao: "As remediações endereçam de fato as questões levantadas? (Do the remediations address the issues?)",
    remSemBloco: (id: string) => `Ameaça ${id} existe na análise mas não aparece no documento.`,
    remSemRemediacao: (id: string) => `Ameaça ${id} sem remediação no documento.`,
    remGenerica: (id: string) =>
      `Remediação de ${id} não cita nenhum identificador deste contrato (função exportada, chave de storage ou host function). Remediação copiada de checklist não endereça a ameaça — é o risco #5 de slop do PROBLEMA.md, e um revisor a derruba lendo uma linha.`,
    remSemAmeaca:
      "Nenhuma ameaça foi derivada do bytecode, então não há remediação a avaliar. Isso não significa contrato seguro: significa que as classes que a ferramenta cobre não dispararam. As letras declaradas como lacuna continuam exigindo análise manual.",
    remAusentes: (ids: string) => `ausentes do documento: ${ids}`,
    remSem: (ids: string) => `sem remediação: ${ids}`,
    remGenericas: (ids: string) => `remediação genérica (não cita a função nem a host function envolvida): ${ids}`,
    remOk: (n: number) =>
      `${n} ameaças, todas com remediação que cita um identificador deste contrato (export, chave de storage ou host function). O que foi conferido é a ancoragem, não o acerto: se a remediação é a correção CERTA, só revisão humana responde.`,
    qLetras: "Cada letra do STRIDE tem entrada — achado com evidência ou lacuna explicitamente declarada?",
    letraSemAchadoNoDoc: (l: string, ids: string) =>
      `${l}: tem achado na análise (${ids}) e nenhum aparece no documento`,
    letraSemAchadoBlocker: (l: string, ids: string) => `Letra ${l}: nenhum dos achados ${ids} aparece no documento.`,
    letraAusente: (l: string) => `${l}: ausente do documento`,
    letraAusenteBlocker: (l: string) =>
      `Letra ${l} não aparece no documento. O template exige ≥1 entrada por letra do STRIDE — achado ou lacuna declarada.`,
    letraEnchimento: (l: string, n: number) => `${l}: ${n} palavras sem declarar lacuna`,
    letraEnchimentoBlocker: (l: string, n: number) =>
      `Letra ${l} não tem achado derivável do bytecode, e o documento a preencheu com ${n} palavras de prosa sem declarar a lacuna. Texto genérico numa seção obrigatória é o que faz o revisor descartar o documento inteiro.`,
    letraVaziaBlocker: (l: string) => `Letra ${l} aparece no documento sem conteúdo e sem lacuna declarada.`,
    letraComAchado: (l: string) => `${l} (achado)`,
    letraComLacuna: (l: string) => `${l} (lacuna declarada)`,
    letraSemIssue: (l: string) => `${l}: lacuna declarada, sem issue (o template exige ao menos uma)`,
    letraSemIssueBlocker: (l: string) =>
      `Letra ${l} do STRIDE sem issue — o template exige ao menos uma; preencher a partir da planilha na seção de lacuna de ${l} (ela lista a superfície concreta a revisar).`,
    letrasPreenchidas: (n: number) => `${n} de 6 letras preenchidas.`,
    letrasResumo: (com: string, sem: string) =>
      `derivadas do bytecode: ${com || "nenhuma"}; sem achado derivável: ${sem || "nenhuma"}.`,
    letrasProblemas: (p: string) => `Problemas: ${p}.`,
    letrasTodas: (ok: string) => `Todas as seis cobertas: ${ok}.`,
    letrasDivergentes: (d: string) =>
      `⚠ ctx.gaps lista ${d} como lacuna, mas há achado dessas letras — contexto inconsistente.`,
    qNivel: "Toda afirmação carrega o nível de evidência (A/B/C) e uma âncora citável?",
    semEvidenciaBlocker: (id: string) => `Ameaça ${id} sem nenhuma evidência.`,
    soInferenciaBlocker: (id: string) =>
      `Ameaça ${id} sustentada só por inferência (nível C), sem fato de bytecode nem observação on-chain.`,
    semMarcaBlocker: (id: string) =>
      `Ameaça ${id} aparece no documento sem nenhuma marca de nível (A/B/C) nas suas afirmações: o leitor não consegue separar fato de bytecode de inferência.`,
    infladoBlocker: (d: string) =>
      `Nível de evidência inflado — ${d}. Apresentar inferência com a força de fato de bytecode ou de observação on-chain é a única regra que este projeto não quebra (PROBLEMA.md, "nunca apresentar C como A").`,
    infladoA: (id: string, doc: number, ev: number) =>
      `${id}: ${doc} afirmações marcadas (A) para ${ev} ${plural(ev, "evidência", "evidências")} de bytecode`,
    infladoB: (id: string, doc: number, ev: number, semJanela: boolean) =>
      `${id}: ${doc} afirmações marcadas (B) para ${ev} ${plural(ev, "observação", "observações")} on-chain${semJanela ? " — e não há nenhuma janela observada no contexto" : ""}`,
    nivelContagem: (a: number, b: number, c: number) =>
      `${a} afirmações nível A, ${b} nível B, ${c} nível C no contexto.`,
    nivelPorAmeaca: (ok: number, presentes: number, faltando: number, total: number) =>
      `Conferido por ameaça: ${ok}/${presentes} ameaças presentes no documento com marca por afirmação e sem inflar o nível${faltando ? ` (${faltando} das ${total} não aparecem no documento e não puderam ser conferidas)` : ""}.`,
    nivelSemAmeaca:
      "Nenhuma ameaça no contexto: não há afirmação cujo nível conferir, e um documento sem ameaça não é um threat model.",
    nivelSemEvidencia: (ids: string) => `sem evidência: ${ids}.`,
    nivelSoC: (ids: string) => `só nível C: ${ids}.`,
    nivelSemMarca: (ids: string) => `sem marca por afirmação: ${ids}.`,
    nivelInflado: (d: string) => `nível inflado: ${d}.`,
    nivelSemNotacao:
      "O documento não explica nem usa a notação de nível em ponto algum — sem isso o leitor não distingue fato de bytecode de opinião.",
    qLimites: "Os limites da análise estão declarados no documento (call graph incompleto, positivo super-aproximado)?",
    limitesNA: (soundness: string) =>
      `Call graph completo (soundness=${soundness}) e nenhum achado depende de caminho via helper: não há imprecisão a declarar.`,
    limitesOk: (soundness: string, n: number, ids: string, motivo?: string) =>
      `Declarado. soundness=${soundness}${motivo ? `, motivo: ${motivo}` : ""}${n ? `, ${n} achados marcados para revisão por caminho via helper: ${ids}` : ""}.`,
    limitesGap: (soundness: string, n: number, ids: string, motivo?: string) =>
      `soundness=${soundness}${motivo ? ` (${motivo})` : ""}${n ? ` e ${n} achados com caminho longo até a escrita (${ids})` : ""}, e o documento não menciona a imprecisão. Afirmar alcançabilidade sem dizer que o positivo é super-aproximado apresenta C com a força de A.`,
    qPosterior: "Surgiram questões adicionais depois do exercício? (Did additional issues surface afterwards?)",
    posteriorOk: (n: number) => `Seção presente com ${n} linhas de conteúdo.`,
    posteriorVazia:
      "A seção existe mas está vazia. Se nada surgiu na revisão, registrar isso explicitamente com data e quem revisou.",
    posteriorAusente:
      "Não há seção registrando o que surgiu depois do exercício. Esta é a única pergunta do checklist que a ferramenta não pode responder sozinha: ela descreve o resultado de uma revisão humana que ainda não aconteceu. O time precisa preencher antes de submeter.",
    qInventario: "O inventário identifica o artefato analisado (contract id, rede, hash do WASM)?",
    invSemIdBlocker: (id: string) =>
      `Contract id ${id || "(vazio)"} ausente do documento: o inventário não identifica o que foi analisado.`,
    invIdOk: (id: string) => `contract id presente (${id})`,
    invIdFalta: (id: string) => `contract id AUSENTE (${id || "vazio no contexto"})`,
    invRedeOk: (n: string) => `rede presente (${n})`,
    invRedeFalta: (n: string) => `rede ausente (${n || "vazia no contexto"})`,
    invHashOk: "hash do WASM presente",
    invHashFalta: (h: string) =>
      `hash do WASM ausente (${h}…) — sem ele o laudo não é reproduzível contra o binário exato`,
    invHashNA: "hash do WASM não disponível no contexto",

    mpSemMonitor: "Nenhum monitor no plano. Um monitoring plan sem monitor não é submetível.",
    semMonitorDetalhe:
      "Nenhum monitor foi derivado para este contrato, então não há o que avaliar aqui. É lacuna, não aprovação: o plano fica sem cobertura ativa e o time precisa definir monitoramento à mão antes de submeter.",
    qCobertura: "Toda ameaça do threat model tem monitor ou justificativa de não-monitorabilidade? (Does the plan cover the threat model?)",
    cobJustificadaSemDono: (id: string, sev: string) =>
      `Ameaça ${id} (${sev}) não tem monitor, e o documento justifica a não-monitorabilidade on-chain com um controle fora da chain nomeado. Falta o dono desse controle: ameaça ${sev} sem cobertura ativa e sem responsável não é submetível.`,
    cobControleAberto: (id: string, sev: string) =>
      `Ameaça ${id} (${sev}) não tem monitor. O documento diz que não há observável on-chain, mas deixa o controle substituto como lacuna — dizer que não dá para monitorar não é cobrir a ameaça.`,
    cobSemJustificativa: (id: string, sev: string) =>
      `Ameaça ${id} (${sev}) sem monitor e sem justificativa de não-monitorabilidade no documento.`,
    cobSemAmeacas: "Não há ameaças no contexto para cobrir — o plano não tem origem rastreável.",
    cobComMonitor: (n: number, total: number) => `${n}/${total} ameaças com monitor`,
    cobJustificadas: (n: number, ids: string) => `${n} declaradas não monitoráveis: ${ids}`,
    cobDescobertas: (ids: string) => `sem monitor e sem justificativa: ${ids}`,
    cobSemEvento: (n: number, total: number) =>
      `${n} de ${total} ${plural(total, "entrypoint invocável", "entrypoints invocáveis")} ${plural(n, "não alcança", "não alcançam")} contract_event (exports reservados \`__*\` excluídos, CAP-0058) — para ${plural(n, "ele", "esses")}, monitoramento por getEvents é impossível`,
    qRastreio: "Todo monitor rastreia até uma ameaça existente, com ID derivado dela?",
    orfaoBlocker: (id: string, threat: string) =>
      `Monitor ${id} aponta para a ameaça ${threat}, que não existe no threat model.`,
    rastreioSemMonitor:
      "Nenhum monitor foi derivado, então não há rastreio a verificar. Isso é lacuna, não aprovação: ou o contrato não tem ameaça com observável on-chain, ou os observáveis não foram derivados — o plano fica sem cobertura ativa e precisa de monitoramento definido à mão.",
    rastreioOrfaos: (ids: string) => `órfãos (ameaça inexistente): ${ids}`,
    rastreioOk: (n: number) =>
      n === 1 ? "o único monitor está ancorado numa ameaça do documento" : `${n} monitores, todos ancorados numa ameaça do documento`,
    rastreioForaDoPadrao: (ids: string) => `ID fora do padrão <ThreatID>.M.<n>: ${ids}`,
    qBaseline: "O baseline vem de observação, não de chute? (Is the baseline grounded, not guesswork?)",
    baseSemBaselineBlocker: (id: string) =>
      `Monitor ${id} sem baseline (baselineTier="none"): não há limiar defensável, e o template exige baseline na seção 4. Sem janela de observação: ${motivoPlaceholder}. Coletar uma janela de \`getEvents\` antes de fixar qualquer limiar — a ferramenta se recusa a inventar o número.`,
    baseJanelaInsuficienteBlocker: (id: string, ledgers: number) =>
      `Monitor ${id} sem baseline: uma janela de ${ledgers} ${plural(ledgers, "ledger", "ledgers")} foi observada, mas está declarada insuficiente para um baseline honesto. A janela FOI coletada — ampliá-la; isto não é "nenhuma observação foi feita".`,
    baseZeroComLimiarBlocker: (id: string, ledgers: number, topics: string) =>
      `Monitor ${id}: janela de ${ledgers} ${plural(ledgers, "ledger", "ledgers")} observada; 0 ocorrências de ${topics} — um zero observado é medição, mas sustenta só gatilho de qualquer ocorrência, não limiar de taxa. Ou o gatilho vira qualquer-ocorrência, ou é preciso uma janela em que o tópico de fato dispare.`,
    baseFillInBlocker: (id: string) =>
      `Monitor ${id} sem baseline registrado: este monitor não é baseado em evento; o baseline dele é o valor on-chain corrente (hash / conjunto de chaves), a registrar na aprovação do plano — ⟨a preencher⟩. Isso é preenchimento, não lacuna de observação: nenhuma janela de \`getEvents\` o produziria.`,
    baseInventadoBlocker: (id: string) =>
      `Monitor ${id} declara baseline nível B sem nenhuma observação on-chain no contexto — baseline afirmado como observado sem dado é exatamente o slop que o documento precisa não ter.`,
    baseJanelaCurtaBlocker: (id: string, ledgers: number) =>
      `Monitor ${id} apresenta baseline numérico sobre uma janela declarada insuficiente (${ledgers} ledgers). O campo deveria dizer "janela insuficiente", não um número plausível.`,
    baseDivergeBlocker: (d: string) =>
      `Baseline nível B que não bate com a observação: ${d}. Número apresentado como medido sem sair da medição é inferência com crachá de fato.`,
    baseTopicoFantasmaBlocker: (t: string) =>
      `Baseline nível B sobre tópico que a janela observada não contém: ${t}. Um baseline só é nível B para o que foi de fato observado.`,
    baseSemTrafegoBlocker: (ledgers: number) =>
      `A janela observada de ${ledgers} ledgers não registrou evento de nenhum tópico deste contrato: isso é ausência de tráfego, não perfil de tráfego. As contagens são reais e ainda assim não sustentam limiar — ampliar a janela, ou declarar os limiares como provisórios, antes de submeter.`,
    baseSemTrafegoDetalhe: (ledgers: number) =>
      `⚠ lacuna: a janela de ${ledgers} ledgers foi coletada e não contém evento de nenhum tópico — ausência de tráfego, não perfil de tráfego.`,
    baseJanela: (ledgers: number, horas: number, topics: number, insuficiente: boolean) =>
      `janela observada: ${ledgers} ledgers (~${horas}h), ${topics} ${plural(topics, "topic distinto", "topics distintos")}${insuficiente ? ", DECLARADA INSUFICIENTE" : ""}`,
    baseSemJanela: (motivo: string) => `nenhuma observação on-chain no contexto (${motivo})`,
    baseSemBaseline: (ids: string) => `sem baseline: ${ids}`,
    baseInventado: (ids: string) => `baseline nível B sem dado: ${ids}`,
    baseJanelaCurta: (ids: string) => `número plausível sobre janela insuficiente: ${ids}`,
    baseDiverge: (d: string) => `contagem que não bate com a janela: ${d}`,
    baseTopicoFantasma: (t: string) => `tópico não observado apresentado como baseline: ${t}`,
    baseZeroComLimiar: (d: string) => `zero observado sustentando limiar de taxa, que ele não sustenta: ${d}`,
    baseInferido: (ids: string) => `baseline inferido (nível C, não observado): ${ids}`,
    baseConferidos: (n: number) => `${n} ${plural(n, "baseline", "baselines")} com a contagem conferida contra a janela`,
    baseZeroObservado: (n: number, ids: string) =>
      `${n} ${plural(n, "baseline é", "baselines são")} zero observado (medição) e não ${plural(n, "conta", "contam")} como conferido contra a janela — num gatilho de qualquer ocorrência a única ocorrência legítima pode ser anterior à janela: ${ids}`,
    qResposta: "Cada monitor tem resposta definida? (Are responses defined?)",
    respSemBlocker: (id: string) =>
      `Monitor ${id} sem resposta definida: um alerta sem procedimento não é monitoramento, é ruído.`,
    respSem: (ids: string) => `sem resposta: ${ids}`,
    respComResposta: (n: number) => `${n} ${plural(n, "monitor com resposta", "monitores com resposta")}`,
    respOca: (exemplo: string, ids: string) => `resposta genérica, sem procedimento ("${exemplo}"): ${ids}`,
    qDono: "Cada monitor tem dono nomeado? (Are owners defined?)",
    donoBlocker: (n: number) =>
      `Atribuir dono e canal de notificação a ${n} ${plural(n, "linha", "linhas")} da §5; nenhum dos dois é derivável do binário, e monitor sem dono não tem para quem disparar.`,
    donoGap: (com: number, total: number, ids: string, mencao: boolean) =>
      `${com}/${total} monitores com dono no documento; sem dono: ${ids}. ${mencao ? "Há menção a responsável em outro ponto do documento, mas não por monitor." : "O documento não nomeia nenhum responsável."} A ferramenta não tem essa informação — ela não está no bytecode nem on-chain, e o time precisa preencher antes de submeter.`,
    donoOk: (n: number) =>
      n === 1 ? "O único monitor tem responsável nomeado no documento." : `Todos os ${n} monitores têm responsável nomeado no documento.`,
    qPrecisao: "A precisão histórica dos alertas foi avaliada? (Have the alerts been historically accurate?)",
    precSemAtivos: (conferidos: number, total: number) =>
      `Nenhum monitor está \`Active\` ainda (${total ? `${total} no plano, todos em \`Tuning\` ou \`Planned\`` : "não há monitor no plano"}); ` +
      `${conferidos} ${plural(conferidos, "carrega", "carregam")} baseline observado e conferido contra a janela, mas nenhum tem histórico de alerta. ` +
      "Precisão só se responde depois de operar: ainda não há alerta sobre o qual acertar ou errar.",
    precSemJanela:
      "Não há janela observada no contexto, então nenhum monitor foi conferido contra dado real: não se sabe quantas vezes cada gatilho teria disparado. Numa primeira emissão isso é esperado — o campo precisa dizer isso e ser reavaliado depois de operar, não ser deixado implícito.",
    precOk: (ativos: number, ledgers: number) =>
      `${ativos === 1 ? "O único monitor ativo tem" : `Os ${ativos} monitores ativos têm`} a contagem do baseline conferida contra a janela de ${ledgers} ledgers. Isso é backtest na janela, não histórico de operação: diz quantas vezes o gatilho teria disparado, não quantos alertas foram úteis.`,
    precParcial: (com: number, ativos: number, ledgers: number, insuficiente: boolean, naoVistos: number, ids: string) =>
      `${com}/${ativos} monitores ativos com a contagem conferida contra a janela observada (${ledgers} ledgers)${insuficiente ? ", que está declarada insuficiente" : ""}. Sem conferir, não há como afirmar taxa de falso positivo${naoVistos ? `; ${naoVistos} topics declarados no spec nunca foram observados: ${ids}` : ""}.`,
    qEnderecos: "O inventário de endereços on-chain está presente e atualizado? (Are the addresses up to date?)",
    endSemIdBlocker: (id: string) =>
      `Contract id ${id || "(vazio)"} ausente do documento: sem o endereço no inventário nenhum monitor é executável.`,
    endSemHashBlocker:
      "Registrar o wasm hash da instância: sem ele o plano não pode ser reconferido contra o que está deployado.",
    endOk: (id: string, rede: string) => `contract id ${id} presente no documento (rede ${rede}).`,
    endGap: (id: string) =>
      `contract id ${id || "vazio no contexto"} não aparece no documento. É o único endereço que a ferramenta conhece com certeza, e ele é o filtro de qualquer chamada de getEvents.`,
    endHashOk: (hash: string, data: string) =>
      ` Análise feita sobre o wasm hash \`${hash}\` em ${data}; hash diferente na instância significa que este plano descreve código que não está mais no ar.`,
    endHashFalta: (l: string) =>
      ` Hash do WASM não foi capturado na geração — sem ele não há como afirmar que o plano ainda descreve o código no ar. ${l}`,
    qFronteiras: "As fronteiras externas (contratos chamados) estão no inventário?",
    frontNA: "Nenhum entrypoint alcança call/try_call: o contrato não cruza fronteira, não há endereço externo a inventariar.",
    frontGap: (n: number, eps: string) =>
      `${n} entrypoints alcançam call/try_call (${eps}). Os endereços de destino são argumentos de runtime: não são deriváveis do bytecode e a ferramenta não os inventa. O inventário precisa ser completado à mão, ou o monitoramento cobre só metade do fluxo.`,
    qOffchain: "As ameaças off-chain estão identificadas e declaradas fora do escopo on-chain? (Have off-chain threats been identified?)",
    offOk: (ancoradas: string) =>
      `O documento liga a fronteira off-chain ao que ficou de fora da análise on-chain: ${ancoradas}.`,
    offSemAncora: "não há letra sem achado nem ameaça sem monitor neste contrato",
    offSolta: (ancoras: string) =>
      `O documento menciona o que é off-chain, mas sem prender a menção a nada que a análise deixou de fora (${ancoras}). Menção solta não identifica ameaça: diz só que a categoria existe.`,
    offAusente: (lacunas: string) =>
      `Nada no documento sobre ameaças off-chain.${lacunas ? ` As letras ${lacunas} não têm achado derivável do bytecode justamente porque dependem de identidade, chaves e processo — que vivem fora da chain e não são monitoráveis por getEvents.` : ""} Um plano que não declara essa fronteira dá a impressão de cobrir o que não cobre.`,
    qSinal: "Cada monitor tem sinal observável concreto e gatilho executável?",
    sinalBlocker: (id: string, oque: string) => `Monitor ${id} sem ${oque}: não dá para executar nem conferir.`,
    sinalObservavel: "sinal observável",
    sinalGatilho: "gatilho",
    sinalSemObservavel: (ids: string) => `sem observável: ${ids}`,
    sinalSemGatilho: (ids: string) => `sem gatilho: ${ids}`,
    sinalMudo: (n: number, ids: string) =>
      `${n} ${plural(n, "monitor não tem", "monitores não têm")} filtro executável de getEvents e ${plural(n, "não declara", "não declaram")} mecanismo alternativo (getLedgerEntries, diff de estado, wasm hash, inspeção da transação) — não há endpoint em que ${plural(n, "ele possa", "eles possam")} disparar: ${ids}`,
    sinalSemTopic: (n: number, total: number, topics: string, ids: string) =>
      `${n} ${plural(n, "monitor baseado em evento não cita", "monitores baseados em evento não citam")} nenhum dos ${total} ${plural(total, "topic declarado", "topics declarados")} no spec (${topics}) — sem topic o filtro de getEvents varre tudo: ${ids}`,
    sinalIncompleto: (n: number, ids: string) =>
      `${n} ${plural(n, "monitor não é executável", "monitores não são executáveis")} por getEvents nem completamente especificado${plural(n, "", "s")} — a consulta não se monta enquanto o preenchimento da linha estiver aberto (durabilidade da entrada, endereço ou hash): ${ids}`,
    sinalComTopic: "todo monitor baseado em evento cita topic declarado no spec",
    sinalSemEventBased:
      "nenhum monitor é baseado em evento, então a checagem de topic não se aplica: os observáveis derivados aqui são ledger entries e a transação, lidos por getLedgerEntries e por inspeção",
    sinalSemSpec: "o spec não declara eventos, então o filtro só pode ser por contractId e o plano depende de diff de estado",
    sinalExecutaveis: (n: number, total: number) =>
      `${n} de ${total} ${plural(total, "monitor vira", "monitores viram")} chamada de RPC sem tradução manual (filtro de tópicos vindo do contract spec)` +
      (n < total ? "; os demais exigem getLedgerEntries ou inspeção da transação" : ""),
  },
});

/* ---------- utilidades de leitura do markdown ---------- */

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** ID de achado/monitor: `Elevation.1` não pode casar dentro de `Elevation.10` nem de `Elevation.1.M.1`. */
const reId = (id: string) => new RegExp(`(?<![\\w.])${esc(id)}(?![\\w.])`);

/**
 * ID de remediação no padrão do template: `Elevation.1.R.1`.
 * Precisa de regex própria porque `reId` tem lookahead negativo de ponto — de propósito,
 * para `Elevation.1` não casar com `Elevation.10` — e isso a impede de ver os `.R.n`.
 */
const reRem = (id: string) => new RegExp(`(?<![\\w.])${esc(id)}\\.R\\.\\d+(?![\\w.])`);

/** Letra do STRIDE: sensível a caixa de propósito — `\bDoS\b` insensível casaria com o "dos" português. */
const reLetra = (l: Stride) => new RegExp(`\\b${l}\\b`);

type Linhas = { linhas: string[]; cercada: boolean[] };

/** Marca as linhas dentro de blocos cercados, inclusive as próprias cercas. */
function fatiar(md: string): Linhas {
  const linhas = md.split(/\r?\n/);
  const cercada: boolean[] = [];
  let aberta: string | undefined;
  for (const l of linhas) {
    const m = /^\s*(```+|~~~+)/.exec(l);
    if (aberta === undefined) {
      if (m) { aberta = m[1][0]; cercada.push(true); } else cercada.push(false);
      continue;
    }
    cercada.push(true);
    if (m && m[1][0] === aberta) aberta = undefined;
  }
  return { linhas, cercada };
}

/**
 * Só a prosa. O conteúdo cercado é excluído porque o mermaid do DFD contém todos os
 * nomes de entrypoint: contá-lo faria qualquer documento "referenciar" o diagrama só
 * por tê-lo desenhado — que é exatamente o oposto do que o checklist pergunta.
 */
function prosa(md: string): string {
  const { linhas, cercada } = fatiar(md);
  return linhas.filter((_, i) => !cercada[i]).join("\n");
}

const EH_TITULO = /^\s{0,3}#{1,6}\s/;
/**
 * Teto de linhas de um bloco. O delimitador real é o próximo título ou o próximo ID
 * concorrente; este número só existe para um documento malformado não varrer o arquivo
 * inteiro. Ficou em 14 enquanto o achado mais longo cabia nisso — e passou a MENTIR quando
 * classes com 5+ linhas de evidência entraram: a janela cortava antes da primeira marca
 * `[C]`, e uma inferência promovida a `[A]` no fim do bloco passava despercebida, que é
 * exatamente a regra que este validador existe para não deixar quebrar.
 */
const LIMITE_BLOCO = 40;

/**
 * Escopo textual de um termo: da linha onde ele aparece até o próximo título, a próxima
 * ocorrência de outro termo concorrente, ou 14 linhas. Cobre as duas formas que os
 * templates usam — seção com título e linha de tabela — sem acoplar a um renderizador
 * específico, o que importa porque quem renderiza é outro módulo.
 */
function blocoLinhas(md: string, re: RegExp, concorrentes: readonly RegExp[] = []): string[] {
  const { linhas, cercada } = fatiar(md);
  const out: string[] = [];
  for (let i = 0; i < linhas.length; i++) {
    if (cercada[i] || !re.test(linhas[i])) continue;
    out.push(linhas[i]);
    for (let j = i + 1; j < Math.min(linhas.length, i + LIMITE_BLOCO); j++) {
      if (cercada[j] || EH_TITULO.test(linhas[j])) break;
      // Identidade de objeto NÃO serve: quem chama monta `reId(id)` na hora e passa a lista
      // pré-construída como concorrentes, então o próprio termo entrava como concorrente de
      // si mesmo e truncava o bloco na segunda menção. Comparar por fonte é o que o desenho
      // sempre quis dizer.
      if (concorrentes.some((c) => c.source !== re.source && c.test(linhas[j]))) break;
      out.push(linhas[j]);
    }
  }
  return out;
}

function bloco(md: string, re: RegExp, concorrentes: readonly RegExp[] = []): string {
  return blocoLinhas(md, re, concorrentes).join("\n");
}

/** Conta as marcas de nível POR AFIRMAÇÃO nas linhas dadas. */
function contaNiveis(linhas: readonly string[]): { A: number; B: number; C: number } {
  const out = { A: 0, B: 0, C: 0 };
  for (const l of linhas) {
    for (const m of l.matchAll(TOKEN_NIVEL)) out[(m[1] ?? m[2]) as "A" | "B" | "C"]++;
  }
  return out;
}

function mencoes(md: string, re: RegExp): string[] {
  const { linhas, cercada } = fatiar(md);
  return linhas.filter((l, i) => !cercada[i] && re.test(l));
}

/** Palavras "de conteúdo": ignora pontuação de tabela e marcação, para medir prosa real. */
const palavras = (s: string) =>
  s.replace(/[|`*_#>[\]()–—-]/g, " ").split(/\s+/).filter((w) => w.length > 2).length;

const lista = (xs: readonly string[], n = 6) =>
  xs.length <= n ? xs.join(", ") : `${xs.slice(0, n).join(", ")} … (+${xs.length - n})`;

const idDe = (f: Finding) => f.id ?? `${f.stride}.?`;

/**
 * Isola as linhas de remediação dentro de um bloco.
 *
 * Medido contra o corpus: testar "esta remediação é concreta?" no bloco inteiro APROVA
 * remediação genérica, porque as linhas de evidência ao lado estão cheias de crases e de
 * nomes de host function e acabam respondendo pela remediação. Um documento com
 * "aplicar controles de acesso adequados" passou verde na primeira rodada por causa disso.
 */
function trechoRemediacao(b: string): string {
  const ls = b.split(/\r?\n/);
  const out: string[] = [];
  for (let i = 0; i < ls.length; i++) {
    if (!MARCA_REMEDIACAO.test(ls[i])) continue;
    out.push(ls[i]);
    for (let j = i + 1; j < ls.length && ls[j].trim() && !MARCA_REMEDIACAO.test(ls[j]); j++) out.push(ls[j]);
  }
  return out.join("\n");
}

/**
 * Célula de dono por linha de tabela. O template oficial põe o responsável numa coluna,
 * e é preciso ler a coluna: procurar a palavra "dono" solta casa dentro da resposta
 * ("escalar para o dono do contrato") e aprova um plano sem nenhum responsável nomeado.
 */
function donoPorLinha(md: string): Map<number, string> {
  const { linhas, cercada } = fatiar(md);
  const out = new Map<number, string>();
  let col = -1;
  for (let i = 0; i < linhas.length; i++) {
    const l = linhas[i].trim();
    if (cercada[i] || !l.startsWith("|")) { col = -1; continue; }
    const celulas = l.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
    if (celulas.every((c) => /^:?-{2,}:?$/.test(c))) continue; // linha separadora da tabela
    const idx = celulas.findIndex((c) => MARCA_DONO.test(c) && palavras(c) <= 3);
    if (col < 0 && idx >= 0) { col = idx; continue; }
    if (col >= 0) out.set(i, celulas[col] ?? "");
  }
  return out;
}

/**
 * A remediação cita algo deste contrato? Qualquer nome de export, chave de storage ou
 * host function serve — a régua é baixa de propósito, porque o que se quer barrar é o
 * texto que serviria para qualquer contrato do mundo, não exigir uma redação específica.
 */
function citaIdentificador(rem: string, ctx: ArtifactContext): boolean {
  if (!rem.trim()) return false;
  if (MARCA_CONCRETA.test(rem)) return true;
  for (const m of rem.matchAll(CRASE_CODIGO)) {
    if (ehCodigo(m[1])) return true;
  }
  const nomes = [
    ...ctx.analysis.entrypoints.map((e) => e.name),
    ...(ctx.storageKeys ?? []).map((k) => k.key),
  ].filter((n) => n.length >= 4);
  return nomes.some((n) => rem.includes(n));
}

/**
 * Tópicos citados num texto de baseline: os símbolos dentro de `[...]`.
 * As marcas de nível (`[A]`, `[B]`, `[C]`) e qualquer coisa com espaço ficam de fora —
 * tópico de evento Soroban é um símbolo, não uma frase.
 */
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

/** Número inteiro que precede imediatamente um termo (`7 emissões`, `17280 ledgers`). */
function numeroAntesDe(txt: string, termo: RegExp): number | undefined {
  const re = new RegExp(`(\\d[\\d.,]*)\\s*(?:${termo.source})`, termo.flags.replace("g", ""));
  const m = re.exec(txt);
  if (!m) return undefined;
  const n = Number(m[1].replace(/[.,]/g, ""));
  return Number.isFinite(n) ? n : undefined;
}

/**
 * TODAS as linhas fora de cerca onde o termo aparece. Pegar só a primeira quebrava a
 * leitura da coluna de dono: um monitor é citado antes na tabela de cenários e só
 * depois na tabela que tem a coluna Owner.
 */
/**
 * O veredito de três estados.
 *
 * Dois estados mentiam nos dois sentidos. `submittable: false` num documento cujo único
 * pendente é "a equipe precisa nomear o dono do alerta" diz ao time que a ferramenta falhou;
 * `submittable: true` só chegaria apagando o pendente. O terceiro estado separa o que a
 * FERRAMENTA deveria ter cumprido (`blockers`) do que só um humano fecha (`needsInput`) —
 * e a ordem importa: um blocker da ferramenta nunca é encoberto por um preenchimento.
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

function linhasDe(md: string, re: RegExp): number[] {
  const { linhas, cercada } = fatiar(md);
  const out: number[] = [];
  for (let i = 0; i < linhas.length; i++) if (!cercada[i] && re.test(linhas[i])) out.push(i);
  return out;
}

/* ================= threat model ================= */

export function validateThreatModel(ctx: ArtifactContext, markdown: string): ValidationReport {
  const md = markdown ?? "";
  const texto = prosa(md);
  const items: ChecklistItem[] = [];
  const blockers: string[] = [];
  /** Pendências que nenhuma análise fecha — ver `veredito`. */
  const needsInput: string[] = [];
  const add = (question: string, status: ChecklistItem["status"], detail: string) =>
    items.push({ question, status, detail });

  if (!md.trim()) blockers.push(M.docVazio);
  // A §1 continua por escrever enquanto o aviso de lacuna do renderizador estiver no documento.
  if (md.trim() && MARCA_LACUNA_EQUIPE.test(md)) needsInput.push(M.inputSecao1);

  const ids = ctx.findings.map(idDe);
  const resIds = ids.map(reId);

  /*
   * Zero ameaças não é "contrato limpo": é a análise não tendo produzido documento.
   * As seis letras cairiam como lacuna declarada e o checklist passaria verde num arquivo
   * que não contém um único threat — o resultado mais enganoso que este módulo pode dar.
   * Medido: 9 dos 75 contratos do corpus caem aqui.
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
    const cruzam = ctx.analysis.entrypoints.filter((e) => callsOut(e)).length;
    const arestasQueCruzam = dfd.edges.filter((e) => e.crossesBoundary).length;
    const faltas: string[] = [];
    if (!processos.length) faltas.push(M.dfdSemProcesso);
    if (!stores.length) faltas.push(M.dfdSemStore);
    if (!dfd.boundaries.length) faltas.push(M.dfdSemFronteira);
    if (semNo.length) faltas.push(M.dfdSemNo(lista(semNo)));
    if (cruzam && !arestasQueCruzam) faltas.push(M.dfdSemTravessia(cruzam));
    add(
      M.qDfd,
      faltas.length ? "gap" : "ok",
      faltas.length
        ? M.dfdDetalheGap(processos.length, stores.length, dfd.boundaries.length, faltas.join("; "))
        : M.dfdDetalheOk(processos.length, stores.length, dfd.boundaries.length, arestasQueCruzam),
    );

    /* 2 — o diagrama foi USADO, ou desenhado e esquecido? */
    const { linhas, cercada } = fatiar(md);
    let fimDiagrama = -1;
    for (let i = 0; i < linhas.length; i++) {
      if (/^\s*(```+|~~~+)\s*mermaid/i.test(linhas[i])) {
        fimDiagrama = i + 1;
        while (fimDiagrama < linhas.length && cercada[fimDiagrama]) fimDiagrama++;
        break;
      }
    }
    if (fimDiagrama < 0) {
      blockers.push(M.dfdSemBloco);
      add(M.qDfdRef, "gap", M.dfdSemBlocoDetalhe);
    } else {
      const depois = linhas.filter((_, i) => i >= fimDiagrama && !cercada[i]).join("\n");
      // Só IDs de nó e de fronteira contam. Repetir o nome do entrypoint não é referenciar o
      // diagrama: toda tabela de ameaças faz isso sem nunca olhar para o DFD.
      const alvos = [...dfd.nodes.map((n) => n.id), ...dfd.boundaries.map((b) => b.id), ...dfd.boundaries.map((b) => b.label)]
        .filter((a) => a && a.length >= 2);
      const citados = [...new Set(alvos.filter((a) => depois.includes(a)))];
      add(M.qDfdRef, citados.length ? "ok" : "gap", citados.length ? M.dfdRefOk(citados.length, lista(citados)) : M.dfdRefGap);
    }
  }

  /* 3 — o exercício produziu questão de DESENHO, ou só relistou a superfície? */
  const ESTRUTURAL = new Set(["silent-mutation", "archival-risk", "write-before-auth", "unguarded-upgrade", "vulnerable-sdk", "initialization-front-running"]);
  const estruturais = ctx.findings.filter((f) => ESTRUTURAL.has(f.class));
  const noDoc = estruturais.filter((f) => reId(idDe(f)).test(texto));
  add(
    M.qDesign,
    noDoc.length ? "ok" : "gap",
    noDoc.length
      ? M.designOk(noDoc.length, lista(noDoc.map((f) => `${idDe(f)} ${f.class}`)))
      : ctx.findings.length
        ? M.designSoEntrypoint(ctx.findings.length)
        : M.designSemAchado,
  );

  /* 4 — remediação presente E específica */
  const semBloco: string[] = [];
  const semRemediacao: string[] = [];
  const genericas: string[] = [];
  for (const f of ctx.findings) {
    const id = idDe(f);
    const b = bloco(md, reId(id), resIds);
    if (!b.trim()) { semBloco.push(id); continue; }
    // A presença do ID `<ameaça>.R.<n>` no documento é o sinal forte; a marca textual
    // só entra como alternativa para documentos editados à mão que não seguiram a numeração.
    const temRem = reRem(id).test(md) || MARCA_REMEDIACAO.test(b);
    if (!temRem) { semRemediacao.push(id); continue; }
    // Só o texto DA remediação entra no teste de concretude — ver trechoRemediacao().
    const rem = bloco(md, reRem(id)) || trechoRemediacao(b);
    if (!citaIdentificador(rem, ctx)) genericas.push(id);
  }
  for (const id of semBloco) blockers.push(M.remSemBloco(id));
  for (const id of semRemediacao) blockers.push(M.remSemRemediacao(id));
  for (const id of genericas) blockers.push(M.remGenerica(id));
  add(
    M.qRemediacao,
    semBloco.length || semRemediacao.length || genericas.length ? "gap" : ctx.findings.length ? "ok" : "gap",
    !ctx.findings.length
      ? M.remSemAmeaca
      : [
          semBloco.length ? M.remAusentes(lista(semBloco)) : "",
          semRemediacao.length ? M.remSem(lista(semRemediacao)) : "",
          genericas.length ? M.remGenericas(lista(genericas)) : "",
        ].filter(Boolean).join("; ")
          || M.remOk(ctx.findings.length),
  );

  /* 5 — as seis letras, com achado ou com lacuna declarada */
  const comAchado = new Set(ctx.findings.map((f) => f.stride));
  const semAchado = LETRAS.filter((l) => !comAchado.has(l));
  const divergentes = ctx.gaps.filter((g) => comAchado.has(g));
  // construídos uma vez: `bloco` identifica o próprio termo por fonte da regex
  const resLetras = LETRAS.map(reLetra);
  const okLetras: string[] = [];
  const problemas: string[] = [];
  // "Preenchida" é letra com issue QUE APARECE no documento — não letra com achado na análise:
  // um achado que não chegou ao texto não cumpre o "≥1 por letra" do template.
  let preenchidas = 0;
  for (const l of LETRAS) {
    if (comAchado.has(l)) {
      const seus = ctx.findings.filter((f) => f.stride === l).map(idDe);
      if (seus.some((id) => reId(id).test(texto))) { okLetras.push(M.letraComAchado(l)); preenchidas++; }
      else {
        problemas.push(M.letraSemAchadoNoDoc(l, lista(seus)));
        blockers.push(M.letraSemAchadoBlocker(l, lista(seus)));
      }
      continue;
    }
    const men = mencoes(md, resLetras[LETRAS.indexOf(l)]);
    if (!men.length) {
      problemas.push(M.letraAusente(l));
      blockers.push(M.letraAusenteBlocker(l));
      continue;
    }
    // A janela do bloco precisa parar na PRÓXIMA letra: numa lista de lacunas, o bullet
    // seguinte ("- Tamper: nenhuma ameaça derivável…") declarava a lacuna da letra anterior
    // e deixava passar uma Spoof preenchida com genérico. Medido na suíte adversarial.
    const b = bloco(md, resLetras[LETRAS.indexOf(l)], resLetras);
    // Lacuna declarada é o texto CERTO (ver PROBLEMA.md: campo honestamente vazio > enchimento),
    // e por isso ela continua listada como cobertura declarada. O template oficial exige ≥1 issue
    // por letra, então a letra vazia continua barrando a submissão — mas como PREENCHIMENTO, não
    // como falha da ferramenta: o bytecode não sustenta issue nessa letra, e a planilha da própria
    // lacuna diz qual é a superfície a revisar. Chamar isso de blocker fazia todo contrato real
    // sair "NÃO submetível" sem distinguir documento errado de documento à espera do time.
    if (MARCA_LACUNA.test(b)) {
      okLetras.push(M.letraComLacuna(l));
      problemas.push(M.letraSemIssue(l));
      needsInput.push(M.letraSemIssueBlocker(l));
      continue;
    }
    const maiorProsa = Math.max(...men.map(palavras));
    problemas.push(M.letraEnchimento(l, maiorProsa));
    blockers.push(maiorProsa >= 8 ? M.letraEnchimentoBlocker(l, maiorProsa) : M.letraVaziaBlocker(l));
  }
  // Contexto que se contradiz não é "ok com ressalva": `ctx.gaps` dizendo lacuna onde há achado
  // significa que o documento vai declarar lacuna numa letra que tem ameaça derivada.
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

  /* 6 — evidência citável e nível marcado */
  const semEvidencia = ctx.findings.filter((f) => !f.evidence.length).map(idDe);
  const semFato = ctx.findings.filter((f) => f.evidence.length && !f.evidence.some((e) => (e.tier === "A" || e.tier === "B") && e.claim.trim())).map(idDe);
  for (const id of semEvidencia) blockers.push(M.semEvidenciaBlocker(id));
  for (const id of semFato) blockers.push(M.soInferenciaBlocker(id));
  const marcaNivel = MARCA_NIVEL.test(texto);
  const nA = ctx.findings.flatMap((f) => f.evidence).filter((e) => e.tier === "A").length;
  const nB = ctx.findings.flatMap((f) => f.evidence).filter((e) => e.tier === "B").length;
  const nC = ctx.findings.flatMap((f) => f.evidence).filter((e) => e.tier === "C").length;
  /*
   * A marca tem que estar EM CADA AFIRMAÇÃO, não em algum lugar do documento. Medido contra o
   * threat model real: apagando todas as marcas por afirmação e deixando um único título
   * "(nível A)", este item continuava verde. E o teste que importa de verdade é o inverso —
   * o documento não pode marcar mais fatos (A/B) do que a análise sustenta, porque é assim
   * que uma inferência vira "fato de bytecode" aos olhos do revisor. Essa é a regra que o
   * PROBLEMA.md diz que não se quebra.
   */
  const semMarcaPropria: string[] = [];
  const inflados: string[] = [];
  let presentes = 0;
  for (const f of ctx.findings) {
    const id = idDe(f);
    const outros = ctx.findings.filter((o) => idDe(o) !== id).map((o) => reId(idDe(o)));
    const proprias = blocoLinhas(md, reId(id), resIds).filter((l) => !outros.some((o) => o.test(l)));
    if (!proprias.length) continue; // ausência do documento já é blocker no item das remediações
    presentes++;
    const doc = contaNiveis(proprias);
    const eA = f.evidence.filter((e) => e.tier === "A").length;
    const eB = f.evidence.filter((e) => e.tier === "B").length;
    if (doc.A + doc.B + doc.C === 0) { semMarcaPropria.push(id); continue; }
    if (doc.A > eA) inflados.push(M.infladoA(id, doc.A, eA));
    else if (doc.B > eB) inflados.push(M.infladoB(id, doc.B, eB, !ctx.observations));
  }
  for (const id of semMarcaPropria) blockers.push(M.semMarcaBlocker(id));
  for (const d of inflados) blockers.push(M.infladoBlocker(d));
  add(
    M.qNivel,
    semEvidencia.length || semFato.length || semMarcaPropria.length || inflados.length || !presentes ? "gap" : "ok",
    [
      M.nivelContagem(nA, nB, nC),
      ctx.findings.length
        ? M.nivelPorAmeaca(
            presentes - semMarcaPropria.length - inflados.length,
            presentes,
            ctx.findings.length - presentes,
            ctx.findings.length,
          )
        : M.nivelSemAmeaca,
      semEvidencia.length ? M.nivelSemEvidencia(lista(semEvidencia)) : "",
      semFato.length ? M.nivelSoC(lista(semFato)) : "",
      semMarcaPropria.length ? M.nivelSemMarca(lista(semMarcaPropria)) : "",
      inflados.length ? M.nivelInflado(lista(inflados, 3)) : "",
      marcaNivel ? "" : M.nivelSemNotacao,
    ].filter(Boolean).join(" "),
  );

  /* 7 — limites da análise ditos em voz alta */
  const aproximado = ctx.analysis.soundness !== "sound";
  const viaHelper = ctx.findings.filter((f) => f.evidence.some((e) => e.tier === "C" && MARCA_REVISAR.test(e.claim))).map(idDe);
  const motivoIncompleto = ctx.analysis.incompleteReason;
  // O documento pode declarar a imprecisão de duas formas: com o vocabulário de marca
  // (call_indirect, aproximado/approximate, rebaixado/downgraded, incompleto/incomplete) ou
  // reproduzindo o motivo que a própria análise registrou.
  const declara = MARCA_APROXIMADO.test(texto) || (!!motivoIncompleto && texto.includes(motivoIncompleto));
  const precisaDeclarar = aproximado || viaHelper.length > 0;
  add(
    M.qLimites,
    !precisaDeclarar ? "n/a" : declara ? "ok" : "gap",
    !precisaDeclarar
      ? M.limitesNA(ctx.analysis.soundness)
      : declara
        ? M.limitesOk(ctx.analysis.soundness, viaHelper.length, lista(viaHelper), motivoIncompleto)
        : M.limitesGap(ctx.analysis.soundness, viaHelper.length, lista(viaHelper), motivoIncompleto),
  );

  /* 8 — o que surgiu DEPOIS do exercício */
  const secaoPosterior = MARCA_POSTERIOR.test(texto);
  const conteudoPosterior = secaoPosterior ? bloco(md, MARCA_POSTERIOR).split(/\r?\n/).filter((l) => palavras(l) >= 5).length : 0;
  add(
    M.qPosterior,
    secaoPosterior && conteudoPosterior > 1 ? "ok" : "gap",
    secaoPosterior ? (conteudoPosterior > 1 ? M.posteriorOk(conteudoPosterior) : M.posteriorVazia) : M.posteriorAusente,
  );

  /* 9 — inventário do artefato analisado */
  const temId = ctx.contractId ? md.includes(ctx.contractId) : false;
  const hash = ctx.spec?.wasmHash;
  const temHash = hash ? md.includes(hash) || md.includes(hash.slice(0, 16)) : false;
  const temRede = ctx.network ? new RegExp(esc(ctx.network), "i").test(md) : false;
  if (!temId) blockers.push(M.invSemIdBlocker(ctx.contractId));
  add(
    M.qInventario,
    temId && temRede && (temHash || !hash) ? "ok" : "gap",
    [
      temId ? M.invIdOk(ctx.contractId) : M.invIdFalta(ctx.contractId),
      temRede ? M.invRedeOk(ctx.network) : M.invRedeFalta(ctx.network),
      hash ? (temHash ? M.invHashOk : M.invHashFalta(hash.slice(0, 16))) : M.invHashNA,
    ].join("; ") + ".",
  );

  return relatorio("threat-model", items, blockers, needsInput);
}

/* ================= monitoring plan ================= */

/**
 * Fonte única do checklist do monitoring plan. `render/monitoring.ts` chama esta função com o
 * documento renderizado ATÉ a §6 e imprime os `items` — o relatório que o CLI mostra é o mesmo
 * objeto, porque o texto da §6 é cortado antes da leitura (ver a nota de desenho no topo).
 */
export function validateMonitoringPlan(ctx: ArtifactContext, markdown: string, monitors: Monitor[]): ValidationReport {
  const md = semChecklist(markdown ?? "");
  const texto = prosa(md);
  const mons = monitors ?? [];
  const items: ChecklistItem[] = [];
  const blockers: string[] = [];
  /** Pendências que nenhuma análise fecha — ver `veredito`. */
  const needsInput: string[] = [];
  const add = (question: string, status: ChecklistItem["status"], detail: string) =>
    items.push({ question, status, detail });

  if (!md.trim()) blockers.push(M.docVazio);
  if (!mons.length) blockers.push(M.mpSemMonitor);

  const idsAmeaca = new Set(ctx.findings.map(idDe));
  const resAmeacas = ctx.findings.map((f) => reId(idDe(f)));
  const resMon = mons.map((m) => reId(m.id));
  const obs = ctx.observations;

  /*
   * "É monitor de evento?" é pergunta ESTRUTURAL, não textual: o monitor é de evento se, e
   * somente se, ele vira um filtro executável de `getEvents` (`toExecutable`). A versão
   * anterior perguntava isso ao texto e discordava da §4 do mesmo documento — a §4 dizia
   * "nenhum destes monitores passa por getEvents, e o mecanismo é getLedgerEntries" e a §6
   * respondia "getEvents nunca vai disparar", sobre as mesmas linhas.
   *
   * Monitor que ESTE contexto não rederiva não tem filtro a inspecionar (um `ctx.monitors`
   * vindo de outra análise); só nesse caso se cai na leitura do texto.
   */
  const rederivaveis = new Set(deriveMonitors(ctx).map((m) => m.id));
  const ehEvento = (m: Monitor): boolean =>
    rederivaveis.has(m.id) ? !!toExecutable(m, ctx) : MARCA_EVENTO.test(`${m.observable} ${m.trigger}`);

  /* 1 — cobertura do threat model */
  const porAmeaca = new Map<string, Monitor[]>();
  for (const m of mons) porAmeaca.set(m.threatId, [...(porAmeaca.get(m.threatId) ?? []), m]);
  const descobertas: string[] = [];
  const justificadas: string[] = [];
  for (const f of ctx.findings) {
    const id = idDe(f);
    if (porAmeaca.get(id)?.length) continue;
    /*
     * O template aceita "não monitorável on-chain" — desde que esteja escrito E desde que o
     * controle substituto esteja nomeado. Uma linha que diz que nada foi derivado e deixa o
     * controle como `⟨a definir⟩` não cobriu a ameaça: declarou a lacuna. As duas coisas são
     * legítimas no documento, mas só a primeira responde "sim" a esta pergunta do checklist.
     */
    const b = bloco(md, reId(id), resAmeacas);
    const grave = f.severity === "Critical" || f.severity === "High";
    const diz = b.trim().length > 0 && MARCA_SEM_MONITOR.test(b);
    const controleAberto = diz && PLACEHOLDER.test(b);
    if (diz && !controleAberto) {
      justificadas.push(id);
      // Justificada continua sendo ameaça grave sem cobertura ativa: o que muda é o que falta.
      if (grave) blockers.push(M.cobJustificadaSemDono(id, f.severity));
      continue;
    }
    descobertas.push(id);
    if (grave) {
      blockers.push(controleAberto ? M.cobControleAberto(id, f.severity) : M.cobSemJustificativa(id, f.severity));
    }
  }
  // Denominador = entrypoints INVOCÁVEIS. `__constructor`/`__check_auth` são exports
  // reservados do protocolo (CAP-0058) e não são chamáveis por InvokeHostFunction; contá-los
  // aqui dava um "42 de 57" que não bate com o "56 invocáveis" do threat model do mesmo binário.
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

  /* 3 — baseline observado, não chutado */
  const semBaseline = mons.filter((m) => m.baselineTier === "none");
  const inventado = mons.filter((m) => m.baselineTier === "B" && !obs);
  const janelaCurta = obs?.window.insufficient
    ? mons.filter((m) => m.baselineTier === "B" && /\d/.test(m.baseline) && !MARCA_LACUNA.test(m.baseline))
    : [];
  const inferido = mons.filter((m) => m.baselineTier === "C");
  /*
   * AQ-1: uma janela coletada em que NENHUM evento de NENHUM tópico apareceu mede ausência de
   * tráfego, não perfil de tráfego. A contagem (0) é real e mesmo assim não sustenta limiar —
   * "3× a taxa medida" sobre taxa zero é um limiar sem base. A linha sai como lacuna e vira
   * blocker, para o revisor não ler "baseline conferido" onde não houve o que conferir.
   */
  const semTrafego = janelaSemTrafego(ctx);
  /*
   * Conferência do NÚMERO contra `ctx.observations`, não só do tier.
   * Sem isto o validador aceitava "412 emissões de [deposit]" com a observação dizendo 7 —
   * medido. Tier B significa "fato observado on-chain"; um número que não sai da janela é
   * uma estimativa usando o crachá de medição, o pior caso do contrato de evidência.
   */
  const conferidos = new Set<string>();
  const divergem: string[] = [];
  const topicoFantasma: string[] = [];
  /** `id|[topics]` — zero medido sustentando um limiar de taxa, que ele não sustenta. */
  const zeroComLimiar: string[] = [];
  /**
   * Zero observado num gatilho de qualquer-ocorrência: medição honesta, conferência nenhuma.
   * O caso real é um `init` de um pool inicializado ANTES da janela: a única ocorrência
   * legítima do tópico é anterior a ela, então o zero sairia zero qualquer que fosse o
   * comportamento do contrato na janela. Contá-lo como "baseline conferido contra a janela"
   * — e, por tabela, como precisão de alerta — era afirmar um backtest que ninguém fez.
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
      const dito = numeroAntesDe(m.baseline, /(emiss|ocorr|event|disparo)/i);
      if (dito === undefined || !tops.length) continue; // baseline sem contagem (ex.: hash da instância)
      const esperado = tops.reduce((s, t) => s + (obs.events.find((e) => e.topic === t)?.count ?? 0), 0);
      if (dito !== esperado) { divergem.push(`${m.id}: ${dito} ≠ ${esperado} [${tops.join(", ")}]`); continue; }
      /*
       * Zero observado numa janela suficiente É medição — e boa: é o que sustenta "qualquer
       * ocorrência" de um evento privilegiado. O que ele NÃO sustenta é limiar de taxa, que
       * seria "3× zero". Só esse par (zero medido + gatilho de taxa) vira blocker.
       */
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
   * SHIP-05, agora POR MONITOR: "sem baseline" tem três causas diferentes e o documento
   * afirmava a primeira nas três. (a) nenhuma janela foi coletada; (b) a janela existe e é
   * curta demais; (c) o monitor não passa por getEvents, então nenhuma janela produziria o
   * baseline dele — o campo é preenchimento na aprovação do plano. Escrever (c) com o texto
   * de (a) contradiz o mesmo documento, que imprime a janela de N ledgers algumas linhas
   * acima da linha que diz "nenhuma janela foi coletada".
   */
  for (const m of semBaseline) {
    // (c) é PREENCHIMENTO: nenhuma janela produziria esse baseline, então não há coleta que a
    // ferramenta tenha deixado de fazer — o valor é lido do ledger na aprovação do plano.
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
    semBaseline.length || inventado.length || janelaCurta.length || inferido.length || divergem.length || topicoFantasma.length || semTrafego || zeroComLimiar.length
      ? "gap"
      : mons.length ? "ok" : "gap",
    [
      obs
        ? M.baseJanela(obs.window.ledgers, obs.window.approxHours, obs.events.length, obs.window.insufficient)
        : M.baseSemJanela(motivo),
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

  /* 5 — dono nomeado. Não está no tipo Monitor: só o documento pode dizer. */
  const secaoDono = MARCA_DONO.test(texto);
  const celulas = donoPorLinha(md);
  const temDono = (m: Monitor) => {
    for (const linha of linhasDe(md, reId(m.id))) {
      const cel = celulas.get(linha);
      if (cel !== undefined && !celulaVazia(cel)) return true;
    }
    return MARCA_DONO_ATRIB.test(bloco(md, reId(m.id), resMon));
  };
  const semDono = mons.filter((m) => !temDono(m));
  // Monitor sem dono não é detalhe de formulário: é alerta sem destinatário, e continua barrando
  // a submissão. Mas nem o binário nem a chain dizem quem é o dono — é preenchimento da equipe,
  // e contá-lo como falha da ferramenta era o que fazia todo plano sair "NÃO submetível".
  if (semDono.length) needsInput.push(M.donoBlocker(semDono.length));
  add(
    M.qDono,
    mons.length && !semDono.length ? "ok" : "gap",
    !mons.length
      ? M.semMonitorDetalhe
      : semDono.length
        ? M.donoGap(mons.length - semDono.length, mons.length, lista(semDono.map((m) => m.id)), secaoDono)
        : M.donoOk(mons.length),
  );

  /* 6 — precisão histórica. Sem histórico de operação, o substituto honesto é o backtest na janela observada.
   *
   * "Ativo" aqui é `status === "Active"`, e só. A §5 do mesmo documento afirma que nenhum
   * monitor sai daqui como `Active` — contar `Tuning` como ativo fazia as duas seções se
   * contradizerem, e dava ✔ a uma pergunta sobre alertas que nunca existiram. Enquanto não
   * houver monitor no ar, a linha é `n/a`: não há alerta cuja precisão medir.
   */
  const ativos = mons.filter((m) => m.status === "Active");
  // Só conta como conferido o monitor cuja contagem FOI comparada com a janela e bateu
  // (`conferidos`, do item 3). "tem um número e existe uma janela" não é conferência —
  // era o que este item media antes, e ele afirmava backtest que ninguém tinha feito.
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
          : M.precParcial(
              comBacktest.length,
              ativos.length,
              obs.window.ledgers,
              obs.window.insufficient,
              obs.declaredButUnseen.length,
              lista(obs.declaredButUnseen),
            ),
  );

  /* 7 — inventário de endereços, e o hash que prende o plano ao binário no ar */
  const temId = ctx.contractId ? md.includes(ctx.contractId) : false;
  const hash = ctx.spec?.wasmHash;
  if (!temId) blockers.push(M.endSemIdBlocker(ctx.contractId));
  // O hash da instância se lê do ledger no momento da aprovação do plano: é registro, não análise.
  if (!hash) needsInput.push(M.endSemHashBlocker);
  add(
    M.qEnderecos,
    temId && hash ? "ok" : "gap",
    (temId ? M.endOk(ctx.contractId, ctx.network) : M.endGap(ctx.contractId)) +
      (hash ? M.endHashOk(hash, ctx.generatedAt) : M.endHashFalta(lacuna())),
  );

  /* 8 — fronteiras externas: endereços que o bytecode não revela */
  const cruzam = ctx.analysis.entrypoints.filter((e) => callsOut(e));
  add(
    M.qFronteiras,
    !cruzam.length ? "n/a" : "gap",
    !cruzam.length ? M.frontNA : M.frontGap(cruzam.length, lista(cruzam.map((e) => e.name))),
  );

  /* 9 — ameaças off-chain */
  const declaraOff = MARCA_OFFCHAIN.test(texto);
  const lacunasSTRIDE = ctx.gaps;
  /*
   * A palavra não basta. Medido: um documento de quatro linhas contendo só "infraestrutura"
   * ganhava `ok` e a frase "trata explicitamente do que está fora da chain" — `ok` por
   * casamento de palavra é o mesmo slop que o módulo existe para barrar. Agora o trecho
   * precisa estar preso a algo do contexto: uma letra sem achado derivável, ou uma ameaça
   * que ficou sem monitor. São exatamente as coisas que caem fora da chain.
   */
  const comMonitorOff = new Set(mons.map((m) => m.threatId));
  const ancoras = [...lacunasSTRIDE, ...ctx.findings.map(idDe).filter((id) => !comMonitorOff.has(id))];
  const blocoOff = declaraOff ? bloco(md, MARCA_OFFCHAIN) : "";
  const ancoradas = ancoras.filter((a) => (LETRAS as readonly string[]).includes(a) ? reLetra(a as Stride).test(blocoOff) : reId(a).test(blocoOff));
  const offOk = declaraOff && (!ancoras.length || ancoradas.length > 0);
  add(
    M.qOffchain,
    offOk ? "ok" : "gap",
    offOk
      ? M.offOk(ancoras.length ? lista(ancoradas) : M.offSemAncora)
      : declaraOff
        ? M.offSolta(lista(ancoras))
        : M.offAusente(lacunasSTRIDE.join(", ")),
  );

  /* 10 — sinal observável e gatilho executável */
  const semObservavel = mons.filter((m) => !m.observable?.trim());
  const semGatilho = mons.filter((m) => !m.trigger?.trim());
  const topicsSpec = ctx.spec?.events?.flatMap((e) => e.prefixTopics) ?? [];
  /*
   * A cobertura de tópicos só faz sentido para quem usa `getEvents`: cobrar topic de um
   * monitor de ledger entry é cobrar um campo do endpoint errado — e o blocker saía sobre
   * monitores que a própria §4 declara como não-getEvents.
   */
  const deEvento = mons.filter(ehEvento);
  const semTopic = topicsSpec.length
    ? deEvento.filter((m) => !topicsSpec.some((t) => `${m.observable} ${m.trigger}`.includes(t)))
    : [];
  /*
   * Monitor sem filtro executável de `getEvents` precisa dizer por qual outro mecanismo o
   * sinal chega (getLedgerEntries, diff de estado, wasm hash, inspeção da transação). Só
   * quando NENHUMA das duas coisas vale — nem filtro, nem mecanismo declarado — o monitor
   * é decorativo. É o caso mais comum do corpus: a maioria dos contratos mainnet não emite
   * evento nos entrypoints que mudam estado.
   */
  const epPorAmeaca = new Map(ctx.findings.map((f) => [idDe(f), f.entrypoint]));
  const semSinalReal = mons.filter(
    (m) => !ehEvento(m) && !MECANISMO_ALTERNATIVO.test(`${m.observable} ${m.trigger}`),
  );
  /*
   * Executável por `getEvents`, OU completamente especificado — não há terceira opção que
   * sustente um ✔. O caso medido: o diff de estado cita as chaves, mas a durabilidade delas
   * é argumento de runtime e entra na chave de ledger; enquanto ela é `⟨a preencher⟩` a
   * consulta não se monta, e o mesmo preenchimento já é blocker de submissão na §6. Uma
   * linha não pode sair ✔ apontando para um bloqueio aberto do próprio documento.
   */
  const naoEspecificados = mons.filter(
    (m) => !toExecutable(m, ctx) && PLACEHOLDER.test(`${m.observable} ${m.trigger}`),
  );
  // Quantos monitores viram chamada de RPC sem tradução manual: é o que separa este plano
  // de um preenchido à mão, e a contagem vinha da §6 que antes o renderizador calculava sozinho.
  const executaveis = mons.filter((m) => toExecutable(m, ctx)).length;
  for (const m of [...semObservavel, ...semGatilho]) {
    blockers.push(M.sinalBlocker(m.id, !m.observable?.trim() ? M.sinalObservavel : M.sinalGatilho));
  }
  add(
    M.qSinal,
    semObservavel.length || semGatilho.length || semTopic.length || semSinalReal.length || naoEspecificados.length
      ? "gap"
      : mons.length ? "ok" : "gap",
    !mons.length
      ? M.semMonitorDetalhe
      : [
          semObservavel.length ? M.sinalSemObservavel(lista(semObservavel.map((m) => m.id))) : "",
          semGatilho.length ? M.sinalSemGatilho(lista(semGatilho.map((m) => m.id))) : "",
          semSinalReal.length
            ? M.sinalMudo(semSinalReal.length, lista(semSinalReal.map((m) => `${m.id}→${epPorAmeaca.get(m.threatId)}`)))
            : "",
          naoEspecificados.length
            ? M.sinalIncompleto(naoEspecificados.length, lista(naoEspecificados.map((m) => m.id)))
            : "",
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
   * Varredura final: uma linha ✔ cujo detalhe carrega uma pendência é uma contradição dentro
   * da própria célula — "está ok, só falta escrever/preencher X". Quem lê o checklist lê a
   * coluna Situação; graduar um pendente como aprovado é o modo mais barato de o documento
   * perder o revisor. A regra é de forma, de propósito: se o texto do item precisou dizer
   * que algo ainda tem de ser feito, o item não é `ok`.
   */
  for (const it of items) {
    if (it.status === "ok" && PENDENCIA_NA_LINHA.test(it.detail)) it.status = "gap";
  }

  return relatorio("monitoring-plan", items, blockers, needsInput);
}
