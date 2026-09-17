/**
 * Renderiza o threat model no template STRIDE oficial da Stellar
 * (developers.stellar.org/docs/build/security-docs/threat-modeling/STRIDE-template).
 *
 * Duas decisões de formato que valem explicar, porque são desvios visíveis do template:
 *
 * 1. A tabela oficial de ameaças tem duas colunas e uma célula por letra. Célula de tabela
 *    markdown não comporta a evidência rotulada por nível sem virar um parágrafo ilegível
 *    com <br> — e a evidência rotulada é o produto inteiro desta ferramenta. Então a tabela
 *    oficial fica como índice (ID · título · níveis · severidade) e cada ameaça ganha um
 *    bloco de detalhe logo abaixo, na mesma seção. Nada é omitido; o que muda é onde cabe.
 *
 * 2. A tabela de remediações mantém o texto completo na célula, porque remediação é um
 *    parágrafo único e não tem mistura de níveis para exibir — a seção inteira é nível C.
 *
 * O que este arquivo NÃO faz: inferir. Tudo que ele escreve ou vem de `ctx`, ou é rótulo
 * do template, ou é declaração de lacuna. Quando não há evidência, a saída diz que não há.
 *
 * Idioma: a saída padrão é INGLÊS (revisores do SCF e templates da Stellar). Todo texto
 * de saída vive em `M` (ver ../i18n.ts); comentários seguem em português, por convenção
 * do repositório.
 */

import type { ArtifactContext } from "../artifact.ts";
import { tierLabels } from "../artifact.ts";
import type { Finding, Stride, Tier } from "../detect.ts";
import type { Entrypoint } from "../analyze.ts";
import {
  caminho, minHops, requiresAuth, writesStorage, emitsEvent, extendsTtl, callsOut, canUpgradeSelf, delegatesAuth,
} from "../analyze.ts";
import { STORAGE_WRITE_FNS, TTL_EXTEND_FNS } from "../hostfns.ts";
import { lang, msgs, plural } from "../i18n.ts";

/* ------------------------------------------------------------------ *
 * Constantes do template oficial — copiadas literalmente, em inglês.
 * Traduzir os cabeçalhos quebraria o reconhecimento pelo revisor do SCF,
 * que procura exatamente estas quatro perguntas e estes IDs.
 * ------------------------------------------------------------------ */

const STRIDE_ORDEM: readonly Stride[] = ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"];

const STRIDE_ROTULO: Record<Stride, string> = {
  Spoof: "**S**poofing",
  Tamper: "**T**ampering",
  Repudiate: "**R**epudiation",
  Info: "**I**nformation Disclosure",
  DoS: "**D**enial of Service",
  Elevation: "**E**levation of Privilege",
};

/** Tabela de lembretes do template, verbatim. */
const LEMBRETES_STRIDE = `| Mnemonic Threat | Definition | Question |
|---|---|---|
| **S**poofing | The ability to impersonate another user or system component to gain unauthorized access. | Is the user who they say they are? |
| **T**ampering | Unauthorized alteration of data or code. | Has the data or code been modified in some way? |
| **R**epudiation | The ability for a system or user to deny having taken a certain action. | Is there enough data to "prove" the user took the action if they were to deny it? |
| **I**nformation Disclosure | The over-sharing of data expected to be kept private. | Is there anywhere where excessive data is being shared or controls are not properly in place to protect private information? |
| **D**enial of Service | The ability for an attacker to negatively affect the availability of a system. | Can someone, without authorization, impact the availability of the service or business? |
| **E**levation of Privilege | The ability for an attacker to gain additional privileges and roles beyond what they initially were granted. | Are there ways for a user, without proper authentication and authorization to gain access to additional privileges, either through standard or illegitimate means? |`;

/** As cinco perguntas de auto-avaliação, verbatim. */
const PERGUNTAS_FINAIS = [
  "Has the data flow diagram been referenced since it was created?",
  "Did the STRIDE model uncover any new design issues or concerns that had not been previously addressed or thought of?",
  'Did the treatments identified in the "What are we going to do about it" section adequately address the issues identified?',
  "Have additional issues been found after the threat model?",
  "Any additional thoughts or insights on the threat modeling process that could help improve it next time?",
] as const;

/* ------------------------------------------------------------------ *
 * Texto de saída, por idioma. `pt` é o texto que o renderizador já
 * emitia; `en` é o padrão.
 * ------------------------------------------------------------------ */

const M = msgs({
  en: {
    /* --- utilitários --- */
    eMais: (n: number) => `and ${n} more`,
    e: "and",
    sim: "yes",
    nao: "no",
    alcancam: (n: number) => `${n} ${plural(n, "reaches", "reach")}`,
    naoInformado: "not provided",

    /* --- motivo da aproximação --- */
    razaoModuloIndireto: "there is `call_indirect` in the module",
    razaoModuloDegradado: "there are degraded function bodies in the module",
    razaoIncompleto: (r: string) => `the module could not be read in full (${r})`,
    razaoSubIndireto: (esc: string) => `\`call_indirect\` ${esc}`,
    razaoSubDegradado: (esc: string) => `a degraded function body ${esc}`,
    escopoEste: "in this entrypoint's subgraph",
    escopoListados: "in the subgraphs of the listed entrypoints",

    /* --- linha de solidez --- */
    solidezSdk: "does not depend on the call graph — the evidence is the binary's own `contractmetav0` custom section",
    escopoNegativa:
      "sound negative for this module's call graph (authorization enforced in a called contract or in " +
      "`__check_auth` is not visible here)",
    solidezModuloOk: (esc: string) => `module call graph complete — ${esc}`,
    solidezRebaixada: (motivo: string) =>
      `**downgraded** — ${motivo}; the negatives count as indication, not as a sound negative`,
    solidezEpOk: (escopo: string, esc: string) => `call graph complete ${escopo} — ${esc}`,

    /* --- 1. What are we working on? --- */
    lacunaEquipe:
      "**Gap to be filled by the team.** soroguard derives this section from the deployed WASM and " +
      "does not know the contract's business purpose. The descriptive paragraph the template asks " +
      "for — what the protocol does, who the actors are, what value it holds in custody, which trust " +
      "assumptions live off-chain — is not derivable from the bytecode and has to be written by the " +
      "people who built the system. What follows is only the measured technical surface.\n",
    hdrObjeto: "### Analyzed object\n",
    thCampoValor: "| Field | Value |",
    lblObjetoAnalisado: (f: string) => `| Analyzed object | local file \`${f}\` |`,
    lblRede: "Network",
    lblTamanhoWasm: "WASM size",
    lblGeradoEm: "Generated at",
    lblSolidez: "Call graph soundness",
    solidezCompleta: "complete — no `call_indirect` in the module",
    solidezAproximada: (motivo: string) => `**approximate** — ${motivo}; the negatives stop being sound`,
    objetoComHash:
      "The whole document describes **this binary**, identified by the hash above — ",
    objetoSemHash:
      "The whole document describes **the analyzed binary**. The hash was not provided in this run, " +
      "so there is no way to prove afterwards that the report is about this bytecode: whoever " +
      "generates it has to record which WASM was read. The object is the binary — ",
    objetoFim:
      "not the repository it supposedly came from. That is the only thing the analysis can assert: " +
      "source and deployment diverge often, and what runs in production is the WASM.\n",
    hdrEvidencia: "### How to read the evidence\n",
    thEvidencia: "| Tier | Means | Who can verify |",
    linhaA: (t: string) => `| **A** | ${t}: reachability in the deployed WASM's call graph | anyone, re-derivable from the binary |`,
    linhaB: (t: string) => `| **B** | ${t}: events actually emitted in the observed window | anyone, via RPC |`,
    linhaC: (t: string) => `| **C** | ${t}. Covers threat class, severity and remediation | human review only |`,
    assimetria:
      "One asymmetry changes how everything below reads: **\"does not reach `require_auth`\" is a sound " +
      "negative for this module's call graph** (when that graph is complete) — it says nothing about " +
      "authorization enforced inside a contract reached through `call`/`try_call`, nor about a custom " +
      "account's `__check_auth`. **\"reaches `put_contract_data`\", on the other hand, is an " +
      "over-approximation** — the write may sit on a branch that entrypoint never executes. That is " +
      "why every positive claim carries its hop count, and long paths are flagged for confirmation " +
      "instead of asserted.\n",
    notaCheckAuth:
      "This module exports `__check_auth`, so it is a **custom account**: authorization is implemented " +
      "*by* `__check_auth`, not requested through `require_auth`. \"No `require_auth` path\" on its " +
      "entrypoints is the expected shape for this kind of contract and is not itself a finding.\n",
    hdrSuperficie: (solido: boolean) =>
      `### Exported surface ${solido ? "(tier A)" : "(tier A **downgraded**)"}\n`,
    avisoSuperficie: (motivo: string) =>
      "> **Read this table as indication, not as fact.** " +
      `${motivo[0].toUpperCase()}${motivo.slice(1)}, so there is a call path the traversal does not ` +
      "follow, and every `no` below (\"does not reach `require_auth`\", \"does not write\") stops being a " +
      "sound negative. " +
      "The `yes` entries are what they always were — reachability, not execution.\n",
    semEntrypoints:
      "No invocable entrypoint was found among the module's exports. That is anomalous for a Soroban " +
      "contract — it may be a SAC, a module compiled without a spec, or a read failure. **Nothing " +
      "below this point has a basis; the artifact is not submittable in this state.**\n",
    resumoSuperficie: (exp: number, inv: number, a: string, g: string, c: string, u: string) =>
      `${exp} exported, ${inv} invocable ${plural(inv, "entrypoint", "entrypoints")} · ${a} ` +
      `\`require_auth*\` · ${g} storage write · ${c} \`call\`/\`try_call\` · ${u} self-code replacement.`,
    reservados: (n: number, l: string) =>
      ` The difference is ${n} reserved \`__*\` ${plural(n, "export", "exports")} (${l}) excluded from ` +
      `the invocable count: the host refuses to invoke ${plural(n, "it", "them")} directly (CAP-0058), ` +
      `so ${plural(n, "it is", "they are")} not evaluated as attack surface.`,
    semReservados: " No `__*` export, so the two counts coincide.",
    thSuperficie: "| Entrypoint | auth | writes | event | upgrade | cross-call | fanout |",
    notaSuperficie:
      "In every column, \"yes\" means it **reaches** the corresponding host function on some call-graph " +
      "path, not that it always executes it.\n",
    hdrStores: "### Inferred data stores\n",
    chavesCertas: (l: string) => `- Keys read from the module's linear memory: ${l}.`,
    chavesProvaveis: (l: string) => `- Likely keys (partial read of the data section): ${l}.`,
    notaDurabilidade:
      "\nThe durability of each key (`temporary` / `persistent` / `instance`) is a runtime argument and " +
      "**does not appear in the bytecode** — do not assume it from this list.\n",
    hdrObservacao: "### On-chain activity observed (tier B)\n",
    janela: (de: number, ate: number, n: number, h: number) =>
      `Window: ledgers ${de}–${ate} (${n} ledgers, ~${h}h).`,
    janelaInsuficiente:
      " **Window too short for an honest baseline** — the rates below are recorded, not to be used as " +
      "a baseline.",
    thEventos: "| Topic | Occurrences | Ledgers | Events/hour |",
    semEventos:
      "No event observed in the window: **no event of any topic was observed for this contract in the " +
      "window — absence of traffic, not a traffic profile.** The count is real and still does not " +
      "support a monitoring threshold.\n",
    declaradosNaoVistos: (l: string, curta: boolean, h: number) =>
      `Topics declared in the spec and not observed in the window: ${l}. ` +
      (curta
        ? "Absence over a window this short is not evidence that the action never happens.\n"
        : `Absence over a ~${h} h window is not evidence the action never happens — only that it did ` +
          "not happen in that window.\n"),
    coletaFalhou: (e: string) =>
      `**Tier B collection FAILED:** ${e}. There is no window because the RPC call did not complete — ` +
      "not because the contract is inactive. No claim about on-chain activity is made in this document.\n",
    coletaOffline:
      "**Tier B collection not run (offline / local target).** A local `.wasm` has no on-chain history, " +
      "and offline mode does not go to the network by choice. No tier B claim here.\n",
    coletaAusente: "No observation window was collected for this contract.\n",
    legendaDfdComChaves:
      "The diagram comes straight out of the analysis: each `process` is a module export, each `store` " +
      "is an inferred storage key, and each edge marked as a boundary is a point where execution " +
      "crosses outside the contract (`call`/`try_call`) or where authorization is required.\n",
    legendaDfdSemChaves:
      "The diagram comes straight out of the analysis: each `process` is a module export, the single " +
      "`store` is the contract storage with its keys **not inferred** — the diagram declares that gap " +
      "instead of drawing keys it does not have — and each edge marked as a boundary is a point where " +
      "execution crosses outside the contract (`call`/`try_call`) or where authorization is required.\n",
    thFronteiras: "| Trust boundary | Contained nodes |",
    /**
     * A fronteira de autorização do DFD diz "require_auth* alcançável", e o revisor lê isso como
     * controle de acesso. Na maior parte dos nós ela é o chamador autorizando o próprio endereço.
     */
    notaFronteiraAuth: (admins: string[], usuarios: string[]) =>
      "**How to read the authorization boundary (tier C, name-shape heuristic).** Reaching " +
      "`require_auth*` is not by itself access control. " +
      (usuarios.length
        ? `On the ${usuarios.length} user-shaped ${plural(usuarios.length, "node", "nodes")} ` +
          `(${listaE(usuarios)}) it is the caller authorizing ${plural(usuarios.length, "its", "their")} ` +
          "own address — the expected shape of a user operation, with no privileged key behind it. "
        : "") +
      (admins.length
        ? `Only the ${admins.length} admin-shaped ${plural(admins.length, "node", "nodes")} ` +
          `(${listaE(admins)}) sit behind a key holder whose custody the review has to trace. `
        : "No node inside the boundary has an administrative name shape, so none of them points at a " +
          "privileged key holder to trace. ") +
      "The split comes from the name, not from the bytecode: the call graph never shows *whose* " +
      "`Address` is authorized.\n",
    dfdAusente:
      "**Declared gap: no data-flow diagram was generated for this contract.** The template requires at " +
      "least one visual diagram, so the artifact is incomplete at this point. This is a generation " +
      "failure, not a claim that the contract has no flows — do not replace it with a generic diagram, " +
      "which would be worse than the gap.\n",
    hdrAvisosSpec: "### Warnings from reading the spec\n",

    /* --- 2. What can go wrong? — lacunas por letra --- */
    corpus:
      "Measured on soroguard's calibration corpus (75 mainnet contracts, `docs/CALIBRACAO.md`): zero " +
      "derivable findings in 100% of them",
    /**
     * `require_auth` num `swap`/`deposit`/`withdraw` é o chamador autorizando o PRÓPRIO endereço:
     * é a forma esperada, não controle de acesso, e mandar rastrear "o detentor da chave" dessas
     * chamadas é trabalho inventado. Só a forma administrativa vale rastreio de custódia. A
     * separação é por FORMA DO NOME — heurística, nível C, e a frase diz isso.
     */
    lacunaSpoofConcreto: (n: number, admins: string[], usuarios: string[], checkAuth: boolean) =>
      ` **Where identity is asserted in this contract:** ${
        n === 0
          ? "no invocable entrypoint reaches `require_auth*`"
          : `${n} invocable ${plural(n, "entrypoint reaches", "entrypoints reach")} \`require_auth*\``
      }. ` +
      (admins.length
        ? `**Admin-shaped (${admins.length}, key-holder trace required):** ${listaE(admins)} — those are ` +
          "the calls whose `Address` the review has to trace back to a key holder: custody, multisig or " +
          "a single key. "
        : "**No admin-shaped entrypoint reaches `require_auth*`**, so this contract has no such call to " +
          "trace back to a key holder. ") +
      (usuarios.length
        ? `**User-shaped (${usuarios.length}, no key-holder trace):** ${listaE(usuarios)} — there ` +
          `\`require_auth\` is the caller authorizing ${plural(usuarios.length, "its", "their")} own ` +
          "address, which is the expected shape of a user operation, not access control; there is no " +
          "privileged key behind it to trace. "
        : "") +
      "**This split is a name-shape heuristic (tier C), not a bytecode fact** — the bytecode shows that " +
      "`require_auth*` is reached, never *whose* address is authorized. Check it against the signatures " +
      "before using the split as a work list. " +
      (checkAuth
        ? "The module also exports `__check_auth`: it is a custom account, and the signature check it " +
          "implements is itself part of the off-chain identity question."
        : "The module does not export `__check_auth`, so the signature check is the host's, not this " +
          "contract's."),
    lacunaInfoConcreto: (chaves: string, topicos: string) =>
      ` **The concrete surface to review in this contract:** inferred storage keys ${chaves}; declared ` +
      `event topics ${topicos}. Those are the fields that end up readable on a public ledger.`,
    listaVazia: "⟨none inferred⟩",
    lacunaSpoof: (corpus: string) =>
      "**Declared gap — not derivable from the bytecode.** The call graph shows *whether* a path " +
      "reaches `require_auth`; never *who* the verified `Address` is, who holds that address's key, " +
      "nor how the client that builds the transaction authenticates the user. Identity " +
      `lives outside the contract. ${corpus} — this is a structural limit of bytecode analysis, not a ` +
      "detector failure on this contract. **Requires manual review of the off-chain flow:** custody of " +
      "the privileged keys (multisig or a single key?), authentication of the frontend/backend that " +
      "signs, and whether any address with an administrative role is a shared account.",
    lacunaInfo: (corpus: string) =>
      "**Declared gap — not derivable from the bytecode.** All ledger state in Soroban is public by " +
      "construction, so \"excessive disclosure\" is a question about *which data the protocol chose to " +
      "put on-chain* — a product decision the WASM does not record. The bytecode also does not say what " +
      `the arguments and the event topics mean. ${corpus} — a structural limit. **Requires manual ` +
      "review:** which fields go into storage and into event topics, and whether any of them is data " +
      "that should not be public or that gives an advantage to whoever reads the ledger before the " +
      "transaction settles.",
    lacunaTamperIntro:
      "**Declared gap — no finding derived for this contract.** Three detectors feed this letter and " +
      "none fired: `write-before-auth` (compares bytecode offsets *within the same body*), " +
      "`host-prng-in-value-path` (host PRNG on a path that changes state or calls out) and " +
      "`vulnerable-sdk` when the advisory is not about authorization. ",
    lacunaTamperRessalva: (l: string) =>
      "**Caveat that invalidates this gap without review:** the analysis recorded a write before " +
      `authorization in ${l}, and still no finding came out under this letter. That is a divergence ` +
      "between the analysis and the detector — check it by hand before accepting the field as empty. ",
    lacunaTamperSemRessalva:
      "The write-before-auth detector compares offsets *inside a single body* and found no body where a " +
      "write precedes the first `require_auth`. It cannot see the ordering when the write and the " +
      "authorization live in different functions, so this is absence of signal, not a demonstration that " +
      "the ordering is correct. ",
    lacunaTamperElev: (n: number) =>
      `Watch the classification: state tampering through **missing** authorization lives under ` +
      `**Elevation** (${n} ${plural(n, "finding", "findings")}), not here. `,
    lacunaTamperFim:
      "**What still requires manual review:** validation of the arguments entering the entrypoints, and " +
      "trust in data coming from another contract (oracle, router) — neither is derivable from " +
      "reachability.",
    lacunaRepudiateIntro:
      "**Declared gap — no finding derived for this contract.** The detector for this letter is " +
      "`silent-mutation`. ",
    lacunaRepudiateSemEscrita:
      "No invocable entrypoint reaches a storage write, so there is no action that needs a trail. ",
    lacunaRepudiateComEscrita: (n: number) =>
      `${n === 1
        ? "The single entrypoint that reaches a write also reaches"
        : `The ${n} entrypoints that reach a write also reach`
      } \`contract_event\` on some path of the subgraph. **That does not prove a trail exists:** ` +
      "reaching `contract_event` is a positive claim, and positives are over-approximate — the event " +
      "may sit on a branch the write does not take. What the absence of a finding supports is only the " +
      "negative: no writer was left without *any* path to an event. ",
    lacunaRepudiateFim:
      "**What the bytecode also does not answer:** whether the event's *content* identifies who took the " +
      "action. An event that does not carry the caller's address does not resolve repudiation, and the " +
      "reachability of `contract_event` says nothing about topics and payload. Check manually.",
    lacunaDosIntro:
      "**Declared gap — no finding derived for this contract.** The detector for this letter is " +
      "`archival-risk`. ",
    lacunaDosTtl: (n: number, l: string, saltos: number | undefined, temReservado: boolean) =>
      `${n} ${plural(n, "export reaches", "exports reach")} the \`extend_*_ttl\` family` +
      (saltos === undefined ? "" : `, the nearest at ${saltos} ${plural(saltos, "hop", "hops")}`) +
      ` (${l}${temReservado ? "; the detector counts any export, including the reserved `__` ones" : ""}), ` +
      "and the detector only fires when none does. **Read that count as an over-approximation:** " +
      "*reaching* is not *executing* — measured on the calibration corpus, ~84% of the bare positives " +
      "go through a shared helper the entrypoint never runs (`docs/CALIBRACAO.md`), and read-only " +
      "entrypoints land in this list for exactly that reason. If those renewal paths do not run during " +
      "the contract's normal " +
      "operation, the archival risk still exists and the bytecode does not show it. ",
    lacunaDosSemEscrita:
      "No invocable entrypoint reaches a storage write, so there is no state to archive. ",
    lacunaDosFim:
      "**What is not derivable from the call graph:** resource exhaustion from large input (ledger " +
      "CPU/memory limits), dependency on the liveness of a contract reached through `call`, and an " +
      "administrative `pause`/`kill` able to freeze the system. These require manual review.",
    lacunaElevIntro: "**Declared gap — no finding derived for this contract.** ",
    lacunaElevResiduo: (n: number, l: string) =>
      `**Caveat that invalidates this gap without review:** ${n} invocable ` +
      `${plural(n, "entrypoint reaches", "entrypoints reach")} a state write or a replacement of its own ` +
      `code without reaching \`require_auth*\` (${l}), and still no finding was emitted — the detector ` +
      `suppressed ${plural(n, "it", "them")} as a likely false positive. The reason for each suppression ` +
      "lives in `detect.ts` and does not reach this document, so **check them one by one before " +
      "accepting the field as empty.** Here the gap is a detector decision, not an analysis result. ",
    lacunaElevSemResiduo:
      "No invocable entrypoint reaches a state write or a replacement of its own code without reaching " +
      "`require_auth*`. ",
    lacunaElevNegativaSolida:
      "This negative is sound for this module's call graph, which is complete — authorization enforced " +
      "inside a contract reached through `call`/`try_call`, or in `__check_auth`, is not visible here. ",
    lacunaElevNegativaFraca: (motivo: string) =>
      `**This negative is weak:** ${motivo}, so there is a path the analysis cannot see. `,
    lacunaElevDelegam: (n: number, l: string) =>
      `**Beyond the reach of any detector:** ${n} ${plural(n, "entrypoint reaches", "entrypoints reach")} ` +
      `\`authorize_as_curr_contract\` (${l}). soroguard treats delegation as inventory and emits no ` +
      "finding, because the real bug is the *shape* of the authorization tree, which plain reachability " +
      "does not reveal — the absence of a finding here is not an analysis result, it is the absence of " +
      "analysis. Review the scope of each delegation by hand. ",
    lacunaElevFim:
      "**What the bytecode does not answer:** whether the `require_auth` that is reached is about the " +
      "*right* address. \"Reaches `require_auth`\" is not \"authorizes whoever should authorize\" — a " +
      "contract that authorizes the caller where it should authorize the admin passes this detector. " +
      "Requires manual review of the authorized addresses in every privileged entrypoint.",

    /* --- 2. What can go wrong? — corpo da seção --- */
    solidezRebaixadaCallout: (motivo: string) =>
      `> **Soundness downgraded.** ${motivo[0].toUpperCase()}${motivo.slice(1)}, so the call graph is ` +
      "incomplete. Every negative claim in this document (\"does not reach `require_auth`\") stops being " +
      "sound and becomes indication: there is a call path the analysis cannot follow. The findings below " +
      "are marked individually on their *Soundness* line.\n",
    viaTabela: (l: string) =>
      `> **Through the function table, these host functions may additionally be reachable:** ${l}. They ` +
      "are not in the direct call graph: indirect dispatch makes them possible, not proven. This is the " +
      "concrete content of the \"approximate\" label above.\n",
    contagemAmeacas: (n: number) => `${n} derived ${plural(n, "threat", "threats")}`,
    contagemSeveridade: (s: string) => ` — ${s}`,
    contagemConfirmar: (n: number) =>
      `. ${n} ${plural(n, "is", "are")} flagged for human confirmation before counting as a finding.`,
    contagemLacunas: (n: number) =>
      ` ${n} ${plural(n, "letter has", "letters have")} no derivable finding and ${plural(n, "is", "are")} ` +
      "declared below as a gap.",
    celulaAmeaca: (id: string, titulo: string, niveis: string, sev: string) =>
      `**${id}** — ${titulo} · tiers ${niveis} · severity ${sev} (C)`,
    marcaConfirmar: " · ⚠ confirm before treating as a finding",
    marcaRebaixada: " · ⚠ downgraded evidence",
    semAmeacaDerivavel: "_No threat derivable from the bytecode._",
    notaTabelaAmeacas:
      "The template asks for at least one issue per letter. Letters without a finding appear as a " +
      "declared gap, not filled in: the tool reads bytecode, and what it cannot derive from there it " +
      "says it could not. An honestly empty field is verifiable; a field filled with boilerplate is not.\n",
    hdrDetalhamento: "### Threat details\n",
    tituloGrupo: (a: string, b: string, cls: string, n: number) =>
      `#### ${a} – ${b} — \`${cls}\` in ${n} entrypoints\n`,
    notaGrupo: (n: number) =>
      `These ${n} findings have byte-for-byte identical evidence and differ only in the entrypoint, so ` +
      "they appear in a single block. Each ID remains individual, with its own remediation in the next " +
      "section.\n",
    thIdEntrypoint: "| ID | Entrypoint |",
    lblClasse: "Class",
    lblAlvo: "Target",
    alvoContrato: "the whole contract",
    alvoEntrypoint: (e: string) => `entrypoint \`${e}\``,
    lblSeveridade: "Severity",
    valorSeveridade: (s: string) => `${s} — **tier C**, a risk judgement, not a bytecode fact`,
    lblSolidezAchado: "Soundness",
    hdrEvidenciaBloco: "**Evidence**\n",
    itemEvidencia: (tier: Tier, rotulo: string, claim: string) => `- **[${tier}]** *(${rotulo})* — ${claim}`,
    aindaNaoAchado: (escopo: string, id: string) =>
      "> **This finding is not yet a finding.** The positive evidence is over-approximate and needs to be " +
      `confirmed in the source ${escopo} before entering a fix plan. See ${id}.R.1.\n`,
    notaJaInicializado: (n: number, h: number) =>
      `> **Tier B/C note.** Observed traffic (${n} ${plural(n, "event", "events")} over ~${h} h) indicates ` +
      "this instance is already initialized, so the tier C wording above describes a window that has " +
      "most likely already closed. The residual risk is **re-initialization**, and that depends on a " +
      "guard the bytecode cannot show: ",
    notaGuardSim: (l: string) =>
      `\`has_contract_data\` IS in the reachable set of ${l} — a likely already-initialized guard when ` +
      "present, though reachability does not prove it covers this path.",
    notaGuardNao: (l: string) =>
      `\`has_contract_data\` IS NOT in the reachable set of ${l} — no already-initialized guard is ` +
      "visible there; it could still live behind a cross-contract call.",
    escopoCadaListado: "of each listed entrypoint",
    escopoDe: (e: string) => `of \`${e}\``,
    hdrLacunas: "### Declared gaps\n",

    /* --- 3. What are we going to do about it? --- */
    introRemediacoes:
      "**This whole section is tier C (inference).** Remediation is not a bytecode fact: it is a proposal, " +
      "derived from the finding and from the concrete entrypoint that produced it, and it needs review by " +
      "someone who knows the system's design. None of them has been applied or verified — the tool reads " +
      "the binary that is in production today.\n",
    /**
     * Quatro células idênticas nesta tabela eram exatamente o "preenchido com genérico" que o
     * cabeçalho do documento promete não fazer. A célula da lacuna não vira remediação — ela
     * aponta a PLANILHA daquela letra, que a seção anterior já nomeou com superfície concreta.
     */
    celulaSemRemediacao: (letra: string, trabalho: string) =>
      `| ${letra} | _No remediation: no threat was derived under this letter (see the declared gap in the ` +
      "previous section)._ Remediation has to be written together with the threat, after manual review — " +
      `filling this in without the finding would produce a fix with no matching problem. **The work this ` +
      `letter leaves for the review:** ${trabalho} |`,
    trabSpoof: (admins: string[], usuarios: string[]) =>
      (admins.length
        ? `review who holds the keys behind the ${admins.length} admin-shaped ` +
          `${plural(admins.length, "entrypoint", "entrypoints")} that reach \`require_auth*\` listed in the ` +
          `Spoofing gap (${listaE(admins)}) — custody, multisig or single key`
        : "no admin-shaped entrypoint reaches `require_auth*` in the Spoofing gap, so what is left is the " +
          "custody of whoever deployed and of whoever signs on the client side") +
      (usuarios.length
        ? `; the ${usuarios.length} user-shaped ${plural(usuarios.length, "one", "ones")} listed there ` +
          `(${listaE(usuarios)}) authorize the caller's own address and need no key-holder trace`
        : "") +
      ".",
    trabTamper: (n: number, l: string) =>
      `review argument validation and trust in data arriving from contracts reached through ` +
      `\`call\`/\`try_call\` in the ${n} ${plural(n, "entrypoint", "entrypoints")} listed in the Tampering ` +
      `gap${n ? ` (${l})` : ""} — the write-before-auth detector only compares offsets inside one body and ` +
      "cannot answer either question.",
    trabRepudiate: (n: number, l: string) =>
      n === 0
        ? "no invocable entrypoint reaches a storage write, as the Repudiation gap states, so what is left " +
          "is to confirm that nothing off-chain acts on this contract's behalf."
        : `open the events of the ${n} ${plural(n, "entrypoint", "entrypoints")} that reach a write listed ` +
          `in the Repudiation gap (${l}) and check whether the payload carries the caller's address — ` +
          "reaching `contract_event` says nothing about topics and payload.",
    trabInfo: (nChaves: number, chaves: string, nTopicos: number, topicos: string) =>
      `review the ${nChaves} inferred storage ${plural(nChaves, "key", "keys")} (${chaves}) and the ` +
      `${nTopicos} declared event ${plural(nTopicos, "topic", "topics")} (${topicos}) listed in the ` +
      "Information-disclosure gap, and decide which of those fields should not be readable on a public " +
      "ledger or gives an advantage to whoever reads the ledger first.",
    trabDos: (n: number, l: string) =>
      (n
        ? `check whether the ${n} renewal ${plural(n, "path", "paths")} listed in the DoS gap (${l}) ` +
          "actually run during normal operation — *reaching* `extend_*_ttl` is not *executing* it"
        : "no export reaches the `extend_*_ttl` family, as the DoS gap states, so the archival deadline of " +
          "every persistent entry has to be checked by hand") +
      ", plus resource exhaustion from large input and the liveness of contracts reached through `call`.",
    trabElevResiduo: (n: number, l: string) =>
      `go one by one through the ${n} ${plural(n, "entrypoint", "entrypoints")} the Elevation gap names as ` +
      `residue (${l}): they reach a write or a code swap without reaching \`require_auth*\` and were ` +
      "suppressed as likely false positives — the gap there is a detector decision, not an analysis result.",
    trabElevDelegam: (n: number, l: string) =>
      `review the scope of the ${n} ${plural(n, "delegation", "delegations")} the Elevation gap names ` +
      `(${l}): \`authorize_as_curr_contract\` is inventoried, never analysed, so the shape of the ` +
      "authorization tree there has never been checked.",
    trabElevAuth: (n: number, l: string) =>
      n === 0
        ? "no invocable entrypoint reaches `require_auth*`, as the Elevation gap states, so there is no " +
          "authorized address to check — what is left is whether any of them should require one."
        : `check, in the ${n} ${plural(n, "entrypoint", "entrypoints")} the Elevation gap lists as reaching ` +
          `\`require_auth*\` (${l}), whether the authorized address is the RIGHT one — a contract that ` +
          "authorizes the caller where it should authorize the admin passes this detector.",
    letrasSemRemediacao: (l: string) =>
      `Letters with no remediation because they have no derived threat: ${l}. This is not "nothing to do" ` +
      "— it is \"not derivable from bytecode analysis\", and the corresponding work is described in each " +
      "declared gap of the previous section.\n",

    remConfirmar: (alvo: string, caminho: string | undefined, id: string) =>
      `Before touching the code, confirm in the source of ${alvo} whether the write is actually executed` +
      (caminho ? ` — shortest path to the write: \`${caminho}\`` : "") +
      `. If the write branch belongs to a shared helper that ${alvo} never executes, ${id} is a **false ` +
      "positive and should be closed**, not remediated.",

    remAuthComEndereco: (alvo: string, n: number, l: string) =>
      `Require authorization in ${alvo} before the first write. The spec declares the \`address\` ` +
      `${plural(n, "parameter", "parameters")} ${l} on this entrypoint — ${plural(n, "a candidate", "candidates")} ` +
      `for \`require_auth()\`, provided ${plural(n, "it is", "they are")} in fact who should consent to the ` +
      "operation; the spec gives the type, not the role. If the correct authorizer is someone else (the " +
      "admin stored in the instance, for example), authorize against that key, not against the parameter.",
    remAuthSemEndereco: (alvo: string) =>
      `Require authorization in ${alvo} before the first write. The spec describes this entrypoint and it ` +
      "takes no `address` parameter, so the authorizer has to come from storage — typically the " +
      "administrative address stored in the instance. The fix is to read that key and call `require_auth` " +
      "on it.",
    remAuthSemSpec: (alvo: string) =>
      `Require authorization in ${alvo} before the first write. **The spec that was read does not describe ` +
      "this entrypoint**, so the tool does not know which parameters it takes and cannot point at the " +
      "candidate for `require_auth` — check the signature in the source before choosing the authorizer.",
    remAuthAceitacao: (alvo: string) =>
      `Explicit alternative, if ${alvo} is public by design: record the risk acceptance here, naming the ` +
      "invariant that prevents abuse (the write only affects the caller's own state, the written value is " +
      "idempotent, and so on). The template allows corporate risk acceptance, but it has to be written " +
      "down: the absence of `require_auth` does not distinguish \"public on purpose\" from \"they forgot\".",

    /**
     * Só vale quando o contrato NÃO exporta `__constructor`. Onde ele existe, mandar mover a
     * inicialização para lá é mandar redeployar uma instância viva — e contradiz a própria
     * linha C do achado, que lê o entrypoint como inicializador de segunda etapa.
     */
    remInitVerificarGuarda: (alvo: string, guarda: boolean) =>
      `The contract already exports \`__constructor\`, so the deploy itself initializes atomically and ` +
      `there is nothing to move: verify in the source that ${alvo} is guarded against re-initialization` +
      (guarda
        ? " (the reachable `has_contract_data` path suggests it is)"
        : " (no `has_contract_data` is reachable from it, so no guard is visible)") +
      `. If it is guarded, close the finding as accepted, with that reading recorded. If it is not, gate ` +
      "it on the admin the constructor recorded — read that key and `require_auth` on it. Redeploying the " +
      "live instance is not on the table here: the finding is about the second stage, not about the deploy.",
    remInitConstrutor: (alvo: string) =>
      `Move ${alvo}'s initialization into \`__constructor\`. In Soroban the constructor runs in the same ` +
      "transaction as the deployment, which closes the front-running window by construction — instead of " +
      "depending on the operator managing to initialize before a mempool watcher.",
    remInitGuard: (alvo: string, temChaves: boolean) =>
      `While ${alvo} keeps existing as a public entrypoint, make it abort when the instance key is already ` +
      `written${temChaves ? " (the inferred keys are in *Inferred data stores*)" : ""}, and cover it with a ` +
      "test that checks the second call fails. A guard without a test does not count as remediation — it is " +
      "the assumption that the guard exists. Verify in the source whether re-initialization is already " +
      "guarded; if it is, close this finding with that justification recorded.",

    remUpgradeAuth: (alvo: string, id: string) =>
      `Require \`require_auth\` from the administrative address in ${alvo} before the path that reaches ` +
      `\`update_current_contract_wasm\`. Today no path from this export reaches \`require_auth*\` (tier A ` +
      `evidence of ${id}), so replacing the code the contract executes has no gatekeeper.`,
    remUpgradeEvento: (alvo: string) =>
      `Emit a \`contract_event\` in ${alvo} carrying the new wasm hash. Without that event, a code swap is ` +
      "only detectable by diffing the ledger, and the monitoring plan has no topic to filter on — the most " +
      "serious threat in the document would be left without detection coverage.",

    remOrdemComEvidencia: (corpo: number, alvo: string, authFn: string, authOff: string, writeFn: string, writeOff: string) =>
      `In body \`fn#${corpo}\`, reached by ${alvo}, move \`${authFn}\` (offset 0x${authOff}) to before ` +
      `\`${writeFn}\` (offset 0x${writeOff}). It is a local reordering, checkable by opening the indicated ` +
      "body in a disassembler.",
    remOrdemSemEvidencia: (id: string) =>
      `Move the authorization to before the first write in the body indicated by the tier A evidence of ${id}.`,
    remOrdemComCrossCall: (alvo: string) =>
      `Before that, check whether there is an external effect between the write and the authorization: ` +
      `${alvo} reaches \`call\`/\`try_call\`, so the write can be observed by another contract before the ` +
      "authorization fails. That is the only scenario where the order matters — in Soroban the whole " +
      "transaction reverts if `require_auth` fails.",
    remOrdemSemCrossCall: (alvo: string, solida: boolean, motivo: string, id: string) =>
      `${alvo} does not reach \`call\` or \`try_call\`` +
      (solida ? " (sound negative for this call graph)" : ` (weak negative — ${motivo})`) +
      `, so there is no external effect between the write and the authorization, and reverting the ` +
      `transaction already undoes the write. If that is confirmed, ${id} can be accepted as zero risk — ` +
      "with this justification written down, not by omission.",

    remSilentEvento: (l: string, temDiff: boolean) =>
      `Emit \`contract_event\` in the entrypoints that today reach a write without reaching an event: ${l}. ` +
      "With no topic emitted there is no `getEvents` filter able to detect the action, so those mutations " +
      "stay outside *event-based* monitoring; they are only detectable by state diff " +
      "(`getLedgerEntries`) or by watching the instance wasm hash. " +
      (temDiff
        ? "The sibling monitoring plan does include such a monitor — which is detection by polling, " +
          "with the resolution of the polling interval, not the per-transaction trail an event gives."
        : "No monitor of that kind is in the sibling plan either, so today the action leaves no trail " +
          "an off-chain observer can follow."),
    remSilentTopico: (n: number, l: string) =>
      `In the event of ${n === 1 ? "that entrypoint" : "each of those entrypoints"} (${l}), the first topic ` +
      "has to be a fixed symbol — one per action, not a value derived from an argument — because that is " +
      "what the monitoring plan's `getEvents` filters on. Which symbol to use is a decision for whoever " +
      "writes the contract: soroguard cannot propose a topic name, only state that without a stable topic " +
      "the detection rule for those mutations is impossible to write.",

    remArchivalTtl: (l: string, id: string) =>
      `Extend the TTL on the write path of the entrypoints that write: ${l}. No entrypoint of this contract ` +
      `reaches the \`extend_*_ttl\` family (tier A evidence of ${id}), so nothing renews the state's deadline.`,
    remArchivalAceitar: (id: string) =>
      `If all of this contract's storage is \`temporary\` by design, write that here and close ${id} as ` +
      "accepted. Durability is a runtime argument and does not appear in the bytecode — the tool cannot " +
      "distinguish \"temporary on purpose\" from \"will be archived without warning\".",

    remPrngRegistrar: (alvo: string, id: string) =>
      `Record what the random value in ${alvo} is used for. The host PRNG is seeded per ledger: if the ` +
      "result decides who gets paid, how much, or which branch the state takes, whoever picks the " +
      "submission ledger picks the draw. If the use is cosmetic or is identifier generation, write that " +
      `down and close ${id} as accepted.`,
    remPrngTrocar: (alvo: string) =>
      `If the value carries economic weight, replace the source in ${alvo} with one the submitter does not ` +
      "control — commit-reveal with more than one party, or off-chain randomness with a proof. There is no " +
      "host PRNG parameter that removes predictability within the ledger, so there is no local fix.",

    remSdkRecompilar: (id: string) =>
      `Recompile with a fixed version of \`soroban-sdk\` (the fixed versions are in the tier A evidence of ` +
      `${id}) and redeploy. As long as the wasm hash in production does not change, the finding stays true: ` +
      "it describes the deployed binary, and updating the repository does not change what is on the ledger.",
    remSdkVerificar: (id: string) =>
      `Before redeploying, check in the source whether the advisory's trigger condition (described in the ` +
      `tier C evidence of ${id}) exists in this contract. If it does not, record the acceptance here with ` +
      "that justification — the exposure is a bytecode fact, the exploitability is not.",

    remLacunaClasse: (cls: string, id: string) =>
      `**Declared gap: no remediation derived automatically for the \`${cls}\` class.** ${id} needs a ` +
      "remediation written by a human reviewer before submission. Checklist text here would be worse than " +
      "the gap.",

    /* --- 4. Did we do a good job? --- */
    introAvaliacao:
      "The template's five questions are answered below with what automatic generation can support. Where " +
      "the answer depends on the team's process rather than on the binary, that is stated instead of " +
      "assumed.\n",
    q1Sim: (data: string, nFront: number, nProc: number) =>
      "**The tool cannot answer this one.** The diagram was generated together with this document, in the " +
      `same run (${data}); whether the team goes back to it afterwards is a process fact, outside the ` +
      "binary, and whoever reviews has to record it. **What is verifiable here is the dependency in the " +
      `other direction:** the diagram's ${nFront} trust ${plural(nFront, "boundary", "boundaries")} over ` +
      `${nProc} \`process\` ${plural(nProc, "node", "nodes")} are what the threat table is organized by — ` +
      "each `process` node is a module export, the open boundary (no reachable `require_auth*`) is the " +
      "group the Elevation findings come from, and the cross-call boundary is what the Tampering gap " +
      "points at. So the threats are derived from the diagram's content, not merely accompanied by it.",
    q1Nao:
      "**No.** No DFD was generated for this contract (see the gap in the *What are we working on?* " +
      "section), so there is no diagram to reference. The artifact is incomplete regarding the template's " +
      "visual-diagram requirement.",
    q2Com: (nAmeacas: number, nLetras: number, nEps: number) =>
      "The tool has no memory of what the team already knew, so it cannot say what is *new* — only what it " +
      `derived: ${nAmeacas} ${plural(nAmeacas, "threat", "threats")} across ${nLetras} STRIDE ` +
      `${plural(nLetras, "letter", "letters")}, from ${nEps} invocable entrypoints. Marking which ones were ` +
      "unknown is the reviewer's job.",
    q2Confirmar: (n: number, ids: string) =>
      ` Point of attention: ${n} of ${plural(n, "them depends", "them depend")} on source confirmation before ` +
      `counting as a finding (${ids}).`,
    q2Sem:
      "No threat was derived from this contract's bytecode. That is not a security attestation: it means " +
      "this tool's detectors — which cover authorization, auth/write ordering, event trail, TTL and SDK " +
      "version — found no signal. The declared gaps say what fell outside their reach.",
    q3Com: (hash: string) =>
      "**Not verified, and not verifiable by this tool.** Every remediation in the previous section is tier " +
      "C and is proposed, not applied. soroguard read the WASM that is deployed" + hash +
      " and cannot observe a fix that has not reached the ledger. **The objective test is concrete:** run " +
      "soroguard again against the contract after the redeploy and check that the corresponding finding " +
      "disappears — if it persists, the fix did not reach the path that produced the evidence.",
    q3Hash: (h: string) => ` (hash \`${h}\`)`,
    q3Sem: "Not applicable: there is no derived threat, so there is no remediation to evaluate.",
    q4: (data: string, lacunas: string, confirmar: string) =>
      `Outside the scope of this run — it depends on audits, manual review and incidents after ${data}. ` +
      `Recorded here as the most likely places for open issues to surface: ${lacunas}${confirmar}. This ` +
      "follow-up section must be updated by whoever reviews it, not regenerated.",
    q4Lacunas: (l: string) => `the letters declared as gaps (${l})`,
    q4LacunasGenerico: "the declared gaps",
    q4Confirmar: (n: number) =>
      `, and the ${plural(n, "threat", "threats")} flagged for human confirmation`,

    insightAssimetria:
      "The analysis is of **deployed bytecode**, and the asymmetry matters: \"does not reach `require_auth`\" " +
      "is a sound negative for this module's call graph — it says nothing about authorization enforced " +
      "inside a contract reached through `call`/`try_call`, nor about `__check_auth`; " +
      "\"reaches `put_contract_data`\" is an over-approximation, because the write may sit on a " +
      "branch the entrypoint never executes. Every positive finding carries its hop count for that reason.",
    insightSolido:
      "This module's call graph is complete (no `call_indirect`), so the negative claims in this document " +
      "are sound with respect to that graph — and only to it.",
    insightRebaixado: (motivo: string) =>
      `**${motivo[0].toUpperCase()}${motivo.slice(1)}**, so the call graph is incomplete and not even the ` +
      "negative claims are sound. Everything here is downgraded to indication, and a second pair of eyes " +
      "over the privileged entrypoints is mandatory.",
    insightSpoofInfo: (nAuth: number, nEps: number, nChaves: number, nTopicos: number) =>
      "Spoofing and Information Disclosure do not come out of the bytecode: they depend on identity and on " +
      "a product decision about which data goes onto a public ledger, and neither is in the binary. " +
      "Measured on the calibration corpus: zero findings in 100% of the 75 mainnet contracts " +
      "(`docs/CALIBRACAO.md`). Filling those two letters with generic text to satisfy the template's \"≥1 " +
      "per letter\" is what would get the document discarded by the first competent reviewer. What this " +
      `run hands the manual review for those two letters, in numbers: ${nAuth} of ${nEps} invocable ` +
      `${plural(nEps, "entrypoint", "entrypoints")} reaching \`require_auth*\`, ${nChaves} inferred ` +
      `storage ${plural(nChaves, "key", "keys")} and ${nTopicos} declared event ` +
      `${plural(nTopicos, "topic", "topics")}.`,
    insightObsInsuficiente:
      "There is on-chain observation (tier B), but the window is too short to serve as a baseline — the " +
      "rates are recorded as raw data, not as a baseline.",
    insightObsOk: (n: number) =>
      "There is on-chain observation (tier B) over the window recorded in the first section, and " +
      `${n} ${plural(n, "monitor", "monitors")} in the sibling plan ${plural(n, "anchors", "anchor")} ` +
      "a baseline on it instead of on a plausible number.",
    insightObsSemAncora: (ledgers: number, h: number, ev: number, topicos: number, motivo: string) =>
      `The window was observed (${ledgers} ledgers, ~${h} h, ${ev} ${plural(ev, "event", "events")} ` +
      `across ${topicos} ${plural(topicos, "topic", "topics")}), but **no monitor in the sibling plan ` +
      `could anchor a baseline on it** — ${motivo}. Tier B here is a record of the window, not a ` +
      "baseline: every threshold in the monitoring plan still has to declare that it has no observed " +
      "basis.",
    motivoSemTrafego: "no event of any topic was observed, so there is nothing to compute a rate from",
    motivoSemVinculo:
      "no monitor binds an observed topic — the plan's rules filter on topics that did not appear in " +
      "the window",
    insightObsFalhou: (e: string) =>
      `**Tier B collection FAILED in this run:** ${e}. The missing window is ours — the RPC call did not ` +
      "complete — and is NOT evidence that the contract is inactive. The whole document rests on tiers A " +
      "and C, and the associated monitoring plan has to declare the failure instead of estimating.",
    insightObsOffline:
      "**Tier B collection was not run in this generation (offline / local target).** The whole document " +
      "rests on tiers A and C. Any baseline in the associated monitoring plan has to declare the missing " +
      "window instead of estimating.",
    insightObsAusente:
      "**There is no on-chain observation (tier B) in this run.** The whole document rests on tiers A and C. " +
      "Any baseline in the associated monitoring plan has to declare the missing window instead of " +
      "estimating.",
    insightForaDoEscopo:
      "What this model does **not** cover, by construction: economic design (incentives, settlement, " +
      "oracle), governance and custody of the privileged keys, security of the frontend and of the " +
      "infrastructure that builds the transactions, and whether the address authorized in each " +
      "`require_auth` is the right address. None of those questions can be answered from the binary.",
    divergencia: (l: string, n: number) =>
      `> **Inconsistent input:** \`ctx.gaps\` lists ${l} as ${plural(n, "a letter", "letters")} with no ` +
      `finding, but findings were derived under ${plural(n, "it", "them")}. The document followed the ` +
      "findings, and this line is recorded so the divergence does not pass silently.\n",

    /* --- cabeçalho do documento --- */
    subtitulo: (rede: string, data: string) =>
      `Network ${rede} · generated at ${data} · official Stellar template (*STRIDE-template*, ` +
      "developers.stellar.org/docs/build/security-docs/threat-modeling).\n",
    introDocumento:
      "Draft generated by soroguard from the deployed WASM. Every claim carries its evidence tier: **A** = " +
      "bytecode fact, **B** = fact observed on-chain, **C** = inference. The sections the analysis cannot " +
      "support appear as a declared gap — never filled with generic text. **Human review is mandatory " +
      "before submission.**\n",
  },

  pt: {
    /* --- utilitários --- */
    eMais: (n: number) => `e mais ${n}`,
    e: "e",
    sim: "sim",
    nao: "não",
    alcancam: (n: number) => `${n} ${n === 1 ? "alcança" : "alcançam"}`,
    naoInformado: "não informado",

    /* --- motivo da aproximação --- */
    razaoModuloIndireto: "há `call_indirect` no módulo",
    razaoModuloDegradado: "há corpos de função degradados no módulo",
    razaoIncompleto: (r: string) => `o módulo não pôde ser lido por inteiro (${r})`,
    razaoSubIndireto: (esc: string) => `\`call_indirect\` ${esc}`,
    razaoSubDegradado: (esc: string) => `corpo de função degradado ${esc}`,
    escopoEste: "no subgrafo deste entrypoint",
    escopoListados: "nos subgrafos dos entrypoints listados",

    /* --- linha de solidez --- */
    solidezSdk: "não depende do call graph — a evidência é a custom section `contractmetav0` do próprio binário",
    escopoNegativa:
      "negativa sólida para o call graph deste módulo (autorização exigida dentro de um contrato chamado " +
      "ou no `__check_auth` não é visível aqui)",
    solidezModuloOk: (esc: string) => `call graph do módulo completo — ${esc}`,
    solidezRebaixada: (motivo: string) =>
      `**rebaixada** — ${motivo}; as negativas valem como indício, não como negativa sólida`,
    solidezEpOk: (escopo: string, esc: string) => `call graph completo ${escopo} — ${esc}`,

    /* --- 1. What are we working on? --- */
    lacunaEquipe:
      "**Lacuna a preencher pela equipe.** A soroguard deriva esta seção do WASM deployado e " +
      "não conhece o propósito de negócio do contrato. O parágrafo de descrição que o template " +
      "pede — o que o protocolo faz, quem são os atores, que valor ele custodia, quais suposições " +
      "de confiança existem fora da cadeia — não é derivável do bytecode e precisa ser escrito por " +
      "quem construiu o sistema. O que segue é só a superfície técnica medida.\n",
    hdrObjeto: "### Objeto analisado\n",
    thCampoValor: "| Campo | Valor |",
    lblObjetoAnalisado: (f: string) => `| Objeto analisado | arquivo local \`${f}\` |`,
    lblRede: "Rede",
    lblTamanhoWasm: "Tamanho do WASM",
    lblGeradoEm: "Gerado em",
    lblSolidez: "Solidez do call graph",
    solidezCompleta: "completo — nenhum `call_indirect` no módulo",
    solidezAproximada: (motivo: string) => `**aproximado** — ${motivo}; as negativas deixam de ser sólidas`,
    objetoComHash:
      "O documento inteiro descreve **este binário**, identificado pelo hash acima — ",
    objetoSemHash:
      "O documento inteiro descreve **o binário analisado**. O hash não foi informado nesta " +
      "geração, então não há como provar depois que o laudo é deste bytecode: quem gerar " +
      "precisa registrar qual WASM foi lido. O objeto é o binário — ",
    objetoFim:
      "não o repositório de onde ele teria saído. É a única coisa que a análise consegue " +
      "afirmar: fonte e deploy divergem com frequência, e o que está em produção é o WASM.\n",
    hdrEvidencia: "### Como ler a evidência\n",
    thEvidencia: "| Nível | Significa | Quem consegue verificar |",
    linhaA: (t: string) => `| **A** | ${t}: alcançabilidade no call graph do WASM deployado | qualquer um, redeterminístico a partir do binário |`,
    linhaB: (t: string) => `| **B** | ${t}: eventos realmente emitidos na janela observada | qualquer um, via RPC |`,
    linhaC: (t: string) => `| **C** | ${t}. Cobre classe de ameaça, severidade e remediação | só revisão humana |`,
    assimetria:
      "Uma assimetria que muda a leitura de tudo abaixo: **\"não alcança `require_auth`\" é negativa " +
      "sólida para o call graph deste módulo** (quando esse grafo está completo) — não diz nada sobre " +
      "autorização exigida dentro de um contrato alcançado por `call`/`try_call`, nem sobre o " +
      "`__check_auth` de uma conta customizada. Já **\"alcança `put_contract_data`\" é " +
      "super-aproximação** — a escrita pode estar num ramo que aquele entrypoint nunca executa. " +
      "Por isso toda afirmação positiva vem com o número de saltos, e caminhos longos ficam " +
      "marcados para confirmação em vez de afirmados.\n",
    notaCheckAuth:
      "Este módulo exporta `__check_auth`, ou seja, é uma **conta customizada**: a autorização é " +
      "implementada *pelo* `__check_auth`, não pedida via `require_auth`. \"Nenhum caminho até " +
      "`require_auth`\" nos entrypoints dele é a forma esperada desse tipo de contrato e não é, por si, " +
      "um achado.\n",
    hdrSuperficie: (solido: boolean) =>
      `### Superfície exportada ${solido ? "(nível A)" : "(nível A **rebaixado**)"}\n`,
    avisoSuperficie: (motivo: string) =>
      "> **Leia esta tabela como indício, não como fato.** " +
      `${motivo[0].toUpperCase()}${motivo.slice(1)}: existe caminho de chamada que a travessia não segue, ` +
      "então cada `não` abaixo (\"não alcança `require_auth`\", \"não escreve\") deixa de ser negativa " +
      "sólida. Os " +
      "`sim` continuam sendo o que sempre foram — alcançabilidade, não execução.\n",
    semEntrypoints:
      "Nenhum entrypoint invocável foi encontrado nos exports do módulo. Isso é anômalo para um " +
      "contrato Soroban — pode ser um SAC, um módulo compilado sem spec, ou falha de leitura. " +
      "**Nada abaixo deste ponto tem base; o artefato não é submissível neste estado.**\n",
    resumoSuperficie: (exp: number, inv: number, a: string, g: string, c: string, u: string) =>
      `${exp} exportados, ${inv} ${inv === 1 ? "entrypoint invocável" : "entrypoints invocáveis"} · ` +
      `${a} \`require_auth*\` · ${g} escrita de storage · ${c} \`call\`/\`try_call\` · ` +
      `${u} troca do próprio código.`,
    reservados: (n: number, l: string) =>
      ` A diferença ${n === 1 ? "é 1 export reservado" : `são ${n} exports reservados`} \`__*\` (${l}) ` +
      `fora da contagem de invocáveis: o host recusa ${n === 1 ? "invocá-lo" : "invocá-los"} ` +
      `diretamente (CAP-0058) e por isso ${n === 1 ? "ele não é avaliado" : "eles não são avaliados"} ` +
      "como superfície de ataque.",
    semReservados: " Nenhum export `__*`, então as duas contagens coincidem.",
    thSuperficie: "| Entrypoint | auth | escreve | evento | upgrade | cross-call | fanout |",
    notaSuperficie:
      "Em todas as colunas, \"sim\" quer dizer **alcança** a host function correspondente em algum " +
      "caminho do call graph, não que a execute sempre.\n",
    hdrStores: "### Data stores inferidos\n",
    chavesCertas: (l: string) => `- Chaves lidas da memória linear do módulo: ${l}.`,
    chavesProvaveis: (l: string) => `- Chaves prováveis (leitura parcial da seção de dados): ${l}.`,
    notaDurabilidade:
      "\nA durabilidade de cada chave (`temporary` / `persistent` / `instance`) é argumento de " +
      "runtime e **não aparece no bytecode** — não a assuma a partir desta lista.\n",
    hdrObservacao: "### Atividade observada on-chain (nível B)\n",
    janela: (de: number, ate: number, n: number, h: number) =>
      `Janela: ledgers ${de}–${ate} (${n} ledgers, ~${h}h).`,
    janelaInsuficiente:
      " **Janela insuficiente para baseline honesto** — as taxas abaixo são registradas, não devem ser usadas como linha de base.",
    thEventos: "| Topic | Ocorrências | Ledgers | Eventos/hora |",
    semEventos:
      "Nenhum evento observado na janela: **nenhum evento de nenhum tópico foi observado neste contrato na " +
      "janela — ausência de tráfego, não perfil de tráfego.** A contagem é real e ainda assim não " +
      "sustenta limiar de monitoramento.\n",
    declaradosNaoVistos: (l: string, curta: boolean, h: number) =>
      `Tópicos declarados no spec e não observados na janela: ${l}. ` +
      (curta
        ? "Ausência numa janela tão curta não é evidência de que a ação nunca ocorre.\n"
        : `Ausência numa janela de ~${h} h não é evidência de que a ação nunca ocorre — só de que ela ` +
          "não ocorreu nessa janela.\n"),
    coletaFalhou: (e: string) =>
      `**Coleta de nível B FALHOU:** ${e}. Não há janela porque a chamada de RPC não ` +
      "completou — e não porque o contrato esteja inativo. Nenhuma afirmação sobre atividade on-chain é " +
      "feita neste documento.\n",
    coletaOffline:
      "**Coleta de nível B não executada (offline / alvo local).** Um `.wasm` local não tem histórico " +
      "on-chain, e o modo offline não vai à rede por opção. Nenhuma afirmação de nível B aqui.\n",
    coletaAusente: "Nenhuma janela de observação foi coletada para este contrato.\n",
    legendaDfdComChaves:
      "O diagrama sai da própria análise: cada `process` é um export do módulo, cada `store` é " +
      "uma chave de storage inferida, e cada aresta marcada como fronteira é um ponto onde a " +
      "execução cruza para fora do contrato (`call`/`try_call`) ou onde a autorização é exigida.\n",
    legendaDfdSemChaves:
      "O diagrama sai da própria análise: cada `process` é um export do módulo, o único `store` é o " +
      "storage do contrato com as chaves **não inferidas** — o diagrama declara essa lacuna em vez de " +
      "desenhar chaves que não tem — e cada aresta marcada como fronteira é um ponto onde a execução " +
      "cruza para fora do contrato (`call`/`try_call`) ou onde a autorização é exigida.\n",
    thFronteiras: "| Fronteira de confiança | Nós contidos |",
    notaFronteiraAuth: (admins: string[], usuarios: string[]) =>
      "**Como ler a fronteira de autorização (nível C, heurística por forma do nome).** Alcançar " +
      "`require_auth*` não é, por si, controle de acesso. " +
      (usuarios.length
        ? `Nos ${usuarios.length} nós com forma de usuário (${listaE(usuarios)}) ela é o chamador ` +
          "autorizando o próprio endereço — forma esperada de operação de usuário, sem chave " +
          "privilegiada atrás. "
        : "") +
      (admins.length
        ? `Só os ${admins.length} nós com forma administrativa (${listaE(admins)}) estão atrás de um ` +
          "detentor de chave cuja custódia a revisão precisa rastrear. "
        : "Nenhum nó dentro da fronteira tem forma administrativa de nome, então nenhum deles aponta " +
          "para um detentor de chave privilegiada a rastrear. ") +
      "A separação vem do nome, não do bytecode: o call graph nunca mostra *de quem* é o `Address` " +
      "autorizado.\n",
    dfdAusente:
      "**Lacuna: nenhum data-flow diagram foi gerado para este contrato.** O template exige ao " +
      "menos um diagrama visual, então o artefato está incompleto neste ponto. Isto é uma falha " +
      "da geração, não uma afirmação de que o contrato não tem fluxos — não substitua por um " +
      "diagrama genérico, que seria pior que a lacuna.\n",
    hdrAvisosSpec: "### Avisos da leitura do spec\n",

    /* --- 2. What can go wrong? — lacunas por letra --- */
    corpus:
      "Medição do corpus de calibração da soroguard (75 contratos de mainnet, `docs/CALIBRACAO.md`): " +
      "zero achado derivável em 100% deles",
    lacunaSpoofConcreto: (n: number, admins: string[], usuarios: string[], checkAuth: boolean) =>
      ` **Onde a identidade é afirmada neste contrato:** ${
        n === 0
          ? "nenhum entrypoint invocável alcança `require_auth*`"
          : `${n} ${n === 1 ? "entrypoint invocável alcança" : "entrypoints invocáveis alcançam"} ` +
            "`require_auth*`"
      }. ` +
      (admins.length
        ? `**Com forma administrativa (${admins.length}, exigem rastreio de chave):** ${listaE(admins)} — ` +
          "são as chamadas cujo `Address` a revisão precisa rastrear até um detentor de chave: custódia, " +
          "multisig ou chave única. "
        : "**Nenhum entrypoint com forma administrativa alcança `require_auth*`**, então não há nessa " +
          "forma chamada a rastrear até detentor de chave. ") +
      (usuarios.length
        ? `**Com forma de usuário (${usuarios.length}, sem rastreio de chave):** ${listaE(usuarios)} — ali ` +
          "o `require_auth` é o chamador autorizando o PRÓPRIO endereço, que é a forma esperada de uma " +
          "operação de usuário, não controle de acesso; não há chave privilegiada atrás dela para rastrear. "
        : "") +
      "**Essa separação é heurística por forma do nome (nível C), não fato de bytecode** — o bytecode " +
      "mostra que `require_auth*` é alcançado, nunca *de quem* é o endereço autorizado. Conferir contra " +
      "as assinaturas antes de usar a separação como lista de trabalho. " +
      (checkAuth
        ? "O módulo também exporta `__check_auth`: é conta customizada, e a verificação de assinatura " +
          "que ele implementa faz parte da própria pergunta de identidade fora da cadeia."
        : "O módulo não exporta `__check_auth`, então a verificação de assinatura é do host, não deste " +
          "contrato."),
    lacunaInfoConcreto: (chaves: string, topicos: string) =>
      ` **A superfície concreta a revisar neste contrato:** chaves de storage inferidas ${chaves}; ` +
      `tópicos de evento declarados ${topicos}. São os campos que terminam legíveis num ledger público.`,
    listaVazia: "⟨nenhuma inferida⟩",
    lacunaSpoof: (corpus: string) =>
      "**Lacuna declarada — não derivável do bytecode.** O call graph mostra *se* um caminho " +
      "alcança `require_auth`; nunca *quem* é o `Address` verificado, como a chave desse endereço " +
      "é custodiada, nem como o cliente que monta a transação autentica o usuário. Identidade " +
      `vive fora do contrato. ${corpus} — é limite estrutural da análise de bytecode, não falha ` +
      "do detector neste contrato. **Exige análise manual do fluxo off-chain:** custódia das " +
      "chaves privilegiadas (multisig ou chave única?), autenticação do frontend/backend que " +
      "assina, e se algum endereço com papel administrativo é uma conta compartilhada.",
    lacunaInfo: (corpus: string) =>
      "**Lacuna declarada — não derivável do bytecode.** Todo o estado de ledger no Soroban é " +
      "público por construção, então \"divulgação excessiva\" é uma pergunta sobre *quais dados o " +
      "protocolo decidiu colocar on-chain* — decisão de produto que o WASM não registra. O " +
      "bytecode também não diz o que os argumentos e os tópicos de evento significam. " +
      `${corpus} — limite estrutural. **Exige análise manual:** revisar quais campos entram em ` +
      "storage e em tópicos de evento, e se algum deles é dado que não deveria ser público ou " +
      "que dá vantagem a quem lê o ledger antes da transação liquidar.",
    lacunaTamperIntro:
      "**Lacuna declarada — nenhum achado derivado neste contrato.** Três detectores alimentam " +
      "esta letra e nenhum disparou: `write-before-auth` (compara offsets de bytecode *dentro do " +
      "mesmo corpo*), `host-prng-in-value-path` (PRNG do host num caminho que muda estado ou chama " +
      "para fora) e `vulnerable-sdk` quando o advisory não é de autorização. ",
    lacunaTamperRessalva: (l: string) =>
      `**Ressalva que invalida esta lacuna sem revisão:** a análise registrou escrita antes de ` +
      `autorização em ${l}, e mesmo assim nenhum achado saiu nesta letra. É divergência ` +
      `entre a análise e o detector — conferir à mão antes de aceitar o campo como vazio. `,
    lacunaTamperSemRessalva:
      "O detector de write-before-auth compara offsets *dentro de um mesmo corpo* e não encontrou corpo " +
      "em que uma escrita preceda o primeiro `require_auth`. Ele não enxerga a ordem quando a escrita e " +
      "a autorização vivem em funções diferentes, então isto é ausência de sinal, não demonstração de " +
      "que a ordem está correta. ",
    lacunaTamperElev: (n: number) =>
      `Atenção à classificação: adulteração de estado por **falta** de autorização está em ` +
      `**Elevation** (${n} ${n === 1 ? "achado" : "achados"}) e não aqui. `,
    lacunaTamperFim:
      "**O que continua exigindo análise manual:** validação dos argumentos que entram nos " +
      "entrypoints, e confiança em dados vindos de outro contrato (oráculo, router) — nenhuma " +
      "das duas é derivável de alcançabilidade.",
    lacunaRepudiateIntro:
      "**Lacuna declarada — nenhum achado derivado neste contrato.** O detector desta letra é " +
      "`silent-mutation`. ",
    lacunaRepudiateSemEscrita:
      "Nenhum entrypoint invocável alcança escrita de storage, então não há ação que precise de trilha. ",
    lacunaRepudiateComEscrita: (n: number) =>
      `${n === 1
        ? "O único entrypoint que alcança escrita também alcança"
        : `Os ${n} entrypoints que alcançam escrita também alcançam`
      } \`contract_event\` em algum caminho do subgrafo. **Isso não prova que existe trilha:** ` +
      "alcançar `contract_event` é afirmação positiva, e positiva é super-aproximada — o evento " +
      "pode estar num ramo que a escrita não percorre. O que a ausência de achado sustenta é " +
      "apenas o negativo: nenhum gravador ficou sem *nenhum* caminho até o evento. ",
    lacunaRepudiateFim:
      "**O que o bytecode também não responde:** se o *conteúdo* do evento identifica o autor da ação. " +
      "Um evento que não carrega o endereço do chamador não resolve repúdio, e a alcançabilidade " +
      "de `contract_event` não diz nada sobre os tópicos e o payload. Conferir manualmente.",
    lacunaDosIntro:
      "**Lacuna declarada — nenhum achado derivado neste contrato.** O detector desta letra é " +
      "`archival-risk`. ",
    lacunaDosTtl: (n: number, l: string, saltos: number | undefined, temReservado: boolean) =>
      `${n} ${n === 1 ? "export alcança" : "exports alcançam"} a família \`extend_*_ttl\`` +
      (saltos === undefined ? "" : `, o mais próximo a ${saltos} ${saltos === 1 ? "salto" : "saltos"}`) +
      ` (${l}${temReservado ? "; o detector conta qualquer export, inclusive os reservados `__`" : ""}), ` +
      "e o detector só dispara quando nenhum alcança. **Leia essa contagem como super-aproximação:** " +
      "*alcançar* não é *executar* — medido no corpus de calibração, ~84% das positivas nuas passam por " +
      "um helper compartilhado que o entrypoint nunca executa (`docs/CALIBRACAO.md`), e entrypoints " +
      "somente-leitura caem nesta lista exatamente por isso. Se esses caminhos de renovação não rodarem " +
      "na operação normal do contrato, o risco de arquivamento continua existindo e o bytecode " +
      "não mostra isso. ",
    lacunaDosSemEscrita:
      "Nenhum entrypoint invocável alcança escrita de storage, então não há estado a arquivar. ",
    lacunaDosFim:
      "**O que não é derivável do call graph:** exaustão de recursos por entrada grande (limites " +
      "de CPU/memória do ledger), dependência de liveness de um contrato alcançado por `call`, " +
      "e um `pause`/`kill` administrativo capaz de travar o sistema. Exigem análise manual.",
    lacunaElevIntro: "**Lacuna declarada — nenhum achado derivado neste contrato.** ",
    lacunaElevResiduo: (n: number, l: string) =>
      `**Ressalva que invalida esta lacuna sem revisão:** ${n} ` +
      `${n === 1 ? "entrypoint invocável alcança" : "entrypoints invocáveis alcançam"} ` +
      `escrita de estado ou troca do próprio código sem alcançar \`require_auth*\` (${l}), ` +
      `e ainda assim nenhum achado foi emitido — o detector ${n === 1 ? "o suprimiu" : "os suprimiu"} ` +
      "como falso positivo provável. O motivo de cada supressão fica em `detect.ts` e não chega a " +
      "este documento, então **confira um a um antes de aceitar o campo como vazio.** Aqui a " +
      "lacuna é decisão do detector, não resultado da análise. ",
    lacunaElevSemResiduo:
      "Nenhum entrypoint invocável alcança escrita de estado nem troca do próprio código sem " +
      "alcançar `require_auth*`. ",
    lacunaElevNegativaSolida:
      "Esta negativa é sólida para o call graph deste módulo, que é completo — autorização exigida " +
      "dentro de um contrato alcançado por `call`/`try_call`, ou no `__check_auth`, não é visível aqui. ",
    lacunaElevNegativaFraca: (motivo: string) =>
      `**Esta negativa é fraca:** ${motivo}, então existe caminho que a análise não enxerga. `,
    lacunaElevDelegam: (n: number, l: string) =>
      `**Fora do alcance de qualquer detector:** ${n} ` +
      `${n === 1 ? "entrypoint alcança" : "entrypoints alcançam"} ` +
      `\`authorize_as_curr_contract\` (${l}). A soroguard trata ` +
      "delegação como inventário e não emite achado, porque o bug real é a *forma* da árvore de " +
      "autorização, que o simples alcance não revela — a ausência de achado aqui não é resultado " +
      "de análise, é ausência de análise. Revisar o escopo de cada delegação à mão. ",
    lacunaElevFim:
      "**O que o bytecode não responde:** se o `require_auth` alcançado é sobre o endereço *certo*. " +
      "\"Alcança `require_auth`\" não é \"autoriza quem deveria\" — um contrato que autoriza o " +
      "chamador onde deveria autorizar o admin passa por este detector. Exige revisão manual dos " +
      "endereços autorizados em cada entrypoint privilegiado.",

    /* --- 2. What can go wrong? — corpo da seção --- */
    solidezRebaixadaCallout: (motivo: string) =>
      `> **Solidez rebaixada.** ${motivo[0].toUpperCase()}${motivo.slice(1)}, então o call graph está ` +
      "incompleto. Toda afirmação negativa deste documento (\"não alcança `require_auth`\") deixa de ser " +
      "sólida e vira indício: existe caminho de chamada que a análise não consegue seguir. Os achados " +
      "abaixo aparecem marcados individualmente na linha *Solidez*.\n",
    viaTabela: (l: string) =>
      `> **Através da tabela de funções, estas host functions podem adicionalmente ser alcançáveis:** ${l}. ` +
      "Elas não estão no call graph direto: o despacho indireto as torna possíveis, não provadas. É o " +
      "conteúdo concreto do rótulo \"aproximado\" acima.\n",
    contagemAmeacas: (n: number) => `${n} ${n === 1 ? "ameaça derivada" : "ameaças derivadas"}`,
    contagemSeveridade: (s: string) => ` — ${s}`,
    contagemConfirmar: (n: number) =>
      `. ${n} ${n === 1 ? "está marcada" : "estão marcadas"} para confirmação humana antes de contar como achado.`,
    contagemLacunas: (n: number) =>
      ` ${n} ${n === 1 ? "letra sem achado derivável, declarada" : "letras sem achado derivável, declaradas"} abaixo como lacuna.`,
    celulaAmeaca: (id: string, titulo: string, niveis: string, sev: string) =>
      `**${id}** — ${titulo} · níveis ${niveis} · severidade ${sev} (C)`,
    marcaConfirmar: " · ⚠ confirmar antes de tratar como achado",
    marcaRebaixada: " · ⚠ evidência rebaixada",
    semAmeacaDerivavel: "_Sem ameaça derivável do bytecode._",
    notaTabelaAmeacas:
      "O template pede ao menos uma issue por letra. As letras sem achado aparecem como lacuna " +
      "declarada, não preenchidas: a ferramenta lê bytecode, e o que ela não consegue derivar dali " +
      "ela diz que não conseguiu. Um campo honestamente vazio é verificável; um campo com genérico " +
      "não é.\n",
    hdrDetalhamento: "### Detalhamento das ameaças\n",
    tituloGrupo: (a: string, b: string, cls: string, n: number) =>
      `#### ${a} – ${b} — \`${cls}\` em ${n} entrypoints\n`,
    notaGrupo: (n: number) =>
      `Estes ${n} achados têm evidência byte a byte idêntica e diferem apenas no ` +
      "entrypoint, então aparecem num bloco só. Cada ID continua individual, com remediação " +
      "própria na seção seguinte.\n",
    thIdEntrypoint: "| ID | Entrypoint |",
    lblClasse: "Classe",
    lblAlvo: "Alvo",
    alvoContrato: "o contrato inteiro",
    alvoEntrypoint: (e: string) => `entrypoint \`${e}\``,
    lblSeveridade: "Severidade",
    valorSeveridade: (s: string) => `${s} — **nível C**, é juízo de risco, não fato de bytecode`,
    lblSolidezAchado: "Solidez",
    hdrEvidenciaBloco: "**Evidência**\n",
    itemEvidencia: (tier: Tier, rotulo: string, claim: string) => `- **[${tier}]** *(${rotulo})* — ${claim}`,
    aindaNaoAchado: (escopo: string, id: string) =>
      "> **Este achado ainda não é um achado.** A evidência positiva é super-aproximada e " +
      `precisa ser confirmada no fonte ${escopo} antes de entrar num plano de correção. Ver ${id}.R.1.\n`,
    notaJaInicializado: (n: number, h: number) =>
      `> **Nota de nível B/C.** O tráfego observado (${n} ${n === 1 ? "evento" : "eventos"} em ~${h} h) ` +
      "indica que esta instância já está inicializada, então o texto de nível C acima descreve uma " +
      "janela que provavelmente já fechou. O risco residual é a **re-inicialização**, e ele depende de " +
      "um guard que o bytecode não mostra: ",
    notaGuardSim: (l: string) =>
      `\`has_contract_data\` ESTÁ no conjunto alcançável de ${l} — provável guard de "já inicializado", ` +
      "embora a alcançabilidade não prove que ele cobre este caminho.",
    notaGuardNao: (l: string) =>
      `\`has_contract_data\` NÃO ESTÁ no conjunto alcançável de ${l} — nenhum guard de "já ` +
      "inicializado\" é visível ali; ele ainda pode viver atrás de uma chamada a outro contrato.",
    escopoCadaListado: "de cada entrypoint listado",
    escopoDe: (e: string) => `de \`${e}\``,
    hdrLacunas: "### Lacunas declaradas\n",

    /* --- 3. What are we going to do about it? --- */
    introRemediacoes:
      "**Toda esta seção é nível C (inferência).** Remediação não é fato de bytecode: é proposta, " +
      "derivada do achado e do entrypoint concreto que o produziu, e precisa de revisão de quem " +
      "conhece o desenho do sistema. Nenhuma delas foi aplicada nem verificada — a ferramenta lê o " +
      "binário que está em produção hoje.\n",
    celulaSemRemediacao: (letra: string, trabalho: string) =>
      `| ${letra} | _Sem remediação: nenhuma ameaça foi derivada nesta letra ` +
      "(ver a lacuna declarada na seção anterior)._ A remediação tem que ser escrita junto com a " +
      "ameaça, depois da análise manual — preencher aqui sem ter o achado produziria uma correção " +
      `sem problema correspondente. **O trabalho que esta letra deixa para a revisão:** ${trabalho} |`,
    trabSpoof: (admins: string[], usuarios: string[]) =>
      (admins.length
        ? `revisar quem detém as chaves atrás dos ${admins.length} entrypoints com forma administrativa ` +
          `que alcançam \`require_auth*\` listados na lacuna de Spoofing (${listaE(admins)}) — custódia, ` +
          "multisig ou chave única"
        : "nenhum entrypoint com forma administrativa alcança `require_auth*` na lacuna de Spoofing, então " +
          "o que sobra é a custódia de quem deployou e de quem assina no cliente") +
      (usuarios.length
        ? `; os ${usuarios.length} com forma de usuário listados ali (${listaE(usuarios)}) autorizam o ` +
          "próprio endereço do chamador e não exigem rastreio de detentor de chave"
        : "") +
      ".",
    trabTamper: (n: number, l: string) =>
      "revisar a validação de argumentos e a confiança em dados vindos de contratos alcançados por " +
      `\`call\`/\`try_call\` nos ${n} entrypoints listados na lacuna de Tampering${n ? ` (${l})` : ""} — ` +
      "o detector de escrita-antes-da-auth só compara offsets dentro de um corpo e não responde nenhuma " +
      "das duas perguntas.",
    trabRepudiate: (n: number, l: string) =>
      n === 0
        ? "nenhum entrypoint invocável alcança escrita de storage, como diz a lacuna de Repúdio, então o " +
          "que sobra é confirmar que nada fora da cadeia age em nome deste contrato."
        : `abrir os eventos dos ${n} entrypoints que alcançam escrita listados na lacuna de Repúdio (${l}) ` +
          "e conferir se o payload carrega o endereço do chamador — alcançar `contract_event` não diz nada " +
          "sobre tópicos e payload.",
    trabInfo: (nChaves: number, chaves: string, nTopicos: number, topicos: string) =>
      `revisar as ${nChaves} chaves de storage inferidas (${chaves}) e os ${nTopicos} tópicos de evento ` +
      `declarados (${topicos}) listados na lacuna de Information disclosure, e decidir quais desses campos ` +
      "não deveriam ser legíveis num ledger público ou dão vantagem a quem lê o ledger primeiro.",
    trabDos: (n: number, l: string) =>
      (n
        ? `conferir se os ${n} caminhos de renovação listados na lacuna de DoS (${l}) de fato rodam na ` +
          "operação normal — *alcançar* `extend_*_ttl` não é *executar*"
        : "nenhum export alcança a família `extend_*_ttl`, como diz a lacuna de DoS, então o prazo de " +
          "arquivamento de cada entrada persistente tem que ser conferido à mão") +
      ", além de exaustão de recursos por entrada grande e da liveness dos contratos alcançados por `call`.",
    trabElevResiduo: (n: number, l: string) =>
      `percorrer um a um os ${n} entrypoints que a lacuna de Elevation nomeia como resíduo (${l}): eles ` +
      "alcançam escrita ou troca de código sem alcançar `require_auth*` e foram suprimidos como provável " +
      "falso positivo — ali a lacuna é decisão do detector, não resultado da análise.",
    trabElevDelegam: (n: number, l: string) =>
      `revisar o escopo das ${n} delegações que a lacuna de Elevation nomeia (${l}): ` +
      "`authorize_as_curr_contract` é inventariado, nunca analisado, então a forma da árvore de autorização " +
      "ali nunca foi conferida.",
    trabElevAuth: (n: number, l: string) =>
      n === 0
        ? "nenhum entrypoint invocável alcança `require_auth*`, como diz a lacuna de Elevation, então não há " +
          "endereço autorizado a conferir — o que sobra é se algum deles deveria exigir um."
        : `conferir, nos ${n} entrypoints que a lacuna de Elevation lista como alcançando \`require_auth*\` ` +
          `(${l}), se o endereço autorizado é o CERTO — um contrato que autoriza o chamador onde deveria ` +
          "autorizar o admin passa por este detector.",
    letrasSemRemediacao: (l: string) =>
      `Letras sem remediação por não terem ameaça derivada: ${l}. ` +
      "Isso não é \"nada a fazer\" — é \"a análise de bytecode não chega lá\", e o trabalho " +
      "correspondente está descrito em cada lacuna da seção anterior.\n",

    remConfirmar: (alvo: string, caminho: string | undefined, id: string) =>
      `Antes de mexer no código, confirmar no fonte de ${alvo} se a escrita é de fato executada` +
      (caminho ? ` — caminho mais curto até a escrita: \`${caminho}\`` : "") +
      `. Se o ramo de escrita pertence a um helper compartilhado que ${alvo} nunca executa, ` +
      `${id} é **falso positivo e deve ser fechado**, não remediado.`,

    remAuthComEndereco: (alvo: string, n: number, l: string) =>
      `Exigir autorização em ${alvo} antes da primeira escrita. O spec declara ` +
      `${n === 1 ? "o parâmetro" : "os parâmetros"} \`address\` ${l} ` +
      `neste entrypoint — ${n === 1 ? "candidato" : "candidatos"} a ` +
      `\`require_auth()\`, desde que ${n === 1 ? "seja" : "sejam"} de fato quem ` +
      `deveria consentir a operação; o spec dá o tipo, não o papel. Se o autorizador correto for outro (o admin gravado na ` +
      `instância, por exemplo), autorizar contra essa chave, não contra o parâmetro.`,
    remAuthSemEndereco: (alvo: string) =>
      `Exigir autorização em ${alvo} antes da primeira escrita. O spec descreve este ` +
      `entrypoint e ele não recebe nenhum parâmetro \`address\`, então o autorizador tem que ` +
      `vir do storage — tipicamente o endereço administrativo gravado na instância. A ` +
      `correção é ler essa chave e chamar \`require_auth\` sobre ela.`,
    remAuthSemSpec: (alvo: string) =>
      `Exigir autorização em ${alvo} antes da primeira escrita. **O spec lido não descreve ` +
      `este entrypoint**, então a ferramenta não sabe que parâmetros ele recebe e não tem ` +
      `como apontar o candidato a \`require_auth\` — conferir a assinatura no fonte antes de ` +
      `escolher o autorizador.`,
    remAuthAceitacao: (alvo: string) =>
      `Alternativa explícita, se ${alvo} é público por desenho: registrar aqui a aceitação de ` +
      `risco, nomeando o invariante que impede abuso (a escrita só afeta o estado do próprio ` +
      `chamador, o valor gravado é idempotente, etc.). O template permite aceitação corporativa ` +
      `do risco, mas ela precisa estar escrita: a ausência de \`require_auth\` não distingue ` +
      `"público de propósito" de "esqueceram".`,

    remInitVerificarGuarda: (alvo: string, guarda: boolean) =>
      `O contrato já exporta \`__constructor\`, então o próprio deploy inicializa atomicamente e não há ` +
      `o que mover: verificar no fonte se ${alvo} está guardado contra re-inicialização` +
      (guarda
        ? " (o caminho alcançável até `has_contract_data` sugere que sim)"
        : " (nenhum `has_contract_data` é alcançável a partir dele, então nenhuma guarda está visível)") +
      `. Se estiver guardado, fechar o achado como aceito, com essa leitura registrada. Se não estiver, ` +
      "condicioná-lo ao admin que o construtor gravou — ler essa chave e chamar `require_auth` sobre ela. " +
      "Redeployar a instância viva não está em questão aqui: o achado é sobre a segunda etapa, não sobre o deploy.",
    remInitConstrutor: (alvo: string) =>
      `Mover a inicialização de ${alvo} para \`__constructor\`. No Soroban o construtor roda na ` +
      `mesma transação do deploy, o que fecha a janela de front-running por construção — em vez ` +
      `de depender de o operador conseguir inicializar antes de um observador da mempool.`,
    remInitGuard: (alvo: string, temChaves: boolean) =>
      `Enquanto ${alvo} continuar existindo como entrypoint público, fazê-lo abortar quando a ` +
      `chave de instância já estiver gravada` +
      (temChaves ? " (as chaves inferidas estão em *Data stores inferidos*)" : "") +
      `, e cobrir com um teste que verifique que a segunda chamada falha. Um guard sem teste não ` +
      `conta como remediação — é a suposição de que ele existe. Verificar no fonte se a ` +
      `re-inicialização já está guardada; se estiver, fechar este achado com essa justificativa registrada.`,

    remUpgradeAuth: (alvo: string, id: string) =>
      `Exigir \`require_auth\` do endereço administrativo em ${alvo} antes do caminho que alcança ` +
      `\`update_current_contract_wasm\`. Hoje nenhum caminho deste export alcança \`require_auth*\` ` +
      `(evidência A de ${id}), então a troca do código que o contrato executa não tem porteiro.`,
    remUpgradeEvento: (alvo: string) =>
      `Emitir um \`contract_event\` em ${alvo} carregando o novo wasm hash. Sem esse evento a troca ` +
      `de código só é detectável por diff de ledger, e o monitoring plan não tem tópico para filtrar ` +
      `— a ameaça mais grave do documento ficaria sem cobertura de detecção.`,

    remOrdemComEvidencia: (corpo: number, alvo: string, authFn: string, authOff: string, writeFn: string, writeOff: string) =>
      `No corpo \`fn#${corpo}\`, alcançado por ${alvo}, mover \`${authFn}\` ` +
      `(offset 0x${authOff}) para antes de \`${writeFn}\` ` +
      `(offset 0x${writeOff}). É uma troca de ordem local, conferível abrindo ` +
      `o corpo indicado no desassemblador.`,
    remOrdemSemEvidencia: (id: string) =>
      `Mover a autorização para antes da primeira escrita no corpo indicado pela evidência A de ${id}.`,
    remOrdemComCrossCall: (alvo: string) =>
      `Antes disso, verificar se existe efeito externo entre a escrita e a autorização: ${alvo} ` +
      `alcança \`call\`/\`try_call\`, então há como a escrita ser observada por outro contrato ` +
      `antes de a autorização falhar. É o único cenário em que a ordem importa — no Soroban a ` +
      `transação inteira reverte se o \`require_auth\` falhar.`,
    remOrdemSemCrossCall: (alvo: string, solida: boolean, motivo: string, id: string) =>
      `${alvo} não alcança \`call\` nem \`try_call\`` +
      (solida ? " (negativa sólida para este call graph)" : ` (negativa fraca — ${motivo})`) +
      `, então não há efeito externo entre a escrita e a autorização e a reversão da transação ` +
      `já desfaz a escrita. Se isso se confirmar, ${id} pode ser aceito como risco nulo — ` +
      `com esta justificativa escrita, não por omissão.`,

    remSilentEvento: (l: string, temDiff: boolean) =>
      `Emitir \`contract_event\` nos entrypoints que hoje alcançam escrita sem alcançar evento: ` +
      `${l}. Sem tópico emitido não existe filtro de \`getEvents\` capaz de detectar a ação, então ` +
      `essas mutações ficam fora do monitoramento *baseado em evento*; elas só são detectáveis por ` +
      `diff de estado (\`getLedgerEntries\`) ou observando o wasm hash da instância. ` +
      (temDiff
        ? "O monitoring plan irmão inclui um monitor desse tipo — que é detecção por polling, com a " +
          "resolução do intervalo de polling, não a trilha por transação que um evento dá."
        : "Nenhum monitor desse tipo está no plano irmão tampouco, então hoje a ação não deixa trilha " +
          "que um observador off-chain consiga seguir."),
    remSilentTopico: (n: number, l: string) =>
      `No evento de ${n === 1 ? "esse entrypoint" : "cada um desses entrypoints"} ` +
      `(${l}), o primeiro tópico precisa ser um símbolo fixo — ` +
      `um por ação, não um valor derivado do argumento — porque é por ele que o \`getEvents\` do ` +
      `monitoring plan filtra. Qual símbolo usar é decisão de quem escreve o contrato: a soroguard ` +
      `não tem como propor um nome de tópico, só dizer que sem tópico estável a regra de detecção ` +
      `dessas mutações é impossível de escrever.`,

    remArchivalTtl: (l: string, id: string) =>
      `Estender o TTL no caminho de escrita dos entrypoints que gravam: ` +
      `${l}. Nenhum entrypoint deste contrato alcança a ` +
      `família \`extend_*_ttl\` (evidência A de ${id}), então nada renova o prazo do estado.`,
    remArchivalAceitar: (id: string) =>
      `Se todo o storage deste contrato for \`temporary\` por desenho, escrever isso aqui e fechar ` +
      `${id} como aceito. A durabilidade é argumento de runtime e não aparece no bytecode — a ` +
      `ferramenta não consegue distinguir "temporário de propósito" de "vai ser arquivado sem aviso".`,

    remPrngRegistrar: (alvo: string, id: string) =>
      `Registrar para que serve o valor aleatório em ${alvo}. O PRNG do host é semeado por ` +
      `ledger: se o resultado decide quem recebe, quanto se paga ou qual ramo o estado toma, ` +
      `quem escolhe o ledger de submissão escolhe o sorteio. Se o uso for cosmético ou for ` +
      `geração de identificador, escrever isso e fechar ${id} como aceito.`,
    remPrngTrocar: (alvo: string) =>
      `Se o valor tiver peso econômico, trocar a fonte em ${alvo} por uma que o submissor não ` +
      `controle — commit-reveal com mais de uma parte, ou aleatoriedade de fora da cadeia com ` +
      `prova. Não existe parâmetro do PRNG do host que remova a previsibilidade dentro do ledger, ` +
      `então não há correção local.`,

    remSdkRecompilar: (id: string) =>
      `Recompilar com uma versão corrigida do \`soroban-sdk\` (as versões com correção estão na ` +
      `evidência A de ${id}) e redeployar. Enquanto o wasm hash em produção não mudar, o ` +
      `achado continua verdadeiro: ele descreve o binário deployado, e atualizar o repositório ` +
      `não altera o que está no ledger.`,
    remSdkVerificar: (id: string) =>
      `Antes do redeploy, verificar no fonte se a condição de disparo do advisory (descrita na ` +
      `evidência C de ${id}) existe neste contrato. Se não existir, registrar aqui a aceitação ` +
      `com essa justificativa — a exposição é fato de bytecode, a explorabilidade não é.`,

    remLacunaClasse: (cls: string, id: string) =>
      `**Lacuna: nenhuma remediação derivada automaticamente para a classe \`${cls}\`.** ` +
      `${id} precisa de uma remediação escrita por um revisor humano antes da submissão. ` +
      `Um texto de checklist aqui seria pior que a lacuna.`,

    /* --- 4. Did we do a good job? --- */
    introAvaliacao:
      "As cinco perguntas do template são respondidas abaixo com o que a geração automática " +
      "consegue sustentar. Onde a resposta depende do processo da equipe, e não do binário, isso " +
      "está dito em vez de suposto.\n",
    q1Sim: (data: string, nFront: number, nProc: number) =>
      "**A ferramenta não responde esta.** O diagrama foi gerado junto com este documento, na mesma " +
      `geração (${data}); se a equipe volta a ele depois é fato de processo, fora do binário, e quem ` +
      "revisa precisa registrar. **O que é conferível aqui é a dependência na outra direção:** as " +
      `${nFront} ${nFront === 1 ? "fronteira de confiança" : "fronteiras de confiança"} do diagrama ` +
      `sobre ${nProc} ${nProc === 1 ? "nó" : "nós"} \`process\` são como a tabela de ameaças está ` +
      "organizada — cada nó `process` é um export do módulo, a fronteira aberta (sem `require_auth*` " +
      "alcançável) é o grupo de onde saem os achados de Elevation, e a fronteira de cross-call é o que " +
      "a lacuna de Tampering aponta. As ameaças saem do conteúdo do diagrama, não apenas o acompanham.",
    q1Nao:
      "**Não.** Nenhum DFD foi gerado para este contrato (ver a lacuna na seção *What are we " +
      "working on?*), então não há diagrama a referenciar. O artefato está incompleto quanto ao " +
      "requisito de diagrama visual do template.",
    q2Com: (nAmeacas: number, nLetras: number, nEps: number) =>
      `A ferramenta não tem memória do que a equipe já sabia, então não consegue dizer o que é ` +
      `*novo* — só o que derivou: ${nAmeacas} ${nAmeacas === 1 ? "ameaça" : "ameaças"} em ` +
      `${nLetras} ${nLetras === 1 ? "letra" : "letras"} do STRIDE, a partir ` +
      `de ${nEps} entrypoints invocáveis. Marcar quais eram desconhecidas é trabalho ` +
      `do revisor.`,
    q2Confirmar: (n: number, ids: string) =>
      ` Ponto de atenção: ${n} ${n === 1 ? "dela depende" : "delas dependem"} ` +
      `de confirmação no fonte antes de contar como achado (${ids}).`,
    q2Sem:
      "Nenhuma ameaça foi derivada do bytecode deste contrato. Isso não é atestado de segurança: " +
      "significa que os detectores desta ferramenta — que cobrem autorização, ordem auth/escrita, " +
      "trilha de eventos, TTL e versão do SDK — não encontraram sinal. As lacunas declaradas dizem " +
      "o que ficou de fora do alcance.",
    q3Com: (hash: string) =>
      "**Não verificado, e não verificável por esta ferramenta.** Toda remediação da seção anterior " +
      "é nível C e está proposta, não aplicada. A soroguard leu o WASM que está deployado" + hash +
      " e não tem como observar uma correção que ainda não foi ao ledger. **O teste objetivo é " +
      "concreto:** rodar a soroguard de novo sobre o contrato depois do redeploy e conferir que o " +
      "achado correspondente desaparece — se ele persistir, a correção não alcançou o caminho que " +
      "gerou a evidência.",
    q3Hash: (h: string) => ` (hash \`${h}\`)`,
    q3Sem: "Não se aplica: não há ameaça derivada, logo não há remediação a avaliar.",
    q4: (data: string, lacunas: string, confirmar: string) =>
      `Fora do alcance desta geração — depende de auditoria, revisão manual e incidentes posteriores ` +
      `a ${data}. O que fica registrado como os lugares mais prováveis de questões posteriores ` +
      `aparecerem: ${lacunas}${confirmar}. Esta seção de itens em aberto deve ser atualizada por quem ` +
      "revisar, não regenerada.",
    q4Lacunas: (l: string) => `as letras declaradas como lacuna (${l})`,
    q4LacunasGenerico: "as lacunas declaradas",
    q4Confirmar: (n: number) =>
      `, e ${n === 1 ? "a ameaça marcada" : "as ameaças marcadas"} para confirmação humana`,

    insightAssimetria:
      "A análise é de **bytecode deployado**, e a assimetria importa: \"não alcança `require_auth`\" é " +
      "negativa sólida para o call graph deste módulo — não diz nada sobre autorização exigida dentro " +
      "de um contrato alcançado por `call`/`try_call`, nem sobre o `__check_auth`; " +
      "\"alcança `put_contract_data`\" é super-aproximação, porque a escrita pode estar num " +
      "ramo que o entrypoint nunca executa. Todo achado positivo carrega o número de saltos por isso.",
    insightSolido:
      "O call graph deste módulo é completo (nenhum `call_indirect`), então as afirmações negativas " +
      "deste documento são sólidas com respeito a esse grafo — e só a ele.",
    insightRebaixado: (motivo: string) =>
      `**${motivo[0].toUpperCase()}${motivo.slice(1)}**, então o call graph é incompleto e nem as ` +
      "afirmações negativas são sólidas. Tudo aqui está rebaixado a indício, e um segundo par de olhos " +
      "sobre os entrypoints privilegiados é obrigatório.",
    insightSpoofInfo: (nAuth: number, nEps: number, nChaves: number, nTopicos: number) =>
      "Spoofing e Information Disclosure não saem do bytecode: dependem de identidade e de decisão de " +
      "produto sobre quais dados vão para um ledger público, e nenhuma das duas está no binário. " +
      "Medido no corpus de calibração: zero achado em 100% dos 75 contratos de mainnet " +
      "(`docs/CALIBRACAO.md`). " +
      "Preencher essas duas letras com texto genérico para cumprir o \"≥1 por letra\" do template é o " +
      "que faria o documento ser descartado pelo primeiro revisor competente. O que esta geração " +
      `entrega à revisão manual dessas duas letras, em números: ${nAuth} de ${nEps} ` +
      `${nEps === 1 ? "entrypoint invocável alcançando" : "entrypoints invocáveis alcançando"} ` +
      `\`require_auth*\`, ${nChaves} ${nChaves === 1 ? "chave" : "chaves"} de storage ` +
      `${nChaves === 1 ? "inferida" : "inferidas"} e ${nTopicos} ` +
      `${nTopicos === 1 ? "tópico de evento declarado" : "tópicos de evento declarados"}.`,
    insightObsInsuficiente:
      "Há observação on-chain (nível B), mas a janela é curta demais para servir de baseline — as " +
      "taxas estão registradas como dado bruto, não como linha de base.",
    insightObsOk: (n: number) =>
      "Há observação on-chain (nível B) na janela registrada na primeira seção, e " +
      `${n} ${n === 1 ? "monitor do plano irmão ancora" : "monitores do plano irmão ancoram"} ` +
      "baseline nela em vez de num número plausível.",
    insightObsSemAncora: (ledgers: number, h: number, ev: number, topicos: number, motivo: string) =>
      `A janela foi observada (${ledgers} ledgers, ~${h} h, ${ev} ${ev === 1 ? "evento" : "eventos"} ` +
      `em ${topicos} ${topicos === 1 ? "tópico" : "tópicos"}), mas **nenhum monitor do plano irmão ` +
      `conseguiu ancorar baseline nela** — ${motivo}. Nível B aqui é registro da janela, não linha de ` +
      "base: todo limiar do monitoring plan continua tendo que declarar que não tem base observada.",
    motivoSemTrafego: "nenhum evento de nenhum tópico foi observado, então não há de onde calcular taxa",
    motivoSemVinculo:
      "nenhum monitor se liga a um tópico observado — as regras do plano filtram tópicos que não " +
      "apareceram na janela",
    insightObsFalhou: (e: string) =>
      `**A coleta de nível B FALHOU nesta geração:** ${e}. A ausência de janela é ` +
      "da nossa chamada de RPC, que não completou — NÃO é evidência de que o contrato esteja inativo. " +
      "Todo o documento se apoia em nível A e C, e o monitoring plan associado precisa declarar a falha " +
      "em vez de estimar.",
    insightObsOffline:
      "**A coleta de nível B não foi executada nesta geração (offline / alvo local).** Todo o documento " +
      "se apoia em nível A e C. Qualquer baseline no monitoring plan associado precisa declarar a " +
      "ausência de janela em vez de estimar.",
    insightObsAusente:
      "**Não há observação on-chain (nível B) nesta geração.** Todo o documento se apoia em nível A " +
      "e C. Qualquer baseline no monitoring plan associado precisa declarar a ausência de janela em " +
      "vez de estimar.",
    insightForaDoEscopo:
      "O que este modelo **não** cobre, por construção: desenho econômico (incentivos, liquidação, " +
      "oráculo), governança e custódia das chaves privilegiadas, segurança do frontend e da " +
      "infraestrutura que monta as transações, e se o endereço autorizado em cada `require_auth` é o " +
      "endereço certo. Nenhuma dessas perguntas é respondível a partir do binário.",
    divergencia: (l: string, _n: number) =>
      `> **Inconsistência na entrada:** \`ctx.gaps\` lista ${l} como letra sem ` +
      "achado, mas há achado derivado nessa(s) letra(s). O documento seguiu os achados, e esta linha " +
      "fica registrada para que a divergência não passe silenciosa.\n",

    /* --- cabeçalho do documento --- */
    subtitulo: (rede: string, data: string) =>
      `Rede ${rede} · gerado em ${data} · ` +
      `template oficial da Stellar (*STRIDE-template*, developers.stellar.org/docs/build/security-docs/threat-modeling).\n`,
    introDocumento:
      "Rascunho gerado pela soroguard a partir do WASM deployado. Cada afirmação carrega seu nível de " +
      "evidência: **A** = fato de bytecode, **B** = fato observado on-chain, **C** = inferência. " +
      "As seções que a análise não consegue sustentar aparecem como lacuna declarada — nunca " +
      "preenchidas com texto genérico. **Revisão humana é obrigatória antes de submeter.**\n",
  },
});

/**
 * Espelha o filtro de `detect.ts`: o host recusa invocação direta de funções com prefixo
 * `__` (RESERVED_CONTRACT_FN_PREFIX, CAP-0058). Recontamos aqui porque as listas que as
 * remediações precisam citar (quem grava sem emitir evento, quem grava sem renovar TTL)
 * não são exportadas junto com o achado — só existem dentro da string de evidência.
 * Se este predicado divergir do de detect.ts, a remediação cita uma lista diferente da
 * que a evidência afirma; é o único acoplamento frágil deste arquivo.
 */
const reservado = (nome: string) => nome.startsWith("__");

/* ------------------------------------------------------------------ *
 * Utilitários de formatação
 * ------------------------------------------------------------------ */

/** Torna um texto seguro dentro de célula de tabela markdown. */
const cel = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");

const fid = (f: Finding): string => f.id ?? `${f.stride}.?`;

/** Níveis de evidência presentes num achado, na ordem A→B→C. */
const niveisDe = (f: Finding): Tier[] =>
  (["A", "B", "C"] as const).filter((t) => f.evidence.some((e) => e.tier === t));

const lista = (nomes: string[], max = 10): string =>
  nomes.length <= max
    ? nomes.map((n) => `\`${n}\``).join(", ")
    : `${nomes.slice(0, max).map((n) => `\`${n}\``).join(", ")} ${M.eMais(nomes.length - max)}`;

/**
 * Mesma lista, com conjunção no último item — uma enumeração curta dentro de uma frase
 * lida como frase, não como saída de `join(", ")`. Quando há corte, o "e mais N" já é a
 * conjunção e um segundo "e" ficaria duplicado.
 */
const listaE = (nomes: string[], max = 6): string => {
  const q = nomes.slice(0, max).map((n) => `\`${n}\``);
  const resto = nomes.length - q.length;
  if (resto > 0) return `${q.join(", ")} ${M.eMais(resto)}`;
  if (q.length <= 1) return q.join("");
  return `${q.slice(0, -1).join(", ")} ${M.e} ${q[q.length - 1]}`;
};

const sim = (b: boolean) => (b ? M.sim : M.nao);

/**
 * Um contrato que exporta `__check_auth` é uma conta customizada: ali a autorização é
 * IMPLEMENTADA, não pedida. Dizer "nenhum caminho até require_auth" sem essa ressalva
 * apresenta a forma esperada do padrão como se fosse ausência de controle.
 */
const exportaCheckAuth = (ctx: ArtifactContext): boolean =>
  ctx.analysis.entrypoints.some((e) => e.name === "__check_auth") ||
  (ctx.spec.fns ?? []).some((f) => f.name === "__check_auth");

/** Tópicos de evento declarados no spec — a superfície concreta da letra I. */
const topicosDeclarados = (ctx: ArtifactContext): string[] => [
  ...new Set((ctx.spec.events ?? []).flatMap((e) => e.prefixTopics)),
];

/**
 * Monitores do plano irmão que ancoram baseline em observação (nível B). É o que decide
 * se a janela observada VIROU linha de base ou ficou só registrada: dizer que permite
 * baseline real quando nenhum monitor a usa é afirmar um efeito que não aconteceu.
 */
const monitoresComBaselineB = (ctx: ArtifactContext): number =>
  (ctx.monitors ?? []).filter((m) => m.baselineTier === "B").length;

/** Monitor que lê estado direto do ledger — a alternativa quando não há evento. */
const MONITOR_DIFF = /wasm hash|getLedgerEntries|state diff|diff of the contract|diff das/i;
const planoTemDiffDeEstado = (ctx: ArtifactContext): boolean =>
  (ctx.monitors ?? []).some((m) => MONITOR_DIFF.test(`${m.observable} ${m.trigger}`));

/** Concordância de número — "1 alcançam" e "1 ameaça(s)" num documento de revisão são ruído. */
const alc = (n: number) => M.alcancam(n);

/**
 * O achado carrega o aviso de super-aproximação como claim de nível C começando com
 * "⚠ REVISAR"/"⚠ REVIEW" (ver detect.ts). Quando ele está presente, a primeira remediação
 * não pode ser "conserte" — tem que ser "confirme que existe o quê consertar".
 */
const MARCA_REVISAR = /^⚠\s*(REVISAR|REVIEW)\b/;
const precisaConfirmar = (f: Finding): boolean =>
  f.evidence.some((e) => e.tier === "C" && MARCA_REVISAR.test(e.claim));

/**
 * Motivo REAL da aproximação, no nível do módulo. `soundness` degrada por três causas
 * distintas (`call_indirect`, corpo degradado, módulo não lido por inteiro) e dizer sempre
 * "há call_indirect" seria afirmar uma causa que pode não ser a verdadeira.
 */
function motivoModulo(ctx: ArtifactContext): string {
  if (ctx.analysis.incompleteReason) return M.razaoIncompleto(ctx.analysis.incompleteReason);
  return ctx.analysis.hasIndirectAnywhere ? M.razaoModuloIndireto : M.razaoModuloDegradado;
}

/** Mesma pergunta, no escopo do subgrafo de um (ou de vários) export. */
function motivoSubgrafo(ctx: ArtifactContext, escopo: string): string {
  if (ctx.analysis.incompleteReason) return M.razaoIncompleto(ctx.analysis.incompleteReason);
  return ctx.analysis.hasIndirectAnywhere ? M.razaoSubIndireto(escopo) : M.razaoSubDegradado(escopo);
}

/**
 * Host functions que só o despacho indireto poderia acrescentar ao alcance. É o conteúdo
 * concreto do rótulo "aproximado": em vez de dizer que existe caminho invisível, nomeia o
 * que esse caminho alcançaria. Determinístico (ordenado) e sem união com `reaches`.
 */
function viaTabela(ctx: ArtifactContext): string[] {
  const out = new Set<string>();
  for (const ep of ctx.analysis.entrypoints) {
    for (const n of ep.reachesViaTable) if (!ep.reaches.has(n)) out.add(n);
  }
  return [...out].sort();
}

/**
 * Como a solidez se lê depende de em que a evidência se apoia. Dizer "call graph completo"
 * num achado que nem usa o call graph seria emprestar a solidez de um tipo de prova a outro.
 */
function linhaSolidez(ctx: ArtifactContext, f: Finding, varios = false): string {
  if (f.class === "vulnerable-sdk") return M.solidezSdk;
  if (f.entrypoint === "<contrato>") {
    return f.sound ? M.solidezModuloOk(M.escopoNegativa) : M.solidezRebaixada(motivoModulo(ctx));
  }
  const escopo = varios ? M.escopoListados : M.escopoEste;
  return f.sound ? M.solidezEpOk(escopo, M.escopoNegativa) : M.solidezRebaixada(motivoSubgrafo(ctx, escopo));
}

/**
 * Agrupa achados cuja classe e evidência são byte a byte idênticas, diferindo só no
 * entrypoint. Nove blocos com o mesmo texto não acrescentam informação — enterram o resto
 * do documento, que é exatamente como um relatório vira ruído. O agrupamento é só de
 * apresentação no detalhamento: cada ID continua listado, individual e rastreável, na
 * tabela de ameaças e na de remediações.
 */
function agrupar(fs: Finding[]): Finding[][] {
  const ordem: string[] = [];
  const m = new Map<string, Finding[]>();
  for (const f of fs) {
    const k = `${f.class} ${f.severity} ${f.sound} ${f.evidence.map((e) => `${e.tier}:${e.claim}`).join("")}`;
    if (!m.has(k)) { m.set(k, []); ordem.push(k); }
    m.get(k)!.push(f);
  }
  return ordem.map((k) => m.get(k)!);
}

/* ------------------------------------------------------------------ *
 * Fatos recalculados a partir de ctx.analysis
 * ------------------------------------------------------------------ */

type Fatos = {
  invocaveis: Entrypoint[];
  gravam: Entrypoint[];
  autenticam: Entrypoint[];
  mudos: Entrypoint[];
  renovamTtl: Entrypoint[];
  cruzam: Entrypoint[];
  trocamCodigo: Entrypoint[];
};

function fatos(ctx: ArtifactContext): Fatos {
  const eps = ctx.analysis.entrypoints;
  const invocaveis = eps.filter((e) => !reservado(e.name));
  return {
    invocaveis,
    gravam: invocaveis.filter(writesStorage),
    autenticam: invocaveis.filter(requiresAuth),
    mudos: invocaveis.filter((e) => writesStorage(e) && !emitsEvent(e)),
    renovamTtl: eps.filter(extendsTtl),
    cruzam: invocaveis.filter(callsOut),
    trocamCodigo: invocaveis.filter(canUpgradeSelf),
  };
}

/** Caminho legível do export até a primeira host function de escrita alcançada. */
function caminhoDeEscrita(ctx: ArtifactContext, ep: Entrypoint | undefined): string | undefined {
  if (!ep) return undefined;
  const n = ctx.analysis.imports.length;
  for (const fn of STORAGE_WRITE_FNS) {
    const c = caminho(ep, fn, n);
    if (c) return c;
  }
  return undefined;
}

/* ------------------------------------------------------------------ *
 * 1. What are we working on?
 * ------------------------------------------------------------------ */

function secaoContexto(ctx: ArtifactContext, ft: Fatos): string {
  const T = tierLabels[lang()];
  const p: string[] = [];
  p.push("## What are we working on?\n");

  p.push(M.lacunaEquipe);

  p.push(M.hdrObjeto);
  p.push(M.thCampoValor);
  p.push("|---|---|");
  p.push(`| Contract ID | \`${cel(ctx.contractId)}\` |`);
  if (ctx.spec.analyzedFile) p.push(M.lblObjetoAnalisado(cel(ctx.spec.analyzedFile)));
  p.push(`| ${M.lblRede} | ${cel(ctx.network)} |`);
  p.push(`| WASM hash | ${ctx.spec.wasmHash ? `\`${cel(ctx.spec.wasmHash)}\`` : M.naoInformado} |`);
  p.push(`| ${M.lblTamanhoWasm} | ${ctx.spec.wasmBytes ? `${ctx.spec.wasmBytes} bytes` : M.naoInformado} |`);
  p.push(`| ${M.lblGeradoEm} | ${cel(ctx.generatedAt)} (UTC) |`);
  p.push(
    `| ${M.lblSolidez} | ${
      ctx.analysis.soundness === "sound" ? M.solidezCompleta : M.solidezAproximada(motivoModulo(ctx))
    } |`,
  );
  p.push("");

  p.push((ctx.spec.wasmHash ? M.objetoComHash : M.objetoSemHash) + M.objetoFim);

  p.push(M.hdrEvidencia);
  p.push(M.thEvidencia);
  p.push("|---|---|---|");
  p.push(M.linhaA(T.A));
  p.push(M.linhaB(T.B));
  p.push(M.linhaC(T.C));
  p.push("");
  p.push(M.assimetria);
  // Conta customizada: a negativa de `require_auth` nos entrypoints dela é a forma do
  // padrão, não ausência de controle. Sem esta linha o documento inteiro se lê como se
  // fosse achado o que é desenho.
  if (exportaCheckAuth(ctx)) p.push(M.notaCheckAuth);

  // O rótulo de nível não pode ser incondicional. Nível A é a NEGATIVA de alcançabilidade, e a
  // negativa só é prova com o call graph completo. Num módulo com `call_indirect`, chamar esta
  // tabela de "nível A" seria apresentar evidência rebaixada com a força de fato — exatamente a
  // regra que docs/PROBLEMA.md diz que não se quebra.
  const solido = ctx.analysis.soundness === "sound";
  p.push(M.hdrSuperficie(solido));
  if (!solido) p.push(M.avisoSuperficie(motivoModulo(ctx)));
  if (!ft.invocaveis.length) {
    p.push(M.semEntrypoints);
  } else {
    const reservados = ctx.analysis.entrypoints.filter((e) => reservado(e.name));
    p.push(
      // As DUAS contagens, explícitas: o monitoring plan conta exports e este documento
      // conta invocáveis, e a diferença (os `__*`) precisa aparecer em vez de virar uma
      // divergência silenciosa entre os dois artefatos do mesmo par.
      M.resumoSuperficie(
        ctx.analysis.entrypoints.length,
        ft.invocaveis.length,
        alc(ft.autenticam.length),
        alc(ft.gravam.length),
        alc(ft.cruzam.length),
        alc(ft.trocamCodigo.length),
      ) +
        (reservados.length
          ? M.reservados(reservados.length, listaE(reservados.map((e) => e.name)))
          : M.semReservados),
    );
    p.push("");
    p.push(M.thSuperficie);
    p.push("|---|---|---|---|---|---|---|");
    for (const e of ft.invocaveis) {
      p.push(
        `| \`${cel(e.name)}\` | ${sim(requiresAuth(e))} | ${sim(writesStorage(e))} | ${sim(emitsEvent(e))} | ` +
          `${sim(canUpgradeSelf(e))} | ${sim(callsOut(e))} | ${e.fanout} |`,
      );
    }
    p.push("");
    p.push(M.notaSuperficie);
  }

  if (ctx.storageKeys?.length) {
    const certas = ctx.storageKeys.filter((k) => k.confidence === "certain").map((k) => k.key);
    const provaveis = ctx.storageKeys.filter((k) => k.confidence === "likely").map((k) => k.key);
    p.push(M.hdrStores);
    if (certas.length) p.push(M.chavesCertas(lista(certas, 20)));
    if (provaveis.length) p.push(M.chavesProvaveis(lista(provaveis, 20)));
    p.push(M.notaDurabilidade);
  }

  if (ctx.observations) {
    const o = ctx.observations;
    p.push(M.hdrObservacao);
    p.push(
      M.janela(o.window.fromLedger, o.window.toLedger, o.window.ledgers, o.window.approxHours) +
        (o.window.insufficient ? M.janelaInsuficiente : ""),
    );
    p.push("");
    if (o.events.length) {
      p.push(M.thEventos);
      p.push("|---|---|---|---|");
      for (const e of o.events) {
        p.push(`| \`${cel(e.topic)}\` | ${e.count} | ${e.firstLedger}–${e.lastLedger} | ${e.ratePerHour} |`);
      }
      p.push("");
    } else {
      p.push(M.semEventos);
    }
    // "janela curta" é afirmação sobre a janela, não fórmula fixa: numa janela de 186 h
    // chamá-la de curta é falso e conferível na linha logo acima.
    if (o.declaredButUnseen.length) {
      p.push(
        M.declaradosNaoVistos(
          lista(o.declaredButUnseen, 20),
          Boolean(o.window.insufficient),
          o.window.approxHours,
        ),
      );
    }
  }

  if (!ctx.observations) {
    p.push(M.hdrObservacao);
    p.push(
      ctx.observationError
        ? M.coletaFalhou(cel(ctx.observationError))
        : ctx.offline
          ? M.coletaOffline
          : M.coletaAusente,
    );
  }

  p.push("### Data flow diagram\n");
  if (ctx.dfd) {
    p.push("```mermaid");
    p.push(ctx.dfd.mermaid.trimEnd());
    p.push("```\n");
    // AQ-9(b): sem chave inferida o único `store` do diagrama é o nó que DECLARA a lacuna.
    // Dizer "cada store é uma chave inferida" ali afirmaria o contrário do que a figura mostra.
    p.push(ctx.storageKeys?.length ? M.legendaDfdComChaves : M.legendaDfdSemChaves);
    if (ctx.dfd.boundaries.length) {
      p.push(M.thFronteiras);
      p.push("|---|---|");
      for (const b of ctx.dfd.boundaries) {
        p.push(`| ${cel(b.label)} | ${b.contains.length ? b.contains.map((n) => `\`${cel(n)}\``).join(", ") : "—"} |`);
      }
      p.push("");
      // A tabela lista os nós; o que ela NÃO diz é que a maioria deles autoriza o próprio
      // chamador. Sem esta nota o revisor lê a fronteira inteira como controle de acesso.
      if (ft.autenticam.length) {
        const nomes = ft.autenticam.map((e) => e.name);
        p.push(M.notaFronteiraAuth(nomes.filter(formaAdmin), nomes.filter((n) => !formaAdmin(n))));
      }
    }
  } else {
    p.push(M.dfdAusente);
  }

  if (ctx.spec.warnings.length) {
    p.push(M.hdrAvisosSpec);
    for (const w of ctx.spec.warnings) p.push(`- ${w}`);
    p.push("");
  }

  return p.join("\n");
}

/* ------------------------------------------------------------------ *
 * 2. What can go wrong?
 * ------------------------------------------------------------------ */

/**
 * Texto da lacuna por letra. Nunca genérico: diz por que aquela letra não saiu do
 * bytecode NESTE contrato, o que a ferramenta mediu, e o que sobra para o humano.
 */
function textoLacuna(ctx: ArtifactContext, s: Stride, ft: Fatos): string {
  switch (s) {
    // A explicação estrutural das duas letras é a mesma em qualquer contrato — é limite da
    // análise de bytecode, não fato deste binário. O que NÃO pode ser igual é o que sobra
    // para a revisão manual: sem nomear a superfície deste contrato, o parágrafo é
    // intercambiável entre laudos e o revisor o lê como texto de enchimento.
    case "Spoof": {
      const nomes = ft.autenticam.map((e) => e.name);
      return (
        M.lacunaSpoof(M.corpus) +
        M.lacunaSpoofConcreto(
          nomes.length,
          nomes.filter(formaAdmin),
          nomes.filter((n) => !formaAdmin(n)),
          exportaCheckAuth(ctx),
        )
      );
    }
    case "Info": {
      const chaves = (ctx.storageKeys ?? []).map((k) => k.key);
      const topicos = topicosDeclarados(ctx);
      return (
        M.lacunaInfo(M.corpus) +
        M.lacunaInfoConcreto(
          chaves.length ? listaE(chaves) : M.listaVazia,
          topicos.length ? listaE(topicos) : M.listaVazia,
        )
      );
    }
    case "Tamper": {
      const ordem = [...ctx.analysis.writeBeforeAuth.keys()].filter((k) => !reservado(k));
      const elev = ctx.findings.filter((f) => f.stride === "Elevation").length;
      return (
        M.lacunaTamperIntro +
        (ordem.length ? M.lacunaTamperRessalva(lista(ordem)) : M.lacunaTamperSemRessalva) +
        (elev ? M.lacunaTamperElev(elev) : "") +
        M.lacunaTamperFim
      );
    }
    case "Repudiate":
      return (
        M.lacunaRepudiateIntro +
        (ft.gravam.length === 0 ? M.lacunaRepudiateSemEscrita : M.lacunaRepudiateComEscrita(ft.gravam.length)) +
        M.lacunaRepudiateFim
      );
    case "DoS":
      return (
        M.lacunaDosIntro +
        (ft.renovamTtl.length
          ? M.lacunaDosTtl(
              ft.renovamTtl.length,
              listaE(ft.renovamTtl.map((e) => e.name), 6),
              // Distância do export mais PRÓXIMO da família: é o número que diz se a
              // positiva é plausível (1–2 saltos) ou provável helper compartilhado.
              ft.renovamTtl
                .map((e) => minHops(e, TTL_EXTEND_FNS))
                .filter((h): h is number => h !== undefined)
                .sort((a, b) => a - b)[0],
              ft.renovamTtl.some((e) => reservado(e.name)),
            )
          : ft.gravam.length === 0
            ? M.lacunaDosSemEscrita
            : "") +
        M.lacunaDosFim
      );
    case "Elevation": {
      // Esta negativa NÃO pode ser deduzida da ausência de achado. Duas razões, ambas medidas:
      //  (a) detect.ts suprime entrypoints de nome read-shaped e crank permissionless ANTES de
      //      avaliar D1/D3, então "sem achado" não implica "sem escrita sem auth". Recomputamos
      //      o resíduo aqui e o nomeamos em vez de afirmar um negativo que a ferramenta não tem.
      //  (b) `authorize_as_curr_contract` foi rebaixado a inventário e NÃO tem detector
      //      (ver `delegacoes()` em detect.ts). Afirmar que ninguém o alcança sem auth seria
      //      apresentar como verificado algo que nunca foi checado.
      const residuo = [
        ...new Set(
          ft.invocaveis
            .filter((e) => (writesStorage(e) || canUpgradeSelf(e)) && !requiresAuth(e))
            .map((e) => e.name),
        ),
      ];
      const delegam = ft.invocaveis.filter(delegatesAuth);
      return (
        M.lacunaElevIntro +
        (residuo.length
          ? M.lacunaElevResiduo(residuo.length, lista(residuo))
          : M.lacunaElevSemResiduo +
            (ctx.analysis.soundness === "sound"
              ? M.lacunaElevNegativaSolida
              : M.lacunaElevNegativaFraca(motivoModulo(ctx)))) +
        (delegam.length ? M.lacunaElevDelegam(delegam.length, lista(delegam.map((e) => e.name))) : "") +
        M.lacunaElevFim
      );
    }
  }
}

/** Nome com forma de inicializador — o mesmo shape que detect.ts usa para a classe de init. */
const FORMA_INIT = /^(__constructor$|init)/i;

/**
 * Forma ADMINISTRATIVA do nome: um `require_auth` aqui é o contrato exigindo o consentimento
 * de um papel privilegiado, e a revisão precisa saber quem guarda aquela chave. Em tudo o mais
 * (`swap`, `deposit`, `withdraw`, `claim`…) o `require_auth` é o chamador autorizando o próprio
 * endereço — forma esperada de operação de usuário, não controle de acesso.
 *
 * É HEURÍSTICA DE NOME (nível C): o bytecode mostra que `require_auth*` é alcançado, nunca de
 * quem é o `Address`. Quem consome isto tem que dizer que é heurística — ver `lacunaSpoofConcreto`.
 */
const FORMA_ADMIN = /^(set|transfer|commit|apply|revert)_|^(upgrade|pause)(_|$)|^(kill|admin|initialize)/i;
const formaAdmin = (nome: string) => FORMA_ADMIN.test(nome);

/**
 * Ameaça de inicialização + tráfego observado na janela = a instância já foi inicializada.
 * Sem esta nota o documento afirma no presente ("qualquer endereço pode inicializar
 * primeiro") o que a própria seção de nível B do mesmo documento contradiz — e um revisor
 * que compara as duas seções derruba as duas. O risco que SOBRA é a re-inicialização, que
 * depende de um guard que o bytecode não mostra; é isso que a nota diz, com a evidência
 * que existe (`has_contract_data` alcançável ou não).
 */
function notaInicializacao(ctx: ArtifactContext, grupo: Finding[]): string | undefined {
  const o = ctx.observations;
  if (!o || !o.events.length) return undefined;
  const alvos = grupo.filter(
    (f) =>
      f.class === "initialization-front-running" ||
      (f.class === "unauthenticated-state-mutation" && FORMA_INIT.test(f.entrypoint)),
  );
  if (!alvos.length) return undefined;

  const eps = alvos
    .map((f) => ctx.analysis.entrypoints.find((e) => e.name === f.entrypoint))
    .filter((e): e is Entrypoint => Boolean(e));
  const com = eps.filter((e) => e.reaches.has("has_contract_data")).map((e) => e.name);
  const sem = eps.filter((e) => !e.reaches.has("has_contract_data")).map((e) => e.name);

  const eventos = o.events.reduce((s, e) => s + e.count, 0);
  const partes = [
    com.length ? M.notaGuardSim(listaE(com)) : "",
    sem.length ? M.notaGuardNao(listaE(sem)) : "",
  ].filter(Boolean);
  return `${M.notaJaInicializado(eventos, o.window.approxHours)}${partes.join(" ")}\n`;
}

function secaoAmeacas(ctx: ArtifactContext, ft: Fatos, gapsEfetivos: Set<Stride>): string {
  const T = tierLabels[lang()];
  const p: string[] = [];
  p.push("## What can go wrong?\n");

  p.push("### STRIDE reminders\n");
  p.push(LEMBRETES_STRIDE);
  p.push("");

  if (ctx.analysis.soundness !== "sound") {
    p.push(M.solidezRebaixadaCallout(motivoModulo(ctx)));
    // O que o despacho indireto acrescentaria ao alcance, nomeado em vez de aludido.
    const vt = viaTabela(ctx);
    if (vt.length) p.push(M.viaTabela(lista(vt, 20)));
  }

  const porSev = (["Critical", "High", "Medium", "Low"] as const)
    .map((s) => ({ s, n: ctx.findings.filter((f) => f.severity === s).length }))
    .filter((x) => x.n > 0);
  const paraConfirmar = ctx.findings.filter(precisaConfirmar).length;
  p.push(
    M.contagemAmeacas(ctx.findings.length) +
      (porSev.length ? M.contagemSeveridade(porSev.map((x) => `${x.n} ${x.s}`).join(", ")) : "") +
      (paraConfirmar ? M.contagemConfirmar(paraConfirmar) : ".") +
      (gapsEfetivos.size ? M.contagemLacunas(gapsEfetivos.size) : ""),
  );
  p.push("");

  p.push("### Threat table\n");
  p.push("| Threat | Issues |");
  p.push("|---|---|");
  for (const s of STRIDE_ORDEM) {
    const fs = ctx.findings.filter((f) => f.stride === s);
    const celula = fs.length
      ? fs
          .map(
            (f) =>
              M.celulaAmeaca(fid(f), cel(f.title), niveisDe(f).join("+"), f.severity) +
              (precisaConfirmar(f) ? M.marcaConfirmar : "") +
              (f.sound ? "" : M.marcaRebaixada),
          )
          .join("<br><br>")
      : `${M.semAmeacaDerivavel} ${cel(textoLacuna(ctx, s, ft).replace(/\*\*/g, ""))}`;
    p.push(`| ${STRIDE_ROTULO[s]} | ${celula} |`);
  }
  p.push("");
  p.push(M.notaTabelaAmeacas);

  if (ctx.findings.length) {
    p.push(M.hdrDetalhamento);
    for (const s of STRIDE_ORDEM) {
      for (const grupo of agrupar(ctx.findings.filter((x) => x.stride === s))) {
        const f = grupo[0];
        const muitos = grupo.length > 1;
        p.push(
          muitos
            ? M.tituloGrupo(fid(f), fid(grupo[grupo.length - 1]), f.class, grupo.length)
            : `#### ${fid(f)} — ${f.title}\n`,
        );
        if (muitos) {
          p.push(M.notaGrupo(grupo.length));
          p.push(M.thIdEntrypoint);
          p.push("|---|---|");
          for (const g of grupo) p.push(`| ${fid(g)} | \`${cel(g.entrypoint)}\` |`);
          p.push("");
        }
        p.push("| | |");
        p.push("|---|---|");
        p.push(`| ${M.lblClasse} | \`${cel(f.class)}\` |`);
        if (!muitos) {
          p.push(
            `| ${M.lblAlvo} | ${f.entrypoint === "<contrato>" ? M.alvoContrato : M.alvoEntrypoint(cel(f.entrypoint))} |`,
          );
        }
        p.push(`| ${M.lblSeveridade} | ${M.valorSeveridade(f.severity)} |`);
        p.push(`| ${M.lblSolidezAchado} | ${linhaSolidez(ctx, f, muitos)} |`);
        p.push("");
        p.push(M.hdrEvidenciaBloco);
        for (const ev of f.evidence) p.push(M.itemEvidencia(ev.tier, T[ev.tier], ev.claim));
        p.push("");
        const nota = notaInicializacao(ctx, grupo);
        if (nota) p.push(nota);
        if (precisaConfirmar(f)) {
          p.push(M.aindaNaoAchado(muitos ? M.escopoCadaListado : M.escopoDe(f.entrypoint), fid(f)));
        }
      }
    }
  }

  const comLacuna = STRIDE_ORDEM.filter((s) => gapsEfetivos.has(s));
  if (comLacuna.length) {
    p.push(M.hdrLacunas);
    for (const s of comLacuna) {
      p.push(`#### ${STRIDE_ROTULO[s]}\n`);
      p.push(`${textoLacuna(ctx, s, ft)}\n`);
    }
  }

  return p.join("\n");
}

/* ------------------------------------------------------------------ *
 * 3. What are we going to do about it?
 * ------------------------------------------------------------------ */

function remediacoes(ctx: ArtifactContext, f: Finding, ft: Fatos): string[] {
  const ep = ctx.analysis.entrypoints.find((e) => e.name === f.entrypoint);
  const alvo = `\`${f.entrypoint}\``;
  const rs: string[] = [];

  // Quando a evidência positiva é super-aproximada, a primeira ação não é corrigir:
  // é descobrir se existe o quê corrigir. Inverter essa ordem é como se produz retrabalho.
  if (precisaConfirmar(f)) {
    rs.push(M.remConfirmar(alvo, caminhoDeEscrita(ctx, ep), fid(f)));
  }

  // O spec escreve os tipos em minúsculas (`address`, `bytesN`, `vec`). Comparar contra
  // "Address" fazia o documento AFIRMAR que não havia parâmetro de endereço onde havia —
  // afirmação falsa e trivial de derrubar. Distinguimos três casos: tem endereço, não tem,
  // e o entrypoint nem aparece no spec (aí a ferramenta não sabe, e diz que não sabe).
  const fn = ctx.spec.fns.find((x) => x.name === f.entrypoint);
  const enderecos = fn?.params.filter((prm) => /^address$/i.test(prm.type)).map((prm) => prm.name) ?? [];

  switch (f.class) {
    case "unauthenticated-state-mutation":
      rs.push(
        enderecos.length
          ? M.remAuthComEndereco(alvo, enderecos.length, lista(enderecos))
          : fn
            ? M.remAuthSemEndereco(alvo)
            : M.remAuthSemSpec(alvo),
      );
      rs.push(M.remAuthAceitacao(alvo));
      break;

    case "initialization-front-running": {
      // Com `__constructor` exportado, "mova para o construtor" é conselho impossível de aplicar
      // sem redeploy — e o próprio achado já lê este entrypoint como segunda etapa.
      const temConstrutor = ctx.analysis.entrypoints.some((e) => e.name === "__constructor");
      rs.push(
        temConstrutor
          ? M.remInitVerificarGuarda(alvo, Boolean(ep?.reaches.has("has_contract_data")))
          : M.remInitConstrutor(alvo),
      );
      rs.push(M.remInitGuard(alvo, Boolean(ctx.storageKeys?.length)));
      break;
    }

    case "unguarded-upgrade":
      rs.push(M.remUpgradeAuth(alvo, fid(f)));
      rs.push(M.remUpgradeEvento(alvo));
      break;

    // NOTA: não há `case "privilege-delegation"`. `detect.ts` rebaixou a delegação de achado para
    // inventário (`delegacoes()`), e a classe não é mais emitida — 0 ocorrências nos 75 contratos
    // do corpus. A remediação que existia aqui afirmava "a alcançabilidade prova que a delegação
    // existe", o que inverte a assimetria: alcance é a positiva, e a positiva não prova nada.
    // Se a classe voltar, o `default` declara a lacuna em vez de emitir conselho errado.

    case "write-before-auth": {
      const o = ctx.analysis.writeBeforeAuth.get(f.entrypoint)?.[0];
      rs.push(
        o
          ? M.remOrdemComEvidencia(
              o.bodyFuncIdx, alvo, o.authFn, o.authOffset.toString(16), o.writeFn, o.writeOffset.toString(16),
            )
          : M.remOrdemSemEvidencia(fid(f)),
      );
      rs.push(
        ep && callsOut(ep)
          ? M.remOrdemComCrossCall(alvo)
          : M.remOrdemSemCrossCall(
              alvo,
              Boolean(ep?.callGraphComplete),
              motivoSubgrafo(ctx, M.escopoEste),
              fid(f),
            ),
      );
      break;
    }

    case "silent-mutation":
      rs.push(M.remSilentEvento(lista(ft.mudos.map((e) => e.name), 12), planoTemDiffDeEstado(ctx)));
      rs.push(M.remSilentTopico(ft.mudos.length, lista(ft.mudos.map((e) => e.name), 12)));
      break;

    case "archival-risk":
      rs.push(M.remArchivalTtl(lista(ft.gravam.map((e) => e.name), 12), fid(f)));
      rs.push(M.remArchivalAceitar(fid(f)));
      break;

    case "host-prng-in-value-path":
      rs.push(M.remPrngRegistrar(alvo, fid(f)));
      rs.push(M.remPrngTrocar(alvo));
      break;

    case "vulnerable-sdk":
      rs.push(M.remSdkRecompilar(fid(f)));
      rs.push(M.remSdkVerificar(fid(f)));
      break;

    default:
      // Classe nova sem remediação escrita: declarar a lacuna em vez de emitir conselho genérico.
      rs.push(M.remLacunaClasse(f.class, fid(f)));
  }

  return rs;
}

/**
 * O que a letra SEM achado deixa para a revisão — citando a planilha que a lacuna daquela letra
 * já montou na seção 2. Sem isto, as células das letras vazias saíam palavra por palavra iguais,
 * que é o "preenchido com genérico" que o cabeçalho deste documento promete não fazer. Cada letra
 * cita uma superfície diferente, então duas células nunca coincidem.
 */
function trabalhoLacuna(ctx: ArtifactContext, s: Stride, ft: Fatos): string {
  switch (s) {
    case "Spoof": {
      const nomes = ft.autenticam.map((e) => e.name);
      return M.trabSpoof(nomes.filter(formaAdmin), nomes.filter((n) => !formaAdmin(n)));
    }
    case "Tamper": {
      const alvos = ft.cruzam.length ? ft.cruzam : ft.invocaveis;
      return M.trabTamper(alvos.length, listaE(alvos.map((e) => e.name)));
    }
    case "Repudiate":
      return M.trabRepudiate(ft.gravam.length, listaE(ft.gravam.map((e) => e.name)));
    case "Info": {
      const chaves = (ctx.storageKeys ?? []).map((k) => k.key);
      const topicos = topicosDeclarados(ctx);
      return M.trabInfo(
        chaves.length,
        chaves.length ? listaE(chaves) : M.listaVazia,
        topicos.length,
        topicos.length ? listaE(topicos) : M.listaVazia,
      );
    }
    case "DoS":
      return M.trabDos(ft.renovamTtl.length, listaE(ft.renovamTtl.map((e) => e.name)));
    case "Elevation": {
      const residuo = [
        ...new Set(
          ft.invocaveis
            .filter((e) => (writesStorage(e) || canUpgradeSelf(e)) && !requiresAuth(e))
            .map((e) => e.name),
        ),
      ];
      if (residuo.length) return M.trabElevResiduo(residuo.length, listaE(residuo));
      const delegam = ft.invocaveis.filter(delegatesAuth).map((e) => e.name);
      if (delegam.length) return M.trabElevDelegam(delegam.length, listaE(delegam));
      return M.trabElevAuth(ft.autenticam.length, listaE(ft.autenticam.map((e) => e.name)));
    }
  }
}

function secaoRemediacoes(ctx: ArtifactContext, ft: Fatos, gapsEfetivos: Set<Stride>): string {
  const p: string[] = [];
  p.push("## What are we going to do about it?\n");
  p.push(M.introRemediacoes);

  p.push("| Threat | Issues |");
  p.push("|---|---|");
  for (const s of STRIDE_ORDEM) {
    const fs = ctx.findings.filter((f) => f.stride === s);
    if (!fs.length) {
      p.push(M.celulaSemRemediacao(STRIDE_ROTULO[s], cel(trabalhoLacuna(ctx, s, ft))));
      continue;
    }
    const blocos: string[] = [];
    for (const f of fs) {
      const rs = remediacoes(ctx, f, ft);
      blocos.push(rs.map((r, i) => `**${fid(f)}.R.${i + 1}** [C] — ${cel(r)}`).join("<br><br>"));
    }
    p.push(`| ${STRIDE_ROTULO[s]} | ${blocos.join("<br><br>")} |`);
  }
  p.push("");

  if (gapsEfetivos.size) p.push(M.letrasSemRemediacao([...gapsEfetivos].join(", ")));

  return p.join("\n");
}

/* ------------------------------------------------------------------ *
 * 4. Did we do a good job?
 * ------------------------------------------------------------------ */

function secaoAvaliacao(ctx: ArtifactContext, ft: Fatos, gapsEfetivos: Set<Stride>, divergencia: Stride[]): string {
  const p: string[] = [];
  p.push("## Did we do a good job?\n");
  p.push(M.introAvaliacao);

  const paraConfirmar = ctx.findings.filter(precisaConfirmar);
  const respostas: string[] = [];

  // 1 — referência ao DFD
  respostas.push(
    ctx.dfd
      ? M.q1Sim(
          ctx.generatedAt,
          ctx.dfd.boundaries.length,
          ctx.dfd.nodes.filter((n) => n.kind === "process").length,
        )
      : M.q1Nao,
  );

  // 2 — o modelo revelou algo novo
  respostas.push(
    ctx.findings.length
      ? M.q2Com(ctx.findings.length, new Set(ctx.findings.map((f) => f.stride)).size, ft.invocaveis.length) +
        (paraConfirmar.length ? M.q2Confirmar(paraConfirmar.length, paraConfirmar.map(fid).join(", ")) : "")
      : M.q2Sem,
  );

  // 3 — as remediações resolvem
  respostas.push(
    ctx.findings.length ? M.q3Com(ctx.spec.wasmHash ? M.q3Hash(ctx.spec.wasmHash) : "") : M.q3Sem,
  );

  // 4 — apareceram outras questões depois
  respostas.push(
    M.q4(
      ctx.generatedAt,
      gapsEfetivos.size ? M.q4Lacunas([...gapsEfetivos].join(", ")) : M.q4LacunasGenerico,
      paraConfirmar.length ? M.q4Confirmar(paraConfirmar.length) : "",
    ),
  );

  // 5 — insights sobre o processo
  const insights: string[] = [];
  insights.push(M.insightAssimetria);
  insights.push(
    ctx.analysis.soundness === "sound" ? M.insightSolido : M.insightRebaixado(motivoModulo(ctx)),
  );
  insights.push(
    M.insightSpoofInfo(
      ft.autenticam.length,
      ft.invocaveis.length,
      (ctx.storageKeys ?? []).length,
      topicosDeclarados(ctx).length,
    ),
  );
  // "permite baseline real" é afirmação sobre o plano irmão, não sobre a janela: só vale
  // se algum monitor de fato ancorou baseline nela. Sem isso, o que houve foi observação
  // registrada — e dizer o contrário promete ao revisor um número que ele não vai achar lá.
  const ancoras = monitoresComBaselineB(ctx);
  insights.push(
    ctx.observations
      ? ctx.observations.window.insufficient
        ? M.insightObsInsuficiente
        : ancoras
          ? M.insightObsOk(ancoras)
          : M.insightObsSemAncora(
              ctx.observations.window.ledgers,
              ctx.observations.window.approxHours,
              ctx.observations.events.reduce((s, e) => s + e.count, 0),
              ctx.observations.events.length,
              ctx.observations.events.length ? M.motivoSemVinculo : M.motivoSemTrafego,
            )
      : ctx.observationError
        ? M.insightObsFalhou(ctx.observationError)
        : ctx.offline
          ? M.insightObsOffline
          : M.insightObsAusente,
  );
  insights.push(M.insightForaDoEscopo);
  respostas.push(insights.map((i) => `\n  - ${i}`).join(""));

  for (let i = 0; i < PERGUNTAS_FINAIS.length; i++) {
    p.push(`**${PERGUNTAS_FINAIS[i]}**\n`);
    p.push(`${respostas[i]}\n`);
  }

  if (divergencia.length) p.push(M.divergencia(divergencia.join(", "), divergencia.length));

  return p.join("\n");
}

/* ------------------------------------------------------------------ *
 * Entrada
 * ------------------------------------------------------------------ */

export function renderThreatModel(ctx: ArtifactContext): string {
  const ft = fatos(ctx);

  // Lacuna é "letra sem achado", e isso é derivável de ctx.findings. `ctx.gaps` é a fonte
  // declarada, mas se as duas discordarem o documento não pode esconder: seguimos os achados
  // (afirmar lacuna onde há achado seria mentir) e registramos a divergência na seção 4.
  const comAchado = new Set(ctx.findings.map((f) => f.stride));
  const gapsEfetivos = new Set(STRIDE_ORDEM.filter((s) => !comAchado.has(s)));
  const divergencia = ctx.gaps.filter((s) => comAchado.has(s));

  const doc: string[] = [];
  doc.push(`# Threat Model (STRIDE) — \`${ctx.contractId}\`\n`);
  doc.push(M.subtitulo(ctx.network, ctx.generatedAt));
  doc.push(M.introDocumento);
  doc.push("---\n");
  doc.push(secaoContexto(ctx, ft));
  doc.push("---\n");
  doc.push(secaoAmeacas(ctx, ft, gapsEfetivos));
  doc.push("---\n");
  doc.push(secaoRemediacoes(ctx, ft, gapsEfetivos));
  doc.push("---\n");
  doc.push(secaoAvaliacao(ctx, ft, gapsEfetivos, divergencia));

  return `${doc.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}
