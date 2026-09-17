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
 * Idioma: a saída é INGLÊS (revisores do SCF e templates da Stellar). Todo texto de saída
 * vive em `M`; comentários seguem em português, por convenção do repositório.
 */

import type { ArtifactContext } from "../artifact.ts";
import { tierLabel } from "../artifact.ts";
import type { Finding, Stride, Tier } from "../detect.ts";
import type { Durability, Entrypoint } from "../analyze.ts";
import {
  caminho, minHops, requiresAuth, writesStorage, emitsEvent, extendsTtl, callsOut, canUpgradeSelf, delegatesAuth,
  writeDurabilities,
} from "../analyze.ts";
import { STORAGE_WRITE_FNS, TTL_EXTEND_FNS } from "../hostfns.ts";
import { declaracaoDeJanela } from "../events.ts";
import { plural } from "../text.ts";
import { validateThreatModel } from "../validate.ts";

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

const M = {
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
  thSuperficie: "| Entrypoint | auth | writes | durability | event | upgrade | cross-call | fanout |",
  notaSuperficie:
    "In every column, \"yes\" means it **reaches** the corresponding host function on some call-graph " +
    "path, not that it always executes it.\n",
  notaDurabilidadeCol: (lidos: number, sites: number) =>
    "\n**durability** is the `StorageType` of the writes reached: `temp`, `pers`, `inst`. The " +
    "three are not interchangeable — `temp` is deleted for good on expiry, `inst` shares one " +
    "64 KiB entry. `?` means the type reaches the call computed; `—` means no write. Read " +
    `literally at ${lidos} of ${sites} storage call sites. It describes the storage layout; it ` +
    "is not a finding.\n",
  hdrStores: "### Inferred data stores\n",
  chavesCertas: (l: string) => `- Keys read from the module's linear memory: ${l}.`,
  chavesProvaveis: (l: string) => `- Likely keys (partial read of the data section): ${l}.`,
  notaDurabilidade:
    "\nDurability is **not** attributable to a key from this list. The `StorageType` is readable " +
    "per call site (see the `durability` column above), but pairing *which key* goes to *which " +
    "durability* needs dataflow from the key to the call, which this analysis does not do — a " +
    "single entrypoint routinely writes several keys at different durabilities. Do not assume " +
    "the durability of any key below.\n",
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
    "**How to read the authorization boundary (tier C, name-shape heuristic).** The boundary says only " +
    "that `require_auth*` is reachable, and that single label covers two different mechanisms. " +
    (admins.length
      ? `**Access control** — ${admins.length} admin-shaped ${plural(admins.length, "node", "nodes")} ` +
        `(${listaE(admins)}): there the authorized \`Address\` is a privileged role, and the review has ` +
        "to trace its custody (multisig or a single key). "
      : "**Access control** — no node inside the boundary has an administrative name shape, so none of " +
        "them points at a privileged key holder to trace. ") +
    (usuarios.length
      ? `**Self-authorization** — ${usuarios.length} user-shaped ${plural(usuarios.length, "node", "nodes")} ` +
        `(${listaE(usuarios)}): there \`require_auth\` is the caller authorizing ` +
        `${plural(usuarios.length, "its", "their")} own address, the expected shape of a user operation ` +
        "(`swap`, `deposit`, `withdraw`), with no privileged key behind it and nothing to trace. "
      : "") +
    "Reading the whole boundary as access control overstates it; reading it as self-authorization " +
    "understates it. The split comes from the name, not from the bytecode: the call graph never shows " +
    "*whose* `Address` is authorized.\n",
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
      ? `**Access control (${admins.length} admin-shaped, key-holder trace required):** ${listaE(admins)} ` +
        "— those are the calls whose `Address` is a privileged role and has to be traced back to a key " +
        "holder: custody, multisig or a single key. "
      : "**Access control: no admin-shaped entrypoint reaches `require_auth*`**, so this contract has no " +
        "such call to trace back to a key holder. ") +
    (usuarios.length
      ? `**Self-authorization (${usuarios.length} user-shaped, no key-holder trace):** ${listaE(usuarios)} ` +
        `— there \`require_auth\` is the caller authorizing ${plural(usuarios.length, "its", "their")} own ` +
        "address (`swap`, `deposit`, `withdraw` are the usual shape), which is a user operation, not " +
        "access control; there is no privileged key behind it to trace. "
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
  /* --- bloco agregado por família --- */
  notaAgregado: (n: number, fam: string, cls: string) =>
    `These ${n} findings are the same shape: family \`${fam}\`, class \`${cls}\`, one per entrypoint. ` +
    "Repeating the block " + `${n} times would bury the rest of the document without adding a fact, so ` +
    "what differs per entrypoint is in the table below, and the evidence and the remediation they share " +
    "are stated once. Each ID stays individual: its row is its anchor, and the threat table and the " +
    "remediations keep every id.\n",
  colId: "ID",
  colEntrypoint: "Entrypoint",
  colNiveis: "Evidence tiers",
  colSeveridadeTab: "Severity",
  colHops: "Hops to the write",
  colGuard: "`has_contract_data`",
  colProbe: "On-chain probe",
  guardSim: "reachable",
  guardNao: "not reachable",
  semDado: "—",
  linhaAncoras: (ids: string) =>
    `**Per-ID anchors:** ${ids}. Each row above is the anchor for its id — the monitor ids ` +
    "`<ThreatID>.M.<n>` in the monitoring plan resolve to them.\n",
  evidenciaCondensada: (n: number) =>
    `**Evidence** — condensed: the reachable set, the hop count and the applied severity rule are ` +
    `per entrypoint and are in the table above. What follows is the evidence the ${n} findings share, ` +
    "stated once.\n",
  remCompartilhada: (a: string, b: string) =>
    `**Shared remediation.** The same actions apply to every entrypoint listed; they stay numbered per ` +
    `id, from ${a} to ${b}, in *What are we going to do about it*.\n`,
  valorSeveridadeVarias: (l: string) =>
    `${l} — per entrypoint, in the table above; **tier C**, a risk judgement, not a bytecode fact`,
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
  /* --- bloco da sondagem de init (probe) — ver notaProbe() --- */
  probeCabecalho: "> **Init probe (tier B).**\n>\n",
  probeLinha: (ep: string, ledger: string, kind: string, detail: string) =>
    `> - \`${ep}\` — Probe (unsigned simulateTransaction${ledger}): **${kind}** — ${detail}.\n`,
  probeLedger: (l: number) => `, ledger ${l}`,
  probeGuarded:
    ">\n> The front-running window is closed on this instance; residual risk is limited to a future re-deploy " +
    "of the same code with the same non-atomic initialization.\n",
  probeOpen:
    ">\n> ⚠ **The initializer executed successfully in simulation with placeholder arguments: any address can " +
    "initialize this instance NOW — treat as High until confirmed.** The simulation was unsigned and never " +
    "submitted; it is evidence that the call is accepted at the current ledger, not that it was executed.\n",
  probeInconclusivo:
    ">\n> The probe did not settle the question: placeholder arguments can fail validation before reaching the " +
    "guard, so this is neither confirmation nor refutation. The tier C wording above stands as written.\n",
  achadoFechadoPorObservacao: (escopo: string, id: string) =>
    "> **This finding is closed by observation.** The unsigned probe above reached an already-initialized " +
    `guard ${escopo}: the front-running window described in tier C has already closed on this instance. ` +
    `It stays in the document as the re-deploy risk it still is — see ${id}.R.1 — not as an open issue.\n`,

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
  /* --- veredito de submissão (três estados) --- */
  hdrVeredito: "### Submission verdict\n",
  vereditoOk:
    "**SUBMITTABLE.** Every check above passes and nothing is left for the team to fill in.\n",
  vereditoInput: (n: number) =>
    `**NEEDS INPUT.** The tool's own checks pass; ${n} ${plural(n, "item", "items")} below ` +
    `${plural(n, "is", "are")} input that no bytecode or on-chain analysis produces. Filling ` +
    `${plural(n, "it", "them")} is what makes this document submittable — nothing in the analysis has to change.\n`,
  vereditoNao: (nb: number, ni: number) =>
    `**NOT SUBMITTABLE.** ${nb} ${plural(nb, "blocker is", "blockers are")} the tool's own to close` +
    (ni ? `, and ${ni} ${plural(ni, "item", "items")} on top of that ${plural(ni, "is", "are")} for the team` : "") +
    ". Do not submit in this state: what follows is an assertion the analysis does not sustain, " +
    "and it is the first thing a reviewer pulls on.\n",
  hdrBlockersDoc: "**Blockers — the tool's own, not the team's:**\n",
  hdrInputDoc: "### Input the team must provide before submitting\n",
  notaInputDoc:
    "None of these comes out of a binary or out of the chain. Each line names the worksheet it is " +
    "filled from; the analysis above does not change when they are answered.\n",
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
};

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

/** Rótulos curtos — a tabela já tem oito colunas e não comporta os nomes por extenso. */
const DUR_ABREV: Record<Durability, string> = {
  temporary: "temp",
  persistent: "pers",
  instance: "inst",
};

/**
 * Célula da coluna `durability`. Três estados, e os três precisam ser distinguíveis:
 * durabilidades lidas · `?` (escreve, mas o `StorageType` chega computado) · `—` (não
 * escreve). Colapsar `?` em `—` diria "não escreve" sobre um entrypoint que escreve.
 */
const durCel = (e: Entrypoint): string => {
  const ds = writeDurabilities(e);
  if (ds.length) return ds.map((d) => `\`${DUR_ABREV[d]}\``).join(", ");
  return writesStorage(e) ? "`?`" : "—";
};

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
 * "⚠ REVIEW" (ver detect.ts). Quando ele está presente, a primeira remediação
 * não pode ser "conserte" — tem que ser "confirme que existe o quê consertar".
 */
const MARCA_REVISAR = /^⚠\s*REVIEW\b/;
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
 * A partir de quantas repetições a família vira um bloco só. Três é onde o custo de ler
 * blocos iguais passa a ser maior que o de ler uma tabela: com dois, a comparação lado a
 * lado ainda é o que o revisor quer.
 */
const MIN_AGREGACAO = 3;

/** Evidência idêntica (nível + texto) em TODOS os achados do grupo, na ordem do primeiro. */
function evidenciaComum(grupo: readonly Finding[]): Finding["evidence"] {
  const chave = (e: Finding["evidence"][number]) => `${e.tier}\u0000${e.claim}`;
  const outros = grupo.slice(1).map((g) => new Set(g.evidence.map(chave)));
  return grupo[0].evidence.filter((e) => outros.every((s) => s.has(chave(e))));
}

/**
 * Chave de agregação por FAMÍLIA: mesma família, mesma classe, mesma solidez e a mesma forma
 * de evidência (a sequência de níveis). A severidade fica FORA da chave de propósito — ela é
 * um fato por entrypoint e vira coluna da tabela; exigi-la igual era o que fazia cinco
 * `initialization-front-running` da mesma forma saírem como cinco blocos iguais.
 *
 * Nunca agrega entre classes: duas classes diferentes na mesma família são duas ameaças
 * diferentes, e uni-las apagaria justamente o que o revisor precisa distinguir.
 */
function chaveFamilia(f: Finding): string | undefined {
  if (!f.family || f.entrypoint === "<contrato>") return undefined;
  return `fam\u0000${f.family}\u0000${f.class}\u0000${f.sound}\u0000${f.evidence.map((e) => e.tier).join("")}`;
}

/**
 * Agrupa achados para o detalhamento. Duas réguas, nesta ordem:
 *
 *  1. FAMÍLIA — ≥3 achados da mesma família e classe, com a mesma forma de evidência, viram um
 *     bloco só, com uma tabela por entrypoint. Cinco blocos com a mesma prosa não acrescentam
 *     informação: enterram o resto do documento, que é como um relatório vira ruído.
 *  2. EVIDÊNCIA IDÊNTICA — o agrupamento byte a byte, para o resto.
 *
 * O agrupamento é só de APRESENTAÇÃO: cada ID continua individual e rastreável na tabela de
 * ameaças, na de remediações e na linha da tabela do próprio bloco — é dela que os ids de
 * monitor `<ThreatID>.M.<n>` dependem para resolver.
 */
function agrupar(fs: Finding[]): Finding[][] {
  const contaFamilia = new Map<string, number>();
  for (const f of fs) {
    const k = chaveFamilia(f);
    if (k) contaFamilia.set(k, (contaFamilia.get(k) ?? 0) + 1);
  }
  const ordem: string[] = [];
  const m = new Map<string, Finding[]>();
  for (const f of fs) {
    const fam = chaveFamilia(f);
    const k =
      fam && (contaFamilia.get(fam) ?? 0) >= MIN_AGREGACAO
        ? fam
        : `exato\u0000${f.class}\u0000${f.severity}\u0000${f.sound}\u0000${f.evidence.map((e) => `${e.tier}:${e.claim}`).join("\u0001")}`;
    if (!m.has(k)) { m.set(k, []); ordem.push(k); }
    m.get(k)!.push(f);
  }
  return ordem.map((k) => m.get(k)!);
}

/**
 * A tabela do bloco agregado: uma linha por achado, com os fatos que diferem entre eles.
 *
 * Cada linha é TAMBÉM a âncora do id — por isso ela carrega as marcas de nível. Sem elas o
 * validador leria um id presente no documento sem nenhuma afirmação marcada e acusaria, com
 * razão, que o leitor não distingue fato de bytecode de inferência naquele achado.
 */
function tabelaAgregada(ctx: ArtifactContext, grupo: readonly Finding[]): string[] {
  const epDe = (f: Finding) => ctx.analysis.entrypoints.find((e) => e.name === f.entrypoint);
  const hops = new Map(grupo.map((f) => [fid(f), (() => { const e = epDe(f); return e ? minHops(e, STORAGE_WRITE_FNS) : undefined; })()]));
  const probes = ctx.spec.probes;
  const comHops = [...hops.values()].some((h) => h !== undefined);
  const comGuard = grupo.some((f) => f.family === "init");
  const comProbe = Boolean(probes) && grupo.some((f) => probes![fid(f)]);

  const cols = [M.colId, M.colEntrypoint, M.colNiveis, M.colSeveridadeTab];
  if (comHops) cols.push(M.colHops);
  if (comGuard) cols.push(M.colGuard);
  if (comProbe) cols.push(M.colProbe);

  const linhas = [`| ${cols.join(" | ")} |`, `|${cols.map(() => "---").join("|")}|`];
  for (const f of grupo) {
    const ep = epDe(f);
    const cells = [
      `**${fid(f)}**`,
      `\`${cel(f.entrypoint)}\``,
      niveisDe(f).map((t) => `[${t}]`).join("+"),
      f.severity,
    ];
    if (comHops) cells.push(hops.get(fid(f))?.toString() ?? M.semDado);
    if (comGuard) cells.push(ep ? (ep.reaches.has("has_contract_data") ? M.guardSim : M.guardNao) : M.semDado);
    if (comProbe) cells.push(probes?.[fid(f)] ? cel(String(probes[fid(f)]!.kind)) : M.semDado);
    linhas.push(`| ${cells.join(" | ")} |`);
  }
  return linhas;
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
  const T = tierLabel;
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
    p.push("|---|---|---|---|---|---|---|---|");
    for (const e of ft.invocaveis) {
      p.push(
        `| \`${cel(e.name)}\` | ${sim(requiresAuth(e))} | ${sim(writesStorage(e))} | ${durCel(e)} | ${sim(emitsEvent(e))} | ` +
          `${sim(canUpgradeSelf(e))} | ${sim(callsOut(e))} | ${e.fanout} |`,
      );
    }
    p.push("");
    p.push(M.notaSuperficie);
    // Cobertura do MÓDULO, não a soma por entrypoint: somar contaria um helper de storage
    // compartilhado uma vez por export que o alcança. Sem este denominador, um `—` na linha
    // não se distingue de "não consegui ler".
    const dc = ctx.analysis.durabilityCoverage;
    if (dc?.sites) p.push(M.notaDurabilidadeCol(dc.literal, dc.sites));
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
    /* ---- declaração de janela (limitedBy) — bloco único, ver events.ts ---- */
    if (ctx.spec.windowLimitedBy) {
      p.push(declaracaoDeJanela(o.window.ledgers, o.window.approxHours, ctx.spec.windowLimitedBy));
      p.push("");
    }
    /* ---- fim da declaração de janela ---- */
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
/* ------------------------------------------------------------------ *
 * BLOCO DA SONDAGEM DE INIT (probe) — início.
 * Tudo que este agente acrescenta ao arquivo fora da declaração de janela
 * está entre este marcador e o de fim, mais a chamada única em secaoAmeacas.
 * ------------------------------------------------------------------ */

/**
 * A linha de nível B que fecha (ou abre de vez) um achado de init.
 *
 * Medido no top 25 de mainnet: 23 dos 66 achados eram front-running de inicializador que
 * JÁ disparou (`docs/PRECISION-TOP25.md`). O documento afirmava no presente uma janela
 * fechada — e um revisor que checa isso em uma chamada de RPC derruba o documento inteiro.
 * A sondagem é `simulateTransaction` NÃO ASSINADA: nada é submetido, nada é assinado.
 *
 * `fechado` só é verdadeiro quando TODO achado sondado do grupo saiu `guarded`: um único
 * `open` ou `inconclusive` no grupo mantém o callout de "ainda não é um achado", porque
 * argumentos placeholder podem falhar antes da guarda.
 */
function notaProbe(ctx: ArtifactContext, grupo: Finding[]): { texto: string; fechado: boolean } | undefined {
  const probes = ctx.spec.probes;
  if (!probes) return undefined;
  const pares = grupo
    .map((f) => ({ f, r: probes[fid(f)] }))
    .filter((x): x is { f: Finding; r: NonNullable<typeof x.r> } => Boolean(x.r));
  if (!pares.length) return undefined;

  let texto = M.probeCabecalho;
  for (const { r } of pares) {
    texto += M.probeLinha(cel(r.entrypoint), r.ledger ? M.probeLedger(r.ledger) : "", r.kind, r.detail);
  }
  const algum = (k: string) => pares.some((x) => x.r.kind === k);
  if (algum("open")) texto += M.probeOpen;
  else if (pares.every((x) => x.r.kind === "guarded")) texto += M.probeGuarded;
  else texto += M.probeInconclusivo;
  return { texto, fechado: !algum("open") && pares.every((x) => x.r.kind === "guarded") };
}

/* ---- BLOCO DA SONDAGEM DE INIT (probe) — fim ---- */

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
  const T = tierLabel;
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
        // Evidência que TODOS do grupo carregam. No grupo exato é a lista inteira; no grupo
        // agregado por família é o que sobra depois de tirar o que é por entrypoint — e o que
        // saiu dali não some: vira coluna da tabela acima.
        const compartilhada = evidenciaComum(grupo);
        const agregado = muitos && compartilhada.length < f.evidence.length;
        if (muitos) {
          p.push(agregado ? M.notaAgregado(grupo.length, f.family ?? "—", f.class) : M.notaGrupo(grupo.length));
          if (agregado) {
            for (const l of tabelaAgregada(ctx, grupo)) p.push(l);
            p.push("");
            p.push(M.linhaAncoras(grupo.map((g) => `\`${fid(g)}\``).join(" · ")));
          } else {
            p.push(M.thIdEntrypoint);
            p.push("|---|---|");
            for (const g of grupo) p.push(`| ${fid(g)} | \`${cel(g.entrypoint)}\` |`);
            p.push("");
          }
        }
        p.push("| | |");
        p.push("|---|---|");
        p.push(`| ${M.lblClasse} | \`${cel(f.class)}\` |`);
        if (!muitos) {
          p.push(
            `| ${M.lblAlvo} | ${f.entrypoint === "<contrato>" ? M.alvoContrato : M.alvoEntrypoint(cel(f.entrypoint))} |`,
          );
        }
        const sevs = [...new Set(grupo.map((g) => g.severity))];
        p.push(
          `| ${M.lblSeveridade} | ${sevs.length > 1 ? M.valorSeveridadeVarias(sevs.join(", ")) : M.valorSeveridade(f.severity)} |`,
        );
        p.push(`| ${M.lblSolidezAchado} | ${linhaSolidez(ctx, f, muitos)} |`);
        p.push("");
        p.push(agregado ? M.evidenciaCondensada(grupo.length) : M.hdrEvidenciaBloco);
        for (const ev of compartilhada) p.push(M.itemEvidencia(ev.tier, T[ev.tier], ev.claim));
        p.push("");
        if (agregado) p.push(M.remCompartilhada(`\`${fid(f)}.R.1\``, `\`${fid(grupo[grupo.length - 1])}.R.1\``));
        const nota = notaInicializacao(ctx, grupo);
        if (nota) p.push(nota);
        /* ---- sondagem de init (probe): uma chamada, ver notaProbe() ---- */
        const sonda = notaProbe(ctx, grupo);
        if (sonda) p.push(sonda.texto);
        if (precisaConfirmar(f)) {
          const escopo = muitos ? M.escopoCadaListado : M.escopoDe(f.entrypoint);
          p.push(sonda?.fechado ? M.achadoFechadoPorObservacao(escopo, fid(f)) : M.aindaNaoAchado(escopo, fid(f)));
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

/**
 * O veredito sai do MESMO validador que o CLI imprime — não de uma contagem própria desta
 * seção. Duas contagens divergem no primeiro contrato que ninguém testou, e um documento que
 * se declara submetível enquanto o terminal diz o contrário perde o revisor de uma vez.
 *
 * O relatório é calculado sobre o documento ATÉ aqui (seções 1-3). Nada que esta seção
 * acrescente pode criar ou apagar ameaça, remediação, letra ou id: o que ela escreve é
 * resposta de auto-avaliação e o próprio veredito.
 */
function secaoAvaliacao(
  ctx: ArtifactContext,
  ft: Fatos,
  gapsEfetivos: Set<Stride>,
  divergencia: Stride[],
  rel: ReturnType<typeof validateThreatModel>,
): string {
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

  /* --- veredito: três estados, e as duas listas separadas --- */
  const input = rel.needsInput ?? [];
  p.push(M.hdrVeredito);
  p.push(
    rel.verdict === "submittable"
      ? M.vereditoOk
      : rel.verdict === "needs-input"
        ? M.vereditoInput(input.length)
        : M.vereditoNao(rel.blockers.length, input.length),
  );
  if (rel.blockers.length) {
    p.push(M.hdrBlockersDoc);
    rel.blockers.forEach((b, i) => p.push(`${i + 1}. ${cel(b)}`));
    p.push("");
  }
  if (input.length) {
    p.push(M.hdrInputDoc);
    p.push(M.notaInputDoc);
    input.forEach((b, i) => p.push(`${i + 1}. ${cel(b)}`));
    p.push("");
  }

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
  // O corpo pronto é a entrada do validador; a §4 é a saída dele. Mesmo desenho da §6 do
  // monitoring plan, pela mesma razão: o veredito no documento e o veredito do CLI são o
  // mesmo objeto, não duas contas parecidas.
  const rel = validateThreatModel(ctx, doc.join("\n"));
  doc.push(secaoAvaliacao(ctx, ft, gapsEfetivos, divergencia, rel));

  return `${doc.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}
