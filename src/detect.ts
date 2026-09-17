import type { Entrypoint, ModuleAnalysis } from "./analyze.ts";
import { STORAGE_WRITE_FNS, STORAGE_READ_FNS, SIG_SCHEME_FNS } from "./hostfns.ts";
import { parseSpecEntries, modelFromEntries } from "./spec.ts";
import { readSdkMeta, advisoriesForWasm, evaluateVersion, ADVISORIES_AS_OF } from "./sdkver.ts";
import { PRNG_FNS } from "./hostfns.ts";
import { msgs, plural } from "./i18n.ts";
import {
  requiresAuth, writesStorage, emitsEvent, canUpgradeSelf, canDeploy, delegatesAuth, callsOut, extendsTtl, minHops,
} from "./analyze.ts";

/**
 * Todo texto que chega ao revisor mora aqui. O que NÃO entra: `tier`, `stride`, `class`,
 * `entrypoint` e os marcadores `<contrato>` / `<downgraded:…>` — são identificadores de dado,
 * lidos por outros módulos (monitors, validate, render) e por isso idênticos nos dois idiomas.
 */
const M = msgs({
  en: {
    /* supressões */
    supReservada: "reserved `__` function, not directly invocable (CAP-0058)",
    supLeitura: "read-shaped name: the write probably comes from a shared helper, not from this path",
    supCrank: "permissionless crank by design (protocol maintenance pattern)",
    supRebaixado:
      "DOWNGRADED (not suppressed): reaches call/try_call — authorization may live in the callee, severity capped at High",

    /* evidência comum */
    semAlcance: "none",
    base: (nome: string, reach: string, fanout: number, sound: boolean) =>
      `export \`${nome}\`: reachable host functions = {${reach}}. Subgraph of ${fanout} functions, call graph ${sound ? "complete" : "INCOMPLETE (call_indirect present)"}.`,

    /* D1/D2 — mutação de estado sem autorização */
    tituloInit: (nome: string) => `\`${nome}\` reaches state initialization without requiring authorization`,
    tituloEscrita: (nome: string) => `\`${nome}\` reaches a state write without requiring authorization`,
    semAuth: (sound: boolean) =>
      `No path reaches require_auth or require_auth_for_args${sound ? " — sound negative" : " — NOT a sound negative, because of call_indirect"}.`,
    caminhoEscrita: (hops: number) =>
      `A path to a storage write exists: ${hops} ${plural(hops, "hop", "hops")} from the export to put_contract_data/del_contract_data.`,
    avisoHelperEscrita: (hops: number) =>
      `⚠ REVIEW: the path to the write is ${hops} hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding.`,
    infInit:
      "The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles.",
    infInitComConstrutor:
      "The contract DOES export `__constructor`, so the deploy itself initializes atomically (CAP-0058). An init-shaped entrypoint kept alongside it is either a second-stage initializer or a legacy one kept for compatibility — in both readings the risk is front-running / re-initialization of that stage, not a generic unauthenticated writer.",
    /**
     * Fato e inferência saem SEPARADOS. Alcançabilidade é bytecode (A); "é uma guarda de
     * já-inicializado" é leitura do que aquele `has_contract_data` faz (C). Numa linha só,
     * sob `[A]`, a opinião viajava de carona no crachá do fato.
     */
    evInitGuardFato: (alcanca: boolean) =>
      alcanca
        ? "`has_contract_data` IS reachable from this export."
        : "`has_contract_data` IS NOT reachable from this export.",
    evInitGuardInferencia: (alcanca: boolean) =>
      alcanca
        ? "A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability."
        : "No already-initialized guard is visible on this path. That the absence means there is none does not follow from the bytecode: the guard could live behind a cross-contract call.",
    regraSeveridadeInit: (guarda: boolean, hops: number, sev: string) =>
      `Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = ${guarda ? "yes" : "no"}, ${hops} ${plural(hops, "hop", "hops")} → ${sev}.`,
    infDelega:
      "No `require_auth` in this module. If authorization is delegated to a called contract (e.g. `require_auth(from)` inside `token.transfer`), it is invisible in this binary — confirm the callee.",
    infQualquer: (nome: string, hops: number, evento: boolean, cross: boolean, upgrade: boolean) => {
      const extra = [
        ...(evento ? ["emits an event"] : []),
        ...(cross ? ["calls another contract"] : []),
        ...(upgrade ? ["can replace its own code"] : []),
      ];
      const cauda = extra.length ? ` and on that path it also ${extra.join(", ")}` : "";
      return `Any address can invoke \`${nome}\`; on some path it reaches a storage write (${hops} ${plural(hops, "hop", "hops")})${cauda}. Whether that path is the one an anonymous caller can drive is not derivable here.`;
    },
    notaDelega:
      "severity capped at High: reaches call/try_call and the authorization may live in the called contract",

    /* D3 — troca do próprio código */
    tituloUpgrade: (nome: string) => `\`${nome}\` reaches a code swap without requiring authorization`,
    evUpgrade:
      "Reaches the self-code-swap family (update_current_contract_wasm / update_current_contract_executable_ref) without reaching require_auth*.",
    infUpgrade: "Allows replacing the contract logic, which subsumes every other protection.",

    /* D8 — escrita antes da autorização */
    tituloWba: (nome: string) =>
      `\`${nome}\`: a storage write appears before \`require_auth\` in the bytecode order of the same body (textual order — branches are not distinguished)`,
    evWba: (body: number, writeFn: string, writeOff: number, authFn: string, authOff: number) =>
      `In fn#${body}: \`${writeFn}\` at offset 0x${writeOff.toString(16)} precedes \`${authFn}\` at offset 0x${authOff.toString(16)}. Comparison of bytecode offsets within the same body — no linearization across functions.`,
    infWba:
      "That the write EXECUTES before the authorization is an inference, not a fact: the comparison is of offsets within the body, with no control-flow model — the two calls may sit on mutually exclusive branches, or the write on a branch that is never taken. If the execution order really is that one, the impact still depends on there being an external effect between the two (typically a cross-contract call), because a failing authorization reverts the whole transaction in Soroban. Review the indicated body.",

    /* D6 — trilha de auditoria ausente */
    tituloSilent: (mudos: number, total: number) =>
      `${mudos} of ${total} state-changing ${plural(mudos, "entrypoint emits", "entrypoints emit")} no event`,
    evSilent: (lista: string) => `Reach put_contract_data and do not reach contract_event: ${lista}.`,
    evExcluidosLeitura: (k: number, lista: string) =>
      `${k} read-shaped ${plural(k, "entrypoint", "entrypoints")} that reach a write through a shared helper were excluded from the count (both numerator and denominator): ${lista}. Emitting events from a quoting getter is not the remediation.`,
    infSilent:
      "Without an event there is no off-chain proof that the action happened, and the change is only detectable by state diff — which makes real-time monitoring of those actions unfeasible.",
    /**
     * A severidade vem da CLASSE da ação silenciosa, não da fração silent/mutadores.
     * Medido em docs/PRECISION-TOP25.md: `2 de 2` num bot anônimo saía High enquanto um
     * `upgrade` sem evento num fundo regulado saía Medium. Fração não é impacto.
     */
    regraSeveridadeSilent: (sev: string, decisores: string, initOnly: boolean) =>
      `Severity rule applied (class of the silent action, not the silent/state-changing fraction): High when any silent entrypoint is upgrade-capable or admin/permission-shaped by name; Low when every silent entrypoint is an init-shaped one-shot; Medium otherwise. Here: ${
        decisores
          ? `deciding entrypoints = ${decisores}`
          : initOnly
            ? "every silent entrypoint is init-shaped"
            : "no upgrade-capable or admin/permission-shaped silent entrypoint"
      } → ${sev}.`,
    evSilentDecisores: (lista: string) =>
      `Of those, upgrade-capable or admin/permission-shaped by name (listed first above): ${lista}.`,

    /* D10 — escrita de terceiro por chamador arbitrário */
    tituloTampering: (nome: string) =>
      `\`${nome}\` lets an arbitrary caller reach a state write while taking an address as a parameter`,
    evTamperParams: (nome: string, lista: string) =>
      `The \`contractspecv0\` spec declares ${plural(lista.split(", ").length, "address parameter", "address parameters")} on \`${nome}\`: ${lista}.`,
    infTamperTaint:
      "The write may touch only the caller's own record — that is not derivable here, because it would require taint from the parameter to the storage key; confirm in source. If the key does derive from the address parameter, any caller can write into a third party's record, which is Tampering rather than privilege elevation.",

    /* D11 — verificação de assinatura implementada no contrato */
    tituloSigVerif:
      "The contract implements signature verification of its own, outside the host's `require_auth` framework",
    evSigSimbolos: (lista: string) =>
      `Spec symbols matching the signature-scheme pattern (domain/type hash, nonce, permit, signature): ${lista}.`,
    evSigErros: (lista: string) => `Error enum variants of a signature scheme: ${lista}.`,
    evSigCrypto: (lista: string) => `Entrypoints reach crypto host functions: ${lista}.`,
    evSigSemCrypto: (n: number) =>
      `No crypto host function is reachable from any export; the classification rests on ${n} spec symbol matches.`,
    infSigVerif:
      "Authorization is implemented inside the contract, outside the host's `require_auth` framework; the Spoofing surface (replay, expiry, key rotation) is not covered by the auth detector — review the verifier.",

    /* D7 — TTL */
    tituloTtl: "No entrypoint of the contract extends storage TTL",
    evTtlEscrevem: (n: number, lista: string) =>
      `${n} ${plural(n, "entrypoint reaches", "entrypoints reach")} put_contract_data: ${lista}.`,
    evTtlNenhum: "No entrypoint of the contract reaches the extend_*_ttl family.",
    infTtl:
      "Persistent/instance entries are archived at the end of their TTL and the state becomes inaccessible. This is only acceptable if all storage is temporary by design — which is not derivable from the bytecode, because durability is a runtime argument.",
    infTtlDurabilidade:
      "Declared gap on the impact: it depends on the durability of each entry — a persistent entry archived at the end of its TTL is restorable through the restore footprint of a later transaction, a temporary entry is lost for good, and an instance entry follows the contract instance. Durability is a runtime argument of put_contract_data and is not read from the bytecode here, so the severity is Medium and the gap is declared rather than resolved.",

    /* D-PRNG */
    avisoHelperPrng: (hops: number) =>
      `⚠ REVIEW: the path to the PRNG is ${hops} hops long and probably goes through a shared helper. Reachability over-approximates the positive — the call may sit on a branch this entrypoint never executes. Confirm before treating this as a finding.`,
    infPrng:
      "The Soroban PRNG is deterministic per ledger. If the result decides something of value, whoever picks the submission ledger influences the draw. Legitimate if the use is cosmetic.",
    tituloPrngAgregado: (n: number, nomes: string) =>
      `${n} entrypoints reach the host PRNG (${nomes}) on a path that changes state`,
    evPrngAgregado: (nomes: string, lista: string) =>
      `Reach ${nomes} and also a storage write or a cross-contract call: ${lista}.`,
    evPrngItem: (nome: string, hops: number) => `${nome} (${hops} ${plural(hops, "hop", "hops")})`,
    evPrngDistancia: (menor: number, maior: number) =>
      `Distance from the export to the PRNG: minimum ${menor} ${plural(menor, "hop", "hops")}, maximum ${maior}.`,
    /** Por que sai agregado é decisão de relatório, não fato do bytecode — logo, nível C. */
    notaPrngUmFato: (n: number) =>
      `A single PRNG import reached by ${n} exports is read here as one fact about the contract, not ${n} independent facts — hence it is reported aggregated.`,
    notaPrngAgregado: (n: number) => `aggregated: same PRNG reached by ${n} entrypoints (> 3)`,
    tituloPrng: (nome: string) => `\`${nome}\` uses the host PRNG on a path that changes state`,
    evPrng: (nomes: string, hops: number, escreve: boolean) =>
      `Reaches ${nomes} in ${hops} ${plural(hops, "hop", "hops")} from the export, and also ${escreve ? "a storage write" : "a cross-contract call"}.`,
    notaPrngRebaixado: (hops: number) => `downgraded to Low: ${hops} hops to the PRNG, likely a shared helper`,

    /* D9 — SDK */
    tituloSdkLacuna: (raw: string) =>
      `Declared gap: rssdkver present but not parseable: ${raw} — advisory range not evaluable`,
    evSdkLacuna: (raw: string) =>
      `Custom section \`contractmetav0\` declares rssdkver = ${raw}, which does not match \`major.minor.patch\`. No range comparison was run over that value.`,
    infSdkLacuna: (asOf: string) =>
      `Not evaluable is not "not affected": the binary may have been compiled with an SDK in an affected range. Determining the real version requires the build or the repository. Advisories curated as of ${asOf}.`,
    tituloSdkExposicao: (versao: string, id: string, sev: string) =>
      `Exposure: compiled with soroban-sdk ${versao}, in a range affected by ${id} (${sev} in the advisory; exploitability not confirmed)`,
    evSdkVersao: (versao: string, commit: string) =>
      `Custom section \`contractmetav0\` declares rssdkver = ${versao}${commit ? ` (commit ${commit})` : ""}.`,
    evSdkAdvisory: (id: string, sev: string, titulo: string, patched: string, url: string) =>
      `${id} (${sev} in the advisory): ${titulo}. Fixed in ${patched}. ${url}`,
    evSdkGate: (lista: string) => `The module imports pairing-curve host functions: ${lista}.`,
    infSdkGate:
      "Heuristic filter: the finding is only emitted when there is a BLS12-381/BN254 import. A contract could, in theory, build and compare `Fr` without importing any of those functions — the absence of the finding does not prove the absence of exposure.",
    infSdkExplorabilidade: (trigger: string) =>
      `The exposure is a fact; exploitability has not been confirmed and requires manual review. ${trigger}`,
    infSdkBaseRate:
      "Base rate measured outside the bytecode (not derivable from this binary, hence tier C). Source verification on 2026-09-16: of the 34 corpus contracts in an affected range, 20 verified as not affected, 0 confirmed vulnerable, 14 without source — docs/CVE-2026-26267-VERIFICACAO.md. This finding is EXPOSURE, not a confirmed vulnerability.",
    infSdkAsOf: (asOf: string) =>
      `Advisory list curated as of ${asOf} and not refreshed at runtime — re-check against RustSec/GHSA on the review date.`,
  },
  pt: {
    supReservada: "função reservada `__`, não invocável diretamente (CAP-0058)",
    supLeitura: "nome de leitura: escrita provavelmente vem de helper compartilhado, não deste caminho",
    supCrank: "crank permissionless por desenho (padrão de manutenção de protocolo)",
    supRebaixado:
      "REBAIXADO (não suprimido): alcança call/try_call — autorização pode estar no callee, severidade limitada a High",

    semAlcance: "nenhuma",
    base: (nome: string, reach: string, fanout: number, sound: boolean) =>
      `export \`${nome}\`: host functions alcançáveis = {${reach}}. Subgrafo de ${fanout} funções, call graph ${sound ? "completo" : "INCOMPLETO (call_indirect presente)"}.`,

    tituloInit: (nome: string) => `\`${nome}\` alcança inicialização de estado sem exigir autorização`,
    tituloEscrita: (nome: string) => `\`${nome}\` alcança escrita de estado sem exigir autorização`,
    semAuth: (sound: boolean) =>
      `Nenhum caminho alcança require_auth nem require_auth_for_args${sound ? " — negativa sólida" : " — negativa NÃO sólida por call_indirect"}.`,
    caminhoEscrita: (hops: number) =>
      `Existe caminho até escrita de storage: ${hops} salto(s) do export até put_contract_data/del_contract_data.`,
    avisoHelperEscrita: (hops: number) =>
      `⚠ REVISAR: o caminho até a escrita tem ${hops} saltos e provavelmente passa por helper compartilhado. A alcançabilidade super-aproxima o positivo — a escrita pode estar num ramo que este entrypoint nunca executa. Confirmar antes de tratar como achado.`,
    infInit:
      "O contrato não exporta `__constructor`, então a inicialização é uma transação separada do deploy (CAP-0058). Entre uma e outra, qualquer endereço pode inicializar primeiro e tomar os papéis privilegiados.",
    infInitComConstrutor:
      "O contrato EXPORTA `__constructor`, então o próprio deploy inicializa atomicamente (CAP-0058). Um entrypoint com nome de init mantido ao lado dele é um inicializador de segunda etapa ou um legado mantido por compatibilidade — nas duas leituras o risco é front-running / re-inicialização dessa etapa, não um escritor genérico sem autenticação.",
    evInitGuardFato: (alcanca: boolean) =>
      alcanca
        ? "`has_contract_data` É alcançável a partir deste export."
        : "`has_contract_data` NÃO é alcançável a partir deste export.",
    evInitGuardInferencia: (alcanca: boolean) =>
      alcanca
        ? "Um `has_contract_data` alcançável é, no padrão idiomático, uma guarda de \"já inicializado\". Se a guarda cobre ESTE caminho, e se ela aborta, não decorre da alcançabilidade."
        : "Nenhuma guarda de \"já inicializado\" é visível neste caminho. Que a ausência signifique que não há guarda não decorre do bytecode: ela pode estar atrás de uma chamada cross-contract.",
    regraSeveridadeInit: (guarda: boolean, hops: number, sev: string) =>
      `Regra de severidade aplicada: High só quando a guarda de já-inicializado NÃO é alcançável E o caminho até a escrita tem ≤ 2 saltos; Medium quando a guarda É alcançável ou o caminho é mais longo. Aqui: guarda alcançável = ${guarda ? "sim" : "não"}, ${hops} salto(s) → ${sev}.`,
    infDelega:
      "Nenhum `require_auth` neste módulo. Se a autorização for delegada a um contrato chamado (p.ex. `require_auth(from)` dentro de `token.transfer`), ela é invisível neste binário — confirmar o callee.",
    infQualquer: (nome: string, hops: number, evento: boolean, cross: boolean, upgrade: boolean) => {
      const extra = [
        ...(evento ? ["emite evento"] : []),
        ...(cross ? ["chama outro contrato"] : []),
        ...(upgrade ? ["pode trocar o próprio código"] : []),
      ];
      const cauda = extra.length ? ` e nesse caminho também ${extra.join(", ")}` : "";
      return `Qualquer endereço pode invocar \`${nome}\`; em algum caminho ele alcança escrita de storage (${hops} salto(s))${cauda}. Se esse caminho é o que um chamador anônimo consegue percorrer não é determinável aqui.`;
    },
    notaDelega:
      "severidade limitada a High: alcança call/try_call e a autorização pode estar no contrato chamado",

    tituloUpgrade: (nome: string) => `\`${nome}\` alcança troca de código sem exigir autorização`,
    evUpgrade:
      "Alcança a família de troca do próprio código (update_current_contract_wasm / update_current_contract_executable_ref) sem alcançar require_auth*.",
    infUpgrade: "Permite substituir a lógica do contrato, o que subsume qualquer outra proteção.",

    tituloWba: (nome: string) =>
      `\`${nome}\`: escrita de storage aparece antes de \`require_auth\` na ordem do bytecode do mesmo corpo (ordem textual — ramos não são distinguidos)`,
    evWba: (body: number, writeFn: string, writeOff: number, authFn: string, authOff: number) =>
      `Em fn#${body}: \`${writeFn}\` no offset 0x${writeOff.toString(16)} precede \`${authFn}\` no offset 0x${authOff.toString(16)}. Comparação de offsets de bytecode no mesmo corpo — sem linearização entre funções.`,
    infWba:
      "Que a escrita EXECUTE antes da autorização é inferência, não fato: a comparação é de offsets no corpo, sem modelo de fluxo de controle — as duas chamadas podem estar em ramos mutuamente exclusivos, ou a escrita num ramo nunca tomado. Se a ordem de execução for mesmo essa, o impacto ainda depende de haver efeito externo entre as duas (tipicamente uma chamada cross-contract), porque uma autorização que falha reverte a transação inteira no Soroban. Revisar o corpo indicado.",

    tituloSilent: (mudos: number, total: number) =>
      `${mudos} de ${total} entrypoints que mudam estado não emitem evento`,
    evSilent: (lista: string) => `Alcançam put_contract_data e não alcançam contract_event: ${lista}.`,
    evExcluidosLeitura: (k: number, lista: string) =>
      `${k} entrypoint(s) com nome de leitura que alcançam escrita por helper compartilhado foram excluídos da conta (numerador e denominador): ${lista}. Emitir evento em getter de cotação não é a remediação.`,
    infSilent:
      "Sem evento não há prova off-chain de que a ação ocorreu, e a mudança só é detectável por diff de estado — o que inviabiliza monitoramento em tempo real dessas ações.",
    regraSeveridadeSilent: (sev: string, decisores: string, initOnly: boolean) =>
      `Regra de severidade aplicada (classe da ação silenciosa, não a fração mudos/mutadores): High quando algum entrypoint mudo pode trocar o próprio código ou tem nome de admin/permissão; Low quando todos os entrypoints mudos são one-shots com nome de init; Medium no resto. Aqui: ${
        decisores
          ? `entrypoints decisores = ${decisores}`
          : initOnly
            ? "todos os entrypoints mudos têm nome de init"
            : "nenhum entrypoint mudo troca código nem tem nome de admin/permissão"
      } → ${sev}.`,
    evSilentDecisores: (lista: string) =>
      `Destes, os que trocam o próprio código ou têm nome de admin/permissão (listados primeiro acima): ${lista}.`,

    tituloTampering: (nome: string) =>
      `\`${nome}\` permite que um chamador arbitrário alcance escrita de estado recebendo um endereço como parâmetro`,
    evTamperParams: (nome: string, lista: string) =>
      `O spec \`contractspecv0\` declara ${plural(lista.split(", ").length, "parâmetro de endereço", "parâmetros de endereço")} em \`${nome}\`: ${lista}.`,
    infTamperTaint:
      "A escrita pode tocar apenas o registro do próprio chamador — isso não é determinável aqui, porque exigiria taint do parâmetro até a chave de storage; confirmar no fonte. Se a chave derivar do parâmetro de endereço, qualquer chamador escreve no registro de um terceiro, o que é Tampering e não elevação de privilégio.",

    tituloSigVerif:
      "O contrato implementa verificação de assinatura própria, fora do framework `require_auth` do host",
    evSigSimbolos: (lista: string) =>
      `Símbolos do spec que casam o padrão de esquema de assinatura (domain/type hash, nonce, permit, signature): ${lista}.`,
    evSigErros: (lista: string) => `Variantes do enum de erro típicas de esquema de assinatura: ${lista}.`,
    evSigCrypto: (lista: string) => `Entrypoints alcançam host functions de cripto: ${lista}.`,
    evSigSemCrypto: (n: number) =>
      `Nenhuma host function de cripto é alcançável de algum export; a classificação se apoia em ${n} símbolos do spec.`,
    infSigVerif:
      "A autorização é implementada dentro do contrato, fora do framework `require_auth` do host; a superfície de Spoofing (replay, expiração, rotação de chave) não é coberta pelo detector de auth — revisar o verificador.",

    tituloTtl: "Nenhum entrypoint do contrato estende TTL de storage",
    evTtlEscrevem: (n: number, lista: string) => `${n} entrypoints alcançam put_contract_data: ${lista}.`,
    evTtlNenhum: "Nenhum entrypoint do contrato alcança a família extend_*_ttl.",
    infTtl:
      "Entradas persistentes/instance são arquivadas ao fim do TTL e o estado fica inacessível. Só é aceitável se todo o storage for temporary por design — o que não é determinável do bytecode, porque a durabilidade é argumento em runtime.",
    infTtlDurabilidade:
      "Lacuna declarada sobre o impacto: ele depende da durabilidade de cada entrada — uma entrada persistent arquivada ao fim do TTL é restaurável pelo restore footprint de uma transação posterior, uma entrada temporary é perdida de vez, e uma entrada instance acompanha a instância do contrato. A durabilidade é argumento em runtime de put_contract_data e não é lida do bytecode aqui, por isso a severidade é Medium e a lacuna fica declarada em vez de resolvida.",

    avisoHelperPrng: (hops: number) =>
      `⚠ REVISAR: o caminho até o PRNG tem ${hops} saltos e provavelmente passa por helper compartilhado. A alcançabilidade super-aproxima o positivo — a chamada pode estar num ramo que este entrypoint nunca executa. Confirmar antes de tratar como achado.`,
    infPrng:
      "O PRNG do Soroban é determinístico por ledger. Se o resultado decide algo com valor, quem escolhe o ledger de submissão influencia o sorteio. Legítimo se o uso for cosmético.",
    tituloPrngAgregado: (n: number, nomes: string) =>
      `${n} entrypoints alcançam o PRNG do host (${nomes}) num caminho que muda estado`,
    evPrngAgregado: (nomes: string, lista: string) =>
      `Alcançam ${nomes} e também escrita de storage ou chamada cross-contract: ${lista}.`,
    evPrngItem: (nome: string, hops: number) => `${nome} (${hops} salto(s))`,
    evPrngDistancia: (menor: number, maior: number) =>
      `Distância do export até o PRNG: mínimo ${menor} salto(s), máximo ${maior}.`,
    notaPrngUmFato: (n: number) =>
      `Um único import de PRNG alcançado por ${n} exports é lido aqui como um fato do contrato, não ${n} fatos independentes — por isso sai agregado.`,
    notaPrngAgregado: (n: number) => `agregado: mesmo PRNG alcançado por ${n} entrypoints (> 3)`,
    tituloPrng: (nome: string) => `\`${nome}\` usa o PRNG do host num caminho que muda estado`,
    evPrng: (nomes: string, hops: number, escreve: boolean) =>
      `Alcança ${nomes} em ${hops} salto(s) do export, e também ${escreve ? "escrita de storage" : "chamada cross-contract"}.`,
    notaPrngRebaixado: (hops: number) => `rebaixado a Low: ${hops} saltos até o PRNG, provável helper compartilhado`,

    tituloSdkLacuna: (raw: string) =>
      `Lacuna declarada: rssdkver presente mas não parseável: ${raw} — faixa de advisory não avaliável`,
    evSdkLacuna: (raw: string) =>
      `Custom section \`contractmetav0\` declara rssdkver = ${raw}, que não casa com \`major.minor.patch\`. Nenhuma comparação de faixa foi executada sobre esse valor.`,
    infSdkLacuna: (asOf: string) =>
      `Não avaliável não é "não afetado": o binário pode ter sido compilado com um SDK em faixa afetada. Determinar a versão real exige o build ou o repositório. Advisories curados em ${asOf}.`,
    tituloSdkExposicao: (versao: string, id: string, sev: string) =>
      `Exposição: compilado com soroban-sdk ${versao}, em faixa afetada por ${id} (${sev} no advisory; explorabilidade não confirmada)`,
    evSdkVersao: (versao: string, commit: string) =>
      `Custom section \`contractmetav0\` declara rssdkver = ${versao}${commit ? ` (commit ${commit})` : ""}.`,
    evSdkAdvisory: (id: string, sev: string, titulo: string, patched: string, url: string) =>
      `${id} (${sev} no advisory): ${titulo}. Corrigido em ${patched}. ${url}`,
    evSdkGate: (lista: string) => `O módulo importa host functions de curva de pareamento: ${lista}.`,
    infSdkGate:
      "Filtro heurístico: o achado só é emitido quando há import de BLS12-381/BN254. Um contrato poderia, em teoria, construir e comparar `Fr` sem importar nenhuma dessas funções — a ausência do achado não prova ausência de exposição.",
    infSdkExplorabilidade: (trigger: string) =>
      `A exposição é fato; a explorabilidade não foi confirmada e exige revisão manual. ${trigger}`,
    infSdkBaseRate:
      "Base rate medida fora do bytecode (não derivável deste binário, por isso nível C). Verificação por fonte em 2026-09-16: dos 34 contratos do corpus em faixa afetada, 20 verificados como não afetados, 0 confirmados vulneráveis, 14 sem fonte — docs/CVE-2026-26267-VERIFICACAO.md. Este achado é EXPOSIÇÃO, não vulnerabilidade confirmada.",
    infSdkAsOf: (asOf: string) =>
      `Lista de advisories curada em ${asOf} e não é atualizada em runtime — reconferir contra o RustSec/GHSA na data da revisão.`,
  },
});

/** Letras do STRIDE, como o template oficial da Stellar as nomeia nos IDs. */
export type Stride = "Spoof" | "Tamper" | "Repudiate" | "Info" | "DoS" | "Elevation";

/**
 * Nível de evidência. Ver docs/PROBLEMA.md — a regra que não se quebra é nunca
 * apresentar uma inferência (C) com a mesma força de um fato de bytecode (A).
 */
export type Tier = "A" | "B" | "C";

export type Evidence = { tier: Tier; claim: string };

export type Finding = {
  /** preenchido na numeração final, ex.: "Elevation.1" */
  id?: string;
  stride: Stride;
  class: string;
  entrypoint: string;
  title: string;
  evidence: Evidence[];
  /** inferência — por isso é sempre nível C */
  severity: "Critical" | "High" | "Medium" | "Low";
  /**
   * Família do achado (`init`, `auth`, `silent`, `ttl`, `sdk`, …). Agrupa classes que um
   * renderizador pode agregar quando o mesmo fato se repete. Opcional e aditivo: quem
   * consome `Finding` hoje continua funcionando sem lê-lo.
   */
  family?: string;
  /** false quando `call_indirect` no subgrafo impede afirmar a negativa */
  sound: boolean;
  /**
   * Anotações de calibração — por que a severidade é a que é (rebaixamento, agregação).
   * Campo opcional e aditivo: quem consome `Finding` hoje continua funcionando sem lê-lo.
   */
  notes?: string[];
};

/**
 * Exceções de ciclo de vida do Soroban. Não são "casos que preferimos ignorar":
 * são entrypoints em que a ausência de require_auth é o comportamento correto.
 *  - __constructor: roda uma única vez, na mesma transação do deploy. Quem deploya é
 *    o autorizador por construção; exigir require_auth ali não adiciona garantia.
 *  - __check_auth: é a IMPLEMENTAÇÃO de autorização de uma smart account (CAP-46-6).
 *    Chamar require_auth dentro dela seria circular.
 */
const LIFECYCLE_EXEMPT = new Set(["__constructor", "__check_auth"]);

/**
 * A regra real do host não é uma lista de nomes: é o prefixo. `rs-soroban-env`
 * define RESERVED_CONTRACT_FN_PREFIX = "__" e recusa invocação direta dessas funções
 * (CAP-0058). Usar o prefixo é à prova de futuro e uma linha a menos.
 */
const reservado = (nome: string) => nome.startsWith("__");

/**
 * Duas famílias de falso positivo medidas em 75 contratos de mainnet, responsáveis por
 * ~41% do ruído deste detector. Não são suprimidas em silêncio: entram em `suppressed`
 * e o número aparece no relatório, porque "cobrimos tudo" quando não se cobriu é slop.
 *
 *  - read-shaped: a alcançabilidade atravessa helper de storage compartilhado e faz um
 *    `get_reserves` "alcançar" put_contract_data. Medido: 31,8% do ruído.
 *  - crank permissionless: `sync`, `gulp`, `poke_oracle` e afins são sem permissão
 *    POR DESENHO — é assim que o protocolo é mantido. Medido: 8,9%.
 */
const READ_SHAPED = /^(get|read|query|view|estimate|simulate|preview|calc|quote|peek|fetch|list|total|balance|price|lastprice|decimals|name|symbol|allowance|has|is)(_|$)|_(reserves|virtual_price|price|balance|supply)$/i;

/**
 * O verbo de leitura nem sempre abre o nome: `gauges_get_reward_info` é leitura com o
 * domínio na frente, e era o 3º falso positivo mais frequente da triagem de calibração.
 * O infixo só vale quando o nome NÃO começa por verbo de escrita — senão `set_get_price`
 * ou `update_view_config` sumiriam, e suprimir uma escrita real é pior que um FP.
 */
const READ_SHAPED_INFIX = /_(get|read|query|view|estimate|simulate|preview|calc|quote|peek|fetch|list)(_|$)/i;
const WRITE_VERB = /^(set|put|add|remove|del|delete|update|upsert|write|store|save|mint|burn|transfer|send|deposit|withdraw|swap|init|initialize|create|new|claim|submit|upgrade|migrate|register|approve|revoke|lock|unlock|stake|unstake|vote|fill|settle|close|open|cancel|execute|apply|commit|finalize|distribute|rebalance|repay|borrow|liquidate|flash|reset|rotate|grant|renounce|pause|unpause)(_|$)/i;

const readShaped = (nome: string) =>
  READ_SHAPED.test(nome) || (!WRITE_VERB.test(nome) && READ_SHAPED_INFIX.test(nome));
const CRANK = /^(sync|gulp|poke|observe|crank|tick|harvest|accrue|refresh|backfill|snapshot|update_interest|bad_debt|new_auction)(_|$)/i;

/** Convenção pré-__constructor: inicialização separada do deploy, logo front-runnable. */
const INIT_LIKE = /^(initialize|init|setup|bootstrap)(_|$)/i;

/**
 * Ação privilegiada por nome: troca de dono, de permissão, de código, de taxa ou de config.
 * Existe para a severidade de `silent-mutation` sair da CLASSE da ação e não da fração
 * mudos/mutadores — a inversão medida em docs/PRECISION-TOP25.md ("2 de 2" num bot anônimo
 * saía High; um `upgrade` sem evento num fundo regulado saía Medium).
 */
const ADMIN_SHAPED =
  /^(set_admin|transfer_admin|propose_admin|accept_admin|set_owner|transfer_ownership|upgrade|set_permission|grant|revoke|set_.*role|add_signer|remove_signer|update_signer|pause|unpause|kill|set_fee|set_.*config)(_|$)/i;

/**
 * Símbolos do spec que delatam um verificador de assinatura escrito no contrato.
 * `permit` exige início de palavra: sem isso `NotPermitted` — erro de autorização comum,
 * medido no corpus — casava e virava achado de esquema de assinatura que não existe.
 */
const SIG_SYMBOL = /domain_?hash|type_?hash|nonce|(?<![A-Za-z])permit|verify_?sig|signature/i;
/** Variantes de erro do mesmo esquema — replay, expiração, assinatura inválida. */
const SIG_ERR = /InvalidSignature|SignatureExpired|BadSignature|InvalidNonce|NonceUsed/i;

/* ------------------------------------------------------------------ *
 * Leitura do spec (`contractspecv0`).
 *
 * Dois detectores precisam do que só o spec diz: quais parâmetros são `Address` (D10) e
 * quais símbolos o contrato exporta (D11). A leitura é read-only e tolerante — spec ausente
 * ou ilegível desliga os dois detectores em vez de derrubar a análise, porque o resto do
 * laudo é fato de bytecode e não depende dela.
 * ------------------------------------------------------------------ */

type SpecInfo = {
  /** export → nomes dos parâmetros do tipo `address` declarados no spec */
  addressParams: Map<string, string[]>;
  /** nomes de funções, UDTs, campos/casos e enums de erro */
  symbols: string[];
  /** variantes do enum de erro, separadas porque casam um padrão próprio */
  errCases: string[];
};

/** `decodeStream(..., "raw")` devolve objeto plano; a API de união devolve métodos. Lemos os dois. */
const chamar = (o: any, k: string): any => (typeof o?.[k] === "function" ? o[k]() : o?.[k]);
const nomeDe = (v: any): string => {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v)) return v.toString();
  if (v.bytes) return Buffer.from(v.bytes).toString();
  if (typeof v.name === "string") return v.name;
  return String(v);
};

/** Nomes de UDT (struct/union/enum) e de seus campos/casos — `modelFromEntries` só devolve fns e erros. */
function nomesDeUdt(entries: unknown[]): string[] {
  const out: string[] = [];
  for (const e of entries as any[]) {
    const bruto = typeof e?.switch === "function" ? e.switch() : (e?.type ?? e?.kind);
    const kind = String(typeof bruto === "string" ? bruto : (bruto?.name ?? bruto));
    // Enums de erro já vêm por `modelFromEntries`; incluí-los aqui contava o mesmo nome
    // duas vezes e inflava a contagem de "casamento forte" (≥2) com um único símbolo.
    if (!/^scSpecEntryUdt/.test(kind) || /UdtErrorEnum/.test(kind)) continue;
    const payload = chamar(e, kind.replace(/^scSpecEntry/, "").replace(/^./, (c) => c.toLowerCase()));
    const n = nomeDe(chamar(payload, "name"));
    if (n) out.push(n);
    for (const campo of (chamar(payload, "fields") ?? chamar(payload, "cases") ?? []) as any[]) {
      const cn = nomeDe(chamar(campo, "name"));
      if (cn) out.push(cn);
    }
  }
  return out;
}

export function lerSpec(wasm: Uint8Array): SpecInfo | undefined {
  try {
    const entries = parseSpecEntries(wasm);
    if (!entries.length) return undefined;
    const { fns, errors } = modelFromEntries(entries);
    const addressParams = new Map<string, string[]>();
    for (const f of fns) {
      const addrs = f.params.filter((p) => p.type === "address").map((p) => p.name);
      if (addrs.length) addressParams.set(f.name, addrs);
    }
    return {
      addressParams,
      symbols: [...fns.map((f) => f.name), ...errors.map((e) => e.name), ...nomesDeUdt(entries)].filter(Boolean),
      errCases: errors.flatMap((e) => e.cases.map((c) => c.name)).filter(Boolean),
    };
  } catch {
    // spec ausente, truncado ou de uma versão de XDR que este SDK não decodifica:
    // os dois detectores que dependem dela não disparam, e nada mais muda.
    return undefined;
  }
}

/**
 * A guarda de "já inicializado" idiomática é um `has_contract_data` na chave de admin/config.
 * Alcançabilidade dela é fato de bytecode (nível A); que ela cubra ESTE caminho é inferência.
 * O nome sai do catálogo para estourar no load se o upstream renomear — um literal errado
 * viraria "NÃO alcançável" silencioso, que é falso positivo apresentado como fato.
 */
const HAS_DATA_FN = "has_contract_data";
if (!STORAGE_READ_FNS.has(HAS_DATA_FN)) throw new Error(`detect: ${HAS_DATA_FN} ausente do catálogo de host functions`);

/**
 * Um entrypoint que "muda estado" para efeito de contagem. Nome de leitura fica de fora:
 * a escrita desses vem de um helper de cache compartilhado, é o mesmo conjunto que o detector
 * de auth já suprime como READ_SHAPED, e contá-los produzia remediação absurda ("emita evento
 * no seu getter de cotação"). A exclusão é declarada na evidência, nunca silenciosa.
 */
const mutadorContavel = (e: Entrypoint) => !reservado(e.name) && writesStorage(e) && !readShaped(e.name);
const excluidoLeitura = (e: Entrypoint) => !reservado(e.name) && writesStorage(e) && readShaped(e.name);

export type DetectResult = { findings: Finding[]; suppressed: { entrypoint: string; motivo: string }[] };

export function detect(an: ModuleAnalysis, wasm?: Uint8Array): Finding[] {
  return detectFull(an, wasm).findings;
}

export function detectFull(an: ModuleAnalysis, wasm?: Uint8Array): DetectResult {
  const out: Finding[] = [];
  // CAP-0058: com __constructor o contrato é inicializado atomicamente no deploy.
  // Sem ele, a inicialização é uma transação separada — e aí sim é front-runnable.
  const temConstrutor = an.entrypoints.some((e) => e.name === "__constructor");
  const spec = wasm ? lerSpec(wasm) : undefined;
  const suppressed: { entrypoint: string; motivo: string }[] = [];
  const push = (f: Finding) => out.push(f);

  for (const ep of an.entrypoints) {
    // Funções reservadas não são invocáveis diretamente: o host recusa (CAP-0058).
    if (reservado(ep.name)) { suppressed.push({ entrypoint: ep.name, motivo: M.supReservada }); continue; }
    if (writesStorage(ep) && !requiresAuth(ep) && readShaped(ep.name)) {
      suppressed.push({ entrypoint: ep.name, motivo: M.supLeitura });
      continue;
    }
    if (writesStorage(ep) && !requiresAuth(ep) && CRANK.test(ep.name)) {
      suppressed.push({ entrypoint: ep.name, motivo: M.supCrank });
      continue;
    }
    const sound = ep.callGraphComplete;
    const reach = [...ep.reaches].sort().join(", ") || M.semAlcance;
    // Quantos saltos até a escrita MAIS PRÓXIMA. Caminho longo = provavelmente helper
    // compartilhado, e a escrita pode estar num ramo que este entrypoint nunca toma.
    // Antes pegava a primeira função de escrita na ordem do Set, que é ordem de catálogo e
    // não de distância: um `del_contract_data` a 5 saltos escondia um `put_contract_data` a 1.
    const hops = minHops(ep, STORAGE_WRITE_FNS) ?? 0;
    const viaHelper = hops > 2;

    const base = (): Evidence => ({ tier: "A", claim: M.base(ep.name, reach, ep.fanout, sound) });

    // D1/D2 — mutação de estado sem autorização
    if (writesStorage(ep) && !requiresAuth(ep)) {
      // Nome de init é SEMPRE front-running/re-inicialização, com ou sem `__constructor`.
      // Antes exigia `!temConstrutor`, e um contrato que exporta os dois caía no detector
      // genérico: o mesmo padrão saía Critical `unauthenticated-state-mutation` num contrato
      // e Medium `initialization-front-running` no outro. A presença do construtor não muda
      // a CLASSE do risco — muda a leitura (segunda etapa ou legado), e isso é nota de nível C.
      const isInit = INIT_LIKE.test(ep.name);
      // Fronteira de confiança: se o entrypoint chama outro contrato, a autorização pode
      // estar DO OUTRO LADO da chamada (`require_auth(from)` dentro de `token.transfer`) e
      // não aparece neste binário. Não é motivo para suprimir — `swap` permissionless num
      // par V2 é correto por desenho e continua declarado —, é motivo para não afirmar
      // Critical sobre o que este módulo não mostra.
      const delega = callsOut(ep);
      // Guarda de "já inicializado" alcançável muda a severidade, não a classe: o achado
      // continua sendo front-running/re-inicialização, mas a janela de tomada de controle
      // provavelmente já está fechada. High só sobra quando NÃO há guarda visível E o caminho
      // até a escrita é curto (≤2 saltos); com guarda, ou com caminho longo, é Medium.
      const guardaInit = ep.reaches.has(HAS_DATA_FN);
      const sevInit: Finding["severity"] = !guardaInit && hops <= 2 ? "High" : "Medium";
      // D10 — escrita de terceiro. O entrypoint é invocável por qualquer endereço, recebe um
      // `Address` no spec e alcança escrita: é a forma "chamador arbitrário escreve no registro
      // de outro". Quando vale, ele SUBSTITUI o achado de Elevation em vez de somar — é o mesmo
      // fato, e a letra certa é Tamper (docs/PRECISION-TOP25.md, recall #2). As supressões
      // (reservada / read-shaped / crank) já rodaram acima e continuam valendo.
      const addrParams = spec?.addressParams.get(ep.name) ?? [];
      const isTampering = !isInit && addrParams.length > 0;
      if (delega && !isInit && !isTampering) {
        // `<downgraded:…>` é marcador de dado, não texto: idêntico nos dois idiomas.
        suppressed.push({ entrypoint: `<downgraded:${ep.name}>`, motivo: M.supRebaixado });
      }
      push({
        stride: isTampering ? "Tamper" : "Elevation",
        class: isInit
          ? "initialization-front-running"
          : isTampering
            ? "third-party-state-tampering"
            : "unauthenticated-state-mutation",
        entrypoint: ep.name,
        family: isInit ? "init" : "auth",
        title: isInit ? M.tituloInit(ep.name) : isTampering ? M.tituloTampering(ep.name) : M.tituloEscrita(ep.name),
        evidence: [
          base(),
          { tier: "A", claim: M.semAuth(sound) },
          { tier: "A", claim: M.caminhoEscrita(hops) },
          ...(isTampering ? [{ tier: "A" as const, claim: M.evTamperParams(ep.name, addrParams.join(", ")) }] : []),
          ...(isTampering ? [{ tier: "C" as const, claim: M.infTamperTaint }] : []),
          ...(isInit
            ? [
                { tier: "A" as const, claim: M.evInitGuardFato(guardaInit) },
                { tier: "C" as const, claim: M.evInitGuardInferencia(guardaInit) },
                { tier: "C" as const, claim: M.regraSeveridadeInit(guardaInit, hops, sevInit) },
              ]
            : []),
          ...(viaHelper ? [{ tier: "C" as const, claim: M.avisoHelperEscrita(hops) }] : []),
          isInit
            ? { tier: "C", claim: temConstrutor ? M.infInitComConstrutor : M.infInit }
            : delega
              ? { tier: "C", claim: M.infDelega }
              : { tier: "C", claim: M.infQualquer(ep.name, hops, emitsEvent(ep), callsOut(ep), canUpgradeSelf(ep)) },
        ],
        // Init nunca é Critical: o risco depende de o deploy e a inicialização não serem
        // atômicos, o que este binário não mostra. E High exige as DUAS condições —
        // sem guarda visível e caminho direto (≤2 saltos). Ver `sevInit`.
        severity: isInit ? sevInit : isTampering ? "Medium" : viaHelper ? "Medium" : delega ? "High" : "Critical",
        sound,
        ...(delega && !isInit && !isTampering ? { notes: [M.notaDelega] } : {}),
      });
    }

    // D3 — troca do próprio código sem autorização
    if (canUpgradeSelf(ep) && !requiresAuth(ep)) {
      push({
        stride: "Elevation",
        class: "unguarded-upgrade",
        entrypoint: ep.name,
        family: "upgrade",
        title: M.tituloUpgrade(ep.name),
        evidence: [
          base(),
          { tier: "A", claim: M.evUpgrade },
          { tier: "C", claim: M.infUpgrade },
        ],
        severity: "Critical",
        sound,
      });
    }

    // D8 — escrita antes da autorização, dentro do mesmo corpo
    const ordem = an.writeBeforeAuth.get(ep.name);
    if (ordem?.length) {
      const o = ordem[0];
      push({
        stride: "Tamper",
        class: "write-before-auth",
        entrypoint: ep.name,
        family: "order",
        title: M.tituloWba(ep.name),
        evidence: [
          base(),
          { tier: "A", claim: M.evWba(o.bodyFuncIdx, o.writeFn, o.writeOffset, o.authFn, o.authOffset) },
          { tier: "C", claim: M.infWba },
        ],
        severity: "Low",
        sound,
      });
    }

  }

  // D6 (escopo de contrato) — trilha de auditoria ausente.
  // Por entrypoint isso gerava 114 achados num corpus de 20 contratos e soterrava o que importa.
  // Uma linha agregada preserva o sinal de Repúdio sem virar parede de ruído.
  const excluidos = an.entrypoints.filter(excluidoLeitura);
  const notaExclusao: Evidence[] = excluidos.length
    ? [{ tier: "C", claim: M.evExcluidosLeitura(excluidos.length, excluidos.map((e) => e.name).join(", ")) }]
    : [];
  const mudos = an.entrypoints.filter((e) => mutadorContavel(e) && !emitsEvent(e));
  const mutadores = an.entrypoints.filter(mutadorContavel);
  if (mudos.length) {
    /*
     * Severidade pela CLASSE da ação silenciosa, não pela fração mudos/mutadores.
     * A fração media quanta da superfície é silenciosa; o que importa é O QUE é silencioso.
     * Medido em docs/PRECISION-TOP25.md: `2 de 2` num bot privado saía High enquanto um
     * `upgrade` sem evento num fundo tokenizado regulado e um `propose_admin` sem evento
     * num pool de crédito grande saíam Medium. Os 21 achados dessa classe na amostra eram
     * todos verdadeiros — só a ordem estava invertida.
     */
    const decisores = mudos.filter((e) => canUpgradeSelf(e) || ADMIN_SHAPED.test(e.name));
    const soInit = mudos.every((e) => INIT_LIKE.test(e.name));
    const sevSilent: Finding["severity"] = decisores.length ? "High" : soInit ? "Low" : "Medium";
    // Os decisores saem PRIMEIRO na lista A: é o que o revisor precisa ver antes da cauda.
    const ordenados = [...decisores, ...mudos.filter((e) => !decisores.includes(e))];
    push({
      stride: "Repudiate",
      class: "silent-mutation",
      entrypoint: "<contrato>",
      family: "silent",
      title: M.tituloSilent(mudos.length, mutadores.length),
      evidence: [
        { tier: "A", claim: M.evSilent(ordenados.map((e) => e.name).join(", ")) },
        ...(decisores.length
          ? [{ tier: "A" as const, claim: M.evSilentDecisores(decisores.map((e) => e.name).join(", ")) }]
          : []),
        ...notaExclusao,
        {
          tier: "C",
          claim: M.regraSeveridadeSilent(sevSilent, decisores.map((e) => e.name).join(", "), soInit),
        },
        { tier: "C", claim: M.infSilent },
      ],
      severity: sevSilent,
      sound: an.soundness === "sound",
    });
  }

  // D7 (escopo de contrato) — nenhum entrypoint do contrato renova TTL.
  // Avaliar por entrypoint produzia ruído: basta UM caminho renovar para o estado sobreviver.
  const escrevem = an.entrypoints.filter(mutadorContavel);
  const renova = an.entrypoints.some((e) => extendsTtl(e));
  if (escrevem.length && !renova) {
    push({
      stride: "DoS",
      class: "archival-risk",
      entrypoint: "<contrato>",
      family: "ttl",
      title: M.tituloTtl,
      evidence: [
        { tier: "A", claim: M.evTtlEscrevem(escrevem.length, escrevem.map((e) => e.name).join(", ")) },
        ...notaExclusao,
        { tier: "A", claim: M.evTtlNenhum },
        { tier: "C", claim: M.infTtl },
        // O impacto depende da durabilidade, e a durabilidade NÃO é lida aqui — por isso
        // Medium com a lacuna declarada, e não High por ausência (docs/PRECISION-TOP25.md).
        { tier: "C", claim: M.infTtlDurabilidade },
      ],
      severity: "Medium",
      sound: an.soundness === "sound",
    });
  }

  // D-PRNG — aleatoriedade do host num caminho que escreve ou chama para fora.
  // O PRNG do Soroban é semeado por ledger e previsível dentro dele; usá-lo para
  // decidir algo com valor é manipulável por quem escolhe quando submeter.
  //
  // Duas correções de calibração aqui:
  //  1. o mesmo tratamento de saltos/helper de D1/D2 — um `prng_bytes_new` a 6 saltos
  //     quase sempre vem de um helper compartilhado (RNG de um `Vec`, um UUID de log),
  //     e afirmar Tamper sem dizer isso é apresentar aproximação como fato;
  //  2. agregação por fan-out. Num contrato do corpus o mesmo import de PRNG saía como
  //     9 achados literalmente idênticos, um por entrypoint. É UM fato do contrato, como
  //     `silent-mutation` já é — repeti-lo 9× não adiciona informação, só parede de ruído.
  type PrngCand = { ep: Entrypoint; hops: number; viaHelper: boolean };
  const porPrng = new Map<string, PrngCand[]>();
  for (const ep of an.entrypoints) {
    if (reservado(ep.name)) continue;
    const prng = [...PRNG_FNS].filter((n) => ep.reaches.has(n)).sort();
    if (!prng.length) continue;
    // Mesma exclusão de nome de leitura: um `quote_*` que "escreve" por helper de cache não é
    // um caminho de valor. Quando o entrypoint cruza para outro contrato, ele continua candidato.
    if (!mutadorContavel(ep) && !callsOut(ep)) continue;
    const hops = minHops(ep, PRNG_FNS) ?? 0;
    const k = prng.join(", ");
    const lista = porPrng.get(k) ?? [];
    lista.push({ ep, hops, viaHelper: hops > 2 });
    porPrng.set(k, lista);
  }

  for (const [prngNomes, cands] of porPrng) {
    if (cands.length > 3) {
      // fan-out alto: um achado de contrato, com os entrypoints listados na evidência.
      const menor = Math.min(...cands.map((c) => c.hops));
      const maior = Math.max(...cands.map((c) => c.hops));
      const todosHelper = cands.every((c) => c.viaHelper);
      push({
        stride: "Tamper",
        class: "host-prng-in-value-path",
        entrypoint: "<contrato>",
        family: "prng",
        title: M.tituloPrngAgregado(cands.length, prngNomes),
        evidence: [
          { tier: "A", claim: M.evPrngAgregado(prngNomes, cands.map((c) => M.evPrngItem(c.ep.name, c.hops)).join(", ")) },
          { tier: "A", claim: M.evPrngDistancia(menor, maior) },
          { tier: "C", claim: M.notaPrngUmFato(cands.length) },
          ...(todosHelper ? [{ tier: "C" as const, claim: M.avisoHelperPrng(menor) }] : []),
          { tier: "C", claim: M.infPrng },
        ],
        severity: todosHelper ? "Low" : "Medium",
        sound: cands.every((c) => c.ep.callGraphComplete),
        notes: [M.notaPrngAgregado(cands.length)],
      });
      continue;
    }
    for (const { ep, hops, viaHelper } of cands) {
      push({
        stride: "Tamper",
        class: "host-prng-in-value-path",
        entrypoint: ep.name,
        family: "prng",
        title: M.tituloPrng(ep.name),
        evidence: [
          { tier: "A", claim: M.evPrng(prngNomes, hops, writesStorage(ep)) },
          ...(viaHelper ? [{ tier: "C" as const, claim: M.avisoHelperPrng(hops) }] : []),
          { tier: "C", claim: M.infPrng },
        ],
        severity: viaHelper ? "Low" : "Medium",
        sound: ep.callGraphComplete,
        ...(viaHelper ? { notes: [M.notaPrngRebaixado(hops)] } : {}),
      });
    }
  }

  // D11 — verificação de assinatura implementada dentro do contrato.
  //
  // O detector de auth só sabe procurar `require_auth`. Um contrato que verifica assinatura
  // por conta própria (permit estilo EIP-712, smart account, oráculo com publisher key) tem
  // TODA a superfície de Spoofing — replay, expiração, rotação de chave — num lugar onde esse
  // detector nunca olha, e por isso a letra S saía declarada como lacuna num contrato cujo
  // spec inteiro é um esquema de assinatura (docs/PRECISION-TOP25.md, recall #3).
  //
  // O gatilho é barato e declarado: símbolos do spec (nível A, o spec está no binário) mais
  // alcançabilidade de host function de cripto (nível A). O que NÃO se afirma é que o
  // verificador está errado — isso é revisão humana, e é exatamente o que a linha C pede.
  if (spec) {
    const simbolos = [...new Set(spec.symbols.filter((s) => SIG_SYMBOL.test(s)))].sort();
    const erros = [...new Set(spec.errCases.filter((c) => SIG_SYMBOL.test(c) || SIG_ERR.test(c)))].sort();
    const cripto = [
      ...new Set(an.entrypoints.flatMap((e) => [...SIG_SCHEME_FNS].filter((n) => e.reaches.has(n)))),
    ].sort();
    // Contagem por NOME distinto: o mesmo símbolo aparecendo no enum e na lista de casos
    // não são dois indícios.
    const hits = new Set([...simbolos, ...erros]).size;
    // Forte = ≥2 casamentos. Um único `nonce` num token não basta para afirmar esquema próprio.
    if (hits > 0 && (cripto.length > 0 || hits >= 2)) {
      push({
        stride: "Spoof",
        class: "self-implemented-signature-verification",
        entrypoint: "<contrato>",
        family: "sig",
        title: M.tituloSigVerif,
        evidence: [
          ...(simbolos.length ? [{ tier: "A" as const, claim: M.evSigSimbolos(simbolos.join(", ")) }] : []),
          ...(erros.length ? [{ tier: "A" as const, claim: M.evSigErros(erros.join(", ")) }] : []),
          cripto.length
            ? { tier: "A" as const, claim: M.evSigCrypto(cripto.join(", ")) }
            : { tier: "A" as const, claim: M.evSigSemCrypto(hits) },
          { tier: "C" as const, claim: M.infSigVerif },
        ],
        severity: "Medium",
        sound: an.soundness === "sound",
      });
    }
  }

  // D9 — versão do SDK gravada no WASM com advisory conhecido.
  // O fonte mostra se o padrão afetado existe; o que só o artefato mostra é qual SDK compilou
  // o binário que está no ledger. Isto é EXPOSIÇÃO (fato A), não vulnerabilidade confirmada:
  // a explorabilidade é nível C e por isso o achado nunca herda a severidade do advisory —
  // ela fica registrada na evidência A, e o achado sai como Low.
  // Um achado por advisory aplicável; métricas devem contar contratos, não somar achados.
  if (wasm) {
    const sdk = readSdkMeta(wasm);
    // `sdk` inteiro, não só `sdk.version`: só o objeto distingue "não declarou rssdkver"
    // (ausente) de "não conseguimos ler o contractmetav0 até o fim" (não-parseável).
    const ev = evaluateVersion(sdk);
    // `rssdkver` presente mas ilegível é LACUNA, não ausência de exposição. Antes disso o
    // parse frouxo (`Number("main")` → NaN) fazia qualquer string cair dentro de toda faixa
    // e emitia um achado de advisory High sem nenhum fato por trás.
    if (ev.status === "nao-parseavel") {
      push({
        stride: "Elevation",
        class: "sdk-version-unparseable",
        entrypoint: "<contrato>",
        family: "sdk",
        title: M.tituloSdkLacuna(ev.raw),
        evidence: [
          { tier: "A", claim: M.evSdkLacuna(ev.raw) },
          { tier: "C", claim: M.infSdkLacuna(ADVISORIES_AS_OF) },
        ],
        severity: "Low",
        sound: true,
      });
    }
    for (const { advisory: a, gateHits } of advisoriesForWasm(wasm, sdk)) {
      push({
        // O título do advisory é traduzido; o teste de letra STRIDE casa os dois idiomas
        // para não depender de qual está ativo.
        stride: /autoriza|authoriz/i.test(a.title) ? "Elevation" : "Tamper",
        class: "vulnerable-sdk",
        entrypoint: "<contrato>",
        family: "sdk",
        title: M.tituloSdkExposicao(String(sdk.version), a.id, a.severity),
        evidence: [
          { tier: "A", claim: M.evSdkVersao(String(sdk.version), sdk.commit ? sdk.commit.slice(0, 10) : "") },
          { tier: "A", claim: M.evSdkAdvisory(a.id, a.severity, a.title, a.patched.join(" / "), a.url) },
          ...(gateHits.length
            ? [
                { tier: "A" as const, claim: M.evSdkGate(gateHits.join(", ")) },
                { tier: "C" as const, claim: M.infSdkGate },
              ]
            : []),
          { tier: "C", claim: M.infSdkExplorabilidade(a.trigger) },
          { tier: "C", claim: M.infSdkBaseRate },
          { tier: "C", claim: M.infSdkAsOf(ADVISORIES_AS_OF) },
        ],
        severity: "Low",
        sound: true,
      });
    }
  }

  return { findings: numerar(out), suppressed };
}

/** IDs no padrão do template oficial: Spoof.1, Elevation.2, … */
function numerar(fs: Finding[]): Finding[] {
  const n: Record<string, number> = {};
  for (const f of fs) {
    n[f.stride] = (n[f.stride] ?? 0) + 1;
    f.id = `${f.stride}.${n[f.stride]}`;
  }
  return fs;
}

/** Onde a execução sai do contrato. Alimenta as fronteiras do data-flow diagram. */
/**
 * `authorize_as_curr_contract` foi rebaixado de achado para inventário: base rate de 17%
 * no corpus e apenas um achado público conhecido, cujo bug real é a FORMA da árvore de
 * autorização — que o simples import não revela. Reportar como ameaça era ruído.
 */
export function delegacoes(an: ModuleAnalysis): string[] {
  return an.entrypoints.filter((e) => delegatesAuth(e)).map((e) => e.name);
}

export function fronteiras(an: ModuleAnalysis): { entrypoint: string; kind: "cross-call" | "auth-check" }[] {
  const out: { entrypoint: string; kind: "cross-call" | "auth-check" }[] = [];
  for (const ep of an.entrypoints) {
    if (callsOut(ep)) out.push({ entrypoint: ep.name, kind: "cross-call" });
    if (requiresAuth(ep)) out.push({ entrypoint: ep.name, kind: "auth-check" });
  }
  return out;
}

/** Letras sem nenhum achado derivável — declaradas como lacuna, nunca preenchidas com genérico. */
export function lacunas(fs: Finding[]): Stride[] {
  const all: Stride[] = ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"];
  const seen = new Set(fs.map((f) => f.stride));
  return all.filter((s) => !seen.has(s));
}
