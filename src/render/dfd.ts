/**
 * Data-flow diagram da seção "What are we working on?" do template STRIDE oficial.
 *
 * O template pede entidades externas, processos, fluxos, armazenamento e trust boundaries.
 * A tradução para Soroban é DERIVADA da análise de bytecode, nunca desenhada à mão:
 *
 *   processo        = cada entrypoint exportado
 *   entidade externa= quem invoca de fora (+ o destino de `call`/`try_call`, + o consumidor
 *                     off-chain do stream de eventos, que é para onde `contract_event` escoa)
 *   data store      = as chaves de storage inferidas; sem elas, um store declarado como não inferido
 *   trust boundary  = onde `require_auth*` é alcançável e onde a execução sai para outro contrato
 *
 * O ponto do módulo é que o desenho REFLITA a análise: um entrypoint que não alcança
 * `require_auth` fica fora da fronteira autenticada, e é isso que torna o diagrama uma
 * evidência em vez de um enfeite. Nada aqui inventa nó ou aresta para deixar o desenho
 * "completo" — o que a análise não sabe aparece rotulado como não sabido.
 */

import type { ArtifactContext, Dfd, DfdEdge, DfdNode } from "../artifact.ts";
import type { Entrypoint } from "../analyze.ts";
import { emitsEvent, readsStorage, writesStorage, canUpgradeSelf } from "../analyze.ts";
import { fronteiras } from "../detect.ts";
import { AUTH_FNS, CROSS_CALL_FNS, EVENT_FNS, STORAGE_READ_FNS, STORAGE_WRITE_FNS, UPGRADE_FNS } from "../hostfns.ts";
import { msgs } from "../i18n.ts";

/* ------------------------------------------------------------------ *
 * Texto de saída, por idioma. `pt` é o texto que o diagrama já emitia;
 * `en` é o padrão. Ids de nó (`p_`, `s_`, `e_`, `x_`, `tb_`) e o marcador
 * `†` são language-neutral de propósito: outros módulos casam com eles.
 * ------------------------------------------------------------------ */

const M = msgs({
  en: {
    /* marcadores de alcance no rótulo do processo */
    marcaAuth: "require_auth",
    marcaLeitura: "read",
    marcaEscrita: "write",
    marcaEvento: "event",
    marcaCrossCall: "cross-call",
    marcaUpgrade: "self-code upgrade",

    /* motivo real da aproximação */
    razaoIncompleto: (r: string) => `module not read in full (${r})`,
    razaoSubIndireto: "call_indirect in this export's subgraph",
    razaoSubDegradado: "degraded function body in this export's subgraph",
    razaoTodosIndireto: "call_indirect in the subgraph of all these exports",
    razaoTodosDegradado: "degraded function body in the subgraph of all these exports",
    razaoCurtaIndireto: "call_indirect",
    razaoCurtaDegradado: "degraded body",
    razaoCurtaIncompleto: "module not read in full",

    /* avisos no rótulo */
    avisoHelper: "⚠ † = via shared helper, tier C",
    avisoEp: (razao: string) => `⚠ ${razao}: the negative stops being sound`,

    /* corpo do rótulo do processo */
    semNome: (idx: number) => `export with no readable name (funcIdx ${idx})`,
    corpoComMarcas: (nome: string, marcas: string) => `${nome} — reaches (hops to host fn): ${marcas}`,
    corpoSemMarcas: (nome: string, n: number) =>
      `${nome} — reaches ${n} host function(s), none from auth, storage, event, cross-call or upgrade`,
    corpoSemAlcance: (nome: string) => `${nome} — no host function reached`,

    /* entidades externas */
    extAnonimo: "Anonymous invoker — any address",
    extAutorizado: "Authenticated invoker — Address required by require_auth* on at least one reachable path",
    extDeployer: "Deployer — same transaction as the deployment (atomic constructor, CAP-0058)",
    extHost: "Soroban host — invokes the reserved entrypoints (__ prefix, CAP-0058)",
    extObservador: "Off-chain consumer of the event stream — getEvents",

    /* arestas */
    arDeploy: "deploy — atomic invocation",
    arCheckAuth: "authorization check",
    arReservada: "reserved invocation by the host",
    arComAuth: "invokes — require_auth reachable",
    arSemAuthSolida: "invokes — no authorization check within reach (sound for this call graph)",
    arSemAuthFraca: (razao: string) => `invokes — no authorization check within reach (NOT sound: ${razao})`,
    arChave: (conf: string) => `inferred key — confidence ${conf}`,
    arLeituraEscrita: "reaches read and write",
    arEscrita: "reaches write",
    arLeitura: "reaches read",
    arCrossCall: (fns: string) => `reaches ${fns}`,
    arEvento: "reaches contract_event",

    /* data stores */
    storeComChaves: "Contract storage",
    storeSemChaves: "Contract storage — keys not inferred",
    chave: (k: string, certa: boolean) => `${k} (${certa ? "certain" : "likely"})`,

    /* outro contrato */
    outroContrato: "Another contract — address resolved at runtime, not determinable from the bytecode",

    /* fronteiras */
    tbExterno: "Outside the contract — untrusted actors",
    tbAuth: "require_auth* reachable on some path — access control (admin-shaped) and self-authorization (caller authorizing its own address) are both inside; the name-shape split is in the threat model's Spoofing gap",
    tbAberto: (forca: string) => `No authorization boundary — no path reaches require_auth* in this module (${forca})`,
    forcaSolida: "sound for this call graph",
    forcaNaoSolida: (razao: string) => `NOT sound: ${razao}`,
    forcaParcial: (n: number, total: number) =>
      `sound for this call graph, except in the ${n} of ${total} nodes flagged as incomplete`,
    tbCiclo: "Lifecycle — invoked by the deployment or by the host, not by an arbitrary caller",
    tbCrossCall: "Third-party code — reached through call/try_call",

    /* lacuna */
    semSuperficie: "No exported entrypoint in the analyzed WASM — there is no surface to diagram",

    /* cabeçalho do mermaid */
    cabecalho: "%% soroguard — data-flow diagram derived from the deployed WASM",
    procedencia: (id: string, rede: string, data: string) =>
      `%% contract ${id} · network ${rede} · generated at ${data}`,
    callGraphCompleto: (n: number) => `%% call graph: complete across ${n} entrypoint(s)`,
    callGraphIncompleto: (razao: string, n: number, total: number) =>
      `%% call graph: INCOMPLETE (${razao}) in ${n} of ${total} entrypoint(s) — only in those does the negative stop being sound`,
    legendaSaltos: "%% legend: reaches X n = there is a path of n hop(s) from the export to host function X.",
    legendaDaga: (limiar: number) =>
      `%% † = path longer than ${limiar} hops. The positive is over-approximate (tier C): it probably goes` +
      ` through a shared helper and the host function may sit on a branch this entrypoint never executes.` +
      ` Confirm before treating it as a finding. Same threshold and same hop count as detect.ts.`,
  },
  pt: {
    marcaAuth: "require_auth",
    marcaLeitura: "leitura",
    marcaEscrita: "escrita",
    marcaEvento: "evento",
    marcaCrossCall: "cross-call",
    marcaUpgrade: "upgrade do próprio código",

    razaoIncompleto: (r: string) => `módulo não lido por inteiro (${r})`,
    razaoSubIndireto: "call_indirect no subgrafo deste export",
    razaoSubDegradado: "corpo de função degradado no subgrafo deste export",
    razaoTodosIndireto: "call_indirect no subgrafo de todos estes exports",
    razaoTodosDegradado: "corpo de função degradado no subgrafo de todos estes exports",
    razaoCurtaIndireto: "call_indirect",
    razaoCurtaDegradado: "corpo degradado",
    razaoCurtaIncompleto: "módulo não lido por inteiro",

    avisoHelper: "⚠ † = via helper compartilhado, nível C",
    avisoEp: (razao: string) => `⚠ ${razao}: a negativa deixa de ser sólida`,

    semNome: (idx: number) => `export sem nome legível (funcIdx ${idx})`,
    corpoComMarcas: (nome: string, marcas: string) => `${nome} — alcança (saltos até a host fn): ${marcas}`,
    corpoSemMarcas: (nome: string, n: number) =>
      `${nome} — alcança ${n} host function(s), nenhuma de auth, storage, evento, cross-call ou upgrade`,
    corpoSemAlcance: (nome: string) => `${nome} — nenhuma host function alcançada`,

    extAnonimo: "Invocador anônimo — qualquer endereço",
    extAutorizado: "Invocador autenticado — Address exigido por require_auth* em pelo menos um caminho alcançável",
    extDeployer: "Deployer — mesma transação do deploy (constructor atômico, CAP-0058)",
    extHost: "Host Soroban — invoca os entrypoints reservados (prefixo __, CAP-0058)",
    extObservador: "Consumidor off-chain do stream de eventos — getEvents",

    arDeploy: "deploy — invocação atômica",
    arCheckAuth: "verificação de autorização",
    arReservada: "invocação reservada pelo host",
    arComAuth: "invoca — require_auth alcançável",
    arSemAuthSolida: "invoca — nenhuma checagem de autorização no alcance (sólida para este call graph)",
    arSemAuthFraca: (razao: string) => `invoca — nenhuma checagem de autorização no alcance (NÃO sólida: ${razao})`,
    arChave: (conf: string) => `chave inferida — confiança ${conf}`,
    arLeituraEscrita: "alcança leitura e escrita",
    arEscrita: "alcança escrita",
    arLeitura: "alcança leitura",
    arCrossCall: (fns: string) => `alcança ${fns}`,
    arEvento: "alcança contract_event",

    storeComChaves: "Storage do contrato",
    storeSemChaves: "Storage do contrato — chaves não inferidas",
    chave: (k: string, certa: boolean) => `${k} (${certa ? "certa" : "provável"})`,

    outroContrato: "Outro contrato — endereço resolvido em runtime, não determinável do bytecode",

    tbExterno: "Fora do contrato — atores não confiáveis",
    tbAuth: "require_auth* alcançável em algum caminho — controle de acesso (forma administrativa) e autoautorização (o chamador autorizando o próprio endereço) estão os dois aqui; a separação por forma do nome está na lacuna de Spoofing do threat model",
    tbAberto: (forca: string) => `Sem fronteira de autorização — nenhum caminho alcança require_auth* neste módulo (${forca})`,
    forcaSolida: "sólida para este call graph",
    forcaNaoSolida: (razao: string) => `NÃO sólida: ${razao}`,
    forcaParcial: (n: number, total: number) =>
      `sólida para este call graph, exceto nos ${n} de ${total} nós marcados como incompletos`,
    tbCiclo: "Ciclo de vida — invocado pelo deploy ou pelo host, não por chamador arbitrário",
    tbCrossCall: "Código de terceiros — alcançado por call/try_call",

    semSuperficie: "Nenhum entrypoint exportado no WASM analisado — não há superfície a diagramar",

    cabecalho: "%% soroguard — data-flow diagram derivado do WASM deployado",
    procedencia: (id: string, rede: string, data: string) =>
      `%% contrato ${id} · rede ${rede} · gerado em ${data}`,
    callGraphCompleto: (n: number) => `%% call graph: completo nos ${n} entrypoint(s)`,
    callGraphIncompleto: (razao: string, n: number, total: number) =>
      `%% call graph: INCOMPLETO (${razao}) em ${n} de ${total} entrypoint(s) — só nesses a negativa deixa de ser sólida`,
    legendaSaltos: "%% legenda: alcança X n = existe caminho de n salto(s) do export até a host function X.",
    legendaDaga: (limiar: number) =>
      `%% † = caminho acima de ${limiar} saltos. A positiva é super-aproximada (nível C): provavelmente passa por` +
      ` helper compartilhado e a host function pode estar num ramo que este entrypoint nunca executa.` +
      ` Confirmar antes de tratar como achado. Mesmo limiar e mesma contagem de saltos de detect.ts.`,
  },
});

/**
 * Motivo REAL da incompletude, no escopo pedido. `callGraphComplete` cai por três causas
 * distintas (`call_indirect`, corpo degradado, módulo não lido por inteiro); dizer sempre
 * "call_indirect" nomearia uma causa que pode não ser a verdadeira.
 */
function razao(ctx: ArtifactContext, escopo: "sub" | "todos" | "curta"): string {
  const an = ctx.analysis;
  if (an.incompleteReason) {
    return escopo === "curta" ? M.razaoCurtaIncompleto : M.razaoIncompleto(an.incompleteReason);
  }
  if (escopo === "curta") return an.hasIndirectAnywhere ? M.razaoCurtaIndireto : M.razaoCurtaDegradado;
  if (escopo === "todos") return an.hasIndirectAnywhere ? M.razaoTodosIndireto : M.razaoTodosDegradado;
  return an.hasIndirectAnywhere ? M.razaoSubIndireto : M.razaoSubDegradado;
}

/**
 * Mesmo critério de `detect.ts`: o host recusa invocação direta de export com prefixo `__`
 * (RESERVED_CONTRACT_FN_PREFIX, CAP-0058). Aqui o efeito é sobre o desenho — esses
 * entrypoints não têm chamador arbitrário (o construtor roda na transação de deploy,
 * `__check_auth` é chamado pelo host durante a verificação). Colocá-los no grupo "sem
 * autorização" desenharia superfície anônima onde não há: é o falso positivo que a
 * calibração removeu da tabela de achados, reintroduzido pela porta do diagrama.
 */
const reservado = (nome: string) => nome.startsWith("__");

/* ------------------------------------------------------------------ *
 * Força da evidência por marcador.
 * ------------------------------------------------------------------ */

/**
 * Acima deste número de saltos a positiva é tratada como provável passagem por helper
 * compartilhado. Mesmo limiar de `detect.ts` (`viaHelper = hops > 2`), pela mesma razão
 * registrada em docs/CALIBRACAO.md: `estimate_swap` alcança `put_contract_data` por um
 * helper cujo ramo de escrita ela nunca executa.
 */
const VIA_HELPER = 2;

/**
 * Saltos do export até a host function, pela MESMA conta que `detect.ts` usa:
 * primeira função do conjunto que for alcançável, `pathTo.length - 1`.
 *
 * A regra é copiada de propósito, incluindo a ordem de varredura do conjunto. Medido no
 * corpus: pegar o caminho mais curto em vez do primeiro muda o número em 77 entrypoints e
 * inverte o veredito de "via helper" em 31 deles. Como o diagrama e a tabela de ameaças
 * saem do mesmo binário no mesmo laudo, divergir aqui faria os dois documentos se
 * contradizerem sobre a força da mesma afirmação.
 */
function saltosAte(ep: Entrypoint, fns: ReadonlySet<string>): number | undefined {
  for (const n of fns) {
    const p = ep.pathTo.get(n);
    if (p) return Math.max(p.length - 1, 0);
  }
  return undefined;
}

/* ------------------------------------------------------------------ *
 * Saneamento para o parser do Mermaid.
 * ------------------------------------------------------------------ */

/**
 * IDs do Mermaid não podem conter o que o parser usa como pontuação, e nomes como `end`,
 * `graph` ou `x` são palavras/operadores reservados em posição de nó. O prefixo por tipo
 * (`p_`, `s_`, `e_`, `x_`) resolve os dois problemas de uma vez, e o contador garante que
 * dois exports diferentes não colapsem no mesmo id depois do saneamento.
 */
function novoId(prefixo: string, bruto: string, usados: Set<string>): string {
  const base = `${prefixo}_${bruto.replace(/[^A-Za-z0-9_]/g, "_").slice(0, 48) || "x"}`;
  let id = base;
  for (let n = 2; usados.has(id); n++) id = `${base}__${n}`;
  usados.add(id);
  return id;
}

/**
 * Rótulos vão sempre entre aspas no Mermaid, o que já cobre espaço, acento e parênteses.
 * Sobram os caracteres que o parser trata mesmo dentro das aspas: `"` fecha a string, `#`
 * abre escape de entidade, `<`/`>` viram HTML, `|` delimita rótulo de aresta e `{}` abre
 * diretiva. Retiramos esses; o resto passa intacto.
 */
function rotulo(s: string): string {
  return s.replace(/["#<>|{}`]/g, "").replace(/\s+/g, " ").trim();
}

/* ------------------------------------------------------------------ *
 * Construção
 * ------------------------------------------------------------------ */

type Grupo = "auth" | "aberto" | "ciclo";

export function buildDfd(ctx: ArtifactContext): Dfd {
  const an = ctx.analysis;

  // As fronteiras vêm de `fronteiras()` e não de uma segunda travessia: duas leituras
  // divergentes do mesmo binário produziriam um diagrama que contradiz a tabela de ameaças.
  const fr = fronteiras(an);
  const comAuth = new Set(fr.filter((f) => f.kind === "auth-check").map((f) => f.entrypoint));
  const comCrossCall = new Set(fr.filter((f) => f.kind === "cross-call").map((f) => f.entrypoint));

  const usados = new Set<string>();
  const nodes: DfdNode[] = [];
  const edges: DfdEdge[] = [];

  // Prioridade: reservado > autenticado > aberto. Um `__constructor` que alcance
  // require_auth continua no grupo de ciclo de vida, mas o marcador `auth` no rótulo
  // preserva o fato — nenhuma informação se perde no agrupamento.
  const grupoDe = (ep: Entrypoint): Grupo =>
    reservado(ep.name) ? "ciclo" : comAuth.has(ep.name) ? "auth" : "aberto";

  /* --- processos: um por entrypoint exportado --- */
  const idPorEntrypoint = new Map<string, string>();
  const porGrupo: Record<Grupo, string[]> = { auth: [], aberto: [], ciclo: [] };

  for (const ep of an.entrypoints) {
    /*
     * Marcadores: alcançabilidade no call graph, nunca leitura do nome. O prefixo "alcança"
     * não é verbosidade — `estimate_swap` alcança put_contract_data por um helper que ela
     * nunca executa (docs/CALIBRACAO.md). Escrever "escreve" no rótulo afirmaria o positivo
     * super-aproximado com a força de um fato, que é o erro que a calibração corrigiu.
     *
     * Só a palavra "alcança", porém, não basta. A correção que a calibração adotou tem três
     * partes, e as três valem aqui: (1) a linguagem muda para "alcança", (2) TODA positiva
     * carrega o número de saltos, (3) caminho acima de `VIA_HELPER` saltos ganha aviso de
     * nível C. Medido neste corpus: 95 dos 125 processos que o diagrama coloca em
     * `tb_aberto` com marcador de escrita têm caminho acima de 2 saltos — a mesma classe que
     * `detect.ts` rebaixa para Medium ou suprime por completo. Sem o peso no rótulo, o
     * diagrama desenha 125 escritores anônimos onde a tabela de ameaças afirma ~27, e o
     * revisor fica com dois documentos do mesmo binário que se contradizem.
     */
    const marcas: string[] = [];
    let viaHelper = false;
    const marcar = (nome: string, ativo: boolean, fns: ReadonlySet<string>) => {
      if (!ativo) return;
      const h = saltosAte(ep, fns);
      if (h === undefined) return; // alcance e caminho vêm da mesma travessia; nunca divergem
      // A marca de helper vai no MARCADOR, não no nó: num mesmo export a escrita pode estar
      // a 4 saltos e o evento a 1, e uma flag única para o nó rebaixaria as duas juntas.
      const longe = h > VIA_HELPER;
      marcas.push(`${nome} ${h}${longe ? "†" : ""}`);
      if (longe) viaHelper = true;
    };
    marcar(M.marcaAuth, comAuth.has(ep.name), AUTH_FNS);
    marcar(M.marcaLeitura, readsStorage(ep), STORAGE_READ_FNS);
    marcar(M.marcaEscrita, writesStorage(ep), STORAGE_WRITE_FNS);
    marcar(M.marcaEvento, emitsEvent(ep), EVENT_FNS);
    marcar(M.marcaCrossCall, comCrossCall.has(ep.name), CROSS_CALL_FNS);
    marcar(M.marcaUpgrade, canUpgradeSelf(ep), UPGRADE_FNS);

    // Avisos que rebaixam a leitura do nó. Ficam no rótulo porque comentário `%%` do Mermaid
    // não é renderizado: quem olha a figura precisa ver a ressalva junto do que ela ressalva.
    const avisos = [
      // Curto de propósito. A frase inteira repetida em 100 nós seria verdadeira para
      // quase todos e não distinguiria nenhum — enchimento com aparência de rigor. O texto
      // completo fica uma vez só, na legenda do cabeçalho.
      viaHelper ? M.avisoHelper : null,
      // Solidez POR ENTRYPOINT, não do módulo. `an.soundness` degrada por um `call_indirect`
      // em qualquer corpo do WASM, inclusive inalcançável: nos 24 módulos aproximados do
      // corpus, 520 dos 553 entrypoints têm call graph completo. `detect.ts` usa
      // `ep.callGraphComplete`; usar o campo do módulo aqui rebaixaria 94% de negativas que
      // a tabela de ameaças afirma como sólidas.
      ep.callGraphComplete ? null : M.avisoEp(razao(ctx, "sub")),
    ].filter(Boolean);

    /*
     * "nenhuma host function alcançada" era falso e conferível: `check_price_data` do
     * oráculo alcança 5 imports (`get_ledger_timestamp`, `obj_to_u64`, …), nenhum deles das
     * seis famílias que o diagrama marca. Afirmar zero alcance é uma negativa de nível A que
     * o primeiro `wasm-objdump` derruba — o rótulo diz o que de fato foi medido.
     */
    /*
     * O saneamento do rótulo pode esvaziar um nome (export `""`, ou só pontuação que o
     * parser do Mermaid não aceita). Um nó sem nome não é rastreável até o export que ele
     * representa, então o índice de função entra no lugar — é o que permite conferir.
     */
    const nome = rotulo(ep.name) || M.semNome(ep.funcIdx);
    const corpo = marcas.length
      ? M.corpoComMarcas(nome, marcas.join(", "))
      : ep.reaches.size
        ? M.corpoSemMarcas(nome, ep.reaches.size)
        : M.corpoSemAlcance(nome);
    const id = novoId("p", ep.name, usados);
    idPorEntrypoint.set(ep.name, id);
    porGrupo[grupoDe(ep)].push(id);
    nodes.push({
      kind: "process",
      id,
      label: rotulo([corpo, ...avisos].join(" ")),
      entrypoint: ep.name,
    });
  }

  /* --- entidades externas: criadas só quando há fluxo que as justifique --- */
  const externos: string[] = [];
  const externo = (chave: string, texto: string): string => {
    const id = novoId("e", chave, usados);
    externos.push(id);
    nodes.push({ kind: "external", id, label: rotulo(texto) });
    return id;
  };

  const abertos = an.entrypoints.filter((e) => grupoDe(e) === "aberto");
  const autenticados = an.entrypoints.filter((e) => grupoDe(e) === "auth");
  const construtor = an.entrypoints.find((e) => e.name === "__constructor");
  const reservadosDoHost = an.entrypoints.filter((e) => reservado(e.name) && e.name !== "__constructor");
  const emitentes = an.entrypoints.filter((e) => emitsEvent(e));

  const idAnon = abertos.length ? externo("anonimo", M.extAnonimo) : undefined;
  // "cuja assinatura é exigida" afirmaria a positiva com força de fato. `require_auth`
  // alcançável não prova que todo caminho do entrypoint passa por ela — só que existe um.
  const idAutor = autenticados.length
    ? externo("autorizado", M.extAutorizado)
    : undefined;
  const idDeploy = construtor
    ? externo("deployer", M.extDeployer)
    : undefined;
  const idHost = reservadosDoHost.length
    ? externo("host", M.extHost)
    : undefined;
  const idObs = emitentes.length
    ? externo("observador", M.extObservador)
    : undefined;

  /*
   * Aresta de invocação: exatamente uma por entrypoint, com o chamador que a análise
   * sustenta. A ordem dos ramos é a mesma de `grupoDe`, senão um entrypoint reservado que
   * alcança require_auth apareceria pendurado no invocador autenticado — chamador que o
   * host não permite.
   */
  for (const ep of an.entrypoints) {
    const destino = idPorEntrypoint.get(ep.name)!;
    if (ep.name === "__constructor" && idDeploy) {
      edges.push({ from: idDeploy, to: destino, label: M.arDeploy, crossesBoundary: true });
    } else if (reservado(ep.name) && idHost) {
      edges.push({
        from: idHost,
        to: destino,
        label: ep.name === "__check_auth" ? M.arCheckAuth : M.arReservada,
        crossesBoundary: true,
      });
    } else if (comAuth.has(ep.name) && idAutor) {
      edges.push({ from: idAutor, to: destino, label: M.arComAuth, crossesBoundary: true });
    } else if (idAnon) {
      // A negativa é o que sustenta esta aresta. Ela só é prova com o call graph completo
      // DESTE export — senão vai rebaixada na própria aresta, não só na fronteira.
      edges.push({
        from: idAnon,
        to: destino,
        label: ep.callGraphComplete ? M.arSemAuthSolida : M.arSemAuthFraca(razao(ctx, "curta")),
        crossesBoundary: true,
      });
    }
  }

  /* --- data stores --- */
  const chaves = ctx.storageKeys ?? [];
  const tocamStorage = an.entrypoints.filter((e) => writesStorage(e) || readsStorage(e));
  let idStore: string | undefined;
  if (tocamStorage.length || chaves.length) {
    idStore = novoId("s", "storage", usados);
    nodes.push({
      kind: "store",
      id: idStore,
      // Sem chaves inferidas o rótulo declara a lacuna em vez de sugerir um store genérico
      // que o leitor tomaria por completo.
      label: rotulo(chaves.length ? M.storeComChaves : M.storeSemChaves),
    });
  }

  /*
   * Cada chave inferida vira um data store, como o template pede. Mas não existe aresta
   * processo → chave: `ArtifactContext.storageKeys` é uma lista plana, sem atribuição por
   * entrypoint. Ligar todo escritor a toda chave afirmaria um acesso que o contexto não
   * sustenta — e é o tipo de aresta que um revisor derruba. As chaves penduram no store;
   * o processo se liga ao storage, que é o que a alcançabilidade de fato prova.
   */
  if (idStore) {
    for (const k of chaves) {
      const id = novoId("s", k.key, usados);
      nodes.push({ kind: "store", id, label: rotulo(M.chave(k.key, k.confidence === "certain")) });
      edges.push({ from: idStore, to: id, label: M.arChave(k.confidence), crossesBoundary: false });
    }
    for (const ep of tocamStorage) {
      const escreve = writesStorage(ep);
      const le = readsStorage(ep);
      edges.push({
        from: idPorEntrypoint.get(ep.name)!,
        to: idStore,
        label: escreve && le ? M.arLeituraEscrita : escreve ? M.arEscrita : M.arLeitura,
        crossesBoundary: false,
      });
    }
  }

  /* --- contrato alcançado por call/try_call --- */
  let idCallee: string | undefined;
  if (comCrossCall.size) {
    idCallee = novoId("x", "callee", usados);
    nodes.push({
      kind: "contract",
      id: idCallee,
      // O contract id do destino é argumento de runtime: afirmar QUAL contrato é chamado
      // seria inferência apresentada como fato de bytecode.
      label: rotulo(M.outroContrato),
    });
    for (const ep of an.entrypoints) {
      if (!comCrossCall.has(ep.name)) continue;
      const quais = [...CROSS_CALL_FNS].filter((n) => ep.reaches.has(n)).sort();
      // "call" seco afirmaria que a chamada acontece. É alcançabilidade, com a mesma
      // super-aproximação das arestas de storage — o rótulo diz "alcança" como as outras.
      edges.push({
        from: idPorEntrypoint.get(ep.name)!,
        to: idCallee,
        label: M.arCrossCall(quais.join(" / ")),
        crossesBoundary: true,
      });
    }
  }

  /* --- fluxo de eventos para fora da cadeia --- */
  if (idObs) {
    for (const ep of emitentes) {
      // Idem: alcançar `contract_event` não prova que o evento sai nesta invocação.
      edges.push({ from: idPorEntrypoint.get(ep.name)!, to: idObs, label: M.arEvento, crossesBoundary: true });
    }
  }

  /* --- fronteiras --- */
  const boundaries: Dfd["boundaries"] = [];
  if (externos.length) {
    boundaries.push({ id: "tb_externo", label: M.tbExterno, contains: externos });
  }
  if (porGrupo.auth.length) {
    boundaries.push({
      id: "tb_auth",
      label: M.tbAuth,
      contains: porGrupo.auth,
    });
  }
  if (porGrupo.aberto.length) {
    // Este grupo é o achado do diagrama: são os processos que a análise NÃO conseguiu
    // colocar atrás de require_auth. Fica como fronteira própria para que a ausência seja
    // visível, em vez de sumir por omissão.
    //
    // A força da negativa é contada sobre os exports DESTE grupo, não sobre o módulo: um
    // `call_indirect` num corpo que nenhum deles alcança não enfraquece nenhuma das
    // negativas aqui dentro, e dizer que enfraquece rebaixaria o que a tabela de ameaças
    // afirma como sólido.
    const incompletos = abertos.filter((e) => !e.callGraphComplete).length;
    const forca = !incompletos
      ? M.forcaSolida
      : incompletos === abertos.length
        ? M.forcaNaoSolida(razao(ctx, "todos"))
        : M.forcaParcial(incompletos, abertos.length);
    boundaries.push({
      id: "tb_aberto",
      label: M.tbAberto(forca),
      contains: porGrupo.aberto,
    });
  }
  if (porGrupo.ciclo.length) {
    boundaries.push({
      id: "tb_ciclo",
      label: M.tbCiclo,
      contains: porGrupo.ciclo,
    });
  }
  if (idCallee) {
    boundaries.push({
      id: "tb_crosscall",
      label: M.tbCrossCall,
      contains: [idCallee],
    });
  }

  /*
   * Módulo sem export analisável (WASM sem entrypoint, ou análise degradada a ponto de não
   * produzir nenhum). O diagrama declara a lacuna em vez de sair vazio: um flowchart em
   * branco é indistinguível de "não desenhamos", e o leitor merece saber qual dos dois é.
   */
  if (!nodes.length) {
    nodes.push({
      kind: "external",
      id: "e_sem_superficie",
      label: rotulo(M.semSuperficie),
    });
  }

  return { nodes, edges, boundaries, mermaid: mermaid(ctx, nodes, edges, boundaries) };
}

/* ------------------------------------------------------------------ *
 * Emissão do Mermaid
 * ------------------------------------------------------------------ */

const forma = (n: DfdNode, texto: string): string => {
  switch (n.kind) {
    case "process": return `${n.id}(["${texto}"])`;      // processo — estádio
    case "store": return `${n.id}[("${texto}")]`;        // data store — cilindro
    case "contract": return `${n.id}[["${texto}"]]`;     // subrotina — outro contrato
    case "external": return `${n.id}["${texto}"]`;       // entidade externa — retângulo
  }
};

function mermaid(ctx: ArtifactContext, nodes: DfdNode[], edges: DfdEdge[], boundaries: Dfd["boundaries"]): string {
  const porId = new Map(nodes.map((n) => [n.id, n]));
  const emSubgrafo = new Set(boundaries.flatMap((b) => b.contains));
  const L: string[] = [];

  // Cabeçalho rastreável. A data vem do contexto — o renderizador não lê relógio, senão
  // dois laudos do mesmo binário sairiam diferentes.
  L.push(M.cabecalho);
  L.push(M.procedencia(rotulo(ctx.contractId), rotulo(ctx.network), rotulo(ctx.generatedAt)));
  // Solidez contada por export, que é a unidade em que a negativa vale ou não vale.
  // `analysis.soundness` é do módulo e degrada por um `call_indirect` em qualquer corpo,
  // inclusive inalcançável — usá-lo aqui rebaixaria negativas que `detect.ts` afirma.
  const eps = ctx.analysis.entrypoints;
  const incompletos = eps.filter((e) => !e.callGraphComplete).length;
  L.push(
    !incompletos
      ? M.callGraphCompleto(eps.length)
      : M.callGraphIncompleto(razao(ctx, "curta"), incompletos, eps.length),
  );
  L.push(M.legendaSaltos);
  L.push(M.legendaDaga(VIA_HELPER));
  L.push("flowchart LR");

  for (const b of boundaries) {
    L.push(`  subgraph ${b.id}["${rotulo(b.label)}"]`);
    for (const id of b.contains) {
      const n = porId.get(id);
      if (n) L.push(`    ${forma(n, n.label)}`);
    }
    L.push("  end");
  }

  // Nós fora de qualquer fronteira (os data stores) ficam no nível de cima.
  for (const n of nodes) if (!emSubgrafo.has(n.id)) L.push(`  ${forma(n, n.label)}`);

  for (const e of edges) {
    if (!porId.has(e.from) || !porId.has(e.to)) continue; // nunca emitir aresta órfã
    // Travessia de fronteira sai pontilhada: é onde o revisor precisa olhar.
    const seta = e.crossesBoundary ? "-.->" : "-->";
    L.push(`  ${e.from} ${seta}|"${rotulo(e.label)}"| ${e.to}`);
  }

  const daClasse = (k: DfdNode["kind"]) => nodes.filter((n) => n.kind === k).map((n) => n.id);
  const estilos: [DfdNode["kind"], string, string][] = [
    ["process", "proc", "fill:#eaf2fb,stroke:#3b6ea5,color:#10243a"],
    ["store", "store", "fill:#fdf3e0,stroke:#b8860b,color:#3a2c10"],
    ["external", "ext", "fill:#f2f2f2,stroke:#7a7a7a,color:#222222"],
    ["contract", "outro", "fill:#fdeaea,stroke:#c05252,color:#3a1010"],
  ];
  for (const [kind, classe, css] of estilos) {
    const ids = daClasse(kind);
    if (!ids.length) continue; // `class` sem membro é erro de sintaxe
    L.push(`  classDef ${classe} ${css}`);
    L.push(`  class ${ids.join(",")} ${classe}`);
  }

  return L.join("\n");
}
