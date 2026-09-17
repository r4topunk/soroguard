#!/usr/bin/env node
import { Command } from "commander";
import { StrKey } from "@stellar/stellar-sdk";
import { mkdirSync, writeFileSync } from "node:fs";
import { modelFromEntries, parseSpecEntries, NETWORKS } from "./spec.ts";
import { analyzeModule, requiresAuth, writesStorage, emitsEvent, canUpgradeSelf, callsOut } from "./analyze.ts";
import { detect, lacunas, fronteiras } from "./detect.ts";
import { buildContext, resolveTarget, isLocalTarget } from "./pipeline.ts";
import { renderThreatModel } from "./render/threatmodel.ts";
import { renderMonitoringPlan } from "./render/monitoring.ts";
import { validateThreatModel, validateMonitoringPlan } from "./validate.ts";
import { setLang, parseLang, msgs, plural } from "./i18n.ts";
import type { ContractModel } from "./model.ts";

/* ------------------------------------------------------------------ *
 * Texto da interface. Tudo o que o usuário lê passa por aqui; nomes de
 * flag, de comando e de rede são identificadores e ficam de fora.
 * ------------------------------------------------------------------ */

const M = msgs({
  en: {
    /** separador de milhar dos tamanhos em bytes */
    locale: "en-US",

    /* ajuda */
    ajudaRpc: (redes: string, padrao: string) =>
      `network or RPC URL (${redes}, or https://…). ` +
      `Default: $SOROGUARD_RPC_URL, otherwise "mainnet" = ${padrao} — public community endpoint, rate limited`,
    descPrograma: "STRIDE threat model and on-chain monitoring plan drafts for Soroban contracts",
    descInspect:
      "Reads the contract spec straight from the WASM (of a deployed contract or a local .wasm) and prints the derived model",
    descAnalyze: "Analyzes the deployed WASM and derives security findings with traceable evidence",
    descArtifact: "Generates the two SCF tranche #2 artifacts: STRIDE threat model and on-chain monitoring plan",
    argTarget: "contract id (C...) or path to a .wasm",
    optJson: "JSON output",
    optMin: "minimum severity: Low|Medium|High|Critical",
    optLang: "output language",
    optDebug: "show the full stack on error",
    optOut: "output directory",
    optOffline: "do not query the network to observe events (no tier-B baseline)",
    optTimeout: "total budget, in seconds, for the on-chain observation phase",
    optDate: "date (UTC) to stamp on the documents (default: today's UTC date)",

    /* erros */
    errSac: "contract is a Stellar Asset Contract (SAC): it has no WASM and no contractspecv0; not supported",
    errEnoent: (p: string) => `file not found: ${p}`,
    errEisdir: (p: string) => `the target is a directory, not a .wasm file: ${p}`,
    errInseguro: "RPC refused for being insecure (http://): use an https:// URL in -n",
    errUrlInvalida: (redes: string) => `invalid RPC URL. Valid values for -n: ${redes}, or a full http(s) URL`,
    errRpcInacessivel: (msg: string) => `RPC unreachable: ${msg}`,
    errContratoAusente: (msg: string) => `contract not found on the selected network: ${msg}`,
    errRedeDesconhecida: (bruto: string, redes: string) =>
      `unknown network: "${bruto}". Valid values: ${redes}, or an http(s) RPC URL.`,
    errIdInvalido: (alvo: string) =>
      `invalid contract id: "${alvo}". Expected a contract StrKey (C… , 56 chars) or the path to a .wasm file.`,
    errTimeout: (v: string) => `--timeout must be a number of seconds > 0 (got: "${v}")`,
    erroPrefixo: (linha: string) => `soroguard: ${linha}`,
    dicaDebug: "  (use --debug to see the stack)",

    /* inspect */
    avisoSemFuncoes:
      "no function in the spec — the contract may be a SAC or may have been compiled without a spec",
    avisoSemEventos:
      "the spec declares no events (#[contractevent] is recent) — the monitoring plan will depend on events observed via getEvents",
    objetoAnalisado: (f: string) => `analyzed object: local file ${f}`,
    linhaWasm: (bytes: string, hash: string) => `wasm ${bytes} bytes${hash ? `  hash ${hash}…` : ""}`,
    superficieMutavel: (mut: number, total: number) => `MUTABLE SURFACE (${mut} of ${total} functions)`,
    tracos: "traits",
    modosDeFalha: "DECLARED FAILURE MODES",
    eventosDeclarados: "EVENTS DECLARED IN THE SPEC",

    /* analyze */
    resumoAnalyze: (eps: number, mut: number, solido: boolean) =>
      `${eps} entrypoints · ${mut} reach mutation · call graph ${solido ? "complete" : "INCOMPLETE (call_indirect — negatives stop being proof)"}`,
    tagAuth: "auth",
    tagEscreve: "writes",
    tagEvento: "event",
    tagUpgrade: "upgrade",
    tagCrossCall: "cross-call",
    cabecalhoEntrypoints: "ENTRYPOINTS",
    cabecalhoAchados: (n: number) => `FINDINGS (${n})`,
    evidenciaRebaixada: "  ⚠ evidence downgraded",
    cabecalhoLacunas: "DECLARED GAPS",
    lacunasSemEvidencia: (letras: string) => `No bytecode evidence for: ${letras}.`,
    lacunasNota1: "The template requires ≥1 issue per STRIDE letter. These need manual review",
    lacunasNota2: "of the off-chain flow — filling them with boilerplate would be worse than declaring the gap.",

    /* artifact */
    resumoArtifact: (ameacas: number, monitores: number, lacunas: number) =>
      `${ameacas} ${plural(ameacas, "threat", "threats")} · ${monitores} ${plural(monitores, "monitor", "monitors")} · ${lacunas} STRIDE ${plural(lacunas, "gap", "gaps")} declared`,
    linhaAnalise: (soundness: string, insuficiente: boolean) =>
      `analysis ${soundness}${insuficiente ? " · observation window insufficient for a baseline" : ""}`,
    obsFalhou: (erro: string) => `⚠ on-chain observation failed: ${erro}`,
    obsFalhouDetalhe: "the documents were written, but without any tier-B baseline.",
    validacao: (rotulo: string, corpo: string) => `VALIDATION — ${rotulo}: ${corpo}`,
    submetivel: "submittable",
    naoSubmetivel: (porque: string) => `NOT submittable${porque}`,
    porqueSemJanela: (blockers: number, semJanela: number, comoResolver: string) =>
      ` — ${blockers} blockers, of which ${semJanela} ${plural(semJanela, "is", "are")} missing observation window (${comoResolver})`,
    resolverOffline: "run without --offline",
    resolverFalhou: "the collection failed; retry",
    resolverJanela: "collect a larger window",
  },
  pt: {
    locale: "pt-BR",

    ajudaRpc: (redes: string, padrao: string) =>
      `rede ou URL de RPC (${redes}, ou https://…). ` +
      `Padrão: $SOROGUARD_RPC_URL, senão "mainnet" = ${padrao} — endpoint público da comunidade, com rate limit`,
    descPrograma: "Rascunhos de threat model (STRIDE) e monitoring plan on-chain para contratos Soroban",
    descInspect:
      "Lê o contract spec direto do WASM (de um contrato deployado ou de um .wasm local) e mostra o modelo derivado",
    descAnalyze: "Analisa o WASM deployado e deriva achados de segurança com evidência rastreável",
    descArtifact: "Gera os dois artefatos do SCF tranche #2: threat model STRIDE e monitoring plan on-chain",
    argTarget: "contract id (C...) ou caminho para um .wasm",
    optJson: "saída em JSON",
    optMin: "severidade mínima: Low|Medium|High|Critical",
    optLang: "idioma da saída",
    optDebug: "mostrar stack completo em caso de erro",
    optOut: "diretório de saída",
    optOffline: "não consultar a rede para observar eventos (sem baseline nível B)",
    optTimeout: "prazo total, em segundos, da fase de observação on-chain",
    optDate: "data (UTC) a estampar nos documentos (default: a data UTC de hoje)",

    errSac: "contrato é um Stellar Asset Contract (SAC): não tem WASM nem contractspecv0; não suportado",
    errEnoent: (p: string) => `arquivo não encontrado: ${p}`,
    errEisdir: (p: string) => `o alvo é um diretório, não um arquivo .wasm: ${p}`,
    errInseguro: "RPC recusado por ser inseguro (http://): use uma URL https:// em -n",
    errUrlInvalida: (redes: string) => `URL de RPC inválida. Valores válidos para -n: ${redes}, ou uma URL http(s) completa`,
    errRpcInacessivel: (msg: string) => `RPC inacessível: ${msg}`,
    errContratoAusente: (msg: string) => `contrato não encontrado na rede escolhida: ${msg}`,
    errRedeDesconhecida: (bruto: string, redes: string) =>
      `rede desconhecida: "${bruto}". Valores válidos: ${redes}, ou uma URL http(s) de RPC.`,
    errIdInvalido: (alvo: string) =>
      `contract id inválido: "${alvo}". Esperado um StrKey de contrato (C… , 56 chars) ou o caminho de um arquivo .wasm.`,
    errTimeout: (v: string) => `--timeout precisa ser um número de segundos > 0 (recebido: "${v}")`,
    erroPrefixo: (linha: string) => `soroguard: ${linha}`,
    dicaDebug: "  (use --debug para ver o stack)",

    avisoSemFuncoes: "nenhuma função no spec — contrato pode ser um SAC ou ter sido compilado sem spec",
    avisoSemEventos:
      "spec não declara eventos (#[contractevent] é recente) — o monitoring plan vai depender de eventos observados via getEvents",
    objetoAnalisado: (f: string) => `objeto analisado: arquivo local ${f}`,
    linhaWasm: (bytes: string, hash: string) => `wasm ${bytes} bytes${hash ? `  hash ${hash}…` : ""}`,
    superficieMutavel: (mut: number, total: number) => `SUPERFÍCIE MUTÁVEL (${mut} de ${total} funções)`,
    tracos: "traços",
    modosDeFalha: "MODOS DE FALHA DECLARADOS",
    eventosDeclarados: "EVENTOS DECLARADOS NO SPEC",

    resumoAnalyze: (eps: number, mut: number, solido: boolean) =>
      `${eps} entrypoints · ${mut} alcançam mutação · call graph ${solido ? "completo" : "INCOMPLETO (call_indirect — negativas deixam de ser prova)"}`,
    tagAuth: "auth",
    tagEscreve: "escreve",
    tagEvento: "evento",
    tagUpgrade: "upgrade",
    tagCrossCall: "cross-call",
    cabecalhoEntrypoints: "ENTRYPOINTS",
    cabecalhoAchados: (n: number) => `ACHADOS (${n})`,
    evidenciaRebaixada: "  ⚠ evidência rebaixada",
    cabecalhoLacunas: "LACUNAS DECLARADAS",
    lacunasSemEvidencia: (letras: string) => `Sem evidência no bytecode para: ${letras}.`,
    lacunasNota1: "O template exige ≥1 issue por letra do STRIDE. Estas exigem análise manual",
    lacunasNota2: "do fluxo off-chain — preencher com genérico seria pior que declarar a lacuna.",

    resumoArtifact: (ameacas: number, monitores: number, lacunas: number) =>
      `${ameacas} ameaças · ${monitores} monitores · ${lacunas} lacunas de STRIDE declaradas`,
    linhaAnalise: (soundness: string, insuficiente: boolean) =>
      `análise ${soundness}${insuficiente ? " · janela de observação insuficiente para baseline" : ""}`,
    obsFalhou: (erro: string) => `⚠ observação on-chain falhou: ${erro}`,
    obsFalhouDetalhe: "os documentos foram escritos, mas sem nenhum baseline de nível B.",
    validacao: (rotulo: string, corpo: string) => `VALIDAÇÃO — ${rotulo}: ${corpo}`,
    submetivel: "submetível",
    naoSubmetivel: (porque: string) => `NÃO submetível${porque}`,
    porqueSemJanela: (blockers: number, semJanela: number, comoResolver: string) =>
      ` — ${blockers} blockers, dos quais ${semJanela} ${semJanela === 1 ? "é ausência" : "são ausência"} de janela de observação (${comoResolver})`,
    resolverOffline: "rode sem --offline",
    resolverFalhou: "a coleta falhou; repita",
    resolverJanela: "colete uma janela maior",
  },
});

/** Rótulos dos dois documentos: são nomes do template oficial, iguais nos dois idiomas. */
const ROTULO_TM = "threat model";
const ROTULO_MP = "monitoring plan";

const listaDeRedes = () => Object.keys(NETWORKS).join(", ");

/* ------------------------------------------------------------------ *
 * Erros de uso — uma linha em stderr, sem stack. Stack só com --debug.
 * ------------------------------------------------------------------ */

/** Erro cuja mensagem já está pronta para o usuário: nada dele vira stack. */
export class ErroDeUso extends Error {}

/**
 * Traduz as falhas conhecidas para uma linha legível. Devolve `undefined` quando o erro
 * não é reconhecido — aí o CLI mostra a mensagem crua, também sem stack.
 *
 * Exportada porque é testável sem rede: o caso do SAC exige RPC para reproduzir de verdade,
 * e um teste que depende de mainnet não é um teste.
 */
export function explicarErro(e: unknown): string | undefined {
  const err = e as { code?: unknown; message?: unknown; path?: unknown };
  const msg = String(err?.message ?? e ?? "");
  const code = err?.code;

  if (/Stellar Asset Contract|\bSAC\b/i.test(msg) || (code === 400 && /asset contract/i.test(msg))) {
    return M.errSac;
  }
  if (code === "ENOENT") return M.errEnoent(String(err?.path ?? msg));
  if (code === "EISDIR") return M.errEisdir(String(err?.path ?? msg));
  if (/insecure soroban RPC|not allowed to connect to insecure/i.test(msg)) {
    return M.errInseguro;
  }
  if (/Invalid URL/i.test(msg)) {
    return M.errUrlInvalida(listaDeRedes());
  }
  if (code === "ENOTFOUND" || code === "ECONNREFUSED" || code === "EAI_AGAIN" || /fetch failed|ETIMEDOUT|ECONNRESET/i.test(msg)) {
    return M.errRpcInacessivel(msg);
  }
  if (/could not find|not found/i.test(msg) && /contract|wasm|ledger entry/i.test(msg)) {
    return M.errContratoAusente(msg);
  }
  return undefined;
}

/** `-n`: nome conhecido ou URL http(s) parseável. Qualquer outra coisa é erro de uso. */
export function resolverRede(v: string | undefined): string {
  const bruto = v ?? process.env.SOROGUARD_RPC_URL ?? "mainnet";
  if (NETWORKS[bruto]) return bruto;
  if (/^https?:\/\//i.test(bruto)) {
    try { new URL(bruto); return bruto; } catch { /* cai no erro abaixo */ }
  }
  throw new ErroDeUso(M.errRedeDesconhecida(bruto, listaDeRedes()));
}

/** Um alvo que não é arquivo local precisa ser um contract id válido — checado antes da rede. */
function validarAlvo(target: string): void {
  if (isLocalTarget(target)) return;
  if (!StrKey.isValidContract(target)) {
    throw new ErroDeUso(M.errIdInvalido(target));
  }
}

/* ------------------------------------------------------------------ *
 * Comandos
 *
 * O programa é montado DEPOIS de `setLang`: os textos de `--help` são lidos
 * na construção dos comandos, então construir no topo do módulo congelaria
 * a ajuda em inglês mesmo com `--lang pt`.
 * ------------------------------------------------------------------ */

export function construirPrograma(): Command {
  const ajudaRpc = M.ajudaRpc(listaDeRedes(), NETWORKS.mainnet);
  const program = new Command();
  program
    .name("soroguard")
    .description(M.descPrograma)
    .version("0.0.1");

  program
    .command("inspect")
    .description(M.descInspect)
    .argument("<target>", M.argTarget)
    .option("-n, --network <name>", ajudaRpc)
    .option("--json", M.optJson, false)
    .option("--lang <en|pt>", M.optLang, "en")
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; json: boolean; lang: string }) => {
      setLang(parseLang(opts.lang));
      const network = resolverRede(opts.network);
      validarAlvo(target);
      const { wasm, wasmHash, contractId, analyzedFile } = await resolveTarget(target, network);
      const entries = parseSpecEntries(wasm);
      const parsed = modelFromEntries(entries);
      const model: ContractModel = {
        contractId,
        network,
        analyzedFile,
        wasmHash,
        wasmBytes: wasm.length,
        observed: [],
        warnings: [],
        ...parsed,
      };
      if (!parsed.fns.length) model.warnings.push(M.avisoSemFuncoes);
      if (!parsed.events.length) model.warnings.push(M.avisoSemEventos);

      if (opts.json) {
        console.log(JSON.stringify(model, null, 2));
        return;
      }

      const mut = model.fns.filter((f) => !f.traits.includes("read_only"));
      console.log(`\n  ${contractId}  (${network})`);
      if (analyzedFile) console.log(`  ${M.objetoAnalisado(analyzedFile)}`);
      console.log(`  ${M.linhaWasm((model.wasmBytes ?? 0).toLocaleString(M.locale), wasmHash ? wasmHash.slice(0, 16) : "")}`);
      console.log(`  spec: ${Object.entries(model.specEntryCounts).map(([k, v]) => `${k.replace(/^scSpecEntry/, "").replace(/V0$/, "")}=${v}`).join("  ")}`);
      console.log(`\n  ${M.superficieMutavel(mut.length, model.fns.length)}`);
      for (const f of mut) {
        const sig = f.params.map((p) => `${p.name}: ${p.type}`).join(", ");
        console.log(`    ${f.name}(${sig})`);
        console.log(`      ${M.tracos}: ${f.traits.filter((t) => t !== "read_only").join(", ") || "—"}`);
      }
      if (model.errors.length) {
        console.log(`\n  ${M.modosDeFalha}`);
        for (const e of model.errors) console.log(`    ${e.name}: ${e.cases.map((c) => c.name).join(", ")}`);
      }
      if (model.events.length) {
        console.log(`\n  ${M.eventosDeclarados}`);
        for (const e of model.events) {
          console.log(`    ${e.name}(${e.params.map((p) => `${p.name}: ${p.type}@${p.location}`).join(", ")})`);
          console.log(`      topics: [${e.prefixTopics.map((t) => `"${t}"`).join(", ")}]  data: ${e.dataFormat}`);
        }
      }
      for (const w of model.warnings) console.log(`\n  ⚠ ${w}`);
      console.log();
    });

  program
    .command("analyze")
    .description(M.descAnalyze)
    .argument("<target>", M.argTarget)
    .option("-n, --network <name>", ajudaRpc)
    .option("--json", M.optJson, false)
    .option("--min <sev>", M.optMin, "Low")
    .option("--lang <en|pt>", M.optLang, "en")
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; json: boolean; min: string; lang: string }) => {
      // Os achados nascem no `detect` abaixo: o idioma precisa estar fixado ANTES dele.
      setLang(parseLang(opts.lang));
      const network = resolverRede(opts.network);
      validarAlvo(target);
      const { wasm } = await resolveTarget(target, network);

      const an = analyzeModule(wasm);
      const ordem = ["Low", "Medium", "High", "Critical"];
      const corte = ordem.indexOf(opts.min);
      const achados = detect(an).filter((f) => ordem.indexOf(f.severity) >= corte);
      const faltam = lacunas(achados);

      if (opts.json) {
        console.log(JSON.stringify({ target, soundness: an.soundness, findings: achados, gaps: faltam, boundaries: fronteiras(an) }, null, 2));
        return;
      }

      const mut = an.entrypoints.filter((e) => writesStorage(e) || canUpgradeSelf(e));
      console.log(`\n  ${target}`);
      console.log(`  ${M.resumoAnalyze(an.entrypoints.length, mut.length, an.soundness === "sound")}`);

      console.log(`\n  ${M.cabecalhoEntrypoints}`);
      for (const e of an.entrypoints) {
        const tags = [
          requiresAuth(e) ? M.tagAuth : null,
          writesStorage(e) ? M.tagEscreve : null,
          emitsEvent(e) ? M.tagEvento : null,
          canUpgradeSelf(e) ? M.tagUpgrade : null,
          callsOut(e) ? M.tagCrossCall : null,
        ].filter(Boolean);
        console.log(`    ${e.name.padEnd(34)} ${tags.join(" · ") || "—"}`);
      }

      console.log(`\n  ${M.cabecalhoAchados(achados.length)}`);
      for (const f of achados) {
        console.log(`\n  ${f.id}  [${f.severity}]${f.sound ? "" : M.evidenciaRebaixada}  ${f.class}`);
        console.log(`    ${f.title}`);
        for (const ev of f.evidence) console.log(`      (${ev.tier}) ${ev.claim}`);
      }
      if (faltam.length) {
        console.log(`\n  ${M.cabecalhoLacunas}`);
        console.log(`    ${M.lacunasSemEvidencia(faltam.join(", "))}`);
        console.log(`    ${M.lacunasNota1}`);
        console.log(`    ${M.lacunasNota2}`);
      }
      console.log();
    });

  program
    .command("artifact")
    .description(M.descArtifact)
    .argument("<target>", M.argTarget)
    .option("-n, --network <name>", ajudaRpc)
    .option("-o, --out <dir>", M.optOut, "out")
    .option("--offline", M.optOffline, false)
    .option("--timeout <s>", M.optTimeout, "60")
    .option("--date <YYYY-MM-DD>", M.optDate)
    .option("--lang <en|pt>", M.optLang, "en")
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; out: string; offline: boolean; timeout: string; date?: string; lang: string }) => {
      const lang = parseLang(opts.lang);
      setLang(lang);
      const network = resolverRede(opts.network);
      validarAlvo(target);
      const segundos = Number(opts.timeout);
      if (!Number.isFinite(segundos) || segundos <= 0) throw new ErroDeUso(M.errTimeout(opts.timeout));

      // Carimbo em UTC. Quem roda às 21:00 em São Paulo vê a data de amanhã — está certo,
      // e o documento diz "(UTC)" ao lado do valor para que isso não pareça erro.
      const generatedAt = opts.date ?? new Date().toISOString().slice(0, 10);
      const ctx = await buildContext({
        target, network, generatedAt, offline: opts.offline, lang,
        timeoutMs: segundos * 1000,
        onProgress: (m) => process.stderr.write(`  … ${m}\n`),
      });

      const tm = renderThreatModel(ctx);
      const mp = renderMonitoringPlan(ctx);
      const vt = validateThreatModel(ctx, tm);
      const vm = validateMonitoringPlan(ctx, mp, ctx.monitors ?? []);

      const nome = target.replace(/.*\//, "").replace(/\.wasm$/, "").slice(0, 20);
      mkdirSync(opts.out, { recursive: true });
      const p1 = `${opts.out}/${nome}-threat-model.md`;
      const p2 = `${opts.out}/${nome}-monitoring-plan.md`;
      writeFileSync(p1, tm);
      writeFileSync(p2, mp);

      console.log(`\n  ${p1}  (${tm.length.toLocaleString(M.locale)} bytes)`);
      console.log(`  ${p2}  (${mp.length.toLocaleString(M.locale)} bytes)`);
      console.log(`\n  ${M.resumoArtifact(ctx.findings.length, ctx.monitors?.length ?? 0, ctx.gaps.length)}`);
      console.log(`  ${M.linhaAnalise(ctx.analysis.soundness, Boolean(ctx.observations?.window.insufficient))}`);

      // A coleta falhada não pode sair igual a `--offline`: o documento continua sendo escrito,
      // mas o operador precisa saber que o baseline faltou por falha nossa, não por contrato parado.
      if (ctx.observationError) {
        console.error(`\n  ${M.obsFalhou(ctx.observationError)}`);
        console.error(`    ${M.obsFalhouDetalhe}`);
        process.exitCode = 2;
      }

      for (const [rot, v] of [[ROTULO_TM, vt], [ROTULO_MP, vm]] as const) {
        const gaps = v.items.filter((i) => i.status === "gap");
        // AQ-8: "NÃO submetível" sem o motivo faz o usuário caçar 13 blockers para descobrir
        // que são todos a mesma coisa — e que a mesma coisa é uma flag que ele mesmo passou.
        const semJanela = v.blockers.filter((b) => b.includes('baselineTier="none"')).length;
        const comoResolver = ctx.offline ? M.resolverOffline : ctx.observationError ? M.resolverFalhou : M.resolverJanela;
        const porque = !v.submittable && semJanela ? M.porqueSemJanela(v.blockers.length, semJanela, comoResolver) : "";
        console.log(`\n  ${M.validacao(rot, v.submittable ? M.submetivel : M.naoSubmetivel(porque))}`);
        for (const b of v.blockers) console.log(`    ✖ ${b}`);
        for (const g of gaps.slice(0, 6)) console.log(`    ○ ${g.question} — ${g.detail}`);
      }
      console.log();
    });

  return program;
}

/* ------------------------------------------------------------------ *
 * Entrada — nenhuma falha sai como stack, a não ser com --debug.
 * ------------------------------------------------------------------ */

/**
 * `--lang` lido do argv cru, antes do commander. É o que permite que `--help` e as
 * mensagens de erro de parse do próprio commander saiam no idioma pedido.
 */
export function langDeArgv(argv: string[]): string | undefined {
  const i = argv.indexOf("--lang");
  if (i >= 0 && argv[i + 1]) return argv[i + 1];
  return argv.find((a) => a.startsWith("--lang="))?.slice("--lang=".length);
}

export async function main(argv: string[] = process.argv): Promise<void> {
  const debug = argv.includes("--debug");
  setLang(parseLang(langDeArgv(argv)));
  const program = construirPrograma();
  // Invocação nua: ajuda e código 1. Sem isso o usuário recebe a ajuda com código 0 e um
  // script que checa `$status` conclui que a ferramenta rodou.
  if (argv.length <= 2) {
    program.outputHelp();
    process.exitCode = 1;
    return;
  }
  try {
    await program.parseAsync(argv);
  } catch (e) {
    if (debug) console.error(e);
    const linha = e instanceof ErroDeUso ? e.message : (explicarErro(e) ?? String((e as Error)?.message ?? e));
    console.error(M.erroPrefixo(linha));
    if (!debug) console.error(M.dicaDebug);
    process.exitCode = 1;
  }
}

// Só roda quando este arquivo é o programa; importar o módulo (teste) não dispara nada.
if (process.argv[1] && import.meta.filename === process.argv[1]) await main();
