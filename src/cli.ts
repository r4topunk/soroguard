#!/usr/bin/env node
import { Command } from "commander";
import { StrKey } from "@stellar/stellar-sdk";
import { mkdirSync, writeFileSync } from "node:fs";
import { modelFromEntries, parseSpecEntries, NETWORKS, endpointDe, redactUrl, rotuloDaRede } from "./spec.ts";
import { analyzeModule, requiresAuth, writesStorage, emitsEvent, canUpgradeSelf, callsOut } from "./analyze.ts";
import { detect, lacunas, fronteiras } from "./detect.ts";
import { buildContext, resolveTarget, isLocalTarget } from "./pipeline.ts";
import { renderThreatModel } from "./render/threatmodel.ts";
import { renderMonitoringPlan } from "./render/monitoring.ts";
import { validateThreatModel, validateMonitoringPlan } from "./validate.ts";
import { resumoDeProbes } from "./probe.ts";
import type { ProbeResult } from "./probe.ts";
import { plural } from "./text.ts";
import type { ContractModel } from "./model.ts";

/* ------------------------------------------------------------------ *
 * Texto da interface. Tudo o que o usuário lê passa por aqui; nomes de
 * flag, de comando e de rede são identificadores e ficam de fora.
 * ------------------------------------------------------------------ */

const M = {
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
  optDebug: "show the full stack on error",
  optOut: "output directory",
  optOffline: "do not query the network to observe events (no tier-B baseline)",
  optTimeout: "total budget, in seconds, for the on-chain observation phase",
  optNoProbe:
    "skip the init probe (unsigned, read-only simulateTransaction on init-shaped entrypoints; never signs or submits)",
  resumoProbe: (n: number, g: number, o: number, i: number) =>
    `${n} init ${plural(n, "finding", "findings")} probed: ${g} guarded · ${o} open · ${i} inconclusive`,
  probeAberto: (eps: string) =>
    `⚠ the initializer(s) ${eps} SUCCEEDED in unsigned simulation: any address can initialize this instance now`,
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
  submetivel: "SUBMITTABLE",
  naoSubmetivel: (porque: string) => `NOT submittable${porque}`,
  verInput: (n: number) => `NEEDS INPUT — ${n} ${plural(n, "item", "items")} for the team (see worksheets)`,
  verNao: (nb: number, ni: number, porque: string) =>
    `NOT SUBMITTABLE — ${nb} ${plural(nb, "blocker", "blockers")}${porque}` + (ni ? ` (+ ${ni} ${plural(ni, "item", "items")} for the team)` : ""),
  rotuloInput: "needs the team:",
  porqueSemJanela: (blockers: number, semJanela: number, comoResolver: string) =>
    `, of which ${semJanela} ${plural(semJanela, "is", "are")} missing observation window (${comoResolver})`,
  resolverOffline: "run without --offline",
  resolverFalhou: "the collection failed; retry",
  resolverJanela: "collect a larger window",
};

/**
 * Linhas de sumário da sondagem de init. Exportada porque é a única parte do sumário que
 * dependeria de rede para ser exercitada — e o `open` é a linha que não pode passar
 * despercebida: é o único caso em que o achado de front-running é real AGORA.
 */
export function linhasDeProbe(probes: ProbeResult[]): string[] {
  if (!probes.length) return [];
  const r = resumoDeProbes(probes);
  const linhas = [M.resumoProbe(r.total, r.guarded, r.open, r.inconclusive)];
  const abertos = probes.filter((x) => x.kind === "open").map((x) => `\`${x.entrypoint}\``);
  if (abertos.length) linhas.push(M.probeAberto(abertos.join(", ")));
  return linhas;
}

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
  // O erro do SDK/`fetch` embute a URL chamada, e um RPC pago tem a API key no path.
  // Redigir AQUI cobre os dois caminhos: a linha que o CLI imprime e qualquer reuso.
  const msg = redactUrl(String(err?.message ?? e ?? ""));
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

/**
 * Rede resolvida: o endpoint por onde falamos com a rede e o rótulo que a saída mostra.
 *
 * Os dois são coisas DIFERENTES e foi confundi-los que vazou credencial: `https://<provedor>/v2/<API_KEY>`
 * era carimbado como "rede" no cabeçalho dos dois documentos, na tabela de inventário, no
 * comentário do mermaid e no stderr. `rpcUrl` não é renderizado em lugar nenhum; `label` é.
 */
export type RedeResolvida = {
  /** endpoint de RPC — possivelmente com credencial no path. NUNCA renderizar. */
  rpcUrl: string;
  /** rótulo, quando o `-n` já é um nome conhecido. Para URL só a passphrase do nó responde. */
  label?: string;
};

/** `-n`: nome conhecido ou URL http(s) parseável. Qualquer outra coisa é erro de uso. */
export function resolverRede(v: string | undefined): RedeResolvida {
  const bruto = v ?? process.env.SOROGUARD_RPC_URL ?? "mainnet";
  if (NETWORKS[bruto]) return { rpcUrl: endpointDe(bruto), label: bruto };
  if (/^https?:\/\//i.test(bruto)) {
    try { new URL(bruto); return { rpcUrl: bruto }; } catch { /* cai no erro abaixo */ }
  }
  throw new ErroDeUso(M.errRedeDesconhecida(bruto, listaDeRedes()));
}

/**
 * Rótulo de rede pronto para renderizar. Nome conhecido responde sozinho; URL exige
 * perguntar ao nó (`getNetwork` → passphrase). Uma ida à rede por execução, e falha vira
 * `custom` — nunca a URL.
 */
export async function rotuloDe(r: RedeResolvida): Promise<string> {
  return r.label ?? (await rotuloDaRede(r.rpcUrl));
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
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; json: boolean }) => {
      const rede = resolverRede(opts.network);
      validarAlvo(target);
      const { wasm, wasmHash, contractId, analyzedFile } = await resolveTarget(target, rede.rpcUrl);
      const network = await rotuloDe(rede);
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
      console.log(`  ${M.linhaWasm((model.wasmBytes ?? 0).toLocaleString("en-US"), wasmHash ? wasmHash.slice(0, 16) : "")}`);
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
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; json: boolean; min: string }) => {
      const rede = resolverRede(opts.network);
      validarAlvo(target);
      const { wasm } = await resolveTarget(target, rede.rpcUrl);

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
    .option("--no-probe", M.optNoProbe)
    .option("--date <YYYY-MM-DD>", M.optDate)
    .option("--debug", M.optDebug, false)
    .action(async (target: string, opts: { network?: string; out: string; offline: boolean; timeout: string; probe: boolean; date?: string }) => {
      const rede = resolverRede(opts.network);
      validarAlvo(target);
      const segundos = Number(opts.timeout);
      if (!Number.isFinite(segundos) || segundos <= 0) throw new ErroDeUso(M.errTimeout(opts.timeout));

      // Carimbo em UTC. Quem roda às 21:00 em São Paulo vê a data de amanhã — está certo,
      // e o documento diz "(UTC)" ao lado do valor para que isso não pareça erro.
      const generatedAt = opts.date ?? new Date().toISOString().slice(0, 10);
      const ctx = await buildContext({
        // Rótulo e endpoint separados: só o rótulo chega ao `ArtifactContext` e aos documentos.
        target, network: await rotuloDe(rede), rpcUrl: rede.rpcUrl, generatedAt, offline: opts.offline,
        timeoutMs: segundos * 1000,
        // commander inverte `--no-probe` em `probe: false`; o default continua sondar.
        probe: opts.probe,
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

      console.log(`\n  ${p1}  (${tm.length.toLocaleString("en-US")} bytes)`);
      console.log(`  ${p2}  (${mp.length.toLocaleString("en-US")} bytes)`);
      console.log(`\n  ${M.resumoArtifact(ctx.findings.length, ctx.monitors?.length ?? 0, ctx.gaps.length)}`);
      console.log(`  ${M.linhaAnalise(ctx.analysis.soundness, Boolean(ctx.observations?.window.insufficient))}`);

      // A sondagem de init é o predicado que fecha um terço da saída atual (docs/PRECISION-TOP25.md).
      // O `open` é o único caso que torna o achado real, então ele não pode sair como mais um número.
      for (const linha of linhasDeProbe(Object.values(ctx.spec.probes ?? {}))) console.log(`  ${linha}`);

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
        const input = v.needsInput ?? [];
        const corpo =
          v.verdict === "submittable" || (v.verdict === undefined && v.submittable) ? M.submetivel
          : v.verdict === "needs-input" ? M.verInput(input.length)
          : M.verNao(v.blockers.length, input.length, porque);
        console.log(`\n  ${M.validacao(rot, corpo)}`);
        for (const b of v.blockers) console.log(`    ✖ ${b}`);
        if (input.length) console.log(`    ${M.rotuloInput}`);
        for (const b of input) console.log(`    ☐ ${b}`);
        for (const g of gaps.slice(0, 6)) console.log(`    ○ ${g.question} — ${g.detail}`);
      }
      console.log();
    });

  return program;
}

/* ------------------------------------------------------------------ *
 * Entrada — nenhuma falha sai como stack, a não ser com --debug.
 * ------------------------------------------------------------------ */

export async function main(argv: string[] = process.argv): Promise<void> {
  const debug = argv.includes("--debug");
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
    // `--debug` imprime o erro cru, stack incluso: é o único caminho em que a URL do RPC
    // pode aparecer, e quem pediu o stack pediu o objeto de erro como ele é.
    if (debug) console.error(e);
    const linha = redactUrl(
      e instanceof ErroDeUso ? e.message : (explicarErro(e) ?? String((e as Error)?.message ?? e)),
    );
    console.error(M.erroPrefixo(linha));
    if (!debug) console.error(M.dicaDebug);
    process.exitCode = 1;
  }
}

// Só roda quando este arquivo é o programa; importar o módulo (teste) não dispara nada.
if (process.argv[1] && import.meta.filename === process.argv[1]) await main();
