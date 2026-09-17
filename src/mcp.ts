#!/usr/bin/env node
/**
 * MCP server sobre stdio, JSON-RPC 2.0 escrito à mão.
 * O SDK oficial resolveria isto, mas o projeto inteiro é zero-dependência de propósito:
 * uma ferramenta de segurança que arrasta árvore de dependência contradiz o próprio pitch.
 *
 * Escrever o protocolo à mão obriga a implementar o que o SDK daria de graça, e o que
 * faltava era exatamente o que um cliente real exercita primeiro: `ping`, o eco da versão
 * do protocolo, erro de parse, e — o defeito caro — nome de ferramenta desconhecido. Antes
 * desta revisão qualquer `name` caía no `analyze` e devolvia uma análise completa como se
 * a ferramenta existisse (SHIP-07). Um servidor que responde com sucesso ao que não
 * entendeu é pior que um que erra: o cliente não tem como saber.
 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { analyzeModule, requiresAuth, writesStorage, emitsEvent, canUpgradeSelf, callsOut } from "./analyze.ts";
import { probeInitFindings } from "./probe.ts";
import type { ProbeResult } from "./probe.ts";
import { detectFull, lacunas, fronteiras, delegacoes } from "./detect.ts";
import { fetchWasm, modelFromEntries, parseSpecEntries, NETWORKS, redactUrl } from "./spec.ts";
import { readSdkMeta, advisoriesForWasm, ADVISORIES_AS_OF } from "./sdkver.ts";

type Req = { jsonrpc: "2.0"; id?: number | string | null; method: string; params?: any };

/** Versões do protocolo MCP que este servidor implementa; a primeira é a preferida. */
const PROTOCOL_VERSIONS = ["2025-06-18", "2024-11-05"] as const;

/** Versão do servidor = versão do pacote. Ler daqui evita dois números divergindo. */
function versaoDoPacote(): string {
  try {
    const require = createRequire(import.meta.url);
    return String((require("../package.json") as { version?: string }).version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}
const SERVER_VERSION = versaoDoPacote();

/**
 * `network` aqui só pode ser um NOME (o schema da ferramenta é um enum sobre `NETWORKS`),
 * então nenhuma URL de RPC entra por aqui. A redação de `redactUrl` na saída de erro cobre
 * o resto: a mensagem do SDK embute a URL que ele chamou.
 */
async function carregar(alvo: string, network: string): Promise<Uint8Array> {
  return alvo.endsWith(".wasm") ? new Uint8Array(readFileSync(alvo)) : (await fetchWasm(alvo, network)).wasm;
}

/**
 * Texto que o AGENTE lê. A descrição da ferramenta é o que decide se ela vai ser chamada e
 * com quais argumentos, então ela diz o que a ferramenta devolve, não só o que ela faz.
 * Chaves do JSON de resposta NÃO passam por aqui: são contrato, não texto.
 */
const M = {
  argTarget: "contract id (C… , 56 chars) of a deployed contract, or the path to a local .wasm file",
  argNetwork: "network to resolve the contract id on; ignored when target is a local .wasm path",
  argMinSeverity: "drop findings below this severity",
  argProbe:
    "probe each init finding with an unsigned, read-only simulateTransaction and return the result under `probes` (deployed target only; never signs or submits). Set false to skip the network round-trip.",
  descInspect:
    "Reads the contract spec of a DEPLOYED Soroban contract (straight from the WASM on mainnet/testnet, no source code needed). Returns the typed functions with their parameters, the declared error enums, and the events declared in the spec with their prefixTopics — which are the actual filters of a getEvents call.",
  descAnalyze:
    "Analyzes the bytecode: builds the call graph and answers, per exported entrypoint, which Soroban host functions it reaches (require_auth, put_contract_data, contract_event, update_current_contract_wasm, call). Returns security findings whose every claim is labelled by evidence tier — A is a bytecode fact, C is an inference — plus the declared suppressions and the STRIDE letters with no derivable evidence.",
  descAdvisories:
    "Reads the soroban-sdk version recorded in the WASM's contractmetav0 custom section and checks it against known advisories. The source shows the pattern an advisory requires; what only the artifact shows is which SDK compiled the binary on the ledger (the repository may have been updated after the deploy). The result is exposure (tier A), not exploitability.",
  erroFerramenta: (nome: string, disponiveis: string) =>
    `unknown tool: "${nome}". Available: ${disponiveis}`,
  erroTarget: (nome: string) => `missing required argument: "target" (string) in ${nome}`,
  erroParams: 'invalid params for tools/call: requires { name: string, arguments?: object }',
  erroMetodo: (m: string) => `unknown method: ${m}`,
  erroExecucao: (m: string) => `ERROR: ${m}`,
  avisoSdk:
    "Exposure is a bytecode fact (tier A); exploitability is not confirmed (tier C) and requires human review. The severity listed is the advisory's, not the contract's.",
  avisoSemSdk: "The contract does not declare rssdkver — absence of data, not absence of risk.",
  soundnessSolido: "Call graph complete: NEGATIVE claims (does not reach X) are proof.",
  soundnessAproximado:
    "call_indirect present: the call graph is incomplete and not even the negatives are proof. Every claim is downgraded.",
};

/** Schemas das ferramentas expostas no `tools/list`. */
const ferramentas = () => [
  {
    name: "soroguard_inspect",
    description: M.descInspect,
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: M.argTarget },
        network: { type: "string", enum: Object.keys(NETWORKS), default: "mainnet", description: M.argNetwork },
      },
      required: ["target"],
    },
  },
  {
    name: "soroguard_analyze",
    description: M.descAnalyze,
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: M.argTarget },
        network: { type: "string", enum: Object.keys(NETWORKS), default: "mainnet", description: M.argNetwork },
        minSeverity: { type: "string", enum: ["Low", "Medium", "High", "Critical"], default: "Low", description: M.argMinSeverity },
        probe: { type: "boolean", default: true, description: M.argProbe },
      },
      required: ["target"],
    },
  },
  {
    name: "soroguard_sdk_advisories",
    description: M.descAdvisories,
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: M.argTarget },
        network: { type: "string", enum: Object.keys(NETWORKS), default: "mainnet", description: M.argNetwork },
      },
      required: ["target"],
    },
  },
];

const TOOL_NAMES_LIST = ["soroguard_inspect", "soroguard_analyze", "soroguard_sdk_advisories"];

const TOOL_NAMES = new Set(TOOL_NAMES_LIST);

/** Erro de protocolo com código JSON-RPC — distinto de erro de execução da ferramenta. */
class RpcError extends Error {
  code: number;
  constructor(code: number, message: string) { super(message); this.code = code; }
}

async function chamar(nome: string, a: any): Promise<string> {
  // Switch explícito: um `name` desconhecido não pode cair no analyze por queda de fluxo.
  if (!TOOL_NAMES.has(nome)) {
    throw new RpcError(-32602, M.erroFerramenta(nome, [...TOOL_NAMES].join(", ")));
  }
  if (!a || typeof a !== "object" || typeof a.target !== "string" || !a.target) {
    throw new RpcError(-32602, M.erroTarget(nome));
  }
  const net = typeof a.network === "string" && a.network ? a.network : "mainnet";
  const wasm = await carregar(a.target, net);

  switch (nome) {
    case "soroguard_inspect": {
      const spec = modelFromEntries(parseSpecEntries(wasm));
      return JSON.stringify({ target: a.target, ...spec }, null, 2);
    }

    case "soroguard_sdk_advisories": {
      const sdk = readSdkMeta(wasm);
      const adv = advisoriesForWasm(wasm, sdk).map(({ advisory, gateHits }) => ({
        ...advisory, requiresHostFn: undefined, importsMatchingFilter: gateHits,
      }));
      return JSON.stringify(
        {
          rssdkver: sdk.version ?? null,
          declared: Boolean(sdk.version),
          advisories: adv,
          curatedAsOf: ADVISORIES_AS_OF,
          note: sdk.version ? M.avisoSdk : M.avisoSemSdk,
        },
        null, 2);
    }

    case "soroguard_analyze": {
      const an = analyzeModule(wasm);
      const { findings, suppressed } = detectFull(an, wasm);
      // Sondagem de init (nível B): só com alvo deployado, e nunca assinando nada. Offline
      // (alvo `.wasm` local) não tem instância on-chain para sondar, e o payload sai sem o
      // campo em vez de sair com um `probes: {}` que pareceria "sondei e não achei nada".
      let probes: Record<string, ProbeResult> | undefined;
      if (!a.target.endsWith(".wasm") && a.probe !== false) {
        const entries = parseSpecEntries(wasm);
        const { errors } = modelFromEntries(entries);
        const r = await probeInitFindings({
          contractId: a.target, findings, specEntries: entries, errors,
          endpoint: net, rede: /:\/\//.test(net) ? "mainnet" : net,
        });
        if (r.size) probes = Object.fromEntries(r);
      }
      const ordem = ["Low", "Medium", "High", "Critical"];
      const corte = ordem.indexOf(a.minSeverity ?? "Low");
      const achados = findings.filter((f) => ordem.indexOf(f.severity) >= corte);
      return JSON.stringify(
        {
          target: a.target,
          soundness: an.soundness,
          soundnessNote: an.soundness === "sound" ? M.soundnessSolido : M.soundnessAproximado,
          entrypoints: an.entrypoints.map((e) => ({
            name: e.name,
            auth: requiresAuth(e), writesStorage: writesStorage(e), emitsEvent: emitsEvent(e),
            canUpgradeSelf: canUpgradeSelf(e), crossCall: callsOut(e),
          })),
          findings: achados,
          ...(probes ? { probes } : {}),
          // `motivo` é o nome do campo interno (usado por scripts/calibrate.mjs); na API
          // pública ele sai como `reason`.
          suppressed: suppressed.map((s) => ({ entrypoint: s.entrypoint, reason: s.motivo })),
          strideGaps: lacunas(achados),
          dfd: { boundaries: fronteiras(an), authDelegations: delegacoes(an) },
        },
        null, 2);
    }

    /* c8 ignore next */
    default:
      throw new RpcError(-32602, M.erroFerramenta(nome, [...TOOL_NAMES].join(", ")));
  }
}

/* ---------- laço JSON-RPC ---------- */

const escrever = (o: unknown) => process.stdout.write(JSON.stringify(o) + "\n");

/** Eco da versão do protocolo pedida pelo cliente, quando é uma que implementamos. */
export function negociarProtocolo(pedida: unknown): string {
  return typeof pedida === "string" && (PROTOCOL_VERSIONS as readonly string[]).includes(pedida)
    ? pedida
    : PROTOCOL_VERSIONS[0];
}

async function despachar(r: Req): Promise<void> {
  const temId = r?.id !== undefined && r?.id !== null;
  const responder = (result: unknown): void => { if (temId) escrever({ jsonrpc: "2.0", id: r.id, result }); };
  const erro = (code: number, message: string): void => { if (temId) escrever({ jsonrpc: "2.0", id: r.id, error: { code, message } }); };

  try {
    switch (r.method) {
      case "initialize":
        return responder({
          protocolVersion: negociarProtocolo(r.params?.protocolVersion),
          capabilities: { tools: {} },
          serverInfo: { name: "soroguard", version: SERVER_VERSION },
        });
      case "notifications/initialized":
      case "notifications/cancelled":
        return;
      case "ping":
        return responder({});
      case "tools/list":
        return responder({ tools: ferramentas() });
      case "tools/call": {
        // `params` ausente é erro de protocolo, não conteúdo de ferramenta: devolver
        // `TypeError: cannot read 'name' of undefined` como texto da ferramenta faria o
        // cliente tratar uma requisição malformada como resultado de análise.
        const p = r.params;
        if (!p || typeof p !== "object" || typeof p.name !== "string") {
          return erro(-32602, M.erroParams);
        }
        const texto = await chamar(p.name, p.arguments ?? {});
        return responder({ content: [{ type: "text", text: texto }] });
      }
      default:
        return erro(-32601, M.erroMetodo(r.method));
    }
  } catch (e) {
    // Erro de protocolo sai como erro JSON-RPC; falha de execução da ferramenta sai como
    // conteúdo com isError, que é o que o MCP manda o modelo ver e corrigir.
    if (e instanceof RpcError) return erro(e.code, e.message);
    if (temId) {
      escrever({ jsonrpc: "2.0", id: r.id, result: { content: [{ type: "text", text: M.erroExecucao(redactUrl((e as Error).message)) }], isError: true } });
    }
  }
}

/**
 * As requisições são servidas UMA DE CADA VEZ. Serializar custa throughput que um servidor
 * stdio não tem como usar, e devolve determinismo à resposta.
 */
let fila: Promise<void> = Promise.resolve();

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => {
  buf += c;
  let i: number;
  while ((i = buf.indexOf("\n")) >= 0) {
    const linha = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!linha) continue;
    let req: Req;
    try {
      req = JSON.parse(linha);
    } catch {
      // Sem JSON não há id: o próprio JSON-RPC manda responder com id null.
      escrever({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
      continue;
    }
    if (!req || typeof req !== "object" || typeof (req as Req).method !== "string") {
      escrever({ jsonrpc: "2.0", id: (req as any)?.id ?? null, error: { code: -32600, message: "invalid request" } });
      continue;
    }
    fila = fila.then(() => despachar(req));
  }
});
