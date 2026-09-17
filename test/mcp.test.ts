/**
 * SHIP-07 — um servidor MCP que responde com sucesso ao que não entendeu é pior que um
 * que erra: o cliente não tem como saber. Antes desta revisão, `tools/call` com
 * `name: "nao_existe"` caía por queda de fluxo no analyze e devolvia uma análise completa,
 * como se a ferramenta existisse. Reproduzido antes de consertar.
 *
 * O protocolo é escrito à mão (decisão do projeto: zero dependência), então o que o SDK
 * daria de graça é testado aqui: initialize, ping, erro de parse, params ausente.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

const MCP = new URL("../src/mcp.ts", import.meta.url).pathname;
const CORPUS = new URL("../corpus/", import.meta.url).pathname;
const ALVO = `${CORPUS}CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm`;

/** Escreve as linhas na entrada do servidor e devolve as respostas JSON, na ordem. */
function conversa(linhas: string[], timeoutMs = 60_000): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [MCP], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let erro = "";
    const t = setTimeout(() => { p.kill("SIGKILL"); reject(new Error(`timeout do servidor MCP\n${erro}`)); }, timeoutMs);
    p.stdout.setEncoding("utf8");
    p.stdout.on("data", (c) => { out += c; });
    p.stderr.setEncoding("utf8");
    p.stderr.on("data", (c) => { erro += c; });
    p.on("close", () => {
      clearTimeout(t);
      try {
        resolve(out.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)));
      } catch (e) {
        reject(new Error(`saída não-JSON do servidor:\n${out}\n${erro}\n${(e as Error).message}`));
      }
    });
    p.on("error", reject);
    for (const l of linhas) p.stdin.write(l + "\n");
    p.stdin.end();
  });
}

const req = (id: number, method: string, params?: unknown) =>
  JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });

test("initialize devolve a versão de protocolo do cliente quando é uma que implementamos", async () => {
  const [a, b, c] = await conversa([
    req(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } }),
    req(2, "initialize", { protocolVersion: "2025-06-18" }),
    req(3, "initialize", { protocolVersion: "1999-01-01" }),
  ]);
  assert.equal(a.result.protocolVersion, "2024-11-05");
  assert.equal(b.result.protocolVersion, "2025-06-18");
  // Versão que não suportamos: respondemos com a nossa mais nova, nunca ecoando o que não implementamos.
  assert.equal(c.result.protocolVersion, "2025-06-18");
  assert.equal(a.result.serverInfo.name, "soroguard");
  // A versão vem do package.json: dois números divergindo é o defeito que isto evita.
  const pkg = JSON.parse(await (await import("node:fs/promises")).readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(a.result.serverInfo.version, pkg.version);
});

test("ping responde objeto vazio — é o health check que todo cliente manda", async () => {
  const [r] = await conversa([req(7, "ping")]);
  assert.deepEqual(r, { jsonrpc: "2.0", id: 7, result: {} });
});

test("tools/list expõe as três ferramentas, com descrição em inglês", async () => {
  const [r] = await conversa([req(1, "tools/list")]);
  const nomes = r.result.tools.map((t: any) => t.name).sort();
  assert.deepEqual(nomes, ["soroguard_analyze", "soroguard_inspect", "soroguard_sdk_advisories"]);
  for (const t of r.result.tools) {
    // a descrição é o que o agente lê para decidir a chamada: inglês
    assert.doesNotMatch(t.description, /[áâãéêíóôõúç]/i, `${t.name} com descrição em português`);
    assert.match(t.inputSchema.properties.target.description, /contract id|\.wasm/);
    assert.match(t.inputSchema.properties.network.description, /network/);
  }
  const analyze = r.result.tools.find((t: any) => t.name === "soroguard_analyze");
  assert.match(analyze.description, /evidence tier/);
  assert.match(analyze.inputSchema.properties.minSeverity.description, /severity/);
});

test("tools/call com nome desconhecido é -32602, não uma análise", async () => {
  const [r] = await conversa([req(9, "tools/call", { name: "nao_existe", arguments: { target: ALVO } })]);
  assert.equal(r.result, undefined, "ferramenta inexistente devolveu resultado");
  assert.equal(r.error.code, -32602);
  assert.match(r.error.message, /unknown tool/);
  // A regressão exata: a análise vazava pelo caminho do analyze.
  assert.doesNotMatch(JSON.stringify(r), /entrypoints|soundness/);
});

test("tools/call sem params é erro de protocolo, não TypeError vestido de conteúdo", async () => {
  const [sem, semNome] = await conversa([
    req(11, "tools/call"),
    req(12, "tools/call", { arguments: { target: ALVO } }),
  ]);
  assert.equal(sem.error.code, -32602);
  assert.equal(semNome.error.code, -32602);
  for (const r of [sem, semNome]) assert.doesNotMatch(JSON.stringify(r), /TypeError|Cannot read/);
});

test("tools/call sem o argumento obrigatório target é -32602", async () => {
  const [r] = await conversa([req(13, "tools/call", { name: "soroguard_inspect", arguments: {} })]);
  assert.equal(r.error.code, -32602);
  assert.match(r.error.message, /target/);
});

test("soroguard_inspect roda sobre um .wasm do corpus e devolve o spec", async () => {
  const [r] = await conversa([req(21, "tools/call", { name: "soroguard_inspect", arguments: { target: ALVO } })]);
  assert.equal(r.error, undefined, JSON.stringify(r.error));
  const payload = JSON.parse(r.result.content[0].text);
  assert.equal(payload.target, ALVO);
  assert.ok(Array.isArray(payload.fns) && payload.fns.length > 0, "spec veio sem funções");
});

test("linha malformada responde -32700 com id null, e o servidor continua vivo", async () => {
  const [parse, ping] = await conversa(["{isto não é json", req(5, "ping")]);
  assert.deepEqual(parse, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
  assert.deepEqual(ping.result, {}, "o servidor morreu depois de uma linha inválida");
});

test("método desconhecido é -32601, e notificação (sem id) não gera resposta", async () => {
  const saidas = await conversa([
    req(31, "metodo/que/nao/existe"),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    req(32, "ping"),
  ]);
  assert.equal(saidas.length, 2, "notificação gerou resposta");
  assert.equal(saidas[0].error.code, -32601);
  assert.equal(saidas[1].id, 32);
});

test("soroguard_analyze devolve chaves em inglês e texto em inglês por padrão", async () => {
  const [r] = await conversa([req(41, "tools/call", { name: "soroguard_analyze", arguments: { target: ALVO } })]);
  assert.equal(r.error, undefined, JSON.stringify(r.error));
  const p = JSON.parse(r.result.content[0].text);
  // contrato da API pública — nomes de campo em inglês
  for (const k of ["target", "soundness", "soundnessNote", "entrypoints", "findings", "suppressed", "strideGaps", "dfd"]) {
    assert.ok(k in p, `payload sem a chave ${k}`);
  }
  for (const k of ["achados", "suprimidos", "avisoSoundness", "lacunasStride"]) {
    assert.ok(!(k in p), `chave antiga ${k} ainda no payload`);
  }
  assert.deepEqual(Object.keys(p.dfd).sort(), ["authDelegations", "boundaries"]);
  assert.ok("name" in p.entrypoints[0] && "writesStorage" in p.entrypoints[0] && "emitsEvent" in p.entrypoints[0]);
  if (p.suppressed.length) assert.ok("reason" in p.suppressed[0] && !("motivo" in p.suppressed[0]));
  assert.match(p.soundnessNote, /^(Call graph complete|call_indirect present)/);
});

test("soroguard_sdk_advisories devolve rssdkver/declared/curatedAsOf/note", async () => {
  const [r] = await conversa([req(61, "tools/call", { name: "soroguard_sdk_advisories", arguments: { target: ALVO } })]);
  assert.equal(r.error, undefined, JSON.stringify(r.error));
  const p = JSON.parse(r.result.content[0].text);
  assert.deepEqual(Object.keys(p).sort(), ["advisories", "curatedAsOf", "declared", "note", "rssdkver"]);
  assert.doesNotMatch(p.note, /[áâãéêíóôõúç]/i, "note em português");
  for (const adv of p.advisories) assert.ok("importsMatchingFilter" in adv, "gate hits sem a chave em inglês");
});
