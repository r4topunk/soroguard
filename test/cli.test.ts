/**
 * SHIP-06 — o CLI não pode responder a erro de uso com stack trace.
 *
 * Um stack de 20 linhas com `at node:internal/...` no meio comunica "a ferramenta quebrou",
 * não "você passou um id inválido". O README promete que SAC é "detectado e avisado"; antes
 * desta revisão ele saía como `triggerUncaughtException`. Cada caso abaixo é um dos que
 * foram reproduzidos à mão.
 *
 * Nada aqui vai à rede: os casos que exigiriam RPC (SAC) são exercitados sobre a função de
 * mapeamento de erro, com o erro que o SDK realmente lança.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { explicarErro, resolverRede, ErroDeUso, linhasDeProbe } from "../src/cli.ts";
import type { ProbeResult } from "../src/probe.ts";
import { NETWORKS, redactUrl } from "../src/spec.ts";
import { setLang } from "../src/i18n.ts";

const exec = promisify(execFile);
const CLI = new URL("../src/cli.ts", import.meta.url).pathname;
const CORPUS = new URL("../corpus/", import.meta.url).pathname;
const ALVO = `${CORPUS}CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm`;

type Saida = { code: number; stdout: string; stderr: string };

async function rodar(args: string[]): Promise<Saida> {
  try {
    const { stdout, stderr } = await exec(process.execPath, [CLI, ...args], { timeout: 60_000, maxBuffer: 32 << 20 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string; killed?: boolean };
    assert.ok(!err.killed, `o comando estourou o timeout: soroguard ${args.join(" ")}`);
    return { code: typeof err.code === "number" ? err.code : 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

/** Uma linha de erro é uma linha: sem frames, sem `at node:internal`. */
function assertSemStack(s: Saida, args: string[]): void {
  assert.doesNotMatch(s.stderr, /at node:internal/, `stack vazou em: soroguard ${args.join(" ")}\n${s.stderr}`);
  assert.doesNotMatch(s.stderr, /^\s+at\s/m, `frame de stack vazou em: soroguard ${args.join(" ")}\n${s.stderr}`);
}

test("inspect aceita um .wasm local — a invocação que o README documenta", async () => {
  const s = await rodar(["inspect", ALVO]);
  assert.equal(s.code, 0, s.stderr);
  assert.match(s.stdout, /MUTABLE SURFACE/);
  // O endereço vem do nome do arquivo; o caminho é metadado, não endereço.
  assert.match(s.stdout, /CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5/);
});

test("contract id inválido sai como uma linha, não como stack", async () => {
  const args = ["inspect", "nao-e-um-id"];
  const s = await rodar(args);
  assert.equal(s.code, 1);
  assertSemStack(s, args);
  assert.match(s.stderr, /invalid contract id/);
});

test("caminho .wasm inexistente sai limpo", async () => {
  const args = ["analyze", "/tmp/nao-existe-soroguard-xyz.wasm"];
  const s = await rodar(args);
  assert.equal(s.code, 1);
  assertSemStack(s, args);
  assert.match(s.stderr, /file not found/);
});

test("-n com rede desconhecida lista os valores válidos em vez de estourar Invalid URL", async () => {
  const args = ["inspect", ALVO, "-n", "futurenet"];
  const s = await rodar(args);
  assert.equal(s.code, 1);
  assertSemStack(s, args);
  assert.doesNotMatch(s.stderr, /Invalid URL/);
  assert.match(s.stderr, /unknown network: "futurenet"/);
  assert.match(s.stderr, /mainnet/);
  assert.match(s.stderr, /testnet/);
});

test("invocação nua mostra ajuda e sai 1 — script que checa $status não pode ler isso como sucesso", async () => {
  const s = await rodar([]);
  assert.equal(s.code, 1);
  assert.match(s.stdout + s.stderr, /Usage: soroguard/);
});

test("o padrão é inglês: nenhum rótulo em português vaza sem --lang", async () => {
  const s = await rodar(["analyze", ALVO]);
  assert.equal(s.code, 0, s.stderr);
  assert.match(s.stdout, /ENTRYPOINTS/);
  assert.match(s.stdout, /FINDINGS \(\d+\)/);
  assert.match(s.stdout, /call graph (complete|INCOMPLETE)/);
  assert.doesNotMatch(s.stdout, /ACHADOS|LACUNAS DECLARADAS|alcançam mutação/);
});

test("--lang pt traduz a saída e a ajuda, sem mudar o código de saída", async () => {
  const a = await rodar(["analyze", ALVO, "--lang", "pt"]);
  assert.equal(a.code, 0, a.stderr);
  assert.match(a.stdout, /ACHADOS \(\d+\)/);
  assert.match(a.stdout, /alcançam mutação/);

  const i = await rodar(["inspect", ALVO, "--lang", "pt"]);
  assert.equal(i.code, 0, i.stderr);
  assert.match(i.stdout, /SUPERFÍCIE MUTÁVEL/);

  // a ajuda também: ela é construída depois de fixar o idioma
  const h = await rodar(["analyze", "--help", "--lang", "pt"]);
  assert.match(h.stdout + h.stderr, /idioma da saída/);
});

test("--help sai em inglês por padrão, nos dois níveis", async () => {
  const raiz = await rodar(["--help"]);
  assert.match(raiz.stdout + raiz.stderr, /STRIDE threat model and on-chain monitoring plan/);
  const art = await rodar(["artifact", "--help"]);
  const t = art.stdout + art.stderr;
  assert.match(t, /output directory/);
  assert.match(t, /output language/);
  assert.doesNotMatch(t, /diretório de saída|idioma da saída/);
});

/* ---------- mapeamento de erro, sem rede ---------- */

test("o erro de SAC do SDK vira a frase que o README promete", () => {
  // Erro real do @stellar/stellar-sdk, reproduzido em mainnet contra CAS3J7GY…
  const sac = { code: 400, message: "Contract CAS3J7GY… is a Stellar Asset Contract (SAC) and has no WASM" };
  assert.equal(
    explicarErro(sac),
    "contract is a Stellar Asset Contract (SAC): it has no WASM and no contractspecv0; not supported",
  );
});

test("ENOENT vira 'file not found', não 'ENOENT: no such file or directory, open …'", () => {
  const e = Object.assign(new Error("ENOENT: no such file or directory, open '/x.wasm'"), { code: "ENOENT", path: "/x.wasm" });
  assert.match(explicarErro(e)!, /^file not found: \/x\.wasm$/);
});

test("RPC inacessível e RPC inseguro são mapeados, e o desconhecido devolve undefined", () => {
  assert.match(explicarErro(Object.assign(new Error("fetch failed"), { code: "ECONNREFUSED" }))!, /RPC unreachable/);
  assert.match(explicarErro(new Error("Cannot connect to insecure soroban RPC server"))!, /https:\/\//);
  assert.equal(explicarErro(new Error("algo que a ferramenta nunca viu")), undefined);
});

test("resolverRede aceita nome conhecido e URL, e recusa o resto com a lista de válidos", () => {
  assert.deepEqual(resolverRede("mainnet"), { rpcUrl: NETWORKS.mainnet, label: "mainnet" });
  // URL: vira endpoint e NÃO vira rótulo. O rótulo só sai da passphrase do nó.
  const url = resolverRede("https://meu-no.example/rpc");
  assert.equal(url.rpcUrl, "https://meu-no.example/rpc");
  assert.equal(url.label, undefined, "URL nunca é rótulo: só a passphrase do nó responde isso");
  assert.throws(() => resolverRede("futurenet"), (e: unknown) => e instanceof ErroDeUso && /futurenet/.test((e as Error).message));
});

test("SOROGUARD_RPC_URL é o padrão quando -n não é passado", () => {
  const antes = process.env.SOROGUARD_RPC_URL;
  process.env.SOROGUARD_RPC_URL = "https://rpc-privado.example";
  try {
    assert.equal(resolverRede(undefined).rpcUrl, "https://rpc-privado.example");
    assert.equal(resolverRede(undefined).label, undefined, "URL nunca é rótulo");
    assert.deepEqual(resolverRede("testnet"), { rpcUrl: NETWORKS.testnet, label: "testnet" }, "-n explícito tem precedência sobre o env");
  } finally {
    if (antes === undefined) delete process.env.SOROGUARD_RPC_URL;
    else process.env.SOROGUARD_RPC_URL = antes;
  }
});

test("as mesmas mensagens de erro saem em português com setLang(\"pt\")", () => {
  setLang("pt");
  try {
    const e = Object.assign(new Error("ENOENT"), { code: "ENOENT", path: "/x.wasm" });
    assert.match(explicarErro(e)!, /^arquivo não encontrado: \/x\.wasm$/);
    assert.throws(
      () => resolverRede("futurenet"),
      (err: unknown) => err instanceof ErroDeUso && /rede desconhecida: "futurenet"/.test((err as Error).message),
    );
  } finally {
    setLang("en");
  }
});

/* ------------------------------------------------------------------ *
 * Vazamento de credencial pelo `-n` — ponta a ponta, pelo binário.
 *
 * `https://<provedor>/v2/<API_KEY>` era carimbado como "rede" nos dois documentos, no
 * comentário do mermaid, no sumário do CLI e nas linhas de progresso. Aqui a URL é falsa
 * (`.invalid` nunca resolve, por RFC 2606): o rótulo tem de cair para `custom` e nem a
 * chave nem o host podem aparecer em stdout, em stderr ou nos arquivos gerados.
 * ------------------------------------------------------------------ */

const RPC_FALSO = "https://rpc.example.invalid/v2/SECRETKEY";
const SEGREDOS = ["SECRETKEY", "example.invalid"];

test("`-n <url com API key>` não vaza a URL em documento, stdout nem stderr", async () => {
  const out = `${await import("node:fs/promises").then((m) => m.mkdtemp("/tmp/soroguard-leak-"))}`;
  const args = ["artifact", ALVO, "-n", RPC_FALSO, "--offline", "-o", out, "--date", "2026-09-17"];
  const s = await rodar(args);
  assert.equal(s.code, 0, s.stderr);

  const { readdirSync, readFileSync } = await import("node:fs");
  const docs = readdirSync(out);
  assert.equal(docs.length, 2, `esperados 2 documentos, veio ${docs.join(", ")}`);

  for (const f of docs) {
    const md = readFileSync(`${out}/${f}`, "utf8");
    for (const seg of SEGREDOS) assert.ok(!md.includes(seg), `"${seg}" vazou em ${f}`);
    // Nenhuma URL além dos links de documentação/advisory que o texto cita de propósito.
    for (const url of md.match(/[a-z]+:\/\/[^\s)`|]+/gi) ?? []) {
      assert.match(url, /^https:\/\/(developers\.stellar\.org|github\.com\/advisories)\//, `URL inesperada no documento: ${url}`);
    }
    assert.ok(md.includes("custom"), `${f}: rótulo derivado ausente — nó inalcançável deveria virar "custom"`);
  }

  for (const seg of SEGREDOS) {
    assert.ok(!s.stdout.includes(seg), `"${seg}" vazou no stdout`);
    assert.ok(!s.stderr.includes(seg), `"${seg}" vazou no stderr`);
  }
});

test("`inspect`/`analyze` com URL de RPC também não ecoam a URL", async () => {
  for (const cmd of ["inspect", "analyze"]) {
    const s = await rodar([cmd, ALVO, "-n", RPC_FALSO]);
    assert.equal(s.code, 0, s.stderr);
    for (const seg of SEGREDOS) {
      assert.ok(!s.stdout.includes(seg), `${cmd}: "${seg}" vazou no stdout`);
      assert.ok(!s.stderr.includes(seg), `${cmd}: "${seg}" vazou no stderr`);
    }
  }
});

test("redactUrl esconde path e query de qualquer URL numa mensagem de erro", () => {
  assert.equal(redactUrl(`fetch failed: ${RPC_FALSO}`), "fetch failed: https://rpc.example.invalid/…");
  assert.equal(redactUrl("GET https://n.example/rpc?key=abc123 -> 401"), "GET https://n.example/… -> 401");
  assert.ok(!redactUrl(`Invalid URL ${RPC_FALSO}`).includes("SECRETKEY"));
  // sem URL, a string passa intacta
  assert.equal(redactUrl("contract not found"), "contract not found");
});

test("explicarErro redige a URL que o SDK embute na mensagem", () => {
  const e = Object.assign(new Error(`fetch failed ${RPC_FALSO}`), { code: "ENOTFOUND" });
  const linha = explicarErro(e)!;
  assert.ok(!linha.includes("SECRETKEY"), `a API key vazou pela mensagem de erro: ${linha}`);
  assert.match(linha, /RPC unreachable/);
});

test("a saída JSON do servidor MCP não carrega URL de RPC", async () => {
  const { spawn } = await import("node:child_process");
  const MCP = new URL("../src/mcp.ts", import.meta.url).pathname;
  const linhas = [
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "soroguard_sdk_advisories", arguments: { target: ALVO } } }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "soroguard_inspect", arguments: { target: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV", network: "mainnet" } } }),
  ];
  const saida: string = await new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [MCP], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    const t = setTimeout(() => { p.kill("SIGKILL"); reject(new Error("timeout do MCP")); }, 60_000);
    p.stdout.setEncoding("utf8");
    p.stdout.on("data", (c) => { out += c; });
    p.on("close", () => { clearTimeout(t); resolve(out); });
    p.on("error", reject);
    for (const l of linhas) p.stdin.write(l + "\n");
    p.stdin.end();
  });
  for (const seg of [...SEGREDOS, "sorobanrpc.com", "soroban-testnet.stellar.org"]) {
    assert.ok(!saida.includes(seg), `"${seg}" vazou no JSON do MCP:\n${saida.slice(0, 2000)}`);
  }
});


/* ------------------------------------------------------------------ *
 * A sondagem de init no CLI.
 *
 * `docs/PRECISION-TOP25.md`: 23 dos 66 achados do top 25 eram init já disparado. O sumário
 * precisa (a) dizer quantos foram sondados e como saíram e (b) NÃO deixar um `open` passar
 * como mais um número — é o único caso em que o achado é real agora.
 * ------------------------------------------------------------------ */

const sonda = (kind: ProbeResult["kind"], entrypoint: string): ProbeResult => ({
  kind, entrypoint, tier: "B", detail: "…",
  reason: kind === "guarded" ? "already-initialized" : kind === "open" ? "simulation-succeeded" : "error",
});

test("o sumário conta guarded/open/inconclusive na mesma linha", () => {
  const linhas = linhasDeProbe([sonda("guarded", "initialize"), sonda("open", "init_pool"), sonda("inconclusive", "setup")]);
  assert.equal(linhas[0], "3 init findings probed: 1 guarded · 1 open · 1 inconclusive");
});

test("um `open` sai numa linha própria, nomeando o entrypoint", () => {
  const linhas = linhasDeProbe([sonda("guarded", "initialize"), sonda("open", "init_pool")]);
  assert.equal(linhas.length, 2);
  assert.match(linhas[1], /⚠/);
  assert.match(linhas[1], /init_pool/);
  assert.match(linhas[1], /any address can initialize this instance now/);
});

test("sem sondagem nenhuma o sumário não ganha linha vazia", () => {
  assert.deepEqual(linhasDeProbe([]), []);
});

test("--lang pt: o sumário da sondagem segue o idioma", () => {
  try {
    setLang("pt");
    const linhas = linhasDeProbe([sonda("guarded", "initialize"), sonda("open", "init_pool")]);
    assert.match(linhas[0], /2 achados de init sondados: 1 guarded · 1 open · 0 inconclusive/);
    assert.match(linhas[1], /qualquer endereço pode inicializar esta instância agora/);
  } finally {
    setLang("en");
  }
});

test("--no-probe é documentado no --help do artifact", async () => {
  const s = await rodar(["artifact", "--help"]);
  assert.equal(s.code, 0, s.stderr);
  assert.match(s.stdout, /--no-probe/);
  assert.match(s.stdout.replace(/\s+/g, " "), /never signs or submits/);
});

test("--no-probe roda e não imprime sumário de sondagem (alvo local, sem rede)", async () => {
  const out = `${tmpdir()}/soroguard-noprobe-${process.pid}`;
  const args = ["artifact", ALVO, "--offline", "--no-probe", "-o", out, "--date", "2026-01-01"];
  const s = await rodar(args);
  assertSemStack(s, args);
  assert.doesNotMatch(s.stdout, /init findings? probed/);
  assert.doesNotMatch(s.stdout, /any address can initialize/);
});
