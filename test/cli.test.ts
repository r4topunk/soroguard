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
import { promisify } from "node:util";
import { explicarErro, resolverRede, ErroDeUso } from "../src/cli.ts";
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
  assert.equal(resolverRede("mainnet"), "mainnet");
  assert.equal(resolverRede("https://meu-no.example/rpc"), "https://meu-no.example/rpc");
  assert.throws(() => resolverRede("futurenet"), (e: unknown) => e instanceof ErroDeUso && /futurenet/.test((e as Error).message));
});

test("SOROGUARD_RPC_URL é o padrão quando -n não é passado", () => {
  const antes = process.env.SOROGUARD_RPC_URL;
  process.env.SOROGUARD_RPC_URL = "https://rpc-privado.example";
  try {
    assert.equal(resolverRede(undefined), "https://rpc-privado.example");
    assert.equal(resolverRede("testnet"), "testnet", "-n explícito tem precedência sobre o env");
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
