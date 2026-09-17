// Corpus de contratos ATIVOS. O RPC público limita agressivamente (429), então
// a estratégia é: baixa concorrência, pausa entre chamadas e backoff exponencial.
// O script é resumível: relê o index e só tenta o que falta ou falhou por 429.
import { writeFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { rpc } from "@stellar/stellar-sdk";

const DIR = new URL("../corpus/", import.meta.url).pathname;
mkdirSync(DIR, { recursive: true });
const TARGET = Number(process.argv[2] ?? 300);
const RPC = "https://mainnet.sorobanrpc.com";
const server = new rpc.Server(RPC);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function jrpc(method, params, tries = 5) {
  for (let t = 0; t < tries; t++) {
    const r = await fetch(RPC, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "soroguard-corpus" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (r.status === 429) { await sleep(1500 * 2 ** t); continue; }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(j.error.message);
    return j.result;
  }
  throw new Error("429 após retries");
}

const retryable = (e) => /429|rate|Could not obtain/i.test(String(e));
async function withRetry(fn, tries = 5) {
  let last;
  for (let t = 0; t < tries; t++) {
    try { return await fn(); }
    catch (e) { last = e; if (!retryable(e)) throw e; await sleep(1200 * 2 ** t); }
  }
  throw last;
}

const idx = existsSync(DIR + "index.json") ? JSON.parse(readFileSync(DIR + "index.json", "utf8")) : {};
const done = (v) => v && (v.bytes || v.skip === "SAC ou sem wasm" || v.skip === "wasm duplicado");

// descoberta: só se ainda não temos candidatos suficientes
let candidates = Object.keys(idx);
if (candidates.length < TARGET) {
  const latest = (await jrpc("getLatestLedger", {})).sequence;
  const freq = new Map(candidates.map((c) => [c, idx[c]?.events ?? 0]));
  let cursor = null;
  for (let page = 0; page < 60 && freq.size < TARGET * 2.5; page++) {
    const pagination = cursor ? { cursor, limit: 1000 } : { limit: 1000 };
    const params = cursor
      ? { filters: [{ type: "contract" }], pagination }
      : { startLedger: latest - 17000, filters: [{ type: "contract" }], pagination };
    let res;
    try { res = await jrpc("getEvents", params); } catch (e) { console.log(`  descoberta parou: ${e.message}`); break; }
    for (const ev of res.events ?? []) freq.set(ev.contractId, (freq.get(ev.contractId) ?? 0) + 1);
    cursor = res.cursor;
    if (!cursor || !(res.events ?? []).length) break;
    await sleep(250);
  }
  for (const [id, n] of freq) if (!idx[id]) idx[id] = { events: n };
  candidates = [...freq.entries()].sort((a, b) => b[1] - a[1]).map(([id]) => id);
}
console.log(`candidatos: ${candidates.length} | já resolvidos: ${candidates.filter((c) => done(idx[c])).length}`);

const seenWasm = new Set(Object.values(idx).map((v) => v.wasmHash).filter(Boolean));
let ok = 0, dup = 0, sac = 0, fail = 0, i = 0;
const pending = candidates.filter((c) => !done(idx[c]));

async function worker(w) {
  while (i < pending.length) {
    const id = pending[i++];
    if (Object.values(idx).filter((v) => v.bytes).length >= TARGET) return;
    try {
      const inst = await withRetry(() => server.getContractInstance(id));
      const hash = inst?.executable?.wasmHash?.toString("hex");
      if (!hash) { idx[id] = { ...idx[id], skip: "SAC ou sem wasm" }; sac++; continue; }
      if (seenWasm.has(hash)) { idx[id] = { ...idx[id], skip: "wasm duplicado", wasmHash: hash }; dup++; continue; }
      seenWasm.add(hash);
      const bytes = await withRetry(() => server.getContractWasmByContractId(id));
      writeFileSync(`${DIR}${id}.wasm`, bytes);
      idx[id] = { ...idx[id], wasmHash: hash, bytes: bytes.length, at: new Date().toISOString() };
      delete idx[id].error;
      ok++;
      if (ok % 10 === 0) { writeFileSync(DIR + "index.json", JSON.stringify(idx, null, 1)); console.log(`  ok=${ok} dup=${dup} sac=${sac} fail=${fail} (${i}/${pending.length})`); }
    } catch (e) {
      idx[id] = { ...idx[id], error: String(e.message ?? e).slice(0, 60) }; fail++;
    }
    await sleep(350 + w * 60); // escalona os workers para não sincronizar rajadas
  }
}
await Promise.all([0, 1].map(worker));
writeFileSync(DIR + "index.json", JSON.stringify(idx, null, 1));
const total = Object.values(idx).filter((v) => v.bytes).length;
console.log(`FIM novos=${ok} dup=${dup} sac=${sac} erro=${fail} | wasm em cache=${total}`);
