// Amplia o corpus via stellar.expert, que pagina por _links.next (o cursor manual
// da primeira versão estava errado e por isso só rendia 9 contratos).
import { writeFileSync, existsSync, readFileSync } from "node:fs";
import { rpc } from "@stellar/stellar-sdk";
const DIR = new URL("../corpus/", import.meta.url).pathname;
const TARGET = Number(process.argv[2] ?? 70);
const server = new rpc.Server("https://mainnet.sorobanrpc.com");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const idx = existsSync(DIR + "index.json") ? JSON.parse(readFileSync(DIR + "index.json", "utf8")) : {};
const seenWasm = new Set(Object.values(idx).map((v) => v.wasmHash).filter(Boolean));
let have = Object.values(idx).filter((v) => v.bytes).length;

const cands = [];
for (const sort of ["created", "payments", "trades", "invocations"]) {
  let url = `https://api.stellar.expert/explorer/public/contract?sort=${sort}&order=desc&limit=200`;
  for (let p = 0; p < 6; p++) {
    let j;
    try { j = await (await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 soroguard" } })).json(); }
    catch { break; }
    const recs = j?._embedded?.records ?? [];
    if (!recs.length) break;
    for (const r of recs) if (r.contract && r.wasm && !seenWasm.has(r.wasm)) cands.push({ id: r.contract, wasm: r.wasm });
    const next = j?._links?.next?.href;
    if (!next) break;
    url = next.startsWith("http") ? next : `https://api.stellar.expert${next}`;
    await sleep(300);
  }
}
// dedup por wasm mantendo a primeira ocorrência
const byWasm = new Map();
for (const c of cands) if (!byWasm.has(c.wasm)) byWasm.set(c.wasm, c);
const list = [...byWasm.values()];
console.log(`candidatos novos com wasm inédito: ${list.length} | já em cache: ${have}`);

let ok = 0, fail = 0;
for (const { id, wasm } of list) {
  if (have + ok >= TARGET) break;
  if (idx[id]?.bytes) continue;
  try {
    const bytes = await server.getContractWasmByContractId(id);
    writeFileSync(`${DIR}${id}.wasm`, bytes);
    idx[id] = { wasmHash: wasm, bytes: bytes.length, at: new Date().toISOString() };
    seenWasm.add(wasm); ok++;
    if (ok % 10 === 0) { writeFileSync(DIR + "index.json", JSON.stringify(idx, null, 1)); console.log(`  +${ok} (total ${have + ok})`); }
  } catch (e) {
    idx[id] = { ...idx[id], wasmHash: wasm, error: String(e.message ?? e).slice(0, 50) }; fail++;
  }
  await sleep(320);
}
writeFileSync(DIR + "index.json", JSON.stringify(idx, null, 1));
console.log(`FIM +${ok} novos, ${fail} falhas, total em cache = ${have + ok}`);
