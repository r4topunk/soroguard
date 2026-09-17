// Roda inferStorageKeys no corpus inteiro e imprime a evidência crua para conferência humana.
// Não "resume": o ponto é um humano bater o olho e dizer se as strings são chaves ou lixo.
import { readdirSync, readFileSync } from "node:fs";
import { inferStorageKeys } from "../src/storagekeys.ts";

const DIR = new URL("../corpus/", import.meta.url).pathname;
const files = readdirSync(DIR).filter((f) => f.endsWith(".wasm"));
const rows = [];
let fails = 0;
for (const f of files) {
  try { rows.push({ id: f.replace(".wasm", ""), keys: inferStorageKeys(new Uint8Array(readFileSync(DIR + f))) }); }
  catch (e) { fails++; console.log(`PARSE FAIL ${f}: ${e.message}`); }
}

const withAny = rows.filter((r) => r.keys.length);
const withCertain = rows.filter((r) => r.keys.some((k) => k.confidence === "certain"));
const dist = rows.map((r) => r.keys.length).sort((a, b) => a - b);
const total = new Map();
for (const r of rows) for (const k of r.keys) {
  const e = total.get(k.key) ?? { n: 0, conf: "likely" };
  e.n++; if (k.confidence === "certain") e.conf = "certain";
  total.set(k.key, e);
}

console.log(`${rows.length} contratos (${fails} falhas de parse)`);
console.log(`  com >=1 chave:        ${withAny.length} (${Math.round(100 * withAny.length / rows.length)}%)`);
console.log(`  com >=1 chave certain:${withCertain.length}`);
console.log(`  chaves distintas:     ${total.size}  (certain ${[...total.values()].filter(v => v.conf === "certain").length})`);
console.log(`  chaves/contrato:      mediana ${dist[dist.length >> 1]}  máx ${dist.at(-1)}`);
console.log(`  distribuição:         ${dist.join(",")}`);

console.log(`\n── amostra por contrato (os 12 com mais chaves) ──`);
for (const r of [...withAny].sort((a, b) => b.keys.length - a.keys.length).slice(0, 12)) {
  console.log(`\n${r.id.slice(0, 14)}…  ${r.keys.length} chaves`);
  for (const k of r.keys.slice(0, 14)) {
    console.log(`   ${k.confidence === "certain" ? "A" : "~"}  ${k.key.padEnd(32)} ${k.foundIn.slice(0, 4).join(", ")}${k.foundIn.length > 4 ? ` +${k.foundIn.length - 4}` : ""}`);
  }
  if (r.keys.length > 14) console.log(`   … +${r.keys.length - 14}`);
}

console.log(`\n── todas as chaves distintas, por frequência ──`);
console.log([...total].sort((a, b) => b[1].n - a[1].n).map(([k, v]) => `${v.conf === "certain" ? "A:" : ""}${k}(${v.n})`).join(" "));
