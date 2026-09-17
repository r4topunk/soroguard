// Roda a taxonomia inteira sobre o corpus e produz a tabela de triagem.
// O objetivo não é contar achados: é encontrar falso positivo antes que um revisor encontre.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { analyzeModule } from "../src/analyze.ts";
import { detectFull, lacunas } from "../src/detect.ts";

const DIR = new URL("../corpus/", import.meta.url).pathname;
const files = readdirSync(DIR).filter((f) => f.endsWith(".wasm"));
const byClass = new Map(), byEntrypoint = new Map(), strideCount = new Map(), supr = new Map();
let contracts = 0, entrypoints = 0, unsound = 0, parseFail = 0, totalFindings = 0;
const lacunaCount = new Map();
const rows = [];

for (const f of files) {
  const id = f.replace(/\.wasm$/, "");
  let an, bytes;
  try { bytes = new Uint8Array(readFileSync(DIR + f)); an = analyzeModule(bytes); }
  catch (e) { parseFail++; rows.push({ id, error: String(e.message).slice(0, 60) }); continue; }
  contracts++;
  entrypoints += an.entrypoints.length;
  if (an.soundness === "approximate") unsound++;
  const r_ = detectFull(an, bytes);
  const fs_ = r_.findings;
  for (const sp of r_.suppressed) supr.set(sp.motivo, (supr.get(sp.motivo) ?? 0) + 1);
  totalFindings += fs_.length;
  for (const fd of fs_) {
    byClass.set(fd.class, (byClass.get(fd.class) ?? 0) + 1);
    strideCount.set(fd.stride, (strideCount.get(fd.stride) ?? 0) + 1);
    const k = `${fd.class}::${fd.entrypoint}`;
    byEntrypoint.set(k, (byEntrypoint.get(k) ?? 0) + 1);
  }
  for (const l of lacunas(fs_)) lacunaCount.set(l, (lacunaCount.get(l) ?? 0) + 1);
  rows.push({ id, eps: an.entrypoints.length, findings: fs_.length, sound: an.soundness,
    classes: [...new Set(fs_.map((x) => x.class))] });
}

const pct = (n) => `${((n / contracts) * 100).toFixed(0)}%`;
console.log(`\nCORPUS: ${contracts} contratos, ${entrypoints} entrypoints, ${parseFail} falhas de parse`);
console.log(`call graph incompleto (call_indirect): ${unsound} (${pct(unsound)})`);
console.log(`achados: ${totalFindings}  |  média ${(totalFindings / contracts).toFixed(1)} por contrato\n`);

console.log("SUPRIMIDOS (declarados, não silenciosos)");
for (const [m, n] of [...supr].sort((a,b)=>b[1]-a[1])) console.log(`  ${String(n).padStart(4)}  ${m}`);
console.log("\nPOR CLASSE");
for (const [c, n] of [...byClass].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${c}`);

console.log("\nPOR LETRA STRIDE");
for (const [s, n] of [...strideCount].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${s}`);

console.log("\nLACUNAS DECLARADAS (letra sem achado derivável)");
for (const [s, n] of [...lacunaCount].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)} contratos sem ${s}`);

console.log("\nTRIAGEM — entrypoints mais recorrentes por classe (candidatos a falso positivo)");
for (const [k, n] of [...byEntrypoint].sort((a, b) => b[1] - a[1]).slice(0, 22)) {
  const [cls, ep] = k.split("::");
  console.log(`  ${String(n).padStart(4)}×  ${cls.padEnd(32)} ${ep}`);
}
writeFileSync(DIR + "calibration.json", JSON.stringify({ contracts, entrypoints, totalFindings, unsound, byClass: [...byClass], rows }, null, 1));
