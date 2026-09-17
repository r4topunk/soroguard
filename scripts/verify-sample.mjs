// Amostra achados e imprime a evidência crua para conferência humana.
import { readdirSync, readFileSync } from "node:fs";
import { analyzeModule } from "../src/analyze.ts";
import { detect } from "../src/detect.ts";
const DIR = new URL("../corpus/", import.meta.url).pathname;
const want = process.argv[2] ?? "unauthenticated-state-mutation";
const N = Number(process.argv[3] ?? 10);
const hits = [];
for (const f of readdirSync(DIR).filter((f) => f.endsWith(".wasm"))) {
  let an; try { an = analyzeModule(new Uint8Array(readFileSync(DIR + f))); } catch { continue; }
  for (const fd of detect(an).filter((x) => x.class === want)) {
    const ep = an.entrypoints.find((e) => e.name === fd.entrypoint);
    hits.push({ id: f.replace(".wasm", ""), fd, ep, soundness: an.soundness });
  }
}
// espalha a amostra por contratos diferentes
const seen = new Map();
const sample = hits.filter((h) => { const n = seen.get(h.id) ?? 0; seen.set(h.id, n + 1); return n < 2; }).slice(0, N);
console.log(`${hits.length} achados de "${want}" em ${new Set(hits.map(h=>h.id)).size} contratos. Amostra de ${sample.length}:\n`);
for (const { id, fd, ep, soundness } of sample) {
  console.log(`── ${id.slice(0, 12)}…  ${fd.entrypoint}   [${fd.severity}] módulo=${soundness} entrypoint=${ep.callGraphComplete ? "completo" : "INCOMPLETO"}`);
  console.log(`   alcança: ${[...ep.reaches].sort().join(", ")}`);
  console.log(`   ordem:   ${ep.orderedHostCalls.join(" → ")}`);
  console.log(`   fanout:  ${ep.fanout} funções internas\n`);
}
