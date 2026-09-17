// Mainnet census: run the soroguard analysis over EVERY distinct contract WASM deployed on
// Stellar mainnet and produce aggregates.
//
// It runs as a PIPELINE, not as a sequence of stages: each page of the contract index is turned
// into new code hashes immediately, those go to a fetch queue, and every fetched module goes to
// an analysis queue. Nothing waits for the previous phase to finish. Aggregation runs at the end
// and every 5 minutes on the partial results, so a partial SUMMARY.md exists early.
//
//   index     enumerate every contract from stellar.expert  -> <PRIV>/index/*.json + index.jsonl
//   hashes    group contracts by code hash                  -> <PRIV>/hashes.json
//   fetch     pull each distinct wasm from the RPC          -> <PRIV>/wasm/<hash>.wasm
//   analyze   analyzeModule + detectFull + sdk + spec       -> <PRIV>/results.jsonl
//   tops      representative + ranked shortlists            -> <PRIV>/{top-by-volume,top-by-instances}.json
//   aggregate only aggregates, into the repo                -> corpus/census/{summary.json,SUMMARY.md}
//
// THE REPRESENTATIVE OF A CODE HASH. One binary is usually deployed many times, and an online
// check can only be run against one of those instances. Picking the wrong one is not a cosmetic
// problem: in 5 of the first 25 triaged families the id that had been picked was 8x–20x quieter
// than the busiest sibling, so the observation described a dormant deploy and said nothing about
// the instance that actually carries traffic. Every hash therefore records BOTH candidates —
// `busiest` (max invocations) and `newest` (max created) — and `--representative` selects which
// one is written wherever an id is emitted. Default: busiest.
//
// Every phase is cached on disk, so a rerun resumes instead of redoing work.
//
// DISCLOSURE: everything that maps a finding to a contract id / code hash stays in the PRIVATE
// directory, which lives OUTSIDE this repository (SECURITY.md). The two files written into the
// repo contain aggregates only — no contract id, no code hash, no project name.
//
// SECRETS: the RPC endpoint carries an API key. It is read at runtime from
// SOROGUARD_RPC_URL or ~/.config/soroguard/rpc-url (chmod 600) and is never written to disk,
// never logged, and redacted out of any error message.
//
//   node scripts/census.mjs                      # the whole pipeline, resumable
//   node scripts/census.mjs aggregate            # only that phase, on whatever is on disk
//   node scripts/census.mjs hashes               # regroup the CACHED index pages, no network,
//                                                #   rewrites hashes.json and the shortlists
//   node scripts/census.mjs tops                 # only the shortlists, from hashes.json
//   node scripts/census.mjs --max-hashes 500     # cap the number of distinct modules
//   node scripts/census.mjs --representative newest   # busiest (default) | newest
//   node scripts/census.mjs --help
//
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/* ------------------------------------------------------------------ *
 * Paths and secrets
 * ------------------------------------------------------------------ */

const SELF = fileURLToPath(import.meta.url);
const REPO = new URL("../", import.meta.url).pathname;
const PRIV = "/Users/r4to/Script/stellar/soroguard-private/census/";
const REPO_OUT = join(REPO, "corpus/census/");

const RPC = process.env.SOROGUARD_RPC_URL
  ?? readFileSync(join(homedir(), ".config/soroguard/rpc-url"), "utf8").trim();

/** The endpoint holds an API key: it must never reach a file, a log or a report. */
const redact = (s) => String(s ?? "").split(RPC).join("[RPC]").replace(/https?:\/\/[^\s"']+/g, "[url]");

const EXPERT = "https://api.stellar.expert/explorer/public";
const INDEX_DIR = PRIV + "index/";
const WASM_DIR = PRIV + "wasm/";
const INDEX_STATE = PRIV + "index-state.json";
const INDEX_JSONL = PRIV + "index.jsonl";
const HASHES_JSON = PRIV + "hashes.json";
const RESULTS = PRIV + "results.jsonl";
const FETCH_LOG = PRIV + "fetch-problems.jsonl";
const PROGRESS = PRIV + "progress.jsonl";
const PAGE_LIMIT = 200;
const WATCHDOG_MS = 30_000;

for (const d of [PRIV, INDEX_DIR, WASM_DIR, REPO_OUT]) mkdirSync(d, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Date.now();
const secs = (t0) => `${((now() - t0) / 1000).toFixed(1)}s`;
const log = (...a) => console.log(...a.map((x) => (typeof x === "string" ? redact(x) : x)));

const readJson = (p, dflt) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : dflt);
const writeJson = (p, v) => writeFileSync(p, JSON.stringify(v, null, 1));

/* ------------------------------------------------------------------ *
 * Progress feed — one short JSON line per event, append-only, also on stderr.
 * ------------------------------------------------------------------ */

const started = { index: now(), fetch: now(), analyze: now(), aggregate: now() };

function prog(stage, { done = 0, total = null, errors = 0, note = "" } = {}) {
  const mins = (now() - (started[stage] ?? now())) / 60000;
  const line = JSON.stringify({
    t: new Date().toISOString(),
    stage,
    done,
    total,
    errors,
    rate_per_min: mins > 0.01 ? Math.round(done / mins) : 0,
    note: redact(note).slice(0, 120),
  });
  try { appendFileSync(PROGRESS, line + "\n"); } catch { /* the feed is never worth a crash */ }
  process.stderr.write(line + "\n");
}

/* ------------------------------------------------------------------ *
 * HTTP with backoff
 * ------------------------------------------------------------------ */

const stats = { expertPages: 0, expert429: 0, expert5xx: 0, rpcCalls: 0, rpc429: 0, rpc5xx: 0 };

// stellar.expert answers 429 with no Retry-After. Measured behaviour: the budget is about 60
// requests per minute per IP, and retrying inside the penalty window EXTENDS it (two runs got
// exactly 60 pages through and then stayed blocked for minutes while the client kept probing).
// So: pace the index at one request per second, and on a 429 back off for a whole window
// instead of hammering. The RPC is a different host and is not affected by this.
const EXPERT_PACE_MS = 1100;
const EXPERT_PENALTY_MS = 70_000;
const backoff = (t, cap = 60_000) => Math.min(cap, 1500 * 2 ** Math.min(t, 6));

async function getJson(url, { tries = 40 } = {}) {
  let last;
  for (let t = 0; t < tries; t++) {
    try {
      const r = await fetch(url, { headers: { "User-Agent": "soroguard-census" }, signal: AbortSignal.timeout(45_000) });
      if (r.status === 429) { stats.expert429++; await sleep(EXPERT_PENALTY_MS); continue; }
      if (r.status >= 500) { stats.expert5xx++; await sleep(backoff(t)); continue; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      stats.expertPages++;
      return await r.json();
    } catch (e) { last = e; await sleep(backoff(t)); }
  }
  throw new Error(`giving up after ${tries} tries: ${redact(last?.message ?? last)}`);
}

async function jrpc(method, params, tries = 12) {
  let last;
  for (let t = 0; t < tries; t++) {
    try {
      const r = await fetch(RPC, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "soroguard-census" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(60_000),
      });
      if (r.status === 429) { stats.rpc429++; await sleep(backoff(t)); continue; }
      if (r.status >= 500) { stats.rpc5xx++; await sleep(backoff(t)); continue; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j.error) throw new Error(redact(j.error.message ?? JSON.stringify(j.error)));
      stats.rpcCalls++;
      return j.result;
    } catch (e) { last = e; await sleep(backoff(t)); }
  }
  throw new Error(`rpc ${method} failed: ${redact(last?.message ?? last)}`);
}

/* ------------------------------------------------------------------ *
 * An async FIFO queue: producers push while consumers are already draining.
 * ------------------------------------------------------------------ */

function makeQueue() {
  const items = [], waiters = [];
  let closed = false;
  return {
    get size() { return items.length; },
    get closed() { return closed; },
    push(x) { items.push(x); waiters.shift()?.(); },
    close() { closed = true; while (waiters.length) waiters.shift()(); },
    /** Up to `n` items; null once the queue is closed AND empty. */
    async take(n = 1) {
      for (;;) {
        if (items.length) return items.splice(0, n);
        if (closed) return null;
        await new Promise((r) => waiters.push(r));
      }
    },
  };
}

/* ------------------------------------------------------------------ *
 * The contract index, as an accumulator shared by the pipeline and the standalone phase.
 * ------------------------------------------------------------------ */

function newIndexAcc() {
  return { byHash: new Map(), contracts: new Set(), wasm: 0, sac: 0, unknown: 0 };
}

/** Folds one explorer record in. Returns the code hash when it is one not seen before. */
function addRecord(acc, r) {
  if (acc.contracts.has(r.contract)) return null;
  acc.contracts.add(r.contract);
  const h = r.wasm ?? null;
  if (!h) { if (r.asset) acc.sac++; else acc.unknown++; return null; }
  acc.wasm++;
  let g = acc.byHash.get(h), fresh = false;
  if (!g) {
    acc.byHash.set(h, (g = {
      instances: 0, invocations: 0, subinvocations: 0, events: 0, errors: 0, minCreated: null,
      busiest: null, newest: null,
    }));
    fresh = true;
  }
  const inv = r.invocations ?? 0, ev = r.events ?? 0;
  g.instances++;
  g.invocations += inv;
  g.subinvocations += r.subinvocation ?? 0;
  g.events += ev;
  g.errors += r.errors ?? 0;
  if (r.created != null && (g.minCreated == null || r.created < g.minCreated)) g.minCreated = r.created;
  // Ties keep the first instance seen; the index is enumerated in ascending creation order, so
  // "first seen" means the oldest, which is the stable choice across reruns.
  if (g.busiest == null || inv > g.busiest.invocations) g.busiest = { contract: r.contract, invocations: inv, events: ev };
  if (r.created != null && (g.newest == null || r.created > g.newest.created)) g.newest = { contract: r.contract, created: r.created };
  return fresh ? h : null;
}

/* ------------------------------------------------------------------ *
 * Representative selection — see the header comment.
 * ------------------------------------------------------------------ */

const REP_MODES = ["busiest", "newest"];
let REPRESENTATIVE = "busiest";

/** The contract id to use for any online check of this code hash, under the current mode. */
function representativeOf(g) {
  const first = REPRESENTATIVE === "newest" ? g?.newest : g?.busiest;
  return first?.contract ?? g?.busiest?.contract ?? g?.newest?.contract ?? null;
}

let CROSS_CHECK = null;

function writeHashes(acc) {
  const hashes = Object.fromEntries([...acc.byHash.entries()]
    .sort((a, b) => b[1].instances - a[1].instances)
    .map(([h, g]) => [h, {
      instances: g.instances,
      siblings: Math.max(0, g.instances - 1),   // instances other than the representative
      invocations: g.invocations,               // kept: the aggregate weights read this name
      invocationsSum: g.invocations,
      subinvocations: g.subinvocations,
      events: g.events,
      eventsSum: g.events,
      errors: g.errors,
      minCreated: g.minCreated,
      busiest: g.busiest,
      newest: g.newest,
      representative: representativeOf(g),
    }]));
  writeJson(HASHES_JSON, {
    generatedAt: new Date().toISOString(),
    representativeBy: REPRESENTATIVE,
    totals: { indexed: acc.contracts.size, wasmContracts: acc.wasm, sacContracts: acc.sac, noCodeNoAsset: acc.unknown, distinctHashes: acc.byHash.size },
    crossCheck: CROSS_CHECK ? { ...CROSS_CHECK, wasmDelta: acc.wasm - CROSS_CHECK.expertWasm, sacDelta: acc.sac - CROSS_CHECK.expertSac } : null,
    hashes,
  });
}

function writeIndexJsonl(acc) {
  const files = readdirSync(INDEX_DIR).filter((f) => f.endsWith(".json")).sort();
  const seen = new Set(), out = [];
  for (const f of files) {
    const body = JSON.parse(readFileSync(INDEX_DIR + f, "utf8"));
    for (const r of body?._embedded?.records ?? []) {
      if (seen.has(r.contract)) continue;
      seen.add(r.contract);
      out.push(JSON.stringify({
        c: r.contract, w: r.wasm ?? null, a: r.asset ?? null, cr: r.created ?? null,
        i: r.invocations ?? 0, s: r.subinvocation ?? 0, e: r.events ?? 0, x: r.errors ?? 0,
      }));
    }
  }
  writeFileSync(INDEX_JSONL, out.join("\n") + "\n");
  return out.length;
}

/** Replays the index pages already on disk (resume) without touching the network. */
function replayCachedPages(acc, onNewHash) {
  const files = readdirSync(INDEX_DIR).filter((f) => f.endsWith(".json")).sort();
  for (const f of files) {
    let body;
    try { body = JSON.parse(readFileSync(INDEX_DIR + f, "utf8")); } catch { continue; }
    for (const r of body?._embedded?.records ?? []) {
      const h = addRecord(acc, r);
      if (h) onNewHash(h);
    }
  }
  return files.length;
}

/* ------------------------------------------------------------------ *
 * HASHES (standalone) — regroup the cached index pages. No network.
 * ------------------------------------------------------------------ */

function stageHashes() {
  const t0 = now();
  const acc = newIndexAcc();
  CROSS_CHECK = readJson(HASHES_JSON, {})?.crossCheck ?? null; // keep whatever the online run measured
  const pages = replayCachedPages(acc, () => {});
  writeHashes(acc);
  log(`  hashes: ${pages} cached pages, ${acc.contracts.size} contracts, ${acc.byHash.size} distinct hashes  ${secs(t0)}`);
  return acc;
}

/* ------------------------------------------------------------------ *
 * TOPS — the private shortlists an online run works from.
 * ------------------------------------------------------------------ */

const TOP_N = 25;

function readResults() {
  if (!existsSync(RESULTS)) return [];
  return readFileSync(RESULTS, "utf8").split("\n").filter(Boolean)
    .flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } });
}

/** One shortlist row. Carries both candidates so a reader can see what was NOT picked. */
function topRow(rank, hash, g) {
  return {
    rank,
    hash,
    inv: g.invocationsSum ?? g.invocations ?? 0,
    inst: g.instances ?? 0,
    events: g.eventsSum ?? g.events ?? 0,
    siblings: g.siblings ?? Math.max(0, (g.instances ?? 1) - 1),
    representativeBy: REPRESENTATIVE,
    contract: representativeOf(g),
    busiest: g.busiest ?? null,
    newest: g.newest ?? null,
  };
}

function writeTops(meta) {
  const entries = Object.entries(meta.hashes);

  const byVolume = entries
    .sort((a, b) => (b[1].invocationsSum ?? 0) - (a[1].invocationsSum ?? 0))
    .slice(0, TOP_N)
    .map(([h, g], i) => topRow(i + 1, h, g));
  writeJson(PRIV + "top-by-volume.json", byVolume);

  const byInstances = entries
    .filter(([, g]) => (g.invocationsSum ?? 0) > 0)   // a never-invoked family has nothing to observe
    .sort((a, b) => (b[1].instances ?? 0) - (a[1].instances ?? 0))
    .slice(0, TOP_N)
    .map(([h, g], i) => topRow(i + 1, h, g));
  writeJson(PRIV + "top-by-instances.json", byInstances);

  return { byVolume: byVolume.length, byInstances: byInstances.length };
}

/**
 * The manual-triage shortlist: a Critical or High unauthenticated-state-mutation on a binary
 * with real deployment. Each row carries the representative id so the online step never has to
 * guess which instance to look at.
 */
function writeTriageCandidates(meta, results) {
  const weightOf = (h) => meta.hashes[h] ?? { instances: 0, invocations: 0 };
  const rows = results
    .filter((r) => r.ok)
    .filter((r) => (r.unauth ?? []).some((u) => u.sev === "Critical" || u.sev === "High"))
    .map((r) => ({ r, w: weightOf(r.hash) }))
    .filter(({ w }) => (w.instances ?? 0) >= 2 || (w.invocations ?? 0) >= 100)
    .sort((a, b) => (b.w.invocationsSum ?? b.w.invocations ?? 0) - (a.w.invocationsSum ?? a.w.invocations ?? 0))
    .map(({ r, w }) => JSON.stringify({
      hash: r.hash,
      instances: w.instances ?? 0,
      siblings: w.siblings ?? Math.max(0, (w.instances ?? 1) - 1),
      invocations: w.invocationsSum ?? w.invocations ?? 0,
      events: w.eventsSum ?? w.events ?? 0,
      representativeBy: REPRESENTATIVE,
      contract: representativeOf(w),
      busiest: w.busiest ?? null,
      newest: w.newest ?? null,
      sdk: r.sdk?.version ?? null,
      soundness: r.soundness,
      entrypoints: (r.unauth ?? []).filter((u) => u.sev === "Critical" || u.sev === "High"),
    }));
  writeFileSync(PRIV + "triage-candidates.jsonl", rows.join("\n") + (rows.length ? "\n" : ""));
  return rows.length;
}

function stageTops() {
  const t0 = now();
  const meta = readJson(HASHES_JSON, null);
  if (!meta) throw new Error("no hashes.json yet");
  if (!Object.values(meta.hashes)[0]?.busiest) throw new Error("hashes.json predates per-instance stats: run `hashes` first");
  const n = writeTops(meta);
  const t = writeTriageCandidates(meta, readResults());
  log(`  tops: top-by-volume=${n.byVolume} top-by-instances=${n.byInstances} triage-candidates=${t} (representative=${REPRESENTATIVE})  ${secs(t0)}`);
}

/* ------------------------------------------------------------------ *
 * FETCH — ContractCode ledger key -> wasm bytes, sha256-verified.
 * ------------------------------------------------------------------ */

/** SDK 17 `fromXDR` returns plain objects for some unions; cover both shapes. */
const arm = (o, k) => (typeof o?.[k] === "function" ? o[k]() : o?.[k]);

async function fetchBatch(xdr, batch, counters) {
  try {
    const keys = batch.map((h) =>
      xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(h, "hex") })).toXDR("base64"));
    const res = await jrpc("getLedgerEntries", { keys });
    const got = [];
    for (const e of res?.entries ?? []) {
      const cc = arm(xdr.LedgerEntryData.fromXDR(e.xdr, "base64"), "contractCode");
      const code = Buffer.from(arm(cc, "code"));
      const sha = createHash("sha256").update(code).digest("hex");
      if (!batch.includes(sha)) {
        counters.mismatch++;
        appendFileSync(FETCH_LOG, JSON.stringify({ t: "sha-mismatch", got: sha }) + "\n");
        continue;
      }
      writeFileSync(WASM_DIR + sha + ".wasm", code);
      counters.ok++;
      got.push(sha);
    }
    const set = new Set(got);
    for (const h of batch) if (!set.has(h)) {
      counters.missing++;
      appendFileSync(FETCH_LOG, JSON.stringify({ t: "missing", hash: h }) + "\n");
    }
    return got;
  } catch (e) {
    counters.failed += batch.length;
    appendFileSync(FETCH_LOG, JSON.stringify({ t: "error", n: batch.length, err: redact(e.message) }) + "\n");
    return [];
  }
}

/* ------------------------------------------------------------------ *
 * ANALYZE — one module, in-process. Shared by the worker child and the corpus baseline.
 * ------------------------------------------------------------------ */

async function analyseOne(bytes) {
  const { analyzeModule } = await import("../src/analyze.ts");
  const { detectFull, lacunas } = await import("../src/detect.ts");
  const { readSdkMeta, advisoriesFor, evaluateVersion } = await import("../src/sdkver.ts");
  const { parseSpecEntries, modelFromEntries } = await import("../src/spec.ts");

  const an = analyzeModule(bytes);
  const det = detectFull(an, bytes);

  const byClass = {}, bySeverity = {}, supp = {};
  const unauthNames = [], unauth = [];
  for (const f of det.findings) {
    byClass[f.class] = (byClass[f.class] ?? 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    if (f.class === "unauthenticated-state-mutation") { unauthNames.push(f.entrypoint); unauth.push({ e: f.entrypoint, sev: f.severity }); }
  }
  for (const s of det.suppressed) supp[s.motivo] = (supp[s.motivo] ?? 0) + 1;

  const sdk = readSdkMeta(bytes);
  const ev = evaluateVersion(sdk.version);
  const advisories = advisoriesFor(sdk.version).map((a) => a.id);

  let spec = { has: false, fns: 0, events: 0, errors: 0 };
  try {
    const entries = parseSpecEntries(bytes);
    if (entries.length) {
      const m = modelFromEntries(entries);
      spec = { has: true, fns: m.fns.length, events: m.events.length, errors: m.errors.length };
    }
  } catch (e) { spec = { has: false, fns: 0, events: 0, errors: 0, err: String(e?.message ?? e).slice(0, 80) }; }

  return {
    ok: true,
    bytes: bytes.length,
    soundness: an.soundness,
    hasIndirect: an.hasIndirectAnywhere === true,
    incomplete: an.incompleteReason != null,
    incompleteReason: an.incompleteReason ? String(an.incompleteReason).slice(0, 120) : null,
    degraded: an.entrypoints.some((e) => !e.callGraphComplete),
    entrypoints: an.entrypoints.length,
    findings: det.findings.length,
    byClass, bySeverity,
    gaps: lacunas(det.findings),
    suppressed: supp,
    suppressedTotal: det.suppressed.length,
    sdk: { declared: sdk.version != null, version: sdk.version ?? null, status: ev.status },
    advisories,
    spec,
    unauthNames,
    unauth,
  };
}

/** Child mode: one JSON request per stdin line, one JSON result per stdout line. */
async function analyzeWorkerMain() {
  process.stdin.setEncoding("utf8");
  let buf = "";
  const queue = [];
  let busy = false;
  const pump = async () => {
    if (busy) return;
    busy = true;
    while (queue.length) {
      const job = queue.shift();
      let out;
      try {
        const bytes = new Uint8Array(readFileSync(job.path));
        out = { hash: job.hash, ...(await analyseOne(bytes)) };
      } catch (e) {
        out = { hash: job.hash, ok: false, reason: String(e?.message ?? e).slice(0, 160), stage: "analyze" };
      }
      process.stdout.write(JSON.stringify(out) + "\n");
    }
    busy = false;
  };
  process.stdin.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (line.trim()) queue.push(JSON.parse(line));
    }
    void pump();
  });
  process.stdin.on("end", () => { /* stay alive until the parent kills us */ });
}

function spawnWorker() {
  const child = spawn(process.execPath, [SELF, "--analyze-worker"], { stdio: ["pipe", "pipe", "inherit"] });
  child.stdout.setEncoding("utf8");
  child.buf = "";
  child.on("error", () => { /* a killed worker is expected: the watchdog respawns it */ });
  return child;
}

/**
 * One analysis slot: a child process that gets one module at a time. A module that does not
 * answer within 30 s gets its child SIGKILLed and a fresh one spawned — a pathological binary
 * can cost 30 s, never the census.
 */
function analysisSlot(onTimeout) {
  let child = spawnWorker();
  return {
    run: (job) => new Promise((resolve) => {
      let settled = false;
      const finish = (v) => {
        if (settled) return;
        settled = true;
        child.stdout.off("data", onData);
        clearTimeout(timer);
        resolve(v);
      };
      const onData = (d) => {
        child.buf += d;
        const j = child.buf.indexOf("\n");
        if (j < 0) return;
        const line = child.buf.slice(0, j);
        child.buf = child.buf.slice(j + 1);
        try { finish(JSON.parse(line)); }
        catch { finish({ hash: job.hash, ok: false, reason: "unparseable worker output", stage: "worker" }); }
      };
      const timer = setTimeout(() => {
        onTimeout?.();
        try { child.kill("SIGKILL"); } catch { /* already gone */ }
        child = spawnWorker();
        finish({ hash: job.hash, ok: false, reason: "watchdog timeout (30s)", stage: "timeout" });
      }, WATCHDOG_MS);
      child.stdout.on("data", onData);
      child.stdin.write(JSON.stringify(job) + "\n");
    }),
    stop: () => { try { child.kill("SIGKILL"); } catch { /* already gone */ } },
  };
}

/* ------------------------------------------------------------------ *
 * THE PIPELINE
 * ------------------------------------------------------------------ */

const FETCH_BATCH = 12, FETCH_CONC = 8, ANALYZE_CONC = 4, AGGREGATE_EVERY_MS = 5 * 60_000;

async function pipeline(maxHashes) {
  const T0 = now();
  started.index = started.fetch = started.analyze = started.aggregate = T0;

  const { xdr } = await import("@stellar/stellar-sdk");
  try { CROSS_CHECK = await getJson(`${EXPERT}/contract-stats`).then((s) => ({ expertWasm: s.wasm, expertSac: s.sac, expertInvocations: s.invocations })); }
  catch { CROSS_CHECK = null; }

  const alreadyAnalyzed = new Set();
  if (existsSync(RESULTS)) {
    for (const l of readFileSync(RESULTS, "utf8").split("\n")) {
      if (!l.trim()) continue;
      try { alreadyAnalyzed.add(JSON.parse(l).hash); } catch { /* truncated tail */ }
    }
  }

  const fetchQ = makeQueue(), analyzeQ = makeQueue();
  const acc = newIndexAcc();
  const counters = { ok: 0, missing: 0, mismatch: 0, failed: 0 };
  let enqueued = 0, fetched = 0, analyzed = 0, analyzeFail = 0, timeouts = 0;

  const enqueue = (h) => {
    if (maxHashes && enqueued >= maxHashes) return;
    enqueued++;
    if (alreadyAnalyzed.has(h)) { analyzed++; return; }
    if (existsSync(WASM_DIR + h + ".wasm")) { fetched++; analyzeQ.push(h); return; }
    fetchQ.push(h);
  };

  /* --- resume: replay whatever the index already has ------------------ */
  const cachedPages = replayCachedPages(acc, enqueue);
  prog("index", { done: cachedPages, total: null, note: `resumed from ${cachedPages} cached pages, ${acc.byHash.size} hashes` });

  /* --- producer: index pagination ------------------------------------- */
  const indexDone = (async () => {
    const state = readJson(INDEX_STATE, { page: 0, next: `/explorer/public/contract?order=asc&limit=${PAGE_LIMIT}`, done: false });
    let { page, next } = state;
    if (state.done) next = null;
    let errors = 0, aborted = false;
    while (next) {
      const file = `${INDEX_DIR}${String(page).padStart(5, "0")}.json`;
      let body;
      if (existsSync(file)) {
        body = JSON.parse(readFileSync(file, "utf8"));
      } else {
        try { body = await getJson(`https://api.stellar.expert${next}`); }
        catch (e) { errors++; aborted = true; prog("index", { done: page, errors, note: `page failed: ${e.message}` }); break; }
        writeFileSync(file, JSON.stringify(body));
        await sleep(EXPERT_PACE_MS); // stay inside the ~60 requests/minute budget
      }
      const records = body?._embedded?.records ?? [];
      for (const r of records) { const h = addRecord(acc, r); if (h) enqueue(h); }
      const nextHref = body?._links?.next?.href;
      page++;
      writeJson(INDEX_STATE, { page, next: nextHref ?? null, done: !nextHref || !records.length });
      prog("index", { done: page, total: null, errors, note: `${acc.contracts.size} contracts, ${acc.byHash.size} hashes` });
      if (!records.length || !nextHref) break;
      next = nextHref;
    }
    // An aborted producer must NOT mark the index complete: the state file is the resume point.
    if (!aborted) writeJson(INDEX_STATE, { ...readJson(INDEX_STATE, {}), page, next: null, done: true });
    const n = writeIndexJsonl(acc);
    writeHashes(acc);
    prog("index", { done: page, total: page, errors,
      note: `${aborted ? "ABORTED" : "complete"}: ${n} contracts, ${acc.byHash.size} distinct hashes` });
    fetchQ.close();
  })();

  /* --- fetch workers --------------------------------------------------- */
  const fetchers = Array.from({ length: FETCH_CONC }, async () => {
    for (;;) {
      const batch = await fetchQ.take(FETCH_BATCH);
      if (!batch) break;
      const got = await fetchBatch(xdr, batch, counters);
      fetched += got.length;
      for (const h of got) analyzeQ.push(h);
      if (fetched % 50 < got.length) {
        prog("fetch", { done: fetched, total: enqueued, errors: counters.missing + counters.mismatch + counters.failed,
          note: `missing=${counters.missing} mismatch=${counters.mismatch} fail=${counters.failed} q=${fetchQ.size}` });
      }
    }
  });
  void Promise.all(fetchers).then(() => {
    prog("fetch", { done: fetched, total: enqueued, errors: counters.missing + counters.mismatch + counters.failed, note: "fetch drained" });
    analyzeQ.close();
  });

  /* --- analysis workers ------------------------------------------------ */
  const analysts = Array.from({ length: ANALYZE_CONC }, async () => {
    const slot = analysisSlot(() => { timeouts++; });
    for (;;) {
      const one = await analyzeQ.take(1);
      if (!one) break;
      const hash = one[0];
      const r = await slot.run({ hash, path: WASM_DIR + hash + ".wasm" });
      if (!r.ok) analyzeFail++;
      analyzed++;
      appendFileSync(RESULTS, JSON.stringify(r) + "\n");
      if (analyzed % 50 === 0) {
        prog("analyze", { done: analyzed, total: enqueued, errors: analyzeFail,
          note: `timeouts=${timeouts} q=${analyzeQ.size}` });
      }
    }
    slot.stop();
  });

  /* --- periodic aggregate ---------------------------------------------- */
  let stop = false;
  const ticker = (async () => {
    while (!stop) {
      await sleep(AGGREGATE_EVERY_MS);
      if (stop) break;
      try {
        writeHashes(acc);
        await stageAggregate({ quiet: true });
        prog("aggregate", { done: analyzed, total: enqueued, note: "partial SUMMARY.md written" });
      } catch (e) { prog("aggregate", { done: analyzed, errors: 1, note: `partial failed: ${e.message}` }); }
    }
  })();

  await indexDone;
  await Promise.all(fetchers);
  await Promise.all(analysts);
  stop = true;

  writeHashes(acc);
  await stageAggregate({});
  prog("done", {
    done: analyzed, total: acc.byHash.size, errors: analyzeFail + counters.failed + counters.missing + counters.mismatch,
    note: `${secs(T0)} | fetched=${fetched} timeouts=${timeouts} 429s=${stats.expert429}/${stats.rpc429}`,
  });
  log(`\npipeline: ${acc.contracts.size} contracts, ${acc.byHash.size} hashes, ${fetched} fetched, ${analyzed} analyzed (${analyzeFail} failed, ${timeouts} timeouts) in ${secs(T0)}`);
  await Promise.race([ticker, sleep(0)]);
}

/* ------------------------------------------------------------------ *
 * The 75-contract corpus, measured with the same code, for the comparison table.
 * ------------------------------------------------------------------ */

async function corpusBaseline() {
  const dir = join(REPO, "corpus/");
  const files = readdirSync(dir).filter((f) => f.endsWith(".wasm"));
  const rows = [];
  for (const f of files) {
    try { rows.push(await analyseOne(new Uint8Array(readFileSync(dir + f)))); }
    catch { rows.push({ ok: false }); }
  }
  const good = rows.filter((r) => r.ok);
  const n = good.length || 1;
  return {
    contracts: rows.length,
    parseFailures: rows.length - good.length,
    findings: good.reduce((a, r) => a + r.findings, 0),
    findingsPerContract: good.reduce((a, r) => a + r.findings, 0) / n,
    unauthRate: good.filter((r) => (r.byClass["unauthenticated-state-mutation"] ?? 0) > 0).length / n,
    callIndirectShare: good.filter((r) => r.hasIndirect).length / n,
    sdkDeclaredRate: good.filter((r) => r.sdk.declared).length / n,
    eventsDeclaredRate: good.filter((r) => r.spec.events > 0).length / n,
    specRate: good.filter((r) => r.spec.has).length / n,
  };
}

/* ------------------------------------------------------------------ *
 * AGGREGATE  ->  the repository (aggregates only)
 * ------------------------------------------------------------------ */

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const num = (x) => Math.round(x).toLocaleString("en-US");

/**
 * Usage tier of a code hash. Raw per-hash numbers are dominated by tutorial and test binaries:
 * most distinct hashes on mainnet are deployed once and never invoked, and they carry
 * entrypoints like `increment`, `sum` or `a`. Stratifying by usage is what separates "a
 * Critical exists in the bytecode" from "a Critical exists in something anyone uses".
 */
const TIERS = ["T0", "T1", "T2", "T3"];
const TIER_LABEL = {
  T0: "T0 — deployed once, never invoked",
  T1: "T1 — deployed once, invoked at least once",
  T2: "T2 — 2–9 instances",
  T3: "T3 — 10 or more instances",
};
function tierOf(w) {
  const inst = w?.instances ?? 0, inv = w?.invocations ?? 0;
  if (inst >= 10) return "T3";
  if (inst >= 2) return "T2";
  return inv > 0 ? "T1" : "T0";
}

/** The per-hash statistics of an arbitrary set of analyzed modules. */
function statBlock(rows, weightOf) {
  const H = rows.length || 1;
  const byClass = {}, bySeverity = {}, adv = {};
  let instances = 0, invocations = 0, findings = 0, critical = 0, high = 0;
  let unauth = 0, sdkDeclared = 0, spec = 0, events = 0, indirect = 0;
  for (const r of rows) {
    const w = weightOf(r.hash);
    instances += w.instances ?? 0;
    invocations += w.invocations ?? 0;
    findings += r.findings;
    critical += r.bySeverity?.Critical ?? 0;
    high += r.bySeverity?.High ?? 0;
    addInto(byClass, r.byClass);
    addInto(bySeverity, r.bySeverity);
    for (const a of r.advisories ?? []) adv[a] = (adv[a] ?? 0) + 1;
    if ((r.byClass?.["unauthenticated-state-mutation"] ?? 0) > 0) unauth++;
    if (r.sdk?.declared) sdkDeclared++;
    if (r.spec?.has) spec++;
    if ((r.spec?.events ?? 0) > 0) events++;
    if (r.hasIndirect) indirect++;
  }
  return {
    hashes: rows.length, instances, invocations,
    findings, findingsPerHash: findings / H,
    criticalTotal: critical, criticalPerHash: critical / H,
    highTotal: high, highPerHash: high / H,
    byClass: sortDesc(byClass), bySeverity: sortDesc(bySeverity),
    unauthRate: unauth / H,
    callIndirectShare: indirect / H,
    sdkDeclaredRate: sdkDeclared / H,
    advisoryExposureByHash: sortDesc(adv),
    specRate: spec / H,
    eventsDeclaredRate: events / H,
  };
}

function addInto(target, src, w = 1) { for (const [k, v] of Object.entries(src ?? {})) target[k] = (target[k] ?? 0) + v * w; }
const sortDesc = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));

async function stageAggregate({ quiet = false } = {}) {
  const t0 = now();
  const meta = readJson(HASHES_JSON, null);
  if (!meta) throw new Error("no hashes.json yet");
  const results = existsSync(RESULTS)
    ? readFileSync(RESULTS, "utf8").split("\n").filter(Boolean).flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } })
    : [];
  if (!results.length) throw new Error("no results yet");
  const weightOf = (h) => meta.hashes[h] ?? { instances: 0, invocations: 0 };

  const ok = results.filter((r) => r.ok);
  const bad = results.filter((r) => !r.ok);
  const H = ok.length || 1;

  let instTotal = 0, invTotal = 0;
  for (const r of ok) { const w = weightOf(r.hash); instTotal += w.instances; invTotal += w.invocations; }

  const byClassH = {}, byClassI = {}, byClassV = {};
  const bySevH = {}, bySevI = {}, bySevV = {};
  const suppH = {}, gapH = {}, sdkVersions = {}, advisoryH = {}, advisoryI = {}, parseFailReasons = {};

  let findingsH = 0, findingsI = 0, findingsV = 0;
  let entrypoints = 0, indirect = 0, indirectI = 0, incomplete = 0, degraded = 0, approximate = 0;
  let sdkDeclared = 0, sdkUnparseable = 0, specHas = 0, eventsDeclared = 0, unauthHashes = 0, unauthInstances = 0;
  let totalBytes = 0, specFns = 0, specEvents = 0;
  const unauthNameFreq = {};

  for (const r of bad) {
    const key = (r.stage === "timeout" ? "watchdog timeout (30s)" : String(r.reason ?? "unknown")).slice(0, 90);
    parseFailReasons[key] = (parseFailReasons[key] ?? 0) + 1;
  }

  for (const r of ok) {
    const w = weightOf(r.hash);
    const wi = w.instances, wv = w.invocations;
    entrypoints += r.entrypoints;
    totalBytes += r.bytes;
    if (r.hasIndirect) { indirect++; indirectI += wi; }
    if (r.incomplete) incomplete++;
    if (r.degraded) degraded++;
    if (r.soundness === "approximate") approximate++;
    if (r.sdk.declared) { sdkDeclared++; sdkVersions[r.sdk.version] = (sdkVersions[r.sdk.version] ?? 0) + 1; }
    if (r.sdk.status === "nao-parseavel") sdkUnparseable++;
    if (r.spec.has) { specHas++; specFns += r.spec.fns; specEvents += r.spec.events; }
    if (r.spec.events > 0) eventsDeclared++;
    findingsH += r.findings; findingsI += r.findings * wi; findingsV += r.findings * wv;
    addInto(byClassH, r.byClass); addInto(byClassI, r.byClass, wi); addInto(byClassV, r.byClass, wv);
    addInto(bySevH, r.bySeverity); addInto(bySevI, r.bySeverity, wi); addInto(bySevV, r.bySeverity, wv);
    addInto(suppH, r.suppressed);
    for (const g of r.gaps) gapH[g] = (gapH[g] ?? 0) + 1;
    for (const a of r.advisories) { advisoryH[a] = (advisoryH[a] ?? 0) + 1; advisoryI[a] = (advisoryI[a] ?? 0) + wi; }
    if ((r.byClass["unauthenticated-state-mutation"] ?? 0) > 0) { unauthHashes++; unauthInstances += wi; }
    for (const n of r.unauthNames ?? []) unauthNameFreq[n] = (unauthNameFreq[n] ?? 0) + 1;
  }

  const singleInstance = Object.values(meta.hashes).filter((g) => g.instances === 1).length;
  const baseline = await corpusBaseline();

  /* --- stratification by usage tier ---------------------------------- */
  const tiered = { T0: [], T1: [], T2: [], T3: [] };
  for (const r of ok) tiered[tierOf(weightOf(r.hash))].push(r);
  const realUsage = [...tiered.T1, ...tiered.T2, ...tiered.T3];
  const byUsageTier = Object.fromEntries(TIERS.map((t) => [t, statBlock(tiered[t], weightOf)]));
  const usageView = {
    allHashes: statBlock(ok, weightOf),
    realUsage: statBlock(realUsage, weightOf),
    t3Only: statBlock(tiered.T3, weightOf),
  };

  /* --- triage candidates (PRIVATE: maps findings to hashes) ----------- */
  const nCandidates = writeTriageCandidates(meta, results);
  // the shortlists an online run works from — also private
  if (Object.values(meta.hashes)[0]?.busiest) writeTops(meta);

  const summary = {
    generatedAt: new Date().toISOString().slice(0, 10),
    network: "Stellar mainnet",
    reproduce: "node scripts/census.mjs",
    indexComplete: readJson(INDEX_STATE, {}).done === true,
    scope: {
      contractsIndexed: meta.totals.indexed,
      wasmContracts: meta.totals.wasmContracts,
      sacContracts: meta.totals.sacContracts,
      contractsWithNeitherCodeNorAsset: meta.totals.noCodeNoAsset,
      distinctCodeHashes: meta.totals.distinctHashes,
      crossCheck: meta.crossCheck,
      hashesFetched: readdirSync(WASM_DIR).filter((f) => f.endsWith(".wasm")).length,
      hashesAnalyzed: results.length,
      hashesAnalyzedOk: ok.length,
      coverageOfDistinctHashes: results.length / (meta.totals.distinctHashes || 1),
      instancesCovered: instTotal,
      coverageOfWasmInstances: instTotal / (meta.totals.wasmContracts || 1),
      invocationsCovered: invTotal,
      singleInstanceHashes: singleInstance,
      singleInstanceShare: singleInstance / (meta.totals.distinctHashes || 1),
      meanWasmKiB: Math.round(totalBytes / H / 102.4) / 10,
    },
    parse: {
      failures: bad.length,
      failureRate: bad.length / (results.length || 1),
      reasons: sortDesc(parseFailReasons),
      incomplete, degraded, approximate,
      approximateShare: approximate / H,
      callIndirectHashes: indirect,
      callIndirectShareByHash: indirect / H,
      callIndirectShareByInstance: indirectI / (instTotal || 1),
      entrypointsTotal: entrypoints,
      entrypointsPerHash: entrypoints / H,
    },
    findings: {
      total: findingsH,
      perHash: findingsH / H,
      perInstance: findingsI / (instTotal || 1),
      perInvocationWeighted: findingsV / (invTotal || 1),
      byClass: { perHash: sortDesc(byClassH), instanceWeighted: sortDesc(byClassI), invocationWeighted: sortDesc(byClassV) },
      bySeverity: { perHash: sortDesc(bySevH), instanceWeighted: sortDesc(bySevI), invocationWeighted: sortDesc(bySevV) },
      unauthenticatedStateMutation: {
        hashes: unauthHashes, hashShare: unauthHashes / H,
        instances: unauthInstances, instanceShare: unauthInstances / (instTotal || 1),
      },
    },
    usage: { view: usageView, byTier: byUsageTier, tierLabels: TIER_LABEL, triageCandidates: nCandidates },
    suppressions: { total: Object.values(suppH).reduce((a, b) => a + b, 0), byReason: sortDesc(suppH) },
    strideGapRateByHash: Object.fromEntries(
      ["Spoof", "Tamper", "Repudiate", "Info", "DoS", "Elevation"].map((s) => [s, (gapH[s] ?? 0) / H])),
    sdk: {
      declaredHashes: sdkDeclared, declaredRate: sdkDeclared / H,
      unparseableVersions: sdkUnparseable,
      versionHistogram: sortDesc(sdkVersions),
      advisoryExposureByHash: sortDesc(advisoryH),
      advisoryExposureByInstance: sortDesc(advisoryI),
    },
    spec: {
      withContractSpecV0: specHas, contractSpecV0Rate: specHas / H,
      withDeclaredEvents: eventsDeclared, declaredEventsRate: eventsDeclared / H,
      functionsPerSpec: specFns / (specHas || 1),
      eventsPerSpec: specEvents / (specHas || 1),
    },
    comparison: {
      corpus75: baseline,
      mainnet: {
        contracts: ok.length,
        findingsPerContract: findingsH / H,
        unauthRate: unauthHashes / H,
        callIndirectShare: indirect / H,
        sdkDeclaredRate: sdkDeclared / H,
        eventsDeclaredRate: eventsDeclared / H,
        specRate: specHas / H,
      },
    },
    endpointBehaviour: stats,
  };

  writeJson(join(REPO_OUT, "summary.json"), summary);
  writeFileSync(join(REPO_OUT, "SUMMARY.md"), renderMarkdown(summary));
  // the name histogram maps findings back to exports: private only
  writeJson(PRIV + "unauth-export-names.json", sortDesc(unauthNameFreq));
  if (!quiet) log(`  aggregate: corpus/census/summary.json + SUMMARY.md  ${secs(t0)}`);
}

function histTable(o, limit = 12) {
  const rows = Object.entries(o).slice(0, limit);
  if (!rows.length) return "| _none_ | |\n";
  return rows.map(([k, v]) => `| \`${k}\` | ${num(v)} |`).join("\n") + "\n";
}

function renderMarkdown(s) {
  const c = s.comparison;
  const cmp = (label, a, b, fmt) => `| ${label} | ${fmt(a)} | ${fmt(b)} |`;
  return `# Mainnet census — every distinct contract WASM on Stellar

Generated ${s.generatedAt} · ${s.network} · reproduce with \`${s.reproduce}\`
${s.indexComplete ? "" : "\n> **Partial run.** The contract index was still being enumerated when these numbers were\n> written. Rerun the command to finish it; the pipeline resumes.\n"}
This file contains **aggregates only**. Per-contract results — which code hash carries which
finding — stay outside this repository under the disclosure policy in \`SECURITY.md\`.

The unit of analysis is the **distinct code hash**, not the contract: one WASM deployed 900
times is one binary with one set of findings. Every rate is therefore given twice — once per
hash (what a binary looks like) and once weighted by the number of deployed instances (what a
contract picked at random on the ledger looks like).

## Scope

| | |
|---|---|
| Contracts indexed | **${num(s.scope.contractsIndexed)}** |
| … with WASM code | ${num(s.scope.wasmContracts)} |
| … Stellar Asset Contracts (no WASM) | ${num(s.scope.sacContracts)} |
| … neither code nor asset recorded | ${num(s.scope.contractsWithNeitherCodeNorAsset)} |
| Distinct code hashes | **${num(s.scope.distinctCodeHashes)}** |
| Hashes fetched from the ledger | ${num(s.scope.hashesFetched)} |
| Hashes analyzed | **${num(s.scope.hashesAnalyzed)}** (${pct(s.scope.coverageOfDistinctHashes)} of distinct) |
| … parsed successfully | ${num(s.scope.hashesAnalyzedOk)} |
| Instances covered by the analyzed hashes | ${num(s.scope.instancesCovered)} (${pct(s.scope.coverageOfWasmInstances)} of WASM contracts) |
| Invocations covered | ${num(s.scope.invocationsCovered)} |
| Hashes deployed exactly once | ${num(s.scope.singleInstanceHashes)} (${pct(s.scope.singleInstanceShare)} of distinct) |
| Mean module size | ${s.scope.meanWasmKiB} KiB |
${s.scope.crossCheck ? `| Cross-check vs \`contract-stats\` (wasm / sac) | ${num(s.scope.crossCheck.expertWasm)} / ${num(s.scope.crossCheck.expertSac)} (delta ${s.scope.crossCheck.wasmDelta} / ${s.scope.crossCheck.sacDelta}) |` : ""}

## Parser and soundness

| | |
|---|---|
| Parse failures | **${num(s.parse.failures)}** (${pct(s.parse.failureRate)}) |
| Modules with \`incomplete\` sections | ${num(s.parse.incomplete)} |
| Modules with a degraded body | ${num(s.parse.degraded)} |
| Analysis downgraded to \`approximate\` | **${num(s.parse.approximate)}** (${pct(s.parse.approximateShare)}) |
| \`call_indirect\` present — per hash | ${num(s.parse.callIndirectHashes)} (${pct(s.parse.callIndirectShareByHash)}) |
| \`call_indirect\` present — instance-weighted | ${pct(s.parse.callIndirectShareByInstance)} |
| Entrypoints | ${num(s.parse.entrypointsTotal)} total · ${s.parse.entrypointsPerHash.toFixed(1)} per hash |

Parse failure reasons:

| Reason | Hashes |
|---|---|
${histTable(s.parse.reasons, 15)}
## Findings — unweighted totals

These are the raw totals over every analyzed binary, usage-blind. They are kept because they
are the honest denominator, but the usage-stratified table further down is the one to quote.

| | Per hash | Instance-weighted | Invocation-weighted |
|---|---|---|---|
| Findings per contract | **${s.findings.perHash.toFixed(2)}** | ${s.findings.perInstance.toFixed(2)} | ${s.findings.perInvocationWeighted.toFixed(2)} |

Total findings over the analyzed hashes: **${num(s.findings.total)}**.

### By class

| Class | Hashes | Instance-weighted |
|---|---|---|
${Object.keys(s.findings.byClass.perHash).map((k) =>
  `| \`${k}\` | ${num(s.findings.byClass.perHash[k])} | ${num(s.findings.byClass.instanceWeighted[k] ?? 0)} |`).join("\n") || "| _none_ | | |"}

### By severity

| Severity | Per hash | Instance-weighted |
|---|---|---|
${["Critical", "High", "Medium", "Low"].map((k) =>
  `| ${k} | ${num(s.findings.bySeverity.perHash[k] ?? 0)} | ${num(s.findings.bySeverity.instanceWeighted[k] ?? 0)} |`).join("\n")}

### \`unauthenticated-state-mutation\`

| | |
|---|---|
| Hashes with at least one | **${num(s.findings.unauthenticatedStateMutation.hashes)}** (${pct(s.findings.unauthenticatedStateMutation.hashShare)}) |
| Instance-weighted | ${num(s.findings.unauthenticatedStateMutation.instances)} contracts (${pct(s.findings.unauthenticatedStateMutation.instanceShare)}) |

## How to read severity

Severity is a **tier-C judgement** applied to a **tier-A over-approximate positive**: the
bytecode fact is "this export does not reach \`require_auth\` and does reach a storage write";
"that is Critical" is an inference on top of it. On the calibration sample of 30 triaged
\`unauthenticated-state-mutation\` findings, **9 (30%) were real** missing authorization and
**0 allowed loss of funds** (\`docs/PRECISION.md\`).

The census makes a second correction necessary. ${pct(s.scope.singleInstanceShare)} of distinct
binaries are deployed exactly once, and a large share of those are tutorials, tests and
abandoned deploys whose exports are named \`increment\`, \`sum\`, \`sub\`, \`a\`, \`exec_op\`.
**A Critical on a single-instance, never-invoked contract is a tutorial contract, not an
incident.** Read the usage-stratified table below, not the raw per-hash counts, and treat the
T3 column as the one that describes code people actually run.

## Findings by usage tier

Tiers come from the index: instances of the hash, and invocations summed over them.

${TIERS.map((t) => `- **${t}** — ${s.usage.tierLabels[t].replace(/^T\d — /, "")}`).join("\n")}

| Tier | Hashes | Instances | Invocations | Findings/hash | Critical/hash | High/hash | unauth-mutation rate | SDK declared | spec / events declared |
|---|---|---|---|---|---|---|---|---|---|
${TIERS.map((t) => {
  const b = s.usage.byTier[t];
  return `| ${t} | ${num(b.hashes)} | ${num(b.instances)} | ${num(b.invocations)} | ${b.findingsPerHash.toFixed(2)} | ${b.criticalPerHash.toFixed(3)} | ${b.highPerHash.toFixed(3)} | ${pct(b.unauthRate)} | ${pct(b.sdkDeclaredRate)} | ${pct(b.specRate)} / ${pct(b.eventsDeclaredRate)} |`;
}).join("\n")}

### Headline — all hashes vs hashes with real usage

| Metric | All hashes | Real usage (T1+T2+T3) | T3 only (≥10 instances) |
|---|---|---|---|
| Hashes | ${num(s.usage.view.allHashes.hashes)} | ${num(s.usage.view.realUsage.hashes)} | ${num(s.usage.view.t3Only.hashes)} |
| Findings per hash | **${s.usage.view.allHashes.findingsPerHash.toFixed(2)}** | **${s.usage.view.realUsage.findingsPerHash.toFixed(2)}** | **${s.usage.view.t3Only.findingsPerHash.toFixed(2)}** |
| Critical per hash | ${s.usage.view.allHashes.criticalPerHash.toFixed(3)} | ${s.usage.view.realUsage.criticalPerHash.toFixed(3)} | ${s.usage.view.t3Only.criticalPerHash.toFixed(3)} |
| \`unauthenticated-state-mutation\` rate | ${pct(s.usage.view.allHashes.unauthRate)} | ${pct(s.usage.view.realUsage.unauthRate)} | ${pct(s.usage.view.t3Only.unauthRate)} |
| \`call_indirect\` share | ${pct(s.usage.view.allHashes.callIndirectShare)} | ${pct(s.usage.view.realUsage.callIndirectShare)} | ${pct(s.usage.view.t3Only.callIndirectShare)} |

### Per class, by tier

| Class | ${TIERS.join(" | ")} |
|---|${TIERS.map(() => "---").join("|")}|
${[...new Set(TIERS.flatMap((t) => Object.keys(s.usage.byTier[t].byClass)))].map((cl) =>
  `| \`${cl}\` | ${TIERS.map((t) => num(s.usage.byTier[t].byClass[cl] ?? 0)).join(" | ")} |`).join("\n") || "| _none_ | | | | |"}

### Per severity, by tier

| Severity | ${TIERS.join(" | ")} |
|---|${TIERS.map(() => "---").join("|")}|
${["Critical", "High", "Medium", "Low"].map((sev) =>
  `| ${sev} | ${TIERS.map((t) => num(s.usage.byTier[t].bySeverity[sev] ?? 0)).join(" | ")} |`).join("\n")}

### Advisory exposure, by tier

| Advisory | ${TIERS.join(" | ")} |
|---|${TIERS.map(() => "---").join("|")}|
${[...new Set(TIERS.flatMap((t) => Object.keys(s.usage.byTier[t].advisoryExposureByHash)))].map((a) =>
  `| ${a} | ${TIERS.map((t) => num(s.usage.byTier[t].advisoryExposureByHash[a] ?? 0)).join(" | ")} |`).join("\n") || "| _none_ | | | | |"}

${num(s.usage.triageCandidates)} hashes qualify for the next manual source triage (a Critical or
High \`unauthenticated-state-mutation\` on a binary with at least 2 instances or 100
invocations). The list itself is private, for the same reason as everything else in this file.

## Declared suppressions

${num(s.suppressions.total)} entrypoints filtered, never silently — each carries a reason.

| Reason | Count |
|---|---|
${histTable(s.suppressions.byReason, 12)}
## STRIDE gap rate

Share of hashes where the letter has **no derivable finding** and ships as a declared gap.

| Letter | Gap rate |
|---|---|
${Object.entries(s.strideGapRateByHash).map(([k, v]) => `| ${k} | ${pct(v)} |`).join("\n")}

## SDK version (\`rssdkver\` in \`contractmetav0\`)

| | |
|---|---|
| Hashes declaring a version | **${num(s.sdk.declaredHashes)}** (${pct(s.sdk.declaredRate)}) |
| Declared but not parseable as semver | ${num(s.sdk.unparseableVersions)} |

Top declared versions:

| Version | Hashes |
|---|---|
${histTable(s.sdk.versionHistogram, 15)}
Advisory exposure — a **bytecode fact** (tier A: which SDK compiled the binary), not
exploitability:

| Advisory | Hashes | Instance-weighted |
|---|---|---|
${Object.keys(s.sdk.advisoryExposureByHash).map((k) =>
  `| ${k} | ${num(s.sdk.advisoryExposureByHash[k])} | ${num(s.sdk.advisoryExposureByInstance[k] ?? 0)} |`).join("\n") || "| _none_ | | |"}

## Contract spec

| | |
|---|---|
| Hashes with \`contractspecv0\` | **${num(s.spec.withContractSpecV0)}** (${pct(s.spec.contractSpecV0Rate)}) |
| Hashes declaring at least one event | ${num(s.spec.withDeclaredEvents)} (${pct(s.spec.declaredEventsRate)}) |
| Functions per spec (mean) | ${s.spec.functionsPerSpec.toFixed(1)} |
| Events per spec (mean) | ${s.spec.eventsPerSpec.toFixed(2)} |

## 75-contract corpus vs whole mainnet

The corpus was selected by on-chain event activity, so it over-samples contracts that are
actually used. The mainnet column is one row per distinct binary, most of which are deployed
once — the two columns are not expected to match, and the gap is the point.

| Metric | 75-contract corpus | Whole mainnet (per hash) |
|---|---|---|
${cmp("Findings per contract", c.corpus75.findingsPerContract, c.mainnet.findingsPerContract, (x) => x.toFixed(2))}
${cmp("Share with `unauthenticated-state-mutation`", c.corpus75.unauthRate, c.mainnet.unauthRate, pct)}
${cmp("`call_indirect` share (analysis downgraded)", c.corpus75.callIndirectShare, c.mainnet.callIndirectShare, pct)}
${cmp("SDK version declared", c.corpus75.sdkDeclaredRate, c.mainnet.sdkDeclaredRate, pct)}
${cmp("Events declared in spec", c.corpus75.eventsDeclaredRate, c.mainnet.eventsDeclaredRate, pct)}
${cmp("Has `contractspecv0`", c.corpus75.specRate, c.mainnet.specRate, pct)}

Corpus baseline recomputed by this script with the same detectors: ${c.corpus75.contracts} contracts,
${c.corpus75.parseFailures} parse failures, ${num(c.corpus75.findings)} findings.

## Method

1. Enumerate every contract from \`api.stellar.expert/explorer/public/contract\` (\`order=asc\`,
   200 per page, following \`_links.next\`). Records carry the current code hash for WASM
   contracts and an asset for Stellar Asset Contracts.
2. Group by code hash; keep per-hash instance count, summed invocations and events, earliest
   creation.
3. Fetch each distinct WASM from a mainnet RPC with a \`ContractCode\` ledger key and verify
   sha256 == the hash.
4. Run \`analyzeModule\` + \`detectFull\` + \`readSdkMeta\` + the \`contractspecv0\` parse on each
   binary, in a child process with a 30 s watchdog so one pathological module cannot stall the
   census.
5. Aggregate. Only this step writes into the repository.

Steps 1–4 run as a pipeline: a hash discovered on page *n* is fetched and analyzed while page
*n+1* is still being requested.

### Caveats

- A code hash is the **current** executable of its instances. Contracts upgraded since the
  index was taken are counted under their new hash.
- Instance and invocation weights come from the explorer, not from the ledger directly.
- Findings are over-approximate positives by construction (see \`README.md\`, "The rule that
  governs the output"): a rate here is an upper bound on a rate of real issues, not a count of
  vulnerabilities. Precision was measured on the 75-contract corpus only (\`docs/PRECISION.md\`).
- Recall is not measured, here or anywhere.
`;
}

/* ------------------------------------------------------------------ *
 * main
 * ------------------------------------------------------------------ */

const HELP = `soroguard mainnet census

  node scripts/census.mjs [stage] [options]

Stages (no stage = the whole pipeline: index -> fetch -> analyze -> aggregate, resumable)
  hashes       regroup the CACHED index pages into hashes.json, then the shortlists. No network.
  tops         rebuild top-by-volume.json, top-by-instances.json and triage-candidates.jsonl
               from hashes.json + results.jsonl. No network.
  aggregate    aggregate whatever is on disk into corpus/census/

Options
  --max-hashes <n>            cap the number of distinct modules fetched/analyzed
  --representative <mode>     which instance of a code hash stands in for the family wherever a
                              contract id is written (hashes.json, the shortlists, the triage
                              list). One of:
                                busiest   the instance with the most invocations  [default]
                                newest    the most recently created instance
                              A family is many deploys of one binary; the wrong pick describes a
                              dormant sibling instead of the deploy that carries the traffic.
  --help, -h                  this text

Per-hash record in hashes.json: instances, siblings, invocationsSum, eventsSum,
busiest {contract, invocations, events}, newest {contract, created}, representative.
`;

if (process.argv.includes("--analyze-worker")) {
  await analyzeWorkerMain();
} else {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(HELP);
    process.exit(0);
  }
  const maxAt = args.indexOf("--max-hashes");
  const maxHashes = maxAt >= 0 ? Number(args[maxAt + 1]) : 0;
  const repAt = args.indexOf("--representative");
  if (repAt >= 0) {
    const mode = args[repAt + 1];
    if (!REP_MODES.includes(mode)) {
      console.error(`--representative must be one of: ${REP_MODES.join(" | ")}`);
      process.exit(2);
    }
    REPRESENTATIVE = mode;
  }
  const valueAt = new Set([maxAt >= 0 ? maxAt + 1 : -1, repAt >= 0 ? repAt + 1 : -1]);
  const wanted = args.filter((a, i) => !a.startsWith("--") && !valueAt.has(i));
  const T0 = now();
  if (wanted.includes("aggregate") && wanted.length === 1) {
    await stageAggregate({});
  } else if (wanted.includes("hashes") && wanted.length === 1) {
    stageHashes();
    stageTops();
  } else if (wanted.includes("tops") && wanted.length === 1) {
    stageTops();
  } else {
    await pipeline(maxHashes);
  }
  log(`\ntotal ${secs(T0)}  |  endpoint: ${JSON.stringify(stats)}`);
  process.exit(0);
}
