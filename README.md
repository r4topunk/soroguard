# soroguard

Generates the two artifacts that an **SCF Build tranche #2** release requires — a STRIDE threat
model and an on-chain monitoring plan, in the official Stellar templates — from the **deployed
WASM** of a Soroban contract. No source code needed. Since round #44 every Build project has to
hand in both documents to unlock tranche #2 (30% of the award), that is roughly 35 teams per
round, and the SDF published the templates without publishing any tooling to fill them. Every
claim in the output carries an evidence tier, and anything the binary does not support is
printed as a declared gap instead of boilerplate.

```sh
npx soroguard artifact CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5   # from a clone: pnpm install && pnpm dev artifact …
```

```
  … observing on-chain events on mainnet, ~15 s…
  … observed window: 239977 ledgers (~375 h), 4 distinct topics, 24 getEvents pages, limited by request-budget
  … probing 1 init finding with unsigned simulateTransaction…
  … probe: 0 guarded · 0 open · 1 inconclusive

  out/CDZZ5HUOBL2QGELMWQMW-threat-model.md
  out/CDZZ5HUOBL2QGELMWQMW-monitoring-plan.md

  1 threat · 1 monitor · 5 STRIDE gaps declared
  analysis sound

  VALIDATION — threat model: NEEDS INPUT — 6 items for the team (see worksheets)
    needs the team:
    ☐ Write section 1, "What are we working on?": …
    ☐ STRIDE letter Spoof has no issue — the template requires at least one; fill it from
      the worksheet in the Spoof gap section (it lists the concrete surface to review).
    ☐ … (Tamper, Repudiate, Info, DoS)
  VALIDATION — monitoring plan: NEEDS INPUT — 1 item for the team (see worksheets)
    ☐ Assign an owner and a notification channel to 1 row of §5; neither is derivable
      from the binary, and a monitor with no owner has no one to fire at.
```

(Abbreviated; the window figures move between runs.) The verdict has three states. **SUBMITTABLE** means
both checklists pass. **NEEDS INPUT** means the tool did its part and lists, numbered, what only the
team can write: the template requires at least one issue per STRIDE letter, and the bytecode supports
one letter for this contract, so each empty letter comes with a worksheet (which entrypoints assert
identity, which storage keys and topics are public, which TTL paths renew) instead of boilerplate.
**NOT SUBMITTABLE** is reserved for the tool's own failures: a claim it cannot back, an orphan
monitor, a baseline that would be invented. Init findings are probed with an unsigned
`simulateTransaction`: an already-initialized revert closes the finding by observation; a successful
simulation means anyone can initialize the instance right now and is surfaced as such.

## Why the deployed binary, not the source

Scout (CoinFabrik), Guard-CLI, Persist and Komet all read Rust source. Reading the artifact
answers a different question: **what is actually live right now.** The repository can move after
the deploy; the ledger does not.

The concrete shape this takes in practice: a repository gains an authorization check months
after several instances were deployed, and those instances keep running the pre-fix code. A
source-level tool pointed at the repository today sees nothing; the deployed WASM shows the
missing check. The corpus contains cases of this shape. They are not described further here
because private disclosure to the affected teams is in progress; `docs/PRECISION.md` gives the
measured numbers without the identities, and the per-finding triage will be published once
disclosure completes.

**CVE-2026-26267 as inventory.** 69 of the 71 corpus contracts declare their SDK version in the
`contractmetav0` custom section; 37 of those were compiled with a version range affected by
CVE-2026-26267 (High, authorization bypass in `soroban-sdk-macros`). Of the 20 whose source we
could obtain when 34 were exposed under the earlier parser, none has the `impl Trait` / `impl C` name collision that triggers the
bug; the other 14 could not be concluded (11 with no public source, 3 with a probable but
unconfirmed one), and **0 were confirmed vulnerable**
(`docs/CVE-2026-26267-VERIFICACAO.md`). Exposure is a bytecode fact (tier A), exploitability
needs the source (tier C) — so the finding ships as **Low**, carrying the advisory's High in its
evidence rather than in its severity. What only the artifact records is which SDK compiled the
binary that is on the ledger.

The second reason is plainer: you can analyze a third-party contract you integrate with without
asking anyone for the repository.

## How it works

```
contract id
  |- getContractWasmByContractId          -> WASM bytes
  |- custom section contractspecv0        -> functions, error enums, events + prefixTopics
  |- custom section contractmetav0        -> soroban-sdk version -> advisories
  |- import section -> env.json           -> 199 host functions (a.0 = require_auth, ...)
  |- code section -> call graph           -> what EACH entrypoint reaches
  |- data section                         -> inferred storage keys
  `- getEvents                            -> what the contract actually emitted + baseline
```

The bridge that makes the monitoring plan executable is in the spec: it declares `prefixTopics`
per event (`tw_withdraw`), and those are the filter of a `getEvents` call. The link between
"event declared in the contract" and "monitoring rule you can run" is already inside the binary.

The threat ID is the foreign key between the two documents: the threat model emits
`Elevation.1`, the monitoring plan derives `Elevation.1.M.1`, and validation refuses a monitor
with no threat behind it.

## The rule that governs the output

**Three evidence tiers, and none is presented as stronger than it is.**

| | What it is | Example |
|---|---|---|
| **A** | bytecode fact | `initialize` does not reach `require_auth` |
| **B** | fact observed on-chain | a 239,977-ledger window (~375 h) recorded 12 events across 4 topics; `initialize` reverted already-initialized in simulation |
| **C** | inference | "this allows front-running if the deploy is not atomic" |

And the asymmetry that everything rests on: **"does not reach X" is proof; "reaches X" is an
over-approximation.** Reachability is path- and context-insensitive, so a positive may cross a
shared helper whose write branch this entrypoint never executes. Every positive claim therefore
carries its hop count, and a long path carries an explicit review warning. When `call_indirect`
is present in the subgraph the call graph is incomplete and not even the negative holds: the
module is marked `approximate` and the claims are downgraded.

A section with no evidence is **declared as a gap**, never filled with generic text. Suppression
is never silent: every filtered entrypoint lands in `suppressed` with a reason, and a test fails
if an entrypoint is both suppressed and reported.

## Usage

```sh
npx soroguard inspect  <target>              # spec: functions, errors, events + topics
npx soroguard analyze  <target>              # call graph, findings, suppressions, gaps
npx soroguard artifact <target>              # the two documents + validation
```

`<target>` is a contract id (`C…`, 56 chars) or the path to a local `.wasm`. The `npx` form works
once the package is on npm; from a clone, with no build step, the same commands are
`node src/cli.ts <command> <target>`.

| Flag | Effect |
|---|---|
| `--offline` | do not touch the network (no tier-B baseline) |
| `-n, --network <name\|url>` | `mainnet`, `testnet`, … or a full https RPC URL |
| `--timeout <s>` | budget, in seconds, for the on-chain observation phase (default 60) |
| `-o, --out <dir>` | output directory (default `out`) |
| `--date <YYYY-MM-DD>` | date (UTC) stamped on the documents |
| `--json` | machine-readable output (`inspect`, `analyze`) |
| `--min <sev>` | drop findings below this severity (`analyze`) |
| `--debug` | print the stack on error instead of a single line |

`SOROGUARD_RPC_URL` sets the default endpoint. Without it, `mainnet` resolves to a public
community RPC that is rate limited.

| Exit code | Meaning |
|---|---|
| `0` | ran; the documents were written |
| `1` | usage error (bad contract id, unknown network, missing file), or no subcommand |
| `2` | documents written, but the on-chain observation failed — no tier-B baseline |

**What `--offline` cannot produce.** Tier B: the observation window, the init probe and the
instance wasm hash. Offline the monitoring plan comes out **NOT SUBMITTABLE** with the reason
(`run without --offline`); an offline run that claimed otherwise would be inventing the one
number the template asks you to measure.

## MCP server

`soroguard-mcp` is a stdio MCP server (JSON-RPC 2.0, hand-written, no extra dependency) exposing
three tools:

| Tool | Returns |
|---|---|
| `soroguard_inspect` | typed functions, error enums, declared events with their `prefixTopics` |
| `soroguard_analyze` | call graph reachability per entrypoint, findings tagged by evidence tier, declared suppressions, STRIDE letters with no derivable evidence |
| `soroguard_sdk_advisories` | the `rssdkver` recorded in the binary checked against known advisories — exposure (tier A), not exploitability |

All three take `target` and an optional `network`.

```sh
claude mcp add soroguard -- npx -y soroguard-mcp
```

```json
{
  "mcpServers": {
    "soroguard": {
      "command": "npx",
      "args": ["-y", "soroguard-mcp"]
    }
  }
}
```

## Precision and recall

Three measurements, all read-only against public source at the deployed commit or unsigned
on-chain probes. Detail in `docs/PRECISION.md` and `docs/PRECISION-TOP25.md`.

| Measurement | Sample | Real unauth. mutation | Loss of funds today | False tier-A claims |
|---|---|---|---|---|
| calibration batches 1+2 | 17 corpus contracts, 26 findings | 5 / 26 | 0 on the triaged instances | 0 |
| top 25 by volume | busiest 25 mainnet binaries, all 66 findings | 0 / 7 | 0 / 66 | 0 |

The missing-authorization detector finds real cases only in small, low-traffic contracts; at the
top of mainnet it finds design (timelocked admin queues, permissionless cranks, self-paying
`claim`), not bugs. In every batch every negative claim matched the source. What the tool is worth
on busy code is the inventory, the data-flow diagram, the declared gaps and the refusal to invent
a baseline.

**Recall**, first evidence from the top-25 triage: three things the source showed and the tool
missed — an SDK version hidden by a duplicated custom section (parser fixed), third-party state
tampering through a permissionless entrypoint (new detector), and a signature verifier implemented
inside the contract (new detector). Recall on a labelled corpus (the Audit Bank's 57 public
reports) is still the measurement that is missing.

For calibration against source-level tools: CoinFabrik measured its `set-contract-storage`
detector on 71 contracts at 59.41% false positives. Bytecode reachability is not better than
source analysis at this class; it answers a different question (what is live).

## Reproducibility

The corpus is committed, not fetched at test time. `corpus/*.wasm` is 71 mainnet contracts (4 more
are withheld pending private disclosure, see `corpus/README.md`);
`corpus/index.json` records the sha256 of each file, which is the wasm hash on-chain, so anyone
can verify the committed bytes are what is deployed:

```sh
shasum -a 256 corpus/<contractId>.wasm   # compare with index.json[<contractId>].wasmHash

node scripts/fetch-corpus.mjs            # re-fetch the corpus from mainnet RPC
node scripts/calibrate.mjs               # run the full taxonomy over the corpus
node scripts/stats.mjs                   # regenerate every number in this README
```

Renderers never read the clock: the date enters through `ArtifactContext.generatedAt`, so the
same wasm always produces byte-identical documents.

## Mainnet census

The corpus is a sample. To check whether it is a representative one, the same
analysis was run over **every distinct contract binary deployed on Stellar mainnet**:

```sh
node scripts/census.mjs                  # index -> fetch -> analyze -> aggregate, resumable
```

| | |
|---|---|
| Contracts indexed (2026-09-17) | **151,079** — 147,051 with WASM, 4,014 Stellar Asset Contracts |
| Distinct code hashes, all fetched and analyzed | **3,677** |
| Parse failures | **0** |
| Findings per binary | **2.21** (2.19 among binaries with real usage, 2.72 among those with ≥10 instances) |
| Binaries with an `unauthenticated-state-mutation` finding | **22.2%** — 3.2% instance-weighted |
| `rssdkver` declared | **56.4%**; 1,592 binaries (139,610 deployed contracts) sit in a CVE-2026-26267 affected range |

The corpus turns out to track mainnet closely: 2.16 vs 2.21 findings per contract, 54.7% vs
56.4% SDK declared, 24.0% vs 23.4% declaring events. Full aggregates, stratified by usage tier
so tutorial binaries do not dominate the severity counts: **[`corpus/census/SUMMARY.md`](corpus/census/SUMMARY.md)**.

Only aggregates are published. Nothing that maps a finding to a contract id, a code hash or a
project enters this repository — see `SECURITY.md`.

<!-- stats:start -->
<!-- Generated by `node scripts/stats.mjs --write` — do not edit by hand. -->

| Measurement | Value |
|---|---|
| Tests (`pnpm test`) | **208 passing** of 208 |
| Corpus (`corpus/*.wasm`) | **71 mainnet contracts**, 1,726 entrypoints, 0 parse failures |
| Findings | **164** total · **2.3 per contract** |
| By class | 48 `silent-mutation` · 38 `vulnerable-sdk` · 35 `initialization-front-running` · 13 `self-implemented-signature-verification` · 10 `unauthenticated-state-mutation` · 9 `archival-risk` · 7 `third-party-state-tampering` · 3 `host-prng-in-value-path` · 1 `write-before-auth` |
| `call_indirect` (analysis downgraded) | **22 of 71** (31%) |
| Declared suppressions | **111**<br>52 — read-shaped name: the write probably comes from a shared helper, not from this path<br>46 — reserved `__` function, not directly invocable (CAP-0058)<br>13 — permissionless crank by design (protocol maintenance pattern) |
| Downgrades (reported, not suppressed) | **4**<br>4 — reaches call/try_call — authorization may live in the callee, severity capped at High |
| SDK version declared (`rssdkver`) | **69 of 71** |
| In a CVE-2026-26267 affected range (High) | **37 of 69** that declare a version |
| Source lines (`src` + `test`) | 13,546 in 31 files |
<!-- stats:end -->

## What it does not do

- **It does not analyze source.** Scout, Guard-CLI and Persist do that, and do it well. Run all
  of them.
- **It is not a linter.** The product is the artifact, not the detector count.
- **It does not propose automatic patches.** Remediation is tier C and goes out labelled as a
  proposal.
- **It does not cover off-chain threats.** It declares the boundary instead of pretending to
  cover it.
- **It does not support contracts without `contractspecv0`** (Stellar Asset Contracts). It
  detects the case and prints a one-line message saying so.

## Known limits

These are boundaries, not bugs, and the documents say so in the output.

- **Spoofing and Information disclosure come out as gaps on most contracts.** Identity and data
  exposure are not observable in bytecode. The exception is the signature-verifier detector,
  which turns Spoofing into an issue on 13 of 71 corpus contracts.
- **Most contracts declare no events** (57 of 71 in the corpus, 23 of the 25 busiest on mainnet),
  so no event-based baseline exists for them. State-diff monitoring via `getLedgerEntries` is
  declared as a fill-in, not built.
- **No document passes its own checklist without human input.** The threat model needs the team
  for every STRIDE letter the bytecode cannot fill; the monitoring plan needs owner and channel.
  The verdict says exactly which items, and separates them from the tool's own failures.
- **Storage durability and TTL are not readable from the bytecode** in the general case; the
  archival finding is declared with that gap.
- **The addresses a contract calls are not derivable** — they are runtime arguments.
- **Positive reachability is over-approximate.** Every "reaches X" carries a hop count and, past
  two hops, a review warning; measured precision is above.

## How this was built

SCF's Open Track requires disclosing AI use. This project is an extreme case of it, so the
disclosure is specific rather than a checkbox.

soroguard was built with AI coding agents: a first session of about 41 minutes of wall-clock
time producing the parser, the detectors, the renderers and the corpus tooling, followed by a
review and hardening pass (English output, committed corpus, fail-closed parser, recalibrated
detectors, packaging, a whole-mainnet census, a triage of the 25 busiest contracts, an init
probe and a de-bloat pass) driven the same way. The design decisions, the quality contract in
`docs/PROBLEMA.md`, and every number published here were reviewed by a human.

Specifically human-verified, not agent-asserted:

- the corpus hashes (sha256 of the committed bytes against the on-chain wasm hash);
- the triage of 30 `unauthenticated-state-mutation` findings against contract source;
- the CVE-2026-26267 source verification: 4 hash matches and one source reading re-checked by hand, the other 15 "not affected" verdicts are agent-produced source readings, 14 contracts have no conclusion;
- the ~40 audit reports the threat taxonomy was confronted with
  (`docs/TAXONOMIA-VALIDACAO.md`).

Recall has first evidence (three misses, above) but no labelled-corpus number yet.

## Documentation

| | |
|---|---|
| `docs/PROBLEMA.md` | the quality contract: evidence tiers and what would turn this into slop |
| `docs/CALIBRACAO.md` | the false-positive removal log, iteration by iteration |
| `docs/TAXONOMIA-VALIDACAO.md` | 16 threat classes confronted with ~40 audits (Veridise, Certora, OtterSec, Runtime Verification, Code4rena, OpenZeppelin), 56 URLs |
| `docs/CVE-2026-26267-VERIFICACAO.md` | the source check of the 34 exposed contracts |
| `SECURITY.md` | disclosure policy for findings about third-party contracts |
| `docs/PRECISION.md` | the 30-finding triage against source, summarised |
| `docs/PRECISION-TOP25.md` | every finding on the 25 most-invoked mainnet code hashes, triaged against source: 0 of 7 auth findings real, 0 of 66 loss of funds, 0 false tier-A claims, and what the tool missed |
| `corpus/README.md` | corpus provenance, verification and regeneration |
| `corpus/census/` | the whole-mainnet census: aggregates over every distinct deployed binary (`SUMMARY.md`, `summary.json`) |
| `CONTRIBUTING.md` | how to change a detector without regressing precision |
| `examples/` | generated documents for real mainnet contracts |
| `docs/HANDOFF.md`, `docs/REVISAO-SCF.md` | internal working notes, in Portuguese: project state and the pre-submission review |

## Requirements

Node ≥ 22.18 (native type-stripping, no build step in development). No runtime dependency
beyond `@stellar/stellar-sdk` and `commander`.

## License

Apache-2.0
