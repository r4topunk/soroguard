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
  … observed window: 120662 ledgers (~185.8 h), 0 distinct topics

  out/CDZZ5HUOBL2QGELMWQMW-threat-model.md
  out/CDZZ5HUOBL2QGELMWQMW-monitoring-plan.md

  1 threat · 1 monitor · 5 STRIDE gaps declared
  analysis sound

  VALIDATION — threat model: NOT submittable
    ✖ STRIDE letter Spoof has no issue — the template requires at least one; fill it from
      the worksheet in the Spoof gap section (it lists the concrete surface to review).
    ✖ … (Tamper, Repudiate, Info, DoS)
  VALIDATION — monitoring plan: NOT submittable
    ✖ The observed window of 120662 ledgers recorded no event of any topic for this
      contract: that is absence of traffic, not a traffic profile. …
    ✖ Assign an owner and a notification channel to 1 row of §5; neither is derivable
      from the binary, and a monitor with no owner has no one to fire at.
```

(Abbreviated; the window figures move between runs.) Both verdicts are the feature, not an
error: the tool validates its own output against the template's "Did we do a good job?"
checklist and refuses to call a document submittable when the evidence is not there. The
template requires at least one issue per STRIDE letter, and the bytecode supports only one
letter for this contract, so the threat model ships with a worksheet per empty letter (the
concrete surface the team has to review: which entrypoints assert identity, which storage keys
and topics are public, which TTL paths renew) instead of boilerplate. The monitoring plan needs
an owner, a channel and a contract that actually emits events. What the tool delivers is the
half of both documents that can be derived and checked, with the other half named.

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

**CVE-2026-26267 as inventory.** 41 of 75 mainnet contracts in the corpus declare their SDK
version in the `contractmetav0` custom section; 34 of those were compiled with a version range
affected by CVE-2026-26267 (High, authorization bypass in `soroban-sdk-macros`). Of the 20 whose
source we could obtain, none has the `impl Trait` / `impl C` name collision that triggers the
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
| **B** | fact observed on-chain | a 120,662-ledger window (~186 h) recorded 0 events of any topic |
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
| `--lang en\|pt` | output language; `en` is the default |
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

**What `--offline` cannot produce.** The baseline in section 4 of the monitoring plan is tier B
by definition: it is an observation window, not something derivable from bytecode. Offline there
is no window, so the monitoring plan comes out marked **not submittable**, with the blockers
named and the reason given (`run without --offline`). That is deliberate — an offline run that
claimed to be submittable would be inventing the one number the template asks you to measure.

## MCP server

`soroguard-mcp` is a stdio MCP server (JSON-RPC 2.0, hand-written, no extra dependency) exposing
three tools:

| Tool | Returns |
|---|---|
| `soroguard_inspect` | typed functions, error enums, declared events with their `prefixTopics` |
| `soroguard_analyze` | call graph reachability per entrypoint, findings tagged by evidence tier, declared suppressions, STRIDE letters with no derivable evidence |
| `soroguard_sdk_advisories` | the `rssdkver` recorded in the binary checked against known advisories — exposure (tier A), not exploitability |

All three take `target`, optional `network`, and `lang` (`en` \| `pt`).

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

## Precision

The honest version, in the order the numbers were produced:

| Step | Measure | What it means |
|---|---|---|
| bare auth predicate | precision **≤16%** (upper bound) | derived from name shape across the corpus, not from human ground truth |
| after three suppression families | `unauthenticated-state-mutation` 89 → 24 findings (today's calibration) | reserved `__` exports (CAP-0058), read-shaped names, permissionless cranks |
| human triage against source | **9 of 30 real** (30%) | 30 findings triaged one by one; 21 permissionless by design; **0 detector bugs**; 0 allow loss of funds today |
| negative claims | **30 of 30 confirmed** | every "does not reach `require_auth`" matched the source |

For calibration: CoinFabrik measured the equivalent source-level detector
(`set-contract-storage`) on 71 contracts and reported 59.41% false positives. That is a
different quantity — theirs is measured against human ground truth, the ≤16% above is a
name-shape upper bound — and saying so is more useful than pretending they are comparable.

The triage numbers were measured **before this week's detector changes**, which suppressed
`gauges_get_reward_info` and capped cross-call findings at High; both changes remove findings,
so the measured precision is a floor for the current code, not a description of it.

**What is not measured: recall.** There is no labelled ground truth, so there is no number for
what the tool misses. That is the first question a reviewer should ask, and the answer today is
that we do not know.

Detail: `docs/PRECISION.md` (the 30-finding triage, summarised by shape until private disclosure completes) and `docs/CALIBRACAO.md`
(the iteration log).

## Reproducibility

The corpus is committed, not fetched at test time. `corpus/*.wasm` is 75 mainnet contracts;
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

The 75-contract corpus is a sample. To check whether it is a representative one, the same
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
| Tests (`pnpm test`) | **161 passing** of 161 |
| Corpus (`corpus/*.wasm`) | **71 mainnet contracts**, 1,726 entrypoints, 0 parse failures |
| Findings | **145** total · **2.0 per contract** |
| By class | 48 `silent-mutation` · 35 `initialization-front-running` · 32 `vulnerable-sdk` · 17 `unauthenticated-state-mutation` · 9 `archival-risk` · 3 `host-prng-in-value-path` · 1 `write-before-auth` |
| `call_indirect` (analysis downgraded) | **22 of 71** (31%) |
| Declared suppressions | **111**<br>52 — read-shaped name: the write probably comes from a shared helper, not from this path<br>46 — reserved `__` function, not directly invocable (CAP-0058)<br>13 — permissionless crank by design (protocol maintenance pattern) |
| Downgrades (reported, not suppressed) | **9**<br>9 — reaches call/try_call — authorization may live in the callee, severity capped at High |
| SDK version declared (`rssdkver`) | **38 of 71** |
| In a CVE-2026-26267 affected range (High) | **31 of 38** that declare a version |
| Source lines (`src` + `test`) | 13,164 in 29 files |
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

- **Spoofing and Information disclosure are zero on 75 of 75 contracts.** Both depend on
  identity and on data exposure, which are not observable in a contract's bytecode. The template
  asks for at least one issue per STRIDE letter; these two always come out as a declared gap
  requiring manual review of the off-chain flow.
- **57 of 75 contracts declare no events in their spec.** For those, no tier-B baseline is
  possible by construction — there is no topic filter to observe. `#[contractevent]` is recent
  and most deployed contracts predate it.
- **No document passes its own checklist with no human input.** The threat model blocks on every
  STRIDE letter the bytecode cannot fill (four of six for the median contract); the monitoring
  plan blocks on owner and channel, and on a baseline for the 57 eventless contracts. State-diff monitoring via `getLedgerEntries`, which is
  what the 57 eventless contracts need, is not built.
- **Storage durability and TTL are not readable from the bytecode** in the general case: the
  durability argument is usually not an immediate literal at the call site.
- **The addresses a contract calls are not derivable** — they are runtime arguments. The
  monitoring plan's inventory says that instead of inventing them.

## How this was built

SCF's Open Track requires disclosing AI use. This project is an extreme case of it, so the
disclosure is specific rather than a checkbox.

soroguard was built with AI coding agents: a first session of about 41 minutes of wall-clock
time producing the parser, the detectors, the renderers and the corpus tooling, followed by a
review and hardening pass (English output, committed corpus, fail-closed parser, recalibrated
detectors, packaging) driven the same way. The design decisions, the quality contract in
`docs/PROBLEMA.md`, and every number published here were reviewed by a human.

Specifically human-verified, not agent-asserted:

- the corpus hashes (sha256 of the committed bytes against the on-chain wasm hash);
- the triage of 30 `unauthenticated-state-mutation` findings against contract source;
- the CVE-2026-26267 source verification: 4 hash matches and one source reading re-checked by hand, the other 15 "not affected" verdicts are agent-produced source readings, 14 contracts have no conclusion;
- the ~40 audit reports the threat taxonomy was confronted with
  (`docs/TAXONOMIA-VALIDACAO.md`).

Not measured, by anyone: recall.

## Documentation

| | |
|---|---|
| `docs/PROBLEMA.md` | the quality contract: evidence tiers and what would turn this into slop |
| `docs/CALIBRACAO.md` | the false-positive removal log, iteration by iteration |
| `docs/TAXONOMIA-VALIDACAO.md` | 16 threat classes confronted with ~40 audits (Veridise, Certora, OtterSec, Runtime Verification, Code4rena, OpenZeppelin), 56 URLs |
| `docs/CVE-2026-26267-VERIFICACAO.md` | the source check of the 34 exposed contracts |
| `SECURITY.md` | disclosure policy for findings about third-party contracts |
| `docs/PRECISION.md` | the 30-finding triage against source, summarised |
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
