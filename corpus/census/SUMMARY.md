# Mainnet census — every distinct contract WASM on Stellar

Generated 2026-09-17 · Stellar mainnet · reproduce with `node scripts/census.mjs`

This file contains **aggregates only**. Per-contract results — which code hash carries which
finding — stay outside this repository under the disclosure policy in `SECURITY.md`.

The unit of analysis is the **distinct code hash**, not the contract: one WASM deployed 900
times is one binary with one set of findings. Every rate is therefore given twice — once per
hash (what a binary looks like) and once weighted by the number of deployed instances (what a
contract picked at random on the ledger looks like).

## Scope

| | |
|---|---|
| Contracts indexed | **151,079** |
| … with WASM code | 147,051 |
| … Stellar Asset Contracts (no WASM) | 4,014 |
| … neither code nor asset recorded | 14 |
| Distinct code hashes | **3,677** |
| Hashes fetched from the ledger | 3,677 |
| Hashes analyzed | **3,677** (100.0% of distinct) |
| … parsed successfully | 3,677 |
| Instances covered by the analyzed hashes | 147,051 (100.0% of WASM contracts) |
| Invocations covered | 792,148,291 |
| Hashes deployed exactly once | 2,682 (72.9% of distinct) |
| Mean module size | 18.2 KiB |
| Cross-check vs `contract-stats` (wasm / sac) | 147,052 / 4,028 (delta -1 / -14) |

## Parser and soundness

| | |
|---|---|
| Parse failures | **0** (0.0%) |
| Modules with `incomplete` sections | 0 |
| Modules with a degraded body | 82 |
| Analysis downgraded to `approximate` | **965** (26.2%) |
| `call_indirect` present — per hash | 965 (26.2%) |
| `call_indirect` present — instance-weighted | 7.2% |
| Entrypoints | 55,785 total · 15.2 per hash |

Parse failure reasons:

| Reason | Hashes |
|---|---|
| _none_ | |

## Findings — unweighted totals

These are the raw totals over every analyzed binary, usage-blind. They are kept because they
are the honest denominator, but the usage-stratified table further down is the one to quote.

| | Per hash | Instance-weighted | Invocation-weighted |
|---|---|---|---|
| Findings per contract | **2.21** | 2.02 | 2.81 |

Total findings over the analyzed hashes: **8,133**.

### By class

| Class | Hashes | Instance-weighted |
|---|---|---|
| `silent-mutation` | 2,441 | 132,828 |
| `unauthenticated-state-mutation` | 1,735 | 7,561 |
| `vulnerable-sdk` | 1,609 | 139,772 |
| `initialization-front-running` | 1,146 | 7,260 |
| `archival-risk` | 1,086 | 3,125 |
| `host-prng-in-value-path` | 61 | 437 |
| `unguarded-upgrade` | 42 | 92 |
| `write-before-auth` | 13 | 6,493 |

### By severity

| Severity | Per hash | Instance-weighted |
|---|---|---|
| Critical | 570 | 3,102 |
| High | 2,671 | 8,227 |
| Medium | 3,263 | 139,896 |
| Low | 1,629 | 146,343 |

### `unauthenticated-state-mutation`

| | |
|---|---|
| Hashes with at least one | **817** (22.2%) |
| Instance-weighted | 4,770 contracts (3.2%) |

## How to read severity

Severity is a **tier-C judgement** applied to a **tier-A over-approximate positive**: the
bytecode fact is "this export does not reach `require_auth` and does reach a storage write";
"that is Critical" is an inference on top of it. On the calibration sample of 30 triaged
`unauthenticated-state-mutation` findings, **9 (30%) were real** missing authorization and
**0 allowed loss of funds** (`docs/PRECISION.md`).

The census makes a second correction necessary. 72.9% of distinct
binaries are deployed exactly once, and a large share of those are tutorials, tests and
abandoned deploys whose exports are named `increment`, `sum`, `sub`, `a`, `exec_op`.
**A Critical on a single-instance, never-invoked contract is a tutorial contract, not an
incident.** Read the usage-stratified table below, not the raw per-hash counts, and treat the
T3 column as the one that describes code people actually run.

## Findings by usage tier

Tiers come from the index: instances of the hash, and invocations summed over them.

- **T0** — deployed once, never invoked
- **T1** — deployed once, invoked at least once
- **T2** — 2–9 instances
- **T3** — 10 or more instances

| Tier | Hashes | Instances | Invocations | Findings/hash | Critical/hash | High/hash | unauth-mutation rate | SDK declared | spec / events declared |
|---|---|---|---|---|---|---|---|---|---|
| T0 | 151 | 151 | 0 | 2.81 | 0.225 | 1.093 | 23.2% | 84.8% | 99.3% / 6.0% |
| T1 | 2,531 | 2,531 | 781,351,753 | 2.06 | 0.149 | 0.728 | 20.9% | 53.5% | 99.9% / 24.3% |
| T2 | 845 | 2,540 | 6,940,034 | 2.46 | 0.148 | 0.688 | 25.2% | 58.7% | 99.8% / 23.7% |
| T3 | 150 | 141,829 | 3,856,504 | 2.72 | 0.220 | 0.547 | 27.3% | 64.7% | 100.0% / 25.3% |

### Headline — all hashes vs hashes with real usage

| Metric | All hashes | Real usage (T1+T2+T3) | T3 only (≥10 instances) |
|---|---|---|---|
| Hashes | 3,677 | 3,526 | 150 |
| Findings per hash | **2.21** | **2.19** | **2.72** |
| Critical per hash | 0.155 | 0.152 | 0.220 |
| `unauthenticated-state-mutation` rate | 22.2% | 22.2% | 27.3% |
| `call_indirect` share | 26.2% | 26.0% | 32.0% |

### Per class, by tier

| Class | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| `vulnerable-sdk` | 121 | 972 | 429 | 87 |
| `silent-mutation` | 94 | 1,681 | 565 | 101 |
| `archival-risk` | 71 | 753 | 231 | 31 |
| `initialization-front-running` | 65 | 673 | 332 | 76 |
| `unauthenticated-state-mutation` | 61 | 1,092 | 489 | 93 |
| `unguarded-upgrade` | 13 | 17 | 10 | 2 |
| `host-prng-in-value-path` | 0 | 33 | 18 | 10 |
| `write-before-auth` | 0 | 3 | 2 | 8 |

### Per severity, by tier

| Severity | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| Critical | 34 | 378 | 125 | 33 |
| High | 165 | 1,843 | 581 | 82 |
| Medium | 105 | 2,027 | 934 | 197 |
| Low | 121 | 976 | 436 | 96 |

### Advisory exposure, by tier

| Advisory | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| CVE-2026-26267 / GHSA-4chv-4c6w-w254 | 121 | 963 | 426 | 82 |
| GHSA-x2hw-px52-wp4m | 9 | 636 | 234 | 55 |

216 hashes qualify for the next manual source triage (a Critical or
High `unauthenticated-state-mutation` on a binary with at least 2 instances or 100
invocations). The list itself is private, for the same reason as everything else in this file.

## Declared suppressions

2,660 entrypoints filtered, never silently — each carries a reason.

| Reason | Count |
|---|---|
| `reserved `__` function, not directly invocable (CAP-0058)` | 1,405 |
| `DOWNGRADED (not suppressed): reaches call/try_call — authorization may live in the callee, severity capped at High` | 760 |
| `read-shaped name: the write probably comes from a shared helper, not from this path` | 403 |
| `permissionless crank by design (protocol maintenance pattern)` | 92 |

## STRIDE gap rate

Share of hashes where the letter has **no derivable finding** and ships as a declared gap.

| Letter | Gap rate |
|---|---|
| Spoof | 100.0% |
| Tamper | 98.4% |
| Repudiate | 33.6% |
| Info | 100.0% |
| DoS | 70.5% |
| Elevation | 37.1% |

## SDK version (`rssdkver` in `contractmetav0`)

| | |
|---|---|
| Hashes declaring a version | **2,075** (56.4%) |
| Declared but not parseable as semver | 0 |

Top declared versions:

| Version | Hashes |
|---|---|
| `22.0.8` | 307 |
| `20.5.0` | 256 |
| `22.0.7` | 201 |
| `22.0.11` | 135 |
| `21.7.7` | 132 |
| `25.3.1` | 77 |
| `20.3.2` | 64 |
| `23.0.2` | 61 |
| `22.0.6` | 56 |
| `23.2.1` | 56 |
| `21.7.6` | 51 |
| `21.1.1` | 49 |
| `25.1.1` | 39 |
| `23.5.3` | 37 |
| `25.3.0` | 30 |

Advisory exposure — a **bytecode fact** (tier A: which SDK compiled the binary), not
exploitability:

| Advisory | Hashes | Instance-weighted |
|---|---|---|
| CVE-2026-26267 / GHSA-4chv-4c6w-w254 | 1,592 | 139,610 |
| GHSA-x2hw-px52-wp4m | 934 | 136,841 |

## Contract spec

| | |
|---|---|
| Hashes with `contractspecv0` | **3,671** (99.8%) |
| Hashes declaring at least one event | 861 (23.4%) |
| Functions per spec (mean) | 15.2 |
| Events per spec (mean) | 3.69 |

## 75-contract corpus vs whole mainnet

The corpus was selected by on-chain event activity, so it over-samples contracts that are
actually used. The mainnet column is one row per distinct binary, most of which are deployed
once — the two columns are not expected to match, and the gap is the point.

| Metric | 75-contract corpus | Whole mainnet (per hash) |
|---|---|---|
| Findings per contract | 2.16 | 2.21 |
| Share with `unauthenticated-state-mutation` | 18.7% | 22.2% |
| `call_indirect` share (analysis downgraded) | 32.0% | 26.2% |
| SDK version declared | 54.7% | 56.4% |
| Events declared in spec | 24.0% | 23.4% |
| Has `contractspecv0` | 100.0% | 99.8% |

Corpus baseline recomputed by this script with the same detectors: 75 contracts,
0 parse failures, 162 findings.

## Method

1. Enumerate every contract from `api.stellar.expert/explorer/public/contract` (`order=asc`,
   200 per page, following `_links.next`). Records carry the current code hash for WASM
   contracts and an asset for Stellar Asset Contracts.
2. Group by code hash; keep per-hash instance count, summed invocations and events, earliest
   creation.
3. Fetch each distinct WASM from a mainnet RPC with a `ContractCode` ledger key and verify
   sha256 == the hash.
4. Run `analyzeModule` + `detectFull` + `readSdkMeta` + the `contractspecv0` parse on each
   binary, in a child process with a 30 s watchdog so one pathological module cannot stall the
   census.
5. Aggregate. Only this step writes into the repository.

Steps 1–4 run as a pipeline: a hash discovered on page *n* is fetched and analyzed while page
*n+1* is still being requested.

### Caveats

- A code hash is the **current** executable of its instances. Contracts upgraded since the
  index was taken are counted under their new hash.
- Instance and invocation weights come from the explorer, not from the ledger directly.
- Findings are over-approximate positives by construction (see `README.md`, "The rule that
  governs the output"): a rate here is an upper bound on a rate of real issues, not a count of
  vulnerabilities. Precision was measured on the 75-contract corpus only (`docs/PRECISION.md`).
- Recall is not measured, here or anywhere.
