# Measured precision at the top of mainnet — the 25 most-invoked code hashes

Date of triage: 2026-09-17. Method: read-only throughout. The two artifacts (STRIDE threat model, on-chain monitoring plan) were generated online for each of the 25 code hashes with the most summed invocations on Stellar mainnet, and **every finding they emitted was triaged one by one** — not only the Critical ones — against the contract's public source at a commit matching the deployed WASM, or, where no source exists, against read-only on-chain probes (`getLedgerEntries`, unsigned `simulateTransaction`). No transaction was signed or submitted, no project was contacted, no issue was opened.

This complements `PRECISION.md`, which measured one detector on a calibration corpus. This measures **every detector, on the busiest code on the network**.

## Result

25/25 runs completed, exit code 0, 440 s total (mean 17.6 s per contract). 66 findings across 25 contracts.

| Classification | Count | Share |
|---|---|---|
| Real, exploitable today | **0** | 0% |
| Real but latent (guarded by state, already-executed one-shot, or no value at risk) | **59** | 89.4% |
| Permissionless by design — the bytecode claim is right, the *threat class* is wrong | **7** | 10.6% |
| Detector bug — a claim (positive or negative) that the source contradicts | **0** | 0% |
| **Total triaged** | **66** | |

- **Precision for "real unauthenticated state mutation": 0 of 7 (0%).** All seven findings of that class are permissionless-by-design: a farming contract whose source carries the comment "No auth_require here so others can call this function on the farmer's behalf", two AMM reward `claim(user)` entrypoints that can only pay the passed-in user, an oracle getter whose only reachable write is protocol-version bookkeeping, and three lending-pool entrypoints that apply a configuration the admin already queued behind a one-week timelock.
- **Precision for "loss of funds possible today": 0 of 66.**
- **All 66 tier-A claims checked out.** Where the source has `require_auth` on the path, the call graph saw it; where it does not, the call graph said so. Zero false claims in either direction.
- **Zero findings required private disclosure.**

Put next to the earlier batches on the same missing-auth detector, the trend is the point:

| Batch | Sample | True positives | Precision |
|---|---|---|---|
| Batch 1 | calibration corpus | 0 / 15 | 0% |
| Batch 2 | calibration corpus | 5 / 11 | 45% |
| **Top 25 by volume** | **top of mainnet** | **0 / 7** | **0%** |

The 45% in batch 2 came from small, low-traffic contracts — demo dApps, dormant wallets, contracts with no owner model at all. At the top of mainnet the rate is **zero**, and that is consistent rather than contradictory: code that survives hundreds of thousands of invocations has either been audited or is permissionless on purpose. **For the top of mainnet, the missing-auth detector finds nothing real.** What it finds there is the protocols' design. The value of the tool on that code is the inventory, the data-flow diagram, the honestly declared gaps and the refusal to invent a baseline — not the auth detector.

### Severity does not survive triage

Both **Critical** findings emitted are false positives of class. Of the 18 **High**, two are the AMM `claim` false positives and sixteen are silent-mutation or archival-risk findings whose severity comes from a ratio or from an absence, not from impact. **No Critical or High in the batch survives triage as an actionable risk.** Two concrete inversions, both measured here:

- Silent-mutation severity is the fraction *silent / state-changing*, so `2 of 2` on an anonymous private bot scores **High**, while an unlogged `upgrade` on a regulated tokenized money-market fund and an unlogged `propose_admin` on a large lending pool both score **Medium**. The signal should be the *class of the silent action* (upgrade, admin change, permission-manager change), not the fraction.
- The same permissionless reward `claim`, in two pools built from the same shared crate, was scored **High** — while the identical pattern in an earlier batch scored Medium at a different hop count. Hop count is not impact.

## Recall: what the tool missed

Precision is not the whole measurement, and this batch produced the first hard recall evidence.

**1. Six findings lost to a duplicated custom section.** All 25 WASMs declare their `soroban-sdk` version in a `contractmetav0` custom section. The tool read it in 14 and reported "no SDK declared" in 11. Root cause, established by reproducing over the 25 binaries: the toolchain writes a **second** `contractmetav0` section (with `cliver` and `source_repo`) after the one the SDK writes (with `rsver` and `rssdkver`), WASM allows repeated custom-section names, and the parser kept only the last one in a map keyed by name. The 11 "absent" contracts were exactly the 11 with two sections. Consequence: **six contracts that do run an SDK version inside the range of a known authorization-bypass advisory got no `vulnerable-sdk` finding at all**, and the same SDK version produced a finding on two contracts and silence on three others. The generated document made no false claim — it said nothing about the SDK — but it silently suppressed a gap. Fixed: all `contractmetav0` sections are now read and merged with a tolerant entry-by-entry decoder, and the three states "absent", "present but unreadable" and "evaluated" are distinct. After the fix, 25 of 25 declare a version and 19 of 25 carry an advisory; on the 71-contract corpus the declared rate went from 38 to 69 of 71.

**2. A Tampering gap declared where the source shows a threat.** One contract's threat model declares Tampering as "no threat derivable from the bytecode". Its source shows one: a permissionless, single-shot-per-round entrypoint lets an arbitrary caller write into a third party's round state before that party can, degrading their reward. No gain to the attacker, no loss of principal — but third-party state modified by an arbitrary caller is the definition of Tampering. The tool has no detector for it: its only "permissionless write" signal files everything under Elevation, and here it filed this one as **Critical Elevation**. Wrong letter, wrong severity, and the threat that actually exists went unreported.

**3. A Spoofing gap declared on a contract whose entire spec is a signature scheme.** Another contract's threat model declares Spoofing as a gap. That contract exports domain-hash, type-hash and nonce management, and its error enum carries `SignatureExpired` and `InvalidSignature`: an EIP-712-style verifier implemented *inside* the contract. The whole spoofing surface of that system — replay, expiry, publisher-key rotation — lives somewhere the detector never looks, because it only knows how to search for `require_auth`. Cheap, high-value predicate: when the spec exports domain/type-hash or nonce symbols, or declares `InvalidSignature`/`SignatureExpired`, the S row stops being a gap and becomes an issue with a directed worksheet.

**4. A credential leak in the deliverable, found while reviewing the 25 generated documents.** When the network argument is an RPC URL — the normal case with a private, API-keyed endpoint — the raw value is stamped into the **Network** field of *both* generated documents: the header, the inventory table and the diagram comment. All 50 documents in this batch came out carrying the credential. Those are exactly the files the tool exists so you can hand them to a grant reviewer. It is not a wrong claim about a contract, so it is not a tier-A bug; it is worse in practice. The Network field should print the network *name*, derived from the passphrase the RPC returns, and never the endpoint.

## What the top of mainnet looks like

**It is one farming contract and its robots.** The four busiest code hashes are a proof-of-work-style farming contract and three batching bots for it: **98.5% of all invocations in the sample**, with the farming contract alone at **88.8%**. Strip those out and the entire rest of the top 25 fits in 1.5% of the volume. Any claim about "the most used contract on Stellar" that omits this is describing token mining, not application usage.

Below that layer, the top is **AMM, oracle and payment infrastructure**: six AMM contracts (constant-product, stableswap and concentrated-liquidity pools, two routers, one fee-taking proxy), three price oracles from three different providers, two lending contracts (a pool and a fee vault built on that same pool), two regulated payment/RWA contracts (a card-issuing coordinator and a tokenized money-market fund), one game NFT, one load-test contract — and **six private arbitrage or routing bots with no public source at all**, one of them with deliberately minified export names (`s`, `u`, `sm`). Those six are, collectively, a larger share of the non-farming volume than any single protocol.

**SDK versions: the top of mainnet does not upgrade.** All 25 declare a version; they span 20.2.0 to 27.0.2, and **14 of 25 (56%) run binaries compiled inside the range of a known authorization-bypass advisory**. Two contracts with over 200,000 invocations each — an AMM router and a lending protocol's own oracle — still run a 2024-era SDK. Only the four pools of one AMM and the two newest oracles are outside the affected range.

**Events: almost nobody declares them.** Only **2 of 25** declare a typed contract event in their spec. **20 of 25 observation windows recorded no event of any topic** — partly because the farming contract and the private bots genuinely emit nothing on their state-changing entrypoints, partly for the sampling reason below. The direct product consequence: at the top of mainnet, **a monitoring plan built on event topics usually has nothing to bind to**; what remains is ledger-entry reads and transaction introspection, which the document itself marks as not executable through a topic filter.

**`call_indirect`: 7 of 25 (28%)**, so the analysis is downgraded to `approximate` on 28% of the busiest code — closely matching the 32% measured earlier on a 75-contract corpus. In those 7, the negative claim "does not reach `require_auth`" stops being proof. Worth recording: in the three of those seven where source was available to check, **no authorization was hiding behind indirect dispatch**. The downgrade is conservative, not corrective — and still the right thing to do.

**Two sampling findings that change how this should be run.** First, for a code hash with many deployed instances, the instance picked as representative is usually **not** the one with traffic: in five of the 25 families, the busiest instance had 8× to 20× the invocations of the one analyzed. The bytecode analysis (tier A) describes the code that runs on the busy instance while the observed baseline (tier B) describes a dormant one. Second, the `getEvents` window is not uniform — it tops out around 240,000 ledgers (~375 h) but **shrinks on exactly the busiest contracts** (down to ~32 h in one case), because they exhaust the RPC's page budget first. The contracts that most need a baseline are the ones that get the shortest window. Both are fixable in the tool: name the sibling instances that share the code hash, and offer the baseline aggregated per hash rather than per requested id.

**Where the findings land.** 66 findings over 25 contracts, mean 2.6:

| Class | Count | Share |
|---|---|---|
| initialization front-running | 23 | 35% |
| silent mutation (state write with no event) | 21 | 32% |
| vulnerable SDK exposure | 12 | 18% |
| unauthenticated state mutation | 7 | 11% |
| archival risk (writes, never extends TTL) | 3 | 5% |

Two classes are **two thirds of everything the tool says about the top of mainnet**, and each collapses under a single cheap predicate. Every one of the 23 initialization findings is a one-shot initializer that has already fired; an unsigned `simulateTransaction` returning an *already-initialized* contract error would have closed all 23 without reading a line of source — it is the highest-return predicate measured so far. The 21 silent-mutation findings are all true, and all need severity driven by the class of the silent action rather than by a fraction. **A third of the product's current output is noise that one RPC call removes.**

The suppression layer, by contrast, is working. Across the 25 contracts it removed or downgraded **59 candidates** — reserved `__` functions, read-shaped names whose write comes from a shared helper, permissionless maintenance cranks, and severity caps where the path crosses into another contract. On two AMM pools alone the read-shaped rule removed 29 findings that would otherwise have been pure noise. **Suppression is the healthiest part of the tool; severity is the weakest.**

## What this measurement is not

- It is precision and recall on **one sample of 25 code hashes**, chosen as the volume-ranked top of mainnet, not a random sample. The volume ranking is itself dominated by a single contract.
- The 25 hashes cover **500 deployed instances**; the artifacts were generated for 25 contract ids. The bytecode conclusions carry to the siblings; the on-chain state and the baselines do not.
- **No WASM was reproduced by a local build.** Source matching relies on hashes published by the projects themselves, third-party reproducible-build verification, embedded build metadata, and entrypoint/type/SDK matching — in that order of strength, with each finding carrying which one it used.
- Six of the 25 have no public source at any commit. Their classification rests on spec, embedded metadata and read-only on-chain probes, and is labelled accordingly.
- Nothing here says the detectors are safe to run unattended. It says that on this sample the tool never asserted something the source contradicts, and that its output at the top of mainnet is currently dominated by two closable classes and one parser bug.
