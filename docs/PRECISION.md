# Measured precision — the `unauthenticated-state-mutation` detector against source

Date of triage: 2026-09-16. Method: read-only. Every finding the detector emitted on a sample of the mainnet corpus was checked one by one against the contract's public source at the commit matching the deployed WASM (spec, SDK version and, where available, the on-chain WASM hash), and where source was unavailable, against read-only on-chain probes (`getLedgerEntries`, unsigned `simulateTransaction`).

## Result

| Classification | Count |
|---|---|
| Real unauthenticated state mutation, exploitable today, low impact | 5 |
| Real unauthenticated state mutation, latent (guarded by state, or dormant instance) | 4 |
| Permissionless by design (false positive of the *class*, not of the bytecode claim) | 21 |
| Detector bug (the negative claim "does not reach `require_auth`" was wrong) | **0** |
| **Total triaged** | **30** |

- **Precision for "state mutation with no authorization in the bytecode": 9 of 30 (30%).**
- **Precision for "loss of funds possible today, on the triaged instance": 0 of 30.** This is a statement about the 30 deployed instances that were triaged, not about the code shapes: the same shape deployed elsewhere, on a live instance with balance, can be exploitable, and at least one such case is under private disclosure.
- **All 30 negative claims matched the source.** Where the source has `require_auth` on the path, the call graph saw it. This is the empirical backing of the soundness asymmetry in `PROBLEMA.md`: the negative is proof, the positive is a candidate.

The 21 permissionless-by-design cases are the reason the class is hard: `claim(user)` that only pays `user`, a Blend pool applying a config the admin already queued behind a timelock, a Uniswap-V2-style pair that mints only against tokens the caller already transferred, a ROSCA settlement callable by anyone after the round ends, lazy expiry cranks inside getters. None is a bug, and every one is a state write with no `require_auth` on its path. The detector is right about the bytecode and wrong about the threat.

## What the real ones look like

The nine real cases are not described individually here: private disclosure to the affected teams has not been completed at the time of writing, and even a description by shape, combined with the public corpus and the detector, would identify them. What can be said: none of the triaged instances allows loss of funds today (other deployments of the same shapes may, and that is what the disclosure in progress is about); four are latent (guarded by state, or dormant instances); the pattern that matters most for this tool is deployed instances that predate an upstream authorization fix, which a source-level tool pointed at today's repository cannot see. The finding-by-finding triage with permalinks will be published once disclosure is done.

## What this measurement is not

- It was taken **before** this week's detector changes (read-shaped suppression widened to catch `*_get_*` getters; cross-contract writers capped at High; PRNG findings aggregated per contract). Those changes only remove or downgrade findings, so 30% is a floor for the current code, not a description of it.
- It measures precision, not **recall**. Nothing here says how many real unauthenticated writers the detector misses. The first candidate for that measurement is the Audit Bank corpus (77 audits, 57 with public reports).
- The sample is 30 findings from 17 contracts, chosen as the full output of two calibration batches, not a random sample of the corpus.

## Detector improvements the triage points at, in order of expected gain

1. Taint from entrypoint parameter to written value (would have cleared 11 of the 15 false positives in the first batch: the write only touches the caller's own record).
2. A read-only `simulateTransaction` probe: a revert on a state or time guard means the write is gated, so downgrade or mark latent.
3. A contract exporting `__check_auth` plus a mutating entrypoint with no auth path is high confidence.
4. Severity from the namespace of the written key rather than from hop count.
