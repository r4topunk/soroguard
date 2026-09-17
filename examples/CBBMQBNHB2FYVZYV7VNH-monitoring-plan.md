# On-Chain Monitoring Plan — `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`

**Network:** mainnet · **Generated:** 2026-09-17 (UTC) · **Source:** deployed WASM, hash `12fca5a7a96577273b6d4184cf9c984036cda0e8f0594747e7b2933dced37ee6`

> **Keep this document internal.** A filled-in monitoring plan is the map of what is and what is not being watched.
> This draft was generated from public mainnet bytecode by a tool and has not been reviewed by the contract's owners; it is not a vulnerability report.

**How to read the evidence marks.** No claim here is worth more than the evidence behind it:

| Marker | Meaning | Who can check it |
|---|---|---|
| (A) | bytecode fact | anyone, by re-running the analysis over the same binary |
| (B) | fact observed on-chain | anyone, over RPC in the same window |
| (C) | inference — requires human review | human review only |
| ⟨to be defined — not derivable from the binary⟩ | the tool does not have this data and does not invent it | whoever operates the protocol has to fill it in |

This plan was derived automatically from the bytecode by soroguard. It is a defensible draft, not a deployment: no monitor is born with status `Active`.

## What are we monitoring?

Contract `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` on mainnet, a 90,057-byte binary. The spec declares 96 functions and 1 event. The bytecode analysis found 96 exported, 96 invocable (`__*` reserved exports excluded, CAP-0058); of the 96 invocable entrypoints, 53 reach a storage write, 38 reach `require_auth*` and 32 reach `contract_event`. Call graph complete — a negative claim here is a sound negative for this module's call graph (authorization enforced in a called contract or in `__check_auth` is not visible here).

Description of the protocol, the value it custodies and its operational context: ⟨to be defined — not derivable from the binary⟩ — none of that is in the binary.

| Component | On-chain address | Function |
|---|---|---|
| Contract instance | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | Executable `12fca5a7a9657727…`; target of every filter in this plan |
| Entrypoint `init_pools_plane` | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | init_pools_plane(plane: address) → void |
| Entrypoint `initialize` | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | initialize(admin: address, privileged_addrs: tuple, router: address, tokens: vec, fee: u32, tick_spacing: i32, protocol_fee_fraction: u32) → void |
| Entrypoint `initialize_all` | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | initialize_all(admin: address, privileged_addrs: tuple, router: address, tokens: vec, fee: u32, tick_spacing: i32, protocol_fee_fraction: u32, reward_config: tuple, plane: address) → void |
| Entrypoint `initialize_boost_config` | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | initialize_boost_config(reward_boost_token: address, reward_boost_feed: address) → void |
| Entrypoint `initialize_rewards_config` | `CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV` | initialize_rewards_config(reward_token: address) → void |
| External contracts invoked | ⟨to be defined — not derivable from the binary⟩ | The destination address of `call`/`try_call` is a runtime argument and is not in the bytecode. Reaching cross-call: `admin_set_rewards_state`, `apply_upgrade`, `backfill_plane_data`, `claim`, `claim_all_position_fees`, `claim_position_fees`, `claim_protocol_fees`, `deposit` (+17) |

> A stale address is the most common cause of a monitor that silently stops working. The addresses above hold for the binary identified in the header; re-check after any upgrade.

**Observed activity (B)** — window of 17667 ledgers (~27 h, ledgers 64448409–64466075):

| Topic | Occurrences | Rate/h | Declared in spec |
|---|---|---|---|
| `update_reserves` | 4,688 | 172 | no |
| `pool_state` | 4,667 | 172 | no |
| `trade` | 4,661 | 171 | no |
| `claim_fees` | 23 | 0.84 | yes |
| `claim_reward` | 18 | 0.66 | no |
| `position_update` | 6 | 0.22 | no |
| `deposit_liquidity` | 4 | 0.15 | no |
| `claim_protocol_fee` | 2 | 0.07 | no |
| `withdraw_liquidity` | 2 | 0.07 | no |

8 of the 9 observed topics are not declared in this contract's spec: undeclared topics come from the SDK's own events (token `transfer`/`approve`, TTL) or from contracts invoked underneath this one. They are still usable as a monitor observable — what they do not carry is the segment count, which only the spec gives, so their filter goes by contractId with the topic triaged client-side.

## What could go wrong?

### Severity reminders

| Severity | Meaning |
|---|---|
| **Critical** | Direct, large-scale loss of funds or of control; requires an immediate response. |
| **High** | Serious impact on funds, users or availability; requires a fast response. |
| **Medium** | Limited or workaround-able impact; the response can be scheduled. |
| **Low** | Minor or informational; monitored for awareness. |

### Threat register

| Threat ID | Threat (from threat model) | Affected component | Severity |
|---|---|---|---|
| Elevation.1 | `init_pools_plane` reaches state initialization without requiring authorization | `init_pools_plane` | Medium |
| Elevation.2 | `initialize` reaches state initialization without requiring authorization | `initialize` | Medium |
| Elevation.3 | `initialize_all` reaches state initialization without requiring authorization | `initialize_all` | Medium |
| Elevation.4 | `initialize_boost_config` reaches state initialization without requiring authorization | `initialize_boost_config` | Medium |
| Elevation.5 | `initialize_rewards_config` reaches state initialization without requiring authorization | `initialize_rewards_config` | Medium |
| Repudiate.1 | 11 of 43 state-changing entrypoints emit no event | Whole contract (CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV) | Medium |

**STRIDE letters with no derivable threat:** Spoof, Tamper, Info, DoS.

The template asks for at least one issue per letter. These are declared instead of filled in. Spoof and Info depend on identity and on data exposure, which do not exist in a contract's bytecode — that is a limit of the tool, not of this binary. For Tamper and DoS, no detector found a signal in this binary — which does not prove absence. All of them require manual analysis of the off-chain flow; filling them with generic text would give an impression of coverage that does not exist.

## What does exploitation look like on-chain?

| Threat ID | Exploitation scenario | Observable on-chain effect(s) |
|---|---|---|
| Elevation.1 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 4 hops → Medium. ⚠ REVIEW: the path to the write is 4 hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding. The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles. | Elevation.1.M.1: invocation of `init_pools_plane` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream |
| Elevation.2 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 3 hops → Medium. ⚠ REVIEW: the path to the write is 3 hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding. The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles. | Elevation.2.M.1: invocation of `initialize` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream |
| Elevation.3 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 3 hops → Medium. ⚠ REVIEW: the path to the write is 3 hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding. The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles. | Elevation.3.M.1: invocation of `initialize_all` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream |
| Elevation.4 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 4 hops → Medium. ⚠ REVIEW: the path to the write is 4 hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding. The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles. | Elevation.4.M.1: invocation of `initialize_boost_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream |
| Elevation.5 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 3 hops → Medium. ⚠ REVIEW: the path to the write is 3 hops long and probably goes through a shared helper. Reachability over-approximates the positive — the write may sit on a branch this entrypoint never executes. Confirm before treating this as a finding. The contract does not export `__constructor`, so initialization is a transaction separate from the deploy (CAP-0058). Between one and the other, any address can initialize first and take the privileged roles. | Elevation.5.M.1: invocation of `initialize_rewards_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream |
| Repudiate.1 | (C) 10 read-shaped entrypoints that reach a write through a shared helper were excluded from the count (both numerator and denominator): estimate_swap, estimate_swap_strict_receive, estimate_working_balance, gauges_get_reward_info, get_rewards_info, get_total_accumulated_reward, get_total_claimed_reward, get_total_configured_reward, get_unused_reward, get_user_reward. Emitting events from a quoting getter is not the remediation. Without an event there is no off-chain proof that the action happened, and the change is only detectable by state diff — which makes real-time monitoring of those actions unfeasible. | **No observable on-chain effect derivable from this analysis** — see §5. |

> Threats with no observable effect were neither dismissed nor handed a for-show monitor: they are in section 5, with the control they require off-chain.

## What will we monitor for?

| Monitor ID | Observable on-chain effect | Trigger condition & baseline | Monitoring rule (plain-language intent) |
|---|---|---|---|
| Elevation.1.M.1 | invocation of `init_pools_plane` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current invocation profile of the entrypoint, read by transaction inspection), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. **Baseline: ⚠ no baseline** | Alert on initialization front running in `init_pools_plane`, tracing back to threat Elevation.1. |
| Elevation.2.M.1 | invocation of `initialize` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current invocation profile of the entrypoint, read by transaction inspection), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. **Baseline: ⚠ no baseline** | Alert on initialization front running in `initialize`, tracing back to threat Elevation.2. |
| Elevation.3.M.1 | invocation of `initialize_all` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current invocation profile of the entrypoint, read by transaction inspection), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. **Baseline: ⚠ no baseline** | Alert on initialization front running in `initialize_all`, tracing back to threat Elevation.3. |
| Elevation.4.M.1 | invocation of `initialize_boost_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current invocation profile of the entrypoint, read by transaction inspection), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. **Baseline: ⚠ no baseline** | Alert on initialization front running in `initialize_boost_config`, tracing back to threat Elevation.4. |
| Elevation.5.M.1 | invocation of `initialize_rewards_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current invocation profile of the entrypoint, read by transaction inspection), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. **Baseline: ⚠ no baseline** | Alert on initialization front running in `initialize_rewards_config`, tracing back to threat Elevation.5. |

One line each:

- **Elevation.1.M.1** — We address **Elevation.1** in **`init_pools_plane`** by monitoring **invocation of `init_pools_plane` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream** at address **`CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`**.
- **Elevation.2.M.1** — We address **Elevation.2** in **`initialize`** by monitoring **invocation of `initialize` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream** at address **`CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`**.
- **Elevation.3.M.1** — We address **Elevation.3** in **`initialize_all`** by monitoring **invocation of `initialize_all` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream** at address **`CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`**.
- **Elevation.4.M.1** — We address **Elevation.4** in **`initialize_boost_config`** by monitoring **invocation of `initialize_boost_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream** at address **`CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`**.
- **Elevation.5.M.1** — We address **Elevation.5** in **`initialize_rewards_config`** by monitoring **invocation of `initialize_rewards_config` by an address that is not the deployer — visible in the transaction's InvokeHostFunction operation, read by transaction inspection, not in the event stream** at address **`CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV`**.

**How each observable was attributed to its threat.** The tier holds per claim: (A) is a bytecode fact, (C) is an inference that still needs human review.

- **Elevation.1.M.1** — (A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.
- **Elevation.2.M.1** — (A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.
- **Elevation.3.M.1** — (A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.
- **Elevation.4.M.1** — (A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.
- **Elevation.5.M.1** — (A) the entrypoint is exported by the WASM; the invocation shows up in the operation whether or not the contract emits an event.

### Executable filters

None of the 5 monitors is directly executable through `getEvents`. That is not a flaw in the plan: the observables derived here are ledger entries and the authorization tree, which are read through `getLedgerEntries` and by inspecting the transaction. A topic filter requires the contract to emit an event attributable to the threat.

## What happens when an alert fires?

| Monitor ID | Severity | Response / action | Owner | Status | Last reviewed |
|---|---|---|---|---|---|
| Elevation.1.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `init_pools_plane` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |
| Elevation.2.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `initialize` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |
| Elevation.3.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `initialize_all` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |
| Elevation.4.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `initialize_boost_config` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |
| Elevation.5.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `initialize_rewards_config` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |

**Status values:** _Active_ (live, alerting), _Tuning_ (live, thresholds being adjusted), _Planned_ (agreed, not implemented yet).

No monitor leaves this document as `Active`: this is the plan, not the deployment. `Tuning` marks what is fully specified — topic attributed and baseline observed — and can be switched on as is. `Planned` marks what still depends on data the tool does not have.

Owner and channel do not appear in the binary: 5 rows await that information, and section 6 counts it as a submission blocker.

### Threats that require an off-chain control

| Threat ID | Why there is no on-chain observable | Required control |
|---|---|---|
| Repudiate.1 | (A) the listed entrypoints reach `put_contract_data` and do not reach `contract_event`: by construction they produce nothing in the event stream. With no storage keys known for certain, not even the state diff is addressable. | Periodic reconciliation between the state read from the contract and the state the backend expects; and, as a design fix, emit an event in the entrypoints listed in the finding. |

## Did we do a good job?

| Checklist question | Status | Detail |
|---|---|---|
| Does every threat in the threat model have a monitor, or a documented reason it cannot be monitored? | ✔ ok | 5/6 threats with a monitor; 1 declared non-monitorable: Repudiate.1; 64 of 96 invocable entrypoints do not reach contract_event (`__*` reserved exports excluded, CAP-0058) — for those, monitoring through getEvents is impossible. |
| Does every monitor trace back to an existing threat, with an ID derived from it? | ✔ ok | 5 monitors, all anchored to a threat in the document. |
| Is the baseline grounded in observation, not guesswork? | ⚠ gap | observed window: 17667 ledgers (~27.2h), 9 distinct topics; without a baseline: Elevation.1.M.1, Elevation.2.M.1, Elevation.3.M.1, Elevation.4.M.1, Elevation.5.M.1; 0 baselines with the count checked against the window. |
| Does every monitor have a defined response? | ✔ ok | 5 monitors with a response. |
| Does every monitor have a named owner? | ⚠ gap | 0/5 monitors with an owner in the document; without an owner: Elevation.1.M.1, Elevation.2.M.1, Elevation.3.M.1, Elevation.4.M.1, Elevation.5.M.1. There is a mention of someone responsible elsewhere in the document, but not per monitor. The tool does not have this information — it is neither in the bytecode nor on-chain, and the team has to fill it in before submitting. |
| Have the alerts been historically accurate? | n/a | No monitor is Active yet (5 in the plan, all `Tuning` or `Planned`); 0 carry an observed baseline that was checked against the window, but none has alert history. Accuracy is only answerable after the monitors run: there is no alert yet to be right or wrong about. |
| Is the on-chain address inventory present and up to date? | ✔ ok | contract id CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV present in the document (network mainnet). Analysis run over wasm hash `12fca5a7a96577273b6d4184cf9c984036cda0e8f0594747e7b2933dced37ee6` on 2026-09-17; a different hash on the instance means this plan describes code that is no longer live. |
| Are the external boundaries (contracts called) in the inventory? | ⚠ gap | 25 entrypoints reach call/try_call (admin_set_rewards_state, apply_upgrade, backfill_plane_data, claim, claim_all_position_fees, claim_position_fees … (+19)). The destination addresses are runtime arguments: they are not derivable from the bytecode and the tool does not invent them. The inventory has to be completed by hand, or the monitoring covers only half the flow. |
| Have off-chain threats been identified and declared out of on-chain scope? | ✔ ok | The document ties the off-chain boundary to what was left out of the on-chain analysis: Spoof, Tamper, Info, DoS, Repudiate.1. |
| Does every monitor have a concrete observable signal and an executable trigger? | ⚠ gap | 5 monitors are neither executable through getEvents nor fully specified — the query cannot be built while the fill-in on the row is open (durability of the entry, address or hash): Elevation.1.M.1, Elevation.2.M.1, Elevation.3.M.1, Elevation.4.M.1, Elevation.5.M.1; no monitor is event-based, so the topic check does not apply: the observables derived here are ledger entries and the transaction, read through getLedgerEntries and by inspecting it; 0 of 5 monitors turn into an RPC call with no manual translation (topic filter from the contract spec); the rest need getLedgerEntries or transaction introspection. |

**Do not submit without closing these points:**

- Monitor Elevation.1.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Monitor Elevation.2.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Monitor Elevation.3.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Monitor Elevation.4.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Monitor Elevation.5.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Assign an owner and a notification channel to 5 rows of §5; neither is derivable from the binary, and a monitor with no owner has no one to fire at.

Treat this plan as a living document: review it whenever the contracts, the addresses or the threat model change.
