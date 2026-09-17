# On-Chain Monitoring Plan — `CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS`

**Network:** mainnet · **Generated:** 2026-09-17 (UTC) · **Source:** deployed WASM, hash `f340242d143b42e273f628f44ccb907f55f5beb256f3de17de2c005fcdbc9783`

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

Contract `CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS` on mainnet, a 34,945-byte binary. The spec declares 15 functions and 14 events. The bytecode analysis found 15 exported, 13 invocable (`__*` reserved exports excluded, CAP-0058); of the 13 invocable entrypoints, 9 reach a storage write, 10 reach `require_auth*` and 8 reach `contract_event`. Call graph complete — a negative claim here is a sound negative for this module's call graph (authorization enforced in a called contract or in `__check_auth` is not visible here). This module exports `__check_auth`: it is a custom account, so authorization is implemented there instead of by a `require_auth` call in each entrypoint — read every negative about `require_auth*` with that in mind.

Description of the protocol, the value it custodies and its operational context: ⟨to be defined — not derivable from the binary⟩ — none of that is in the binary.

| Component | On-chain address | Function |
|---|---|---|
| Contract instance | `CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS` | Executable `f340242d143b42e2…`; target of every filter in this plan |
| External contracts invoked | ⟨to be defined — not derivable from the binary⟩ | The destination address of `call`/`try_call` is a runtime argument and is not in the bytecode. Reaching cross-call: `__constructor`, `__check_auth`, `add_context_rule`, `remove_context_rule`, `add_policy`, `remove_policy`, `execute` |

> A stale address is the most common cause of a monitor that silently stops working. The addresses above hold for the binary identified in the header; re-check after any upgrade.

window of 120661 ledgers (~186 h) — limited by RPC retention.

**Observed activity (B)** — window of 120661 ledgers (~186 h, ledgers 64346934–64467594): no event of any topic. Absence of traffic is not a traffic profile.

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
| Repudiate.1 | 1 of 9 state-changing entrypoint emits no event | Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS) | High |
| Spoof.1 | The contract implements signature verification of its own, outside the host's `require_auth` framework | Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS) | Medium |
| Elevation.1 | Exposure: compiled with soroban-sdk 23.4.0, in a range affected by CVE-2026-26267 / GHSA-4chv-4c6w-w254 (High in the advisory; exploitability not confirmed) | Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS) | Low |

**STRIDE letters with no derivable threat:** Tamper, Info, DoS.

The template asks for at least one issue per letter. These are declared instead of filled in. Info depend on identity and on data exposure, which do not exist in a contract's bytecode — that is a limit of the tool, not of this binary. For Tamper and DoS, no detector found a signal in this binary — which does not prove absence. All of them require manual analysis of the off-chain flow; filling them with generic text would give an impression of coverage that does not exist.

## What does exploitation look like on-chain?

| Threat ID | Exploitation scenario | Observable on-chain effect(s) |
|---|---|---|
| Repudiate.1 | (C) Severity rule applied (class of the silent action, not the silent/state-changing fraction): High when any silent entrypoint is upgrade-capable or admin/permission-shaped by name; Low when every silent entrypoint is an init-shaped one-shot; Medium otherwise. Here: deciding entrypoints = upgrade → High. Without an event there is no off-chain proof that the action happened, and the change is only detectable by state diff — which makes real-time monitoring of those actions unfeasible. | Repudiate.1.M.1: diff of the 1 key inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`MIGRATING`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `upgrade` |
| Spoof.1 | (C) Authorization is implemented inside the contract, outside the host's `require_auth` framework; the Spoofing surface (replay, expiry, key rotation) is not covered by the auth detector — review the verifier. | **No observable on-chain effect derivable from this analysis** — see §5. |
| Elevation.1 | (C) The exposure is a fact; exploitability has not been confirmed and requires manual review. Only triggers if the contract has `impl Trait for C` with #[contractimpl] AND `impl C` with a function of the same name: the macro exports the inherent function instead of the trait one. The source shows that collision; the bytecode does not. Base rate measured outside the bytecode (not derivable from this binary, hence tier C). Source verification on 2026-09-16: of the 34 corpus contracts in an affected range, 20 verified as not affected, 0 confirmed vulnerable, 14 without source — docs/CVE-2026-26267-VERIFICACAO.md. This finding is EXPOSURE, not a confirmed vulnerability. Advisory list curated as of 2026-09-16 and not refreshed at runtime — re-check against RustSec/GHSA on the review date. | Elevation.1.M.1: instance wasm hash staying equal to the vulnerable binary (read via getLedgerEntries) |

> Threats with no observable effect were neither dismissed nor handed a for-show monitor: they are in section 5, with the control they require off-chain.

## What will we monitor for?

| Monitor ID | Observable on-chain effect | Trigger condition & baseline | Monitoring rule (plain-language intent) |
|---|---|---|---|
| Repudiate.1.M.1 | diff of the 1 key inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`MIGRATING`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `upgrade` | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current value of the storage keys, read via getLedgerEntries), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. Durability ⟨to be filled: temporary / persistent / instance⟩ — needed to build the ledger key. **Baseline: ⚠ no baseline** | Alert on silent mutation in Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS), tracing back to threat Repudiate.1. |
| Elevation.1.M.1 | instance wasm hash staying equal to the vulnerable binary (read via getLedgerEntries) | Periodic check (getLedgerEntries): the wasm hash of the instance executable differs from the hash recorded at plan approval — `f340242d143b42e273f628f44ccb907f55f5beb256f3de17de2c005fcdbc9783`. While it stays equal, the state described in the finding still holds; when it changes, the new binary needs to be re-analyzed. **Baseline (B):** instance wasm hash when this plan was generated: `f340242d143b42e273f628f44ccb907f55f5beb256f3de17de2c005fcdbc9783`. Any different value is a code change. | Alert on vulnerable sdk in Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS), tracing back to threat Elevation.1. |

One line each:

- **Repudiate.1.M.1** — We address **Repudiate.1** in **Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS)** by monitoring **diff of the 1 key inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`MIGRATING`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `upgrade`** at address **`CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS`**.
- **Elevation.1.M.1** — We address **Elevation.1** in **Whole contract (CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS)** by monitoring **instance wasm hash staying equal to the vulnerable binary (read via getLedgerEntries)** at address **`CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS`**.

**How each observable was attributed to its threat.** The tier holds per claim: (A) is a bytecode fact, (C) is an inference that still needs human review.

- **Repudiate.1.M.1** — (A) `upgrade` reaches put_contract_data and does not reach contract_event. (A) the keys were extracted from the bytecode as arguments of storage host functions, with `certain` confidence. (C) which of those keys each silent entrypoint writes is NOT derivable from this context — the monitor covers the whole set and may alert on changes from other paths. ⟨to be defined — not derivable from the binary⟩: the durability of each entry, which is a runtime argument and decides the ledger key to query.
- **Elevation.1.M.1** — (A) the SDK version is recorded in this binary's `contractmetav0` custom section; it only changes with an upgrade.

### Executable filters

None of the 2 monitors is directly executable through `getEvents`. That is not a flaw in the plan: the observables derived here are ledger entries and the authorization tree, which are read through `getLedgerEntries` and by inspecting the transaction. A topic filter requires the contract to emit an event attributable to the threat.

## What happens when an alert fires?

| Monitor ID | Severity | Response / action | Owner | Status | Last reviewed |
|---|---|---|---|---|---|
| Repudiate.1.M.1 | High | Reconcile the observed state against what the backend expects. The right response is a design change, not an on-call one: add events to the entrypoints listed. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |
| Elevation.1.M.1 | Low | Confirm in the source whether the advisory's trigger condition (evidence C of the finding) exists in this contract; if it does, recompile with the fixed version and run the upgrade. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |

**Status values:** _Active_ (live, alerting), _Tuning_ (live, thresholds being adjusted), _Planned_ (agreed, not implemented yet).

No monitor leaves this document as `Active`: this is the plan, not the deployment. `Tuning` marks what is fully specified — topic attributed and baseline observed — and can be switched on as is. `Planned` marks what still depends on data the tool does not have.

Owner and channel do not appear in the binary: 2 rows await that information, and section 6 counts it as a submission blocker.

### Threats that require an off-chain control

| Threat ID | Why there is no on-chain observable | Required control |
|---|---|---|
| Spoof.1 | No observable effect was derived for this class from the bytecode. | ⟨to be defined — not derivable from the binary⟩ |

## Did we do a good job?

| Checklist question | Status | Detail |
|---|---|---|
| Does every threat in the threat model have a monitor, or a documented reason it cannot be monitored? | ⚠ gap | 2/3 threats with a monitor; no monitor and no justification: Spoof.1; 5 of 13 invocable entrypoints do not reach contract_event (`__*` reserved exports excluded, CAP-0058) — for those, monitoring through getEvents is impossible. |
| Does every monitor trace back to an existing threat, with an ID derived from it? | ✔ ok | 2 monitors, all anchored to a threat in the document. |
| Is the baseline grounded in observation, not guesswork? | ⚠ gap | observed window: 120661 ledgers (~185.55h), 0 distinct topics; ⚠ gap: the window of 120661 ledgers was collected and holds no event of any topic — absence of traffic, not a traffic profile.; without a baseline: Repudiate.1.M.1; 0 baselines with the count checked against the window. |
| Does every monitor have a defined response? | ✔ ok | 2 monitors with a response. |
| Does every monitor have a named owner? | ⚠ gap | 0/2 monitors with an owner in the document; without an owner: Repudiate.1.M.1, Elevation.1.M.1. There is a mention of someone responsible elsewhere in the document, but not per monitor. The tool does not have this information — it is neither in the bytecode nor on-chain, and the team has to fill it in before submitting. |
| Have the alerts been historically accurate? | n/a | No monitor is Active yet (2 in the plan, all `Tuning` or `Planned`); 0 carry an observed baseline that was checked against the window, but none has alert history. Accuracy is only answerable after the monitors run: there is no alert yet to be right or wrong about. |
| Is the on-chain address inventory present and up to date? | ✔ ok | contract id CDZY62OKIPJAB4HH44BI6PPYO4NGFQV7INDJH4KU6V6RNNSLCTUX3SCS present in the document (network mainnet). Analysis run over wasm hash `f340242d143b42e273f628f44ccb907f55f5beb256f3de17de2c005fcdbc9783` on 2026-09-17; a different hash on the instance means this plan describes code that is no longer live. |
| Are the external boundaries (contracts called) in the inventory? | ⚠ gap | 7 entrypoints reach call/try_call (__constructor, __check_auth, add_context_rule, remove_context_rule, add_policy, remove_policy … (+1)). The destination addresses are runtime arguments: they are not derivable from the bytecode and the tool does not invent them. The inventory has to be completed by hand, or the monitoring covers only half the flow. |
| Have off-chain threats been identified and declared out of on-chain scope? | ✔ ok | The document ties the off-chain boundary to what was left out of the on-chain analysis: Tamper, Info, DoS, Spoof.1. |
| Does every monitor have a concrete observable signal and an executable trigger? | ⚠ gap | 1 monitor is neither executable through getEvents nor fully specified — the query cannot be built while the fill-in on the row is open (durability of the entry, address or hash): Repudiate.1.M.1; no monitor is event-based, so the topic check does not apply: the observables derived here are ledger entries and the transaction, read through getLedgerEntries and by inspecting it; 0 of 2 monitors turn into an RPC call with no manual translation (topic filter from the contract spec); the rest need getLedgerEntries or transaction introspection. |

**Do not submit without closing these points:**

- The observed window of 120661 ledgers recorded no event of any topic for this contract: that is absence of traffic, not a traffic profile. The counts are real and still cannot support a threshold — widen the window, or state that the thresholds are provisional, before submitting.

### Input the team must provide before submitting

1. Monitor Repudiate.1.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
2. Assign an owner and a notification channel to 2 rows of §5; neither is derivable from the binary, and a monitor with no owner has no one to fire at.

Treat this plan as a living document: review it whenever the contracts, the addresses or the threat model change.
