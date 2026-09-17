# On-Chain Monitoring Plan — `CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ`

**Network:** mainnet · **Generated:** 2026-09-17 (UTC) · **Source:** deployed WASM, hash `003710b383f9da7d650a7f719a7be479110266427817ebbed61d924505fcd7c7`

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

Contract `CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ` on mainnet, a 90,138-byte binary. The spec declares 57 functions and 14 events. The bytecode analysis found 57 exported, 56 invocable (`__*` reserved exports excluded, CAP-0058); of the 56 invocable entrypoints, 20 reach a storage write, 15 reach `require_auth*` and 15 reach `contract_event`. Call graph complete — a negative claim here is a sound negative for this module's call graph (authorization enforced in a called contract or in `__check_auth` is not visible here).

Description of the protocol, the value it custodies and its operational context: ⟨to be defined — not derivable from the binary⟩ — none of that is in the binary.

| Component | On-chain address | Function |
|---|---|---|
| Contract instance | `CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ` | Executable `003710b383f9da7d…`; target of every filter in this plan |
| Entrypoint `initialize` | `CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ` | initialize(sqrt_price_x96: u256) → result |
| External contracts invoked | ⟨to be defined — not derivable from the binary⟩ | The destination address of `call`/`try_call` is a runtime argument and is not in the bytecode. Reaching cross-call: `swap`, `swap_prefunded`, `collect`, `collect_protocol`, `flash_begin`, `flash_end`, `get_protocol_fee_0`, `get_protocol_fee_1` (+4) |

> A stale address is the most common cause of a monitor that silently stops working. The addresses above hold for the binary identified in the header; re-check after any upgrade.

**Observed activity (B)** — window of 120663 ledgers (~186 h, ledgers 64345409–64466071):

| Topic | Occurrences | Rate/h | Declared in spec |
|---|---|---|---|
| `swap` | 2,319 | 12 | yes |

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
| Elevation.1 | `initialize` reaches state initialization without requiring authorization | `initialize` | Medium |
| Repudiate.1 | 6 of 20 state-changing entrypoints emit no event | Whole contract (CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ) | Medium |

**STRIDE letters with no derivable threat:** Spoof, Tamper, Info, DoS.

The template asks for at least one issue per letter. These are declared instead of filled in. Spoof and Info depend on identity and on data exposure, which do not exist in a contract's bytecode — that is a limit of the tool, not of this binary. For Tamper and DoS, no detector found a signal in this binary — which does not prove absence. All of them require manual analysis of the off-chain flow; filling them with generic text would give an impression of coverage that does not exist.

## What does exploitation look like on-chain?

| Threat ID | Exploitation scenario | Observable on-chain effect(s) |
|---|---|---|
| Elevation.1 | (C) A reachable `has_contract_data` is, in the idiomatic pattern, an already-initialized guard. Whether the guard covers THIS path, and whether it aborts, does not follow from reachability. Severity rule applied: High only when the already-initialized guard is NOT reachable AND the path to the write is ≤ 2 hops; Medium when the guard IS reachable or the path is longer. Here: guard reachable = yes, 2 hops → Medium. The contract DOES export `__constructor`, so the deploy itself initializes atomically (CAP-0058). An init-shaped entrypoint kept alongside it is either a second-stage initializer or a legacy one kept for compatibility — in both readings the risk is front-running / re-initialization of that stage, not a generic unauthenticated writer. | Elevation.1.M.1: initialization executed — event with topics [init] |
| Repudiate.1 | (C) Without an event there is no off-chain proof that the action happened, and the change is only detectable by state diff — which makes real-time monitoring of those actions unfeasible. | Repudiate.1.M.1: diff of the 6 keys inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`bline`, `FLOCK`, `padmin`, `params`, `pstate`, `schema_v`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `set_router_authorized`, `snapshot_cumulatives_inside`, `observe_single`, `observe`, `poke_oracle`, `poke_oracle_with_hints` |

## What will we monitor for?

| Monitor ID | Observable on-chain effect | Trigger condition & baseline | Monitoring rule (plain-language intent) |
|---|---|---|---|
| Elevation.1.M.1 | initialization executed — event with topics [init] | Any occurrence of [init], which never happened in the observed window. **Baseline (B):** 0 emissions of [init] in the window of 120663 ledgers (~186 h, ledgers 64345409–64466071) — topic declared in the spec and confirmed as never observed. An observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold. | Alert on initialization front running in `initialize`, tracing back to threat Elevation.1. |
| Repudiate.1.M.1 | diff of the 6 keys inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`bline`, `FLOCK`, `padmin`, `params`, `pstate`, `schema_v`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `set_router_authorized`, `snapshot_cumulatives_inside`, `observe_single`, `observe`, `poke_oracle`, `poke_oracle_with_hints` | Any occurrence of the observable on this row. No numeric threshold can be set — this monitor is not event-based; its baseline is the current on-chain value (current value of the storage keys, read via getLedgerEntries), to be recorded at plan approval — ⟨to be defined — not derivable from the binary⟩. This is a fill-in, not an observation gap: no `getEvents` window would produce it. Durability ⟨to be filled: temporary / persistent / instance⟩ — needed to build the ledger key. **Baseline: ⚠ no baseline** | Alert on silent mutation in Whole contract (CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ), tracing back to threat Repudiate.1. |

One line each:

- **Elevation.1.M.1** — We address **Elevation.1** in **`initialize`** by monitoring **initialization executed — event with topics [init]** at address **`CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ`**.
- **Repudiate.1.M.1** — We address **Repudiate.1** in **Whole contract (CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ)** by monitoring **diff of the 6 keys inferred from the data section (non-exhaustive; entries keyed by runtime arguments are not listed) (`bline`, `FLOCK`, `padmin`, `params`, `pstate`, `schema_v`) across ledgers (getLedgerEntries) — with no event, the state diff is the only possible reading; silent entrypoints: `set_router_authorized`, `snapshot_cumulatives_inside`, `observe_single`, `observe`, `poke_oracle`, `poke_oracle_with_hints`** at address **`CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ`**.

**How each observable was attributed to its threat.** The tier holds per claim: (A) is a bytecode fact, (C) is an inference that still needs human review.

- **Elevation.1.M.1** — (A) `initialize` reaches contract_event in 1 hop(s). The topics and the segment count come from the `contractspecv0` section of the WASM itself. (C) the event↔entrypoint link is by name (InitializeEvent).
- **Repudiate.1.M.1** — (A) `set_router_authorized`, `snapshot_cumulatives_inside`, `observe_single`, `observe`, `poke_oracle`, `poke_oracle_with_hints` reach put_contract_data and do not reach contract_event. (A) the keys were extracted from the bytecode as arguments of storage host functions, with `certain` confidence. (C) which of those keys each silent entrypoint writes is NOT derivable from this context — the monitor covers the whole set and may alert on changes from other paths. ⟨to be defined — not derivable from the binary⟩: the durability of each entry, which is a runtime argument and decides the ledger key to query.

### Executable filters

1 of 2 monitors turns into an RPC call with no manual translation. The topics below come from `prefixTopics` in the contract spec recorded in the WASM itself. On the wire each segment goes as a base64 ScVal symbol (the raw string is rejected with `invalid parameters`) and the list must have the same length as the event's topic list — a filter that is too short does not error, it returns zero.

`InitializeEvent` declares 0 topic parameters in the spec, so the filter has no `*`.

```json
[
  {
    "monitorId": "Elevation.1.M.1",
    "contractId": "CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ",
    "filter": {
      "type": "contract",
      "contractIds": [
        "CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ"
      ],
      "topics": [
        [
          "init"
        ]
      ]
    },
    "condition": {
      "kind": "any-occurrence"
    },
    "note": "Topics read from `contractspecv0` in the WASM itself, with one `*` per parameter declared in TopicList. On the wire each segment goes as a base64 ScVal symbol — the raw string is rejected with `invalid parameters`; `*` matches exactly one segment and the list must have the same length as the event's (measured on mainnet). Baseline (B): 0 emissions of [init] in the window of 120663 ledgers (~186 h, ledgers 64345409–64466071) — topic declared in the spec and confirmed as never observed. An observed zero is a measurement, but it supports only an any-occurrence trigger, not a rate threshold."
  }
]
```

## What happens when an alert fires?

| Monitor ID | Severity | Response / action | Owner | Status | Last reviewed |
|---|---|---|---|---|---|
| Elevation.1.M.1 | Medium | Check that the emitter and the recorded roles match the legitimate deployment. If they diverge, treat the instance as compromised, pause integrations that trust its roles, and verify in source whether `initialize` is guarded against re-initialization — if it is not, redeploy; the bytecode does not show the guard. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Tuning | never reviewed — generated on 2026-09-17 |
| Repudiate.1.M.1 | Medium | Reconcile the observed state against what the backend expects. The right response is a design change, not an on-call one: add events to the entrypoints listed. Channel and automated action: ⟨to be defined — not derivable from the binary⟩ | ⟨to be defined — not derivable from the binary⟩ | Planned | never reviewed — generated on 2026-09-17 |

**Status values:** _Active_ (live, alerting), _Tuning_ (live, thresholds being adjusted), _Planned_ (agreed, not implemented yet).

No monitor leaves this document as `Active`: this is the plan, not the deployment. `Tuning` marks what is fully specified — topic attributed and baseline observed — and can be switched on as is. `Planned` marks what still depends on data the tool does not have.

Owner and channel do not appear in the binary: 2 rows await that information, and section 6 counts it as a submission blocker.

## Did we do a good job?

| Checklist question | Status | Detail |
|---|---|---|
| Does every threat in the threat model have a monitor, or a documented reason it cannot be monitored? | ✔ ok | 2/2 threats with a monitor; 41 of 56 invocable entrypoints do not reach contract_event (`__*` reserved exports excluded, CAP-0058) — for those, monitoring through getEvents is impossible. |
| Does every monitor trace back to an existing threat, with an ID derived from it? | ✔ ok | 2 monitors, all anchored to a threat in the document. |
| Is the baseline grounded in observation, not guesswork? | ⚠ gap | observed window: 120663 ledgers (~185.79h), 1 distinct topic; without a baseline: Repudiate.1.M.1; 1 baseline is an observed zero (measurement) and does not count as checked against the window — for an any-occurrence trigger the only legitimate occurrence may predate the window: Elevation.1.M.1; 0 baselines with the count checked against the window. |
| Does every monitor have a defined response? | ✔ ok | 2 monitors with a response. |
| Does every monitor have a named owner? | ⚠ gap | 0/2 monitors with an owner in the document; without an owner: Elevation.1.M.1, Repudiate.1.M.1. There is a mention of someone responsible elsewhere in the document, but not per monitor. The tool does not have this information — it is neither in the bytecode nor on-chain, and the team has to fill it in before submitting. |
| Have the alerts been historically accurate? | n/a | No monitor is Active yet (2 in the plan, all `Tuning` or `Planned`); 0 carry an observed baseline that was checked against the window, but none has alert history. Accuracy is only answerable after the monitors run: there is no alert yet to be right or wrong about. |
| Is the on-chain address inventory present and up to date? | ✔ ok | contract id CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ present in the document (network mainnet). Analysis run over wasm hash `003710b383f9da7d650a7f719a7be479110266427817ebbed61d924505fcd7c7` on 2026-09-17; a different hash on the instance means this plan describes code that is no longer live. |
| Are the external boundaries (contracts called) in the inventory? | ⚠ gap | 12 entrypoints reach call/try_call (swap, swap_prefunded, collect, collect_protocol, flash_begin, flash_end … (+6)). The destination addresses are runtime arguments: they are not derivable from the bytecode and the tool does not invent them. The inventory has to be completed by hand, or the monitoring covers only half the flow. |
| Have off-chain threats been identified and declared out of on-chain scope? | ✔ ok | The document ties the off-chain boundary to what was left out of the on-chain analysis: Spoof, Tamper, Info, DoS. |
| Does every monitor have a concrete observable signal and an executable trigger? | ⚠ gap | 1 monitor is neither executable through getEvents nor fully specified — the query cannot be built while the fill-in on the row is open (durability of the entry, address or hash): Repudiate.1.M.1; every event-based monitor cites a topic declared in the spec; 1 of 2 monitors turns into an RPC call with no manual translation (topic filter from the contract spec); the rest need getLedgerEntries or transaction introspection. |

**Do not submit without closing these points:**

- Monitor Repudiate.1.M.1 has no recorded baseline: this monitor is not event-based; its baseline is the current on-chain value (hash / key set), to be recorded at plan approval — ⟨to be filled⟩. That is a fill-in, not an observation gap: no `getEvents` window would produce it.
- Assign an owner and a notification channel to 2 rows of §5; neither is derivable from the binary, and a monitor with no owner has no one to fire at.

Treat this plan as a living document: review it whenever the contracts, the addresses or the threat model change.
