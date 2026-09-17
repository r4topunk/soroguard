# Security and disclosure policy

soroguard reads the deployed bytecode of Soroban contracts on public networks. Anyone can run it on any contract. That makes two things explicit.

## Findings about third-party contracts

The generated documents are analyses of public bytecode. They are drafts, they are not reviewed by the contract's owners, and they are not vulnerability reports. Every positive claim they make is marked as over-approximate and needs confirmation in source.

When the maintainers of this project find, during calibration, something that looks like a real vulnerability in a third-party contract, the rule is:

1. Do not publish the contract id, the project name, or a description specific enough to identify it.
2. Contact the project privately first (repository security policy, security contact, or the address on the deployment's public page). Give at least 90 days, or until a fix is deployed, before any public mention.
3. Only aggregate numbers go into this repository before disclosure completes (see `docs/PRECISION.md`).

At the time of writing, private disclosure for the findings from the 2026-09-16 calibration batch is in progress. The finding-by-finding triage will be published once it is done.

## Reporting a problem in soroguard itself

If the tool asserts something about a contract that the bytecode does not support (a tier A claim that is wrong, a suppressed finding that should have been reported, a parser crash or hang on a valid module), open an issue with the contract id or the `.wasm` file and the generated document. A wrong tier A claim is treated as a bug of the highest priority: it is the one thing the tool promises not to do.

If the problem itself would expose a third-party contract, do not open a public issue; use the maintainer contact in `package.json`.

## Scope

No secrets are handled. The tool makes read-only RPC calls (`getLedgerEntries`, `getEvents`, `simulateTransaction` is not used). It never signs or submits transactions.
