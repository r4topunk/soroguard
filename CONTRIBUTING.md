# Contributing

## Setup

```sh
pnpm install
pnpm test
```

Run the CLI directly against a wasm file without building:

```sh
node src/cli.ts artifact corpus/<contractId>.wasm --offline
```

See `src/cli.ts` for the full command surface (`inspect`, `analyze`, `artifact`).

## Changing a detector

Any change to `src/detect.ts` (or anything a detector depends on) must be
bracketed by a calibration run, before and after:

```sh
node scripts/calibrate.mjs
```

This runs the full taxonomy over the committed corpus (`corpus/*.wasm`) and
prints findings per contract, per class, and per STRIDE category.

**Findings-per-contract going up is a regression signal, not a coverage
win.** The corpus and its calibration output are how false positives get
caught before a reviewer does — see `docs/PROBLEMA.md` §4.3 for why solidity
of the taxonomy matters more than raw finding count.

## The corpus is committed bytecode

`corpus/*.wasm` (75 files, ~2.4 MB) and `corpus/index.json` are the evidence
base every number in `README.md` and `docs/` is computed from. They are
tracked in git deliberately — do not gitignore them, do not treat them as
build output. See `corpus/README.md` for provenance, verification, and how
to regenerate them.

## Quality contract

`docs/PROBLEMA.md` is the contract that every other document and every
detector obeys. Read it before making any change that affects what the tool
claims about a contract — it defines what would turn this project into slop.

## Determinism

Renderers (`src/render/*.ts`) must not read the clock. Output must be a pure
function of the analysis input — no `Date.now()`, no `new Date()` with no
argument, no other non-deterministic source — so the same wasm always
produces byte-identical artifacts.
