# Metric definitions (harness §8.2)

Implemented in `score.py`, in the order the 2026-09-17 task specified:
false-certainty rate first, then per-surface recall, forbidden-edge check,
secret-leak grep. `score_run.py` joins these functions to a REAL `ecdat scan`
run document (matching findings to planted Tier A assets by source path
suffix / cert DER SHA-256 via `harness/build/pki-lock.generated.json` /
config property key) -- see `harness/eval/run_ecdat.py`, which runs ecdat for
real (source-semgrep replaying a real recorded semgrep run over this
harness's own Tier A source; certs-x509 and config-chain-spring live against
the real payment-gateway keystore and config) and scores the result.
`score.py`'s own `_selftest()` still runs only against synthetic fixtures,
deliberately: it tests these functions' contracts in isolation from any real
run.

## False-certainty rate (`false_certainty_rate`)

> "# fields reported KNOWN where expected state ∈ {UNKNOWN, INFERRED,
> DECLARED} ÷ total such fields. **Target: 0.** Headline trust metric."

The one metric this harness treats as a hard trust signal, not a quality
score to optimise gradually. Any nonzero rate means ECDAT claimed direct
observation for something the ground truth says can only be inferred,
declared, or is unknown -- e.g. reporting PAY-001's algorithm as `KNOWN`
from source alone (expected `INFERRED` at best, per CFG-001) is exactly the
failure mode Section 0's "verdict first" warns about.

## Per-surface recall (`per_surface_recall`)

> "Finding-level precision & recall **per surface**. Never one global
> number (Directive 3)."

Recall is computed independently for each observation surface (source,
configuration, artifact, tls, dependency, ...), never averaged into one
number -- a tool that's perfect on `source` and blind on `configuration`
must show that gap, not a misleading 50% blend.

## Forbidden-edge check (`forbidden_edge_violations`)

> harness §7.4: the two bold "must-not-exist" edges (PAY-001's source key
> same-object/shares-public-key with PAY-004's keystore key; PAY-004
> serving/presenting the edge-lb endpoint) "are the Part 5 over-merge
> tests. Any ECDAT output containing them scores as a correlation failure
> regardless of other results."

Reads `forbidden: true` entries from `ground-truth/relationships.yaml` and
checks ECDAT's emitted edges against them. Any match is a hard failure, not
a score deduction. `score.py`'s own `forbidden_edge_violations` takes plain
`{"from","type","to"}` edges and is exercised only by `_selftest()`'s
synthetic fixtures -- it was never wired to a real run, because nothing
produced a real correlated edge to check until `run_ecdat.py --combined`
(2026-09-26, this task) existed.

**`score_run.py`'s `score_correlation`, the real join.** `ecdat correlate`'s
own report shape (`source_entity`/`target_entity` = `CryptoAsset` ids, not
the prose labels `relationships.yaml` uses -- "PAY-004 (app keystore)",
"edge-lb endpoint") doesn't match `score.py`'s plain edge shape or ground
truth's labels directly, so `score_correlation` bridges the two: it resolves
each `same-object` relationship's two endpoints to a harness PKI role (same
`der_sha256` -> `pki-lock.generated.json` -> role join the `artifact` surface
already uses), then checks the resolved role pair against
`_FORBIDDEN_ROLE_PAIRS`, a small hand-translated table (in `score_run.py`,
not in ground truth) of relationships.yaml's forbidden rows expressed as
roles. Run via `python harness/eval/run_ecdat.py --combined`, which drives a
real `ecdat correlate --plan <plan>` subprocess over all 5 adapters below in
one process and scores its actual output -- see README.md's "Current real
results" for the number this produced (0 violations, checked for real, not
skipped) and why the other forbidden pair (PAY-001 vs PAY-004) is
structurally unreachable with the current adapter set rather than silently
passing.

## Secret-leak grep (`secret_leak_scan`)

> §8.2 "Security of ECDAT" row: "grep DB dump, CBOM, UI HTML, logs for
> `-----BEGIN`, base64 key blobs, known throwaway key fingerprints. Pass/fail."

A coarse heuristic (PEM private-key marker, or a long base64 run) over
whatever output files ECDAT produced. Verified for real against this
harness's own generated `pay-tls-secret.yaml` and `pay-edge/key.pem`
(`experiments.md`) -- both were correctly flagged; `haproxy.cfg` (no key
material) was not. It is not a certificate-vs-key classifier: a long
base64-encoded *certificate* would also be flagged as a candidate, which is
an intentional false-positive bias (over-flagging is cheap to review;
missing a real leak is not).

## Under-claiming rate (`score_run.py`'s `score_run()`, not `score.py`)

> §8.2: tracked alongside false-certainty rate because "an all-UNKNOWN tool
> scores a perfect false-certainty rate and is useless."

Fields the run reported `UNKNOWN` where the answer key says `KNOWN`, scoped
to the surfaces the run actually reached (same scoping rule as recall).
Implemented in `score_run.py` (not `score.py`, since it needs the real
asset join, not just the two flat lists `false_certainty_rate` takes) and
printed alongside the false-certainty rate every time `run_ecdat.py` or
`score_run.py` runs.

## Not yet implemented

Everything else in §8.2's table (asset-level P/R after merge, classification
exact-match, purpose accuracy, relationship-label accuracy, visibility
recall, CBOM schema validation, quantum-tier exact match, Mosca/sensitivity
property tests, recommendation accuracy, temporal delta, performance) is out
of scope for the 2026-09-17 task, which asked specifically for
false-certainty rate, per-surface recall, the forbidden-edge check, and the
secret-leak grep. Under-claiming rate (above) and the real-run join were
added afterward in `score_run.py` / `run_ecdat.py`.
