# Metric definitions (harness §8.2)

Implemented in `score.py`, in the order the 2026-09-17 task specified:
false-certainty rate first, then per-surface recall, forbidden-edge check,
secret-leak grep. Every function below currently runs only against
synthetic fixtures (`score.py --selftest`) plus a real run of
`secret_leak_scan` against this harness's own generated artifacts (see
`experiments.md`) -- there is no real ECDAT output to score yet, since
`ecdat/src/ecdat/adapters/` has no adapters built.

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
a score deduction.

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

## Not yet implemented

Everything else in §8.2's table (asset-level P/R after merge, classification
exact-match, purpose accuracy, under-claiming rate, relationship-label
accuracy, visibility recall, CBOM schema validation, quantum-tier exact
match, Mosca/sensitivity property tests, recommendation accuracy, temporal
delta, performance) is out of scope for the 2026-09-17 task, which asked
specifically for false-certainty rate, per-surface recall, the
forbidden-edge check, and the secret-leak grep.
