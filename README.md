# ECDAT Synthetic Enterprise Test Harness

Ground truth, synthetic target fixtures, and the scoring tooling used to
evaluate [ECDAT](../ecdat) (a crypto-evidence correlation and PQC migration
decision-support layer) against Tier A planted assets. See
`docs/ECDAT_Synthetic_Enterprise_Test_Harness.md` for the full spec.

This harness never edits ECDAT and never edits `ground-truth/` to make a
score look better. All scoring glue lives here.

## How to run a real score, end to end

```bash
# 1. Generate the harness's internal PKI (root-ca, int-ca-ecc, pay-edge,
#    gateway-p12). Regenerated fresh each time -- nothing here is committed
#    (H3: no key material in git).
bash harness/build/generate-pki.sh

# 2. (Optional, needs Maven/JDK) Build the payment-gateway fixture and
#    validate the CFG-001 state matrix against a real running JVM:
python harness/eval/validate_cfg_r1.py

# 3. Run ecdat for real against the Tier A payment-gateway target, convert
#    its output, and score it -- all in one step:
python harness/eval/run_ecdat.py
```

`run_ecdat.py` locates ecdat via the `ECDAT_REPO` environment variable
(default: `../ecdat`, i.e. a sibling checkout of this repo), invokes
`python -m ecdat.cli scan` as a real subprocess for each adapter below,
validates and converts each run document (`harness/eval/ecdat_convert.py`),
writes it to `harness/eval/out/` (gitignored), and scores it with
`harness/eval/score_run.py`.

Adapters run, and why:

| Adapter | Mode | What it reads |
|---|---|---|
| `source-semgrep` | replay | `ecdat/tests/fixtures/recorded/semgrep/1.99.0/ecdat-rules/tier-a-java.raw.json` -- a REAL semgrep 1.99.0 run recorded against this harness's own `targets/payments/payment-gateway/src`. CLAUDE.md: "Replay of a recorded file (`--input`) is for tests and scoring only" -- this is exactly that. |
| `certs-x509` | **live** | The real `targets/payments/payment-gateway/keystore/gateway.p12` keystore generate-pki.sh just produced. No external tool subprocess -- python-cryptography reads the file directly. |
| `config-chain-spring` | **live** | The real `application.yml` / `application-prod.yml` under `targets/payments/payment-gateway`, resolving `pay.keywrap.transformation`. No external tool subprocess -- ecdat's own static resolver. |

`packages-trivy`, `images-cbomkit-theia`, `hsm-pkcs11`, `kms-aws`,
`binary-yara-readelf` and `tls-endpoint` are not run by this script: trivy,
Docker, a PKCS#11 module, a real AWS account and a live TLS listener are not
available in this environment, and `score_run.py`'s join
(`_canonical_surface`) currently only recognises three ground-truth surfaces
(`source`, `artifact`, `configuration`) -- see "What ecdat missed" below.

Run `harness/eval/run_ecdat.py --allow-missing-pki` to score anyway if PKI
generation is unavailable (certificate findings will show as out of reach
rather than scored); otherwise a missing
`harness/build/pki-lock.generated.json` is a loud, non-zero-exit failure,
never a silent note.

To score an already-produced run document directly (e.g. from CI, or a
`packages-trivy --live` run against a real rootfs):

```bash
python harness/eval/score_run.py harness/eval/out/*.run.json
```

## Current real results (2026-09-26, this environment)

Maven/Docker/semgrep/trivy binaries are not installed on this Windows
machine, so this is `source-semgrep` (replay of a real recorded run),
`certs-x509` and `config-chain-spring` (both live) only -- see
`harness/eval/experiments.md` for tool-version provenance.

- **False-certainty rate: 0.0** on all three runs (0 fields reported `KNOWN`
  where ground truth expects `UNKNOWN`/`INFERRED`/`DECLARED`). Each run's
  metric self-check confirms the metric is live (an all-`KNOWN` copy of the
  same run scores 1.0), so this 0.0 is a real result, not a broken join.
- **Per-surface recall:** `source` 4/4 (PAY-001, PAY-002, PAY-003, TRAP-01),
  `artifact` 1/1 (PAY-004's gateway-p12 certificate), `configuration` 1/1
  (PAY-001's `pay.keywrap.transformation`). Every other surface
  (`tls`, `dependency`, and `artifact`/`configuration` for the assets these
  three adapters never reached) is reported "out of reach", not scored as a
  miss -- these adapters were never pointed at those targets.
- **Under-claiming rate: 0.0** on all three runs (0 fields reported
  `UNKNOWN` where ground truth expects `KNOWN`).
- **Forbidden-edge violations:** not exercised -- no `correlate` run was
  produced (no plan combining these three adapters' output has been built
  yet; each was scored as an independent `scan`, not a `correlate`).
- **Secret-leak scan:** not run against these three runs' output (none of
  them write key bytes; `certs-x509`'s module docstring notes every finding
  is run through the shared secret guard before being returned). Previously
  verified for real against this harness's own generated
  `pay-tls-secret.yaml` / `pay-edge/key.pem` (see `harness/eval/experiments.md`).

### What ecdat missed, and why

- **Tool unavailable, not a detection gap:** `packages-trivy` (PAY-008,
  Bouncy Castle dependency), `tls-endpoint` (PAY-005/006/007, the wire
  observation), `hsm-pkcs11`, `kms-aws`, `images-cbomkit-theia` were not run
  -- trivy/Docker/a PKCS#11 token/a live TLS listener/an AWS account are not
  available here. ecdat has real adapters for all of these; they were never
  invoked.
- **Mapping gap, not a detection gap:** `INF-017` (the k8s secret carrying
  the reused `pay-edge` private key) has no adapter in this harness's run at
  all -- no ecdat adapter reads a raw Kubernetes Secret manifest as its own
  surface. `score_run.py`'s `_canonical_surface` also only recognises
  `source`/`artifact`/`configuration`; a `packages-trivy` or `tls-endpoint`
  run would produce findings score_run.py cannot currently join to
  anything, which is why they were left out rather than run and shown as an
  artificial 0.
- **Not a real gap:** every asset these three adapters *did* reach was
  found, with the correct epistemic state, and zero false certainty.

## Layout

- `ground-truth/` -- planted assets, expected observations, traps, relationships.
- `targets/` -- synthetic enterprise fixtures (Tier A payment-gateway/edge-lb
  are wired for real scoring; other tiers are fixtures only).
- `harness/build/` -- `generate-pki.sh` (internal PKI, gitignored output),
  `build-binaries.sh`, `build-images.sh`.
- `harness/eval/` -- `score.py` (metric functions), `score_run.py` (the real
  join + CLI scorer), `run_ecdat.py` (drives ecdat for real and scores the
  result), `ecdat_convert.py` (validates/converts ecdat's run-document JSON),
  `test_ecdat_convert.py` (fixture-based unit tests for the converter),
  `validate_cfg_r1.py`, `metrics.md`, `experiments.md`.
- `docs/` -- the full harness spec.
