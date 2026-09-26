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
#    gateway-p12). DETERMINISTIC (see "Deterministic PKI" below): the same
#    command always produces byte-identical keys/certs. Nothing here is
#    committed regardless (H3: no key material in git).
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

## Deterministic PKI

Before 2026-09-26, `generate-pki.sh` created **fresh random** keys on every
run. That's fine for the harness's own scoring (`score_run.py` joins ground
truth to the PKI through `pki-lock.generated.json` -- role names, never
fingerprints -- exactly so a regeneration never breaks scoring), but it
silently broke every fixture in `ecdat/tests/fixtures/recorded/` that cites
this PKI's exact bytes (`openssl/3.5.4/topo_x3_der_hash_equality/`,
`openssl/3.5.4/e4_seclevel_tier_a_certs/`, `sslyze/6.2.0/tier_a_edge_lb.raw.json`)
every single time someone re-ran this script -- including the run that
deleted the keys those fixtures were recorded against and triggered this
fix (`tests/unit/correlation/test_engine.py`'s
`test_the_wire_certificate_and_the_on_disk_certificate_are_the_same_object`).
Not the same issue as ecdat's OI-014 ("Host OpenSSL is 3.0.13; the fixtures
were recorded against 3.5.4") -- that's about a *different* host/OpenSSL
build entirely and is unaffected by this fix. This PKI-staleness problem
(fresh random keys on every `generate-pki.sh` run breaking recorded fixture
bytes) has no open-issue entry of its own yet in ecdat's
`docs/open-issues.md`; whoever owns that file next should file one (next
free number as of 2026-09-26 is OI-019).

**Fix:** `generate-pki.sh` is now fully deterministic --
**same command, byte-identical output, every run** (verified by
`harness/build/test_pki_reproducibility.py`, part of `python -m pytest
harness`). Three pieces make that true:

1. **Keys derived from a fixed seed.** `harness/build/generate_pki_keys.py`
   derives every role's private key from one documented constant
   (`PKI_SEED`) via HKDF-SHA256 -- an EC scalar directly for `int-ca-ecc`/
   `pay-edge` (`cryptography`'s `ec.derive_private_key`), a deterministic
   byte stream fed to `pycryptodome`'s `RSA.generate(randfunc=...)` for
   `root-ca`/`gateway-p12`. This is a recipe, not key material: H3 ("No key
   material committed to git") still holds exactly as before -- the derived
   key *bytes* are written only under the gitignored `harness/build/out/`
   tree, never committed. The only thing committed is the code that
   reproduces them, same as it always was (anyone with this repo's source
   could already regenerate *a* PKI; they now regenerate the *same* one).
2. **Fixed serials and validity dates** (`-set_serial`, `-not_before`,
   `-not_after` in `generate-pki.sh`) instead of an auto-incrementing `.srl`
   file and "now". `pay-edge`'s 90-day validity window is anchored to a
   documented reference date (currently 2026-09-01) that needs a periodic
   bump to stay non-expired against real wall-clock -- the same maintenance
   a random-every-run script always needed, just explicit now instead of
   automatic. `score_run.py` already evaluates lifecycle state against
   `pki-lock.generated.json`, never wall-clock, so this changes nothing it
   reads.
3. **RFC 6979 deterministic ECDSA nonces** (`-sigopt nonce-type:1`, OpenSSL
   3.2+) for every signature `int-ca-ecc`'s EC key makes (it signs
   `pay-edge` and `gateway-p12`, and self-signs its own CSR). RSA (PKCS#1
   v1.5) signatures are already deterministic given the same key+message, so
   `root-ca`'s self-signature needs no extra flag.

**Known, documented exception:** `gateway-p12/gateway.p12` itself (the
PKCS12 container) is *not* byte-identical across runs -- `openssl pkcs12
-export` bakes a random PBKDF2/MAC salt into the container with no
CLI-exposed override. The `cert.pem`/`key.pem` it's built from are fully
deterministic; `test_pki_reproducibility.py` checks those instead. This
matches every recorded ecdat fixture's own behaviour: they always
canonicalize to DER via `openssl x509 -outform DER` before hashing, never
hash the raw `.p12` bytes (see `topo_x3_der_hash_equality/README.md`'s
finding on why that canonicalization step is load-bearing, not a
formality).

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
- `harness/build/` -- `generate-pki.sh` (internal PKI, gitignored output;
  deterministic, see "Deterministic PKI" above), `generate_pki_keys.py`
  (the deterministic key derivation `generate-pki.sh` calls),
  `test_pki_reproducibility.py` (proves two runs are byte-identical),
  `build-binaries.sh`, `build-images.sh`.
- `harness/eval/` -- `score.py` (metric functions), `score_run.py` (the real
  join + CLI scorer), `run_ecdat.py` (drives ecdat for real and scores the
  result), `ecdat_convert.py` (validates/converts ecdat's run-document JSON),
  `test_ecdat_convert.py` (fixture-based unit tests for the converter),
  `validate_cfg_r1.py`, `metrics.md`, `experiments.md`.
- `docs/` -- the full harness spec.
