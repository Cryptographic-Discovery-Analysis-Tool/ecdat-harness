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

# 3b. Also run a combined `ecdat correlate` over all 5 adapters and score
#     the forbidden-edge check for real (harness §7.4):
python harness/eval/run_ecdat.py --combined

# 3c. Run source-semgrep and packages-trivy LIVE (real subprocess, not
#     replay of tests/fixtures/recorded/) instead of the default replay --
#     needs a WSL (or other launcher) with semgrep/trivy installed; see
#     "Live mode" below:
ECDAT_SEMGREP_LAUNCHER="wsl -e" ECDAT_TRIVY_LAUNCHER="wsl -e" \
  python harness/eval/run_ecdat.py --live
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

Two more adapters are run as REPLAYS of recordings captured for real against
this harness's own Tier A targets (both READMEs under
`ecdat/tests/fixtures/recorded/` confirm this):

| Adapter | Mode | What it reads |
|---|---|---|
| `tls-endpoint` | replay | `ecdat/tests/fixtures/recorded/sslyze/6.2.0/tier_a_edge_lb.raw.json` -- a REAL sslyze 6.2.0 run against `openssl s_server` standing in for haproxy, presenting the real `generate-pki.sh`-produced `pay-edge.pem` on `edge-lb:8443` (haproxy itself is not installable on this machine; see that fixture's README, "Substitution recorded"). |
| `packages-trivy` | replay | `ecdat/tests/fixtures/recorded/trivy/0.74.0/e1_supplemental_payment-gateway-fatjar.raw.json` -- a REAL `trivy rootfs` run against this harness's own built `payment-gateway` Spring Boot fat jar (trivy is not installed on this machine; see that fixture's README). |

`score_run.py`'s join (`_canonical_surface`) now recognises five
ground-truth surfaces: `source`, `artifact`, `configuration`, `tls` (joined
by `host:port`, and -- since one wire probe is evidence for three planted
"logical" assets at that endpoint, PAY-005/006/007 -- matched to all three at
once, not just one) and `dependency` (joined by package name/purl; reachable
scope is "did a `packages-trivy` run happen at all", not path-suffix,
because trivy observes a dependency via the BUILT artifact while ground
truth's PAY-008 location names the SOURCE `pom.xml` -- no path connects the
two honestly, see `_in_reach`'s docstring in `score_run.py`).

`images-cbomkit-theia`, `hsm-pkcs11` and `kms-aws` are still not run: Docker,
a PKCS#11 module and a real AWS account are not available in this
environment.

### Combined run: `ecdat correlate` and the forbidden-edge check

```bash
python harness/eval/run_ecdat.py --combined
```

Runs all 5 adapters above through a REAL `ecdat correlate --plan <plan>`
subprocess (one process, one `CorrelationReport`) instead of 5 independent
`scan`s, and scores its actual `same-object` relationships against
`ground-truth/relationships.yaml`'s forbidden pairs via `score_run.py`'s new
`score_correlation` (see `metrics.md`). This is the first run in this
harness where the forbidden-edge check is exercised against something real
rather than only `score.py`'s synthetic self-test.

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

### Live mode: `source-semgrep`/`packages-trivy` for real, not replayed

```bash
ECDAT_SEMGREP_LAUNCHER="wsl -e" ECDAT_TRIVY_LAUNCHER="wsl -e" \
  python harness/eval/run_ecdat.py --live
```

By default `run_ecdat.py` replays the two recorded fixtures named in the table
above (CLAUDE.md: replay is for tests and scoring only, but it is also the
only thing that works on a machine without semgrep/trivy installed -- which
is why replay stays the default and CI does not need this flag). `--live`
switches `source-semgrep` to a real `semgrep --config rules/semgrep ...`
subprocess against this harness's own `targets/payments/payment-gateway/src`,
and `packages-trivy` to a real `trivy rootfs ...` subprocess against the
payment-gateway's built fat jar (`targets/payments/payment-gateway/target/*.jar`
-- built separately, this script does not build it; run
`cd targets/payments/payment-gateway && mvn -q package -DskipTests` first,
from wherever Maven and network access to Maven Central are available). If
that jar has not been built, `--live` prints the exact command above, reports
itself blocked for that one adapter, and falls back to the recorded trivy
fixture so the rest of the run still completes.

Neither tool needs to be installed on the host running this script: ecdat's
own `adapters/live_launcher.py` (see ecdat's `docs/deviations.md` DEV-015)
routes the subprocess through `ECDAT_SEMGREP_LAUNCHER`/`ECDAT_TRIVY_LAUNCHER`
(or the generic `ECDAT_TOOL_LAUNCHER`) -- `"wsl -e"` on a Windows machine
with WSL, but the mechanism is generic (any launcher prefix), and this
script never hardcodes WSL itself; it only reads whatever launcher env vars
are already set in the calling shell and lets the ecdat subprocess inherit
them. With `--live`, both adapters also run once in replay mode purely for
comparison (not scored) and print a "live vs replay" section: finding counts,
coverage counts, and a set difference of finding content. A real run on a
Windows dev machine reproduced the recorded semgrep fixture's 5 findings
exactly (same rule/file/line/value); the only difference was the `path`
field's literal string, because the *recorded fixture* itself stores
`/mnt/c/...`-style paths from when it was captured directly inside WSL,
while a live run today translates back to a Windows path -- a
path-representation difference from how the fixture was captured, not a
difference in what was found (see DEV-015 for the full comparison).

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
   documented reference date (currently 2026-09-27; see "Bumping the PKI"
   below) that needs a periodic bump to stay non-expired against real
   wall-clock -- the same maintenance a random-every-run script always
   needed, just explicit now instead of automatic (and, since
   `harness/build/bump-pki.sh` was added, one command instead of a hand
   edit). `score_run.py` already evaluates lifecycle state against
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

### Bumping the PKI

`pay-edge` is genuinely short-lived by design (90d, harness §6 table), so
its fixed `NOT_BEFORE` anchor in `generate-pki.sh` needs periodic bumping to
stay non-expired against real wall-clock -- the same maintenance a
random-every-run script always needed, just explicit now. Run:

```bash
harness/build/bump-pki.sh <YYYYMMDD>
```

This rewrites `generate-pki.sh`'s five fixed dates from one new anchor
(same offsets as always: root +20y, int-ca-ecc +10y, pay-edge +90d,
gateway-p12 +1y) and re-runs it. `harness/build/test_pki_freshness.py`
(part of `python -m pytest harness`) fails loudly, with the same
instructions, once any generated cert is within 30 days of expiry -- that
failure is the trigger to run this.

**A bump is not just a harness-side operation.** Every ecdat fixture that
cites this PKI's exact bytes goes stale the moment the anchor date changes
(this happened on 2026-09-26, `ecdat/docs/open-issues.md` OI-019, and again
on 2026-09-27) and must be re-recorded by hand with real tools -- no
hand-editing recorded output. `bump-pki.sh`'s own header comment carries
the full checklist (which ecdat fixtures, which exact commands); the short
version:

1. `python -m pytest harness/build/test_pki_reproducibility.py` (confirm
   still byte-identical across two runs).
2. In `ecdat`, re-record `tests/fixtures/recorded/openssl/3.5.4/
   topo_x3_der_hash_equality/`, `.../e4_seclevel_tier_a_certs/`, and
   `tests/fixtures/recorded/sslyze/6.2.0/tier_a_edge_lb.raw.json` (+ its
   README and `tier_a_edge_lb_scan.py`'s companion `.stderr.log`) against a
   local `openssl s_server` mirroring
   `targets/payments/edge-lb/haproxy.cfg`, and update
   `tests/unit/adapters/test_tls.py`'s hardcoded `der_sha256`/`spki_sha256`
   constants (`spki_sha256` usually does NOT change -- the key is
   seed-derived, not date-derived; only `der_sha256`, which hashes the whole
   certificate including its validity dates, does).
3. Kill any `s_server` you started.
4. `python -m pytest -q` (once at a time) + every `tools/ci/check_*.py` in
   `ecdat`; `python -m pytest -q harness` and
   `python harness/eval/run_ecdat.py --combined` (10/10, 0 forbidden-edge
   violations) in `ecdat-harness`.

Ground truth (`ground-truth/`) references PKI roles by NAME, never by
fingerprint or date (H3), so a bump never requires editing it.

## Current real results (2026-09-27, this environment)

Maven/Docker/semgrep/trivy/haproxy binaries are not installed on this
Windows machine, so `source-semgrep`, `tls-endpoint` and `packages-trivy` are
REPLAYS of real recorded tool runs against this harness's own Tier A
targets; `certs-x509`, `certs-x509-root-ca`, `k8s-secret` and
`config-chain-spring` are LIVE. See `harness/eval/experiments.md` and each
fixture's own README (linked above) for tool-version provenance.

`certs-x509-root-ca` and `k8s-secret` are new runs added in this session:
`certs-x509-root-ca` re-runs the same `certs-x509` adapter over
`harness/build/out/` directly (the original `certs-x509` run only ever
pointed at the payment-gateway keystore, so `root-ca` was never in reach --
a target-scope gap, not a detection gap; see `run_ecdat.py`'s own docstring
for the full explanation). `k8s-secret` is ecdat's new generic Kubernetes
Secret adapter (`src/ecdat/adapters/k8s_secret/`, ecdat DEV-014), reading
the real `pay-tls-secret.yaml` this harness's own `generate-pki.sh` renders
from its template.

- **False-certainty rate: 0.0** on every run that has anything eligible to
  score (`source-semgrep` 0/8, `certs-x509` 0/2, `certs-x509-root-ca` 0/10,
  `config-chain-spring` 0/3). `k8s-secret`, `tls-endpoint` and
  `packages-trivy` report "not applicable" -- every field either has no
  stated expectation on that surface, or is itself a direct read expected
  `KNOWN` -- not a broken join; each run's own metric self-check (or the
  "not applicable" branch itself) confirms this.
- **Per-surface recall, now 10/10 planted Tier A assets (PAY-001..008,
  INF-001, INF-017) that ANY adapter reaches**, up from 8/10 before this
  session: `source` 4/4 (PAY-001, PAY-002, PAY-003, TRAP-01), `artifact`
  1/1 on the keystore-scoped `certs-x509` run (PAY-004's gateway-p12
  certificate) **plus 3/3 on the new `certs-x509-root-ca` run** (PAY-004,
  PAY-005, **INF-001's root-ca certificate** -- previously unscored because
  nothing scanned `harness/build/out/root-ca/cert.pem`), `configuration`
  1/1 on `config-chain-spring` (PAY-001's `pay.keywrap.transformation`)
  **plus 1/1 on the new `k8s-secret` run (INF-017's `data.tls.key`,
  previously unscored because no adapter read k8s Secret manifests at
  all)**, `tls` 3/3 (PAY-005/006/007, one real sslyze wire probe of
  `edge-lb:8443`), `dependency` 1/1 (PAY-008's
  `org.bouncycastle:bcprov-jdk18on`, one real trivy rootfs scan of the
  built fat jar). Every surface an adapter did not reach is still reported
  "out of reach", never scored as a miss.
- **Under-claiming rate: 0.0** on every run with anything expected `KNOWN`
  in scope.
- **Forbidden-edge violations: 0, genuinely exercised.**
  `python harness/eval/run_ecdat.py --combined` runs a real `ecdat correlate`
  over all 7 adapter runs above in one process: 36 assets, 3 same-object
  relationships (all within the `certs-x509`/`certs-x509-root-ca` PKI-role
  family -- e.g. the same `gateway-p12`/`pay-edge`/`int-ca-ecc` certificates
  read twice across the two certs-x509 runs; gateway-p12 and pay-edge
  themselves remain different certificates with different `der_sha256`
  hashes, so they are never linked to each other).
  `score_run.py`'s `score_correlation` resolves 7 assets to harness PKI
  roles (`pay-edge`, `int-ca-ecc`, `gateway-p12`, `root-ca`) and checks
  `ground-truth/relationships.yaml`'s forbidden `gateway-p12`/`pay-edge`
  same-object pair against all 3 relationships: 0 violations. The OTHER
  forbidden pair (PAY-001's source-code RSA key vs PAY-004's keystore key)
  is **not exercised** -- reported as such by `score_correlation`, not
  silently passed -- because `source-semgrep` emits no
  `der_sha256`/`spki_sha256` field at all, so no hash exists on that side
  for ecdat's identity rule to ever compare.
- **Secret-leak scan: clean.** None of the seven runs' output writes key
  bytes; `k8s-secret` decodes the real `pay-edge` EC private key inside
  `pay-tls-secret.yaml` in memory and reports only
  `contains_private_key_material: KNOWN(true)`, `key_algorithm: EC`,
  `key_size: 256`, `key_curve: secp256r1` -- every adapter's own module
  docstring notes findings are run through the shared secret guard
  (`ecdat.security.secrets.scan_for_secrets`) before being returned, and
  ecdat's own `test_k8s_secret.py` asserts the guard fires on a real key and
  that the serialised k8s-secret result contains neither PEM armour nor the
  base64 blob. Also previously verified manually against this harness's own
  generated `pay-tls-secret.yaml` / `pay-edge/key.pem` (see
  `harness/eval/experiments.md`).

### What ecdat missed, and why

- **Tool unavailable, not a detection gap:** `images-cbomkit-theia`,
  `hsm-pkcs11`, `kms-aws` were not run -- Docker, a PKCS#11 token and a real
  AWS account are not available here. ecdat has real adapters for all three;
  they were never invoked.
- **Not a real gap:** every Tier A asset an adapter above actually reached
  was found, with the correct epistemic state, zero false certainty, and
  (for the identity-bearing surfaces this combined run could compare) zero
  forbidden merges. All 10 planted Tier A assets are now in reach and found.

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
  join + CLI scorer, plus `score_correlation` for the combined-run
  forbidden-edge check), `run_ecdat.py` (drives ecdat for real, including
  `--combined`, and scores the result), `ecdat_convert.py`
  (validates/converts ecdat's run-document JSON), `test_ecdat_convert.py`
  (fixture-based unit tests for the converter), `test_score_run.py`
  (fixture-based unit tests for the `tls`/`dependency` joins and
  `score_correlation`), `validate_cfg_r1.py`, `metrics.md`, `experiments.md`.
- `docs/` -- the full harness spec.
