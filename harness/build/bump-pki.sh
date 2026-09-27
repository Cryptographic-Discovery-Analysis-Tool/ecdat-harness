#!/usr/bin/env bash
# One-command PKI date bump: harness/build/bump-pki.sh <YYYYMMDD>
#
# Rewrites the NOT_BEFORE/*_NOT_AFTER constants in generate-pki.sh from a
# single new anchor date, using the SAME offsets that file has always
# hardcoded (root +20y, int-ca-ecc +10y, pay-edge +90d, gateway-p12 +1y),
# then re-runs generate-pki.sh so harness/build/out/ and
# pki-lock.generated.json reflect the new dates.
#
# This exists because generate-pki.sh's dates are fixed absolute strings
# (required for byte-identical, deterministic cert bytes -- see README.md
# "Deterministic PKI"), and pay-edge's 90-day validity window is short
# enough that <anchor date> needs periodic bumping to stay non-expired
# against real wall-clock. harness/build/test_pki_freshness.py fails loudly
# (with a pointer to this script) once any generated cert is within 30 days
# of expiry -- that failure is the signal to run this.
#
# Usage:
#   harness/build/bump-pki.sh 20261201
#
# IMPORTANT -- this script only regenerates the harness's own PKI. Every
# recorded ecdat fixture that cites this PKI's exact bytes (cert hashes,
# raw sslyze/openssl captures) goes stale the moment the anchor date
# changes, EXACTLY as it did on 2026-09-26 (ecdat docs/open-issues.md
# OI-019) and again on 2026-09-27. After running this script you MUST, by
# hand, with real tools (no hand-editing recorded output -- CLAUDE.md):
#
#   1. Re-run `python -m pytest harness/build/test_pki_reproducibility.py`
#      to confirm the new dates are still byte-identical across two runs.
#   2. In the ecdat repo, re-record every fixture that embeds this PKI's
#      bytes/hashes/dates:
#        - tests/fixtures/recorded/openssl/3.5.4/topo_x3_der_hash_equality/
#          (re-run its openssl DER/PKCS12-extraction/sha256sum commands --
#          see that directory's results.txt for the exact command
#          transcript to reproduce)
#        - tests/fixtures/recorded/openssl/3.5.4/e4_seclevel_tier_a_certs/
#          (re-run its results.txt command transcript: openssl verify,
#          x509 -text, and the two s_client @SECLEVEL probes against a
#          local s_server)
#        - tests/fixtures/recorded/sslyze/6.2.0/tier_a_edge_lb.raw.json
#          (re-run tier_a_edge_lb_scan.py against a local `openssl
#          s_server` mirroring targets/payments/edge-lb/haproxy.cfg --
#          exact flags recorded in that fixture's README.md) and update
#          tier_a_edge_lb.stderr.log and the README's "Verification" section
#          with the new der_sha256/spki_sha256 hex and run date
#        - tests/unit/adapters/test_tls.py's hardcoded
#          leaf_der_sha256/leaf_spki_sha256/der_sha256/spki_sha256 constants
#          (grep the file for the old hash string and replace both call
#          sites)
#        - grep the whole ecdat repo for the OLD der_sha256/spki_sha256 hex
#          strings (printed by this script's own generate-pki.sh run, in
#          pki-lock.generated.json) to catch any other reference
#   3. Kill any `openssl s_server` you started for step 2.
#   4. `python -m pytest -q` (run once at a time) and every
#      `tools/ci/check_*.py` in ecdat must pass clean, plus
#      `python -m pytest -q harness` and
#      `python harness/eval/run_ecdat.py --combined` (still 10/10, 0
#      forbidden-edge violations) in ecdat-harness.
#
# Ground truth (ecdat-harness/ground-truth/) references PKI roles by NAME,
# never by fingerprint/date (H3), so it never needs editing for a bump.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

ANCHOR="${1:?usage: bump-pki.sh <YYYYMMDD>}"
[[ "$ANCHOR" =~ ^[0-9]{8}$ ]] || { echo "bump-pki.sh: anchor must be YYYYMMDD, got '$ANCHOR'" >&2; exit 1; }

PYTHON=python3
command -v python3 >/dev/null || PYTHON=python
command -v "$PYTHON" >/dev/null || { echo "bump-pki.sh: python3/python not found on PATH" >&2; exit 1; }

# Compute the five fixed dates from one anchor, with the offsets
# generate-pki.sh has always used (+20y/+10y/+90d/+1y), and rewrite that
# script's constants block in place.
"$PYTHON" - "$ANCHOR" <<'PYEOF'
import re
import sys
from datetime import date, timedelta

anchor = sys.argv[1]
nb = date(int(anchor[0:4]), int(anchor[4:6]), int(anchor[6:8]))

def fmt(d: date) -> str:
    return d.strftime("%Y%m%d000000Z")

def add_years(d: date, years: int) -> date:
    try:
        return d.replace(year=d.year + years)
    except ValueError:
        # Feb 29 anchor with a non-leap target year -> fall back to Feb 28.
        return d.replace(year=d.year + years, day=28)

not_before = fmt(nb)
root_not_after = fmt(add_years(nb, 20))
intca_not_after = fmt(add_years(nb, 10))
payedge_not_after = fmt(nb + timedelta(days=90))
gateway_not_after = fmt(add_years(nb, 1))

path = "generate-pki.sh"
text = open(path, "r", encoding="utf-8").read()

replacements = {
    "NOT_BEFORE": not_before,
    "ROOT_NOT_AFTER": root_not_after,
    "INTCA_NOT_AFTER": intca_not_after,
    "PAYEDGE_NOT_AFTER": payedge_not_after,
    "GATEWAY_NOT_AFTER": gateway_not_after,
}
for var, value in replacements.items():
    pattern = re.compile(rf'^{var}="[0-9A-Za-z]+"(.*)$', re.MULTILINE)
    text, n = pattern.subn(f'{var}="{value}"' + r"\1", text)
    if n != 1:
        raise SystemExit(f"bump-pki.sh: expected exactly one '{var}=' line, found {n}")

bump_note = re.compile(r"^# last bumped .*$", re.MULTILINE)
today_note = f"# last bumped {date.today().isoformat()} (anchor {nb.isoformat()}; pay-edge expires {(nb + timedelta(days=90)).isoformat()}, re-bump before then)."
text, n = bump_note.subn(today_note, text)
if n != 1:
    raise SystemExit("bump-pki.sh: expected exactly one '# last bumped' comment line")

open(path, "w", encoding="utf-8").write(text)
print(f"bump-pki.sh: NOT_BEFORE={not_before} ROOT_NOT_AFTER={root_not_after} "
      f"INTCA_NOT_AFTER={intca_not_after} PAYEDGE_NOT_AFTER={payedge_not_after} "
      f"GATEWAY_NOT_AFTER={gateway_not_after}")
PYEOF

echo "bump-pki.sh: regenerating PKI with new dates..."
BASH_BIN="${BASH:-bash}"
"$BASH_BIN" generate-pki.sh

cat <<'EOM'

bump-pki.sh: done. generate-pki.sh's dates are updated and harness/build/out/
+ pki-lock.generated.json now reflect them.

REMINDER (see this script's own header comment for the full checklist):
every ecdat fixture that cites this PKI's exact bytes is now STALE and must
be re-recorded by hand with real tools (openssl s_server + real sslyze
6.2.0) -- no hand-editing recorded output. Then re-run:
  ecdat:         python -m pytest -q   (once at a time)  +  tools/ci/check_*.py
  ecdat-harness: python -m pytest -q harness
  ecdat-harness: python harness/eval/run_ecdat.py --combined   (10/10, 0 forbidden-edge violations)
EOM
