#!/usr/bin/env bash
# Generates the harness internal PKI (harness §6). Output is never committed
# (H3: "No key material committed to git."). This script covers only the
# four roles Tier A needs: root-ca, int-ca-ecc, pay-edge, gateway-p12
# (harness §6 defines more roles for Tiers B/C -- out of scope here).
#
# DETERMINISTIC BY DESIGN (see README.md "Deterministic PKI" section):
# same command -> byte-identical key.pem/cert.pem/chain.pem/pay-edge.pem for
# every role, every run, forever. Three ingredients make that true:
#   1. Every private key is derived from one fixed, documented seed
#      (generate_pki_keys.py) instead of a fresh random key each run.
#   2. Every certificate uses a fixed notBefore/notAfter and a fixed serial
#      (below) instead of "now" and an auto-incrementing .srl file.
#   3. Every ECDSA signature (int-ca-ecc is an EC key, so every cert or CSR
#      it signs, plus pay-edge's CSR self-signature) uses RFC 6979
#      deterministic nonces (`-sigopt nonce-type:1`, OpenSSL 3.2+) instead of
#      a random per-signature k. RSA (PKCS#1 v1.5) signatures are already
#      deterministic given the same key+message, so root-ca's self-signature
#      and gateway-p12's CSR self-signature need no extra flag.
# Exception: `openssl pkcs12 -export` (gateway.p12) has no CLI knob to fix
# its internal PBKDF2/MAC salts, so that one *container* is not
# byte-identical across runs -- but the cert/key it wraps are (verified by
# harness/build/test_pki_reproducibility.py), which is all any recorded
# ecdat fixture ever hashes (always via `openssl x509 ... -outform DER`
# canonicalization, never raw .p12 bytes -- see
# ecdat/tests/fixtures/recorded/openssl/3.5.4/topo_x3_der_hash_equality/).
#
# Output layout:
#   harness/build/out/<role>/{key.pem,cert.pem,...}
#   harness/build/pki-lock.generated.json   -- role -> fingerprint/serial/notAfter (gitignored)
#
# ground-truth/ references roles by NAME, never by fingerprint (H3), so
# regenerating this script's output must never require editing ground truth.
set -euo pipefail

# MSYS/Git-Bash rewrites any argument that looks like a leading-slash unix
# path (e.g. "/O=Harness Root CA/CN=...") into a Windows path, which breaks
# every openssl -subj argument below. Disable that rewriting for this script.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# cd into this script's own directory and use RELATIVE paths throughout.
# On this harness's dev environment (Windows, Git-for-Windows openssl.exe),
# openssl cannot open an absolute path containing an apostrophe (observed:
# any repo checked out under a path like ".../Atharv's Stack/..." breaks
# every -out/-in flag). Relative paths sidestep it entirely and are more
# portable regardless.
cd "$(dirname "${BASH_SOURCE[0]}")"

# Overridable only so harness/build/test_pki_reproducibility.py can run this
# script twice into two throwaway directories without clobbering the real
# build output or the target fixture copies. Never overridden in normal use.
OUT="${HARNESS_PKI_OUT:-out}"
LOCKFILE="${HARNESS_PKI_LOCKFILE:-pki-lock.generated.json}"
SKIP_TARGET_COPY="${HARNESS_PKI_SKIP_TARGET_COPY:-0}"

# Fixed anchor date + fixed per-role validity periods (harness §6 table).
# Absolute dates, not "-days N from now", are what makes cert bytes
# reproducible on any day this is run. score_run.py already evaluates
# lifecycle state against pki-lock.generated.json, never wall-clock (harness
# doc §6: "the scorer must evaluate them against the lock file, not
# wall-clock guesses").
#
# pay-edge is genuinely short-lived (90d, harness §6) -- that was true before
# this change too (every old run also had a real, eventually-expiring 90-day
# cert). Anchoring to a fixed date doesn't remove that; it just means the
# anchor needs a periodic bump to keep pay-edge non-expired against real
# wall-clock (e.g. for `openssl verify` / a live TLS handshake / ecdat's own
# lifecycle read), the same way the old random-each-run script needed a
# re-run to get a fresh 90-day window. Bump NOT_BEFORE below (and re-run this
# script) if pay-edge's window has passed; last bumped 2026-09-26.
NOT_BEFORE="20260901000000Z"
ROOT_NOT_AFTER="20460901000000Z"     # +20y
INTCA_NOT_AFTER="20360901000000Z"    # +10y
PAYEDGE_NOT_AFTER="20261130000000Z"  # +90d
GATEWAY_NOT_AFTER="20270901000000Z"  # +1y

# Fixed serials (harness §6 doesn't mandate specific values, only that
# ground truth references roles by NAME -- these just need to stop coming
# from a random/auto-incrementing .srl file so the cert bytes are stable).
ROOT_SERIAL="0x1001"
INTCA_SERIAL="0x1002"
PAYEDGE_SERIAL="0x1003"
GATEWAY_SERIAL="0x1004"

# RFC 6979 deterministic-ECDSA-nonce signature option (OpenSSL 3.2+).
ECDSA_DETERMINISTIC=(-sigopt nonce-type:1)

rm -rf "$OUT"
mkdir -p "$OUT/root-ca" "$OUT/int-ca-ecc" "$OUT/pay-edge" "$OUT/gateway-p12"

fail() { echo "generate-pki.sh: $*" >&2; exit 1; }

command -v openssl >/dev/null || fail "openssl not found on PATH"

PYTHON=python3
command -v python3 >/dev/null || PYTHON=python
command -v "$PYTHON" >/dev/null || fail "python3/python not found on PATH"

# --- deterministic key generation for all four roles (generate_pki_keys.py) ---
"$PYTHON" generate_pki_keys.py "$OUT"

# --- root-ca: RSA-4096, sha256WithRSA, 20y, keyCertSign+cRLSign (harness §6) ---
# Self-signed with its own (deterministic) RSA key: RSA PKCS#1 v1.5 signing
# is already deterministic given the same key+message, no extra flag needed.
openssl req -x509 -new -key "$OUT/root-ca/key.pem" -sha256 \
  -not_before "$NOT_BEFORE" -not_after "$ROOT_NOT_AFTER" -set_serial "$ROOT_SERIAL" \
  -subj "/O=Harness Root CA/CN=Harness Root CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/root-ca/cert.pem"

# --- int-ca-ecc: ECDSA P-384, ecdsa-with-SHA384, 10y, keyCertSign, signed by root-ca ---
openssl req -new -key "$OUT/int-ca-ecc/key.pem" \
  -subj "/O=Harness Intermediate CA (ECC)/CN=Harness Intermediate CA ECC" \
  -sha384 "${ECDSA_DETERMINISTIC[@]}" \
  -out "$OUT/int-ca-ecc/csr.pem"
printf "basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign\n" > "$OUT/int-ca-ecc/ext.cnf"
# Signed by root-ca's RSA key -> already deterministic, no sigopt needed.
openssl x509 -req -in "$OUT/int-ca-ecc/csr.pem" \
  -CA "$OUT/root-ca/cert.pem" -CAkey "$OUT/root-ca/key.pem" \
  -not_before "$NOT_BEFORE" -not_after "$INTCA_NOT_AFTER" -set_serial "$INTCA_SERIAL" \
  -sha384 \
  -extfile "$OUT/int-ca-ecc/ext.cnf" \
  -out "$OUT/int-ca-ecc/cert.pem"
cat "$OUT/int-ca-ecc/cert.pem" "$OUT/root-ca/cert.pem" > "$OUT/int-ca-ecc/chain.pem"

# --- pay-edge: ECDSA P-256, ecdsa-with-SHA256, 90d, serverAuth, signed by int-ca-ecc ---
# (harness §6: "LB cert on the wire"; harness §5.3 references pay-edge.pem)
openssl req -new -key "$OUT/pay-edge/key.pem" \
  -subj "/O=Harness Payments/CN=pay-edge" \
  -sha256 "${ECDSA_DETERMINISTIC[@]}" \
  -out "$OUT/pay-edge/csr.pem"
printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pay-edge\n" > "$OUT/pay-edge/ext.cnf"
# Signed by int-ca-ecc's EC key -> RFC 6979 deterministic nonce required.
openssl x509 -req -in "$OUT/pay-edge/csr.pem" \
  -CA "$OUT/int-ca-ecc/cert.pem" -CAkey "$OUT/int-ca-ecc/key.pem" \
  -not_before "$NOT_BEFORE" -not_after "$PAYEDGE_NOT_AFTER" -set_serial "$PAYEDGE_SERIAL" \
  -sha256 "${ECDSA_DETERMINISTIC[@]}" \
  -extfile "$OUT/pay-edge/ext.cnf" \
  -out "$OUT/pay-edge/cert.pem"
# haproxy wants key+cert+chain concatenated in one PEM
cat "$OUT/pay-edge/cert.pem" "$OUT/pay-edge/key.pem" "$OUT/int-ca-ecc/cert.pem" > "$OUT/pay-edge/pay-edge.pem"

# --- gateway-p12: RSA-2048, sha256WithRSA, 1y, serverAuth+keyEncipherment ---
# (harness §6: "In-app keystore, not on the wire"; harness §5.1 keystore/gateway.p12)
openssl req -new -key "$OUT/gateway-p12/key.pem" \
  -subj "/O=Harness Payments/CN=payment-gateway" \
  -out "$OUT/gateway-p12/csr.pem"
printf "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > "$OUT/gateway-p12/ext.cnf"
# Signed by int-ca-ecc's EC key -> RFC 6979 deterministic nonce required.
openssl x509 -req -in "$OUT/gateway-p12/csr.pem" \
  -CA "$OUT/int-ca-ecc/cert.pem" -CAkey "$OUT/int-ca-ecc/key.pem" \
  -not_before "$NOT_BEFORE" -not_after "$GATEWAY_NOT_AFTER" -set_serial "$GATEWAY_SERIAL" \
  -sha256 "${ECDSA_DETERMINISTIC[@]}" \
  -extfile "$OUT/gateway-p12/ext.cnf" \
  -out "$OUT/gateway-p12/cert.pem"
# NOTE: the .p12 container itself is NOT byte-identical across runs (OpenSSL
# salts its PBKDF2/MAC internals with no exposed override) -- see the file
# header comment above. The cert.pem/key.pem it's built from are.
openssl pkcs12 -export \
  -inkey "$OUT/gateway-p12/key.pem" -in "$OUT/gateway-p12/cert.pem" \
  -certfile "$OUT/int-ca-ecc/cert.pem" \
  -name payment-gateway -passout pass:changeit \
  -out "$OUT/gateway-p12/gateway.p12"

if [ "$SKIP_TARGET_COPY" != "1" ]; then
  # --- copy generated material into the target fixtures that reference it ---
  # (still gitignored at the target paths -- see .gitignore -- H3 applies there too)
  mkdir -p ../../targets/payments/payment-gateway/keystore
  cp "$OUT/gateway-p12/gateway.p12" ../../targets/payments/payment-gateway/keystore/gateway.p12

  mkdir -p ../../targets/payments/edge-lb/certs
  cp "$OUT/pay-edge/pay-edge.pem" ../../targets/payments/edge-lb/certs/pay-edge.pem

  # INF-017 / TRAP-09: render the k8s secret template with the real,
  # throwaway pay-edge private key (base64), never committed (H3).
  PAY_EDGE_KEY_B64=$(openssl base64 -A -in "$OUT/pay-edge/key.pem")
  sed "s#__PAY_EDGE_PRIVATE_KEY_BASE64__#$PAY_EDGE_KEY_B64#" \
    ../../targets/infrastructure/k8s/secrets/pay-tls-secret.yaml.template \
    > ../../targets/infrastructure/k8s/secrets/pay-tls-secret.yaml
fi

# --- pki-lock.generated.json: role -> fingerprint/serial/notAfter ---
"$PYTHON" - "$OUT" "$LOCKFILE" <<'PYEOF'
import hashlib, json, subprocess, sys, pathlib

out_dir = pathlib.Path(sys.argv[1])
lockfile = pathlib.Path(sys.argv[2])

roles = ["root-ca", "int-ca-ecc", "pay-edge", "gateway-p12"]
result = {}
for role in roles:
    cert_path = out_dir / role / "cert.pem"
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    fingerprint = hashlib.sha256(der).hexdigest()
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial", "-enddate"],
        check=True, capture_output=True, text=True,
    ).stdout
    serial = None
    not_after = None
    for line in text.splitlines():
        if line.startswith("serial="):
            serial = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            not_after = line.split("=", 1)[1]
    result[role] = {
        "sha256_fingerprint_der": fingerprint,
        "serial": serial,
        "not_after": not_after,
    }

lockfile.write_text(json.dumps(result, indent=2) + "\n")
print(f"wrote {lockfile}")
PYEOF

echo "generate-pki.sh: done. Output in $OUT (gitignored), lockfile at $LOCKFILE (gitignored)."
