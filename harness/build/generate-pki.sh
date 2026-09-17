#!/usr/bin/env bash
# Generates the harness internal PKI (harness §6). Output is never committed
# (H3: "No key material committed to git."). This script covers only the
# four roles Tier A needs: root-ca, int-ca-ecc, pay-edge, gateway-p12
# (harness §6 defines more roles for Tiers B/C -- out of scope here).
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
OUT="out"
LOCKFILE="pki-lock.generated.json"

rm -rf "$OUT"
mkdir -p "$OUT/root-ca" "$OUT/int-ca-ecc" "$OUT/pay-edge" "$OUT/gateway-p12"

fail() { echo "generate-pki.sh: $*" >&2; exit 1; }

command -v openssl >/dev/null || fail "openssl not found on PATH"

# --- root-ca: RSA-4096, sha256WithRSA, 20y, keyCertSign+cRLSign (harness §6) ---
openssl genrsa -out "$OUT/root-ca/key.pem" 4096 2>/dev/null
openssl req -x509 -new -key "$OUT/root-ca/key.pem" -sha256 -days 7300 \
  -subj "/O=Harness Root CA/CN=Harness Root CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/root-ca/cert.pem"

# --- int-ca-ecc: ECDSA P-384, ecdsa-with-SHA384, 10y, keyCertSign, signed by root-ca ---
openssl ecparam -name secp384r1 -genkey -noout -out "$OUT/int-ca-ecc/key.pem"
openssl req -new -key "$OUT/int-ca-ecc/key.pem" \
  -subj "/O=Harness Intermediate CA (ECC)/CN=Harness Intermediate CA ECC" \
  -out "$OUT/int-ca-ecc/csr.pem"
printf "basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign\n" > "$OUT/int-ca-ecc/ext.cnf"
openssl x509 -req -in "$OUT/int-ca-ecc/csr.pem" \
  -CA "$OUT/root-ca/cert.pem" -CAkey "$OUT/root-ca/key.pem" -CAcreateserial \
  -days 3650 -sha384 \
  -extfile "$OUT/int-ca-ecc/ext.cnf" \
  -out "$OUT/int-ca-ecc/cert.pem"
cat "$OUT/int-ca-ecc/cert.pem" "$OUT/root-ca/cert.pem" > "$OUT/int-ca-ecc/chain.pem"

# --- pay-edge: ECDSA P-256, ecdsa-with-SHA256, 90d, serverAuth, signed by int-ca-ecc ---
# (harness §6: "LB cert on the wire"; harness §5.3 references pay-edge.pem)
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/pay-edge/key.pem"
openssl req -new -key "$OUT/pay-edge/key.pem" \
  -subj "/O=Harness Payments/CN=pay-edge" \
  -out "$OUT/pay-edge/csr.pem"
printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pay-edge\n" > "$OUT/pay-edge/ext.cnf"
openssl x509 -req -in "$OUT/pay-edge/csr.pem" \
  -CA "$OUT/int-ca-ecc/cert.pem" -CAkey "$OUT/int-ca-ecc/key.pem" -CAcreateserial \
  -days 90 -sha256 \
  -extfile "$OUT/pay-edge/ext.cnf" \
  -out "$OUT/pay-edge/cert.pem"
# haproxy wants key+cert+chain concatenated in one PEM
cat "$OUT/pay-edge/cert.pem" "$OUT/pay-edge/key.pem" "$OUT/int-ca-ecc/cert.pem" > "$OUT/pay-edge/pay-edge.pem"

# --- gateway-p12: RSA-2048, sha256WithRSA, 1y, serverAuth+keyEncipherment ---
# (harness §6: "In-app keystore, not on the wire"; harness §5.1 keystore/gateway.p12)
openssl genrsa -out "$OUT/gateway-p12/key.pem" 2048 2>/dev/null
openssl req -new -key "$OUT/gateway-p12/key.pem" \
  -subj "/O=Harness Payments/CN=payment-gateway" \
  -out "$OUT/gateway-p12/csr.pem"
printf "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > "$OUT/gateway-p12/ext.cnf"
openssl x509 -req -in "$OUT/gateway-p12/csr.pem" \
  -CA "$OUT/int-ca-ecc/cert.pem" -CAkey "$OUT/int-ca-ecc/key.pem" -CAcreateserial \
  -days 365 -sha256 \
  -extfile "$OUT/gateway-p12/ext.cnf" \
  -out "$OUT/gateway-p12/cert.pem"
openssl pkcs12 -export \
  -inkey "$OUT/gateway-p12/key.pem" -in "$OUT/gateway-p12/cert.pem" \
  -certfile "$OUT/int-ca-ecc/cert.pem" \
  -name payment-gateway -passout pass:changeit \
  -out "$OUT/gateway-p12/gateway.p12"

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

# --- pki-lock.generated.json: role -> fingerprint/serial/notAfter ---
PYTHON=python3
command -v python3 >/dev/null || PYTHON=python
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
