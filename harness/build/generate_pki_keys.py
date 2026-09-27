#!/usr/bin/env python3
"""Deterministic private-key generation for harness/build/generate-pki.sh.

Goal: `generate-pki.sh` twice in a row -> byte-identical `key.pem` (and,
combined with fixed serials/dates/RFC-6979 signing in generate-pki.sh
itself, byte-identical `cert.pem`) for every role, every time, on this
harness's pinned toolchain. See the "Deterministic PKI" section of
../../README.md for the full rationale and the reproducibility check.

Why this exists: before this change, every `generate-pki.sh` run created
FRESH RANDOM keys, so ecdat's recorded fixtures that cite this PKI's exact
bytes (e.g. tests/fixtures/recorded/openssl/3.5.4/topo_x3_der_hash_equality/
pay-edge.der.crt) went stale on every regeneration -- including the
regeneration that triggered this fix. Deriving every key from one fixed,
documented seed makes the whole PKI a pure function of this file's code, so
it never needs to drift again.

H3 ("No key material committed to git") still holds: this seed and this
code are a *recipe*, not key material -- the derived private key bytes are
written only under the gitignored harness/build/out/ tree (and the
similarly-gitignored target fixture copies generate-pki.sh makes), exactly
as before this change. Anyone with this repo's source could already
regenerate *a* harness PKI by running generate-pki.sh; the only change is
that they now regenerate the SAME one.

Caveat this file does NOT solve: `openssl pkcs12 -export` (used by
generate-pki.sh for gateway-p12/gateway.p12) bakes a random PBKDF2 salt/MAC
salt into the container on every run, and there is no CLI-exposed openssl
option to fix that. gateway.p12 the FILE is therefore not byte-identical
across runs -- but the certificate and key it contains are, which is what
every recorded ecdat fixture actually hashes (always after canonicalizing
back to DER, never the raw .p12 bytes). See topo_x3_der_hash_equality's
README for why that canonicalization step exists.
"""
from __future__ import annotations

import hashlib
import hmac
import pathlib
import sys

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Fixed, documented seed all keys are derived from. Do not change this
# casually -- every derived key (and therefore every downstream cert) changes
# with it, and ecdat's recorded PKI-dependent fixtures are pinned to the
# exact bytes this seed currently produces (see docs/open-issues.md OI-014).
PKI_SEED = b"ecdat-harness/build/generate-pki.sh deterministic-pki-seed-v1"

# role -> curve (harness §6)
ROLES_EC: dict[str, ec.EllipticCurve] = {
    "int-ca-ecc": ec.SECP384R1(),
    "pay-edge": ec.SECP256R1(),
}
# role -> modulus size in bits (harness §6)
ROLES_RSA: dict[str, int] = {
    "root-ca": 4096,
    "gateway-p12": 2048,
}

# Standard (public) group orders for the two curves used above. Not secret --
# these are the well-known NIST P-256/P-384 order constants.
_CURVE_ORDERS = {
    "secp256r1": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "secp384r1": int(
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
        "c7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        16,
    ),
}


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand (HMAC-SHA256). PKI_SEED is used directly as the
    PRK -- it already has more entropy/length than HKDF-Extract would add."""
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_ec_key(role: str, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
    """Deterministic EC private key: scalar d = HKDF-Expand(seed, role) mod
    (n-1), +1, so d is always in the valid range [1, n-1]."""
    n_bytes = (curve.key_size + 7) // 8 + 8  # extra bytes reduce modulo bias
    raw = _hkdf_expand(PKI_SEED, b"ec-scalar:" + role.encode(), n_bytes)
    order = _CURVE_ORDERS[curve.name]
    d = (int.from_bytes(raw, "big") % (order - 1)) + 1
    return ec.derive_private_key(d, curve)


def _deterministic_stream(role: str):
    """A read(n)-style deterministic byte source for pycryptodome's
    RSA.generate(randfunc=...). Counter-mode HMAC-SHA256 keyed off the same
    PKI_SEED, one independent stream per role."""
    prk = hmac.new(PKI_SEED, b"rsa-stream:" + role.encode(), hashlib.sha256).digest()
    state = {"counter": 0, "buf": b""}

    def read(n: int) -> bytes:
        while len(state["buf"]) < n:
            state["counter"] += 1
            state["buf"] += hmac.new(
                prk, state["counter"].to_bytes(4, "big"), hashlib.sha256
            ).digest()
        out, state["buf"] = state["buf"][:n], state["buf"][n:]
        return out

    return read


def derive_rsa_key(role: str, bits: int):
    return RSA.generate(bits, randfunc=_deterministic_stream(role))


def _write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: generate_pki_keys.py <out-dir>", file=sys.stderr)
        return 2
    out_dir = pathlib.Path(argv[1])

    for role, curve in ROLES_EC.items():
        key = derive_ec_key(role, curve)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _write(out_dir / role / "key.pem", pem)

    for role, bits in ROLES_RSA.items():
        key = derive_rsa_key(role, bits)
        pem = key.export_key(format="PEM", pkcs=1)
        if isinstance(pem, str):
            pem = pem.encode("ascii")
        _write(out_dir / role / "key.pem", pem)

    print(
        "generate_pki_keys.py: wrote deterministic key.pem for "
        f"{sorted(list(ROLES_EC) + list(ROLES_RSA))} into {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
