"""Proves harness/build/generate-pki.sh is deterministic: running it twice,
back to back, into two independent output directories produces byte-identical
key/cert/chain files for every role.

This is the check called for by the 2026-09-26 task that made PKI generation
deterministic in the first place (see the "Deterministic PKI" section of
README.md and the header comment in generate-pki.sh): ecdat's recorded
fixtures cite this PKI's exact bytes
(e.g. ecdat/tests/fixtures/recorded/openssl/3.5.4/topo_x3_der_hash_equality/
pay-edge.der.crt), so a regeneration that silently changes those bytes is
exactly the failure mode this test exists to catch.

Run with: python -m pytest harness/build/test_pki_reproducibility.py
(or just `python -m pytest harness`, which picks this up too).

Deliberately excluded from the comparison: gateway-p12/gateway.p12 itself.
OpenSSL's `pkcs12 -export` bakes a random PBKDF2/MAC salt into the container
on every run with no CLI-exposed override, so the .p12 FILE is not
byte-identical -- only the cert/key it wraps are (checked here by comparing
the antecedent cert.pem/key.pem instead, which is also all any recorded
ecdat fixture ever hashes: always via `openssl x509 ... -outform DER`
canonicalization first, never raw .p12 bytes).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

BUILD_DIR = Path(__file__).resolve().parent


def _find_bash() -> str | None:
    """Prefer Git for Windows' own bash over a bare "bash" from PATH: on
    Windows, System32\\bash.exe (the WSL launcher) can shadow Git Bash
    depending on PATH order, and generate-pki.sh's own MSYS-path handling
    assumes it's actually running under Git Bash/MSYS, not WSL (whose
    python3 has no reason to have this repo's pinned pycryptodome/
    cryptography installed)."""
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return shutil.which("bash")


BASH = _find_bash()

# Every file generate-pki.sh writes into $OUT that must be byte-identical
# across two runs with the same code (gateway.p12 is intentionally excluded
# -- see module docstring).
COMPARED_FILES = [
    "root-ca/key.pem",
    "root-ca/cert.pem",
    "int-ca-ecc/key.pem",
    "int-ca-ecc/cert.pem",
    "int-ca-ecc/chain.pem",
    "pay-edge/key.pem",
    "pay-edge/cert.pem",
    "pay-edge/pay-edge.pem",
    "gateway-p12/key.pem",
    "gateway-p12/cert.pem",
]

pytestmark = pytest.mark.skipif(
    BASH is None or shutil.which("openssl") is None,
    reason="generate-pki.sh needs (Git) bash and openssl on PATH",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_generate_pki(out_dir: Path, lockfile: Path) -> None:
    env = dict(os.environ)
    env["HARNESS_PKI_OUT"] = str(out_dir)
    env["HARNESS_PKI_LOCKFILE"] = str(lockfile)
    # Never touch the real target/ fixture copies or the real
    # harness/build/out from this test.
    env["HARNESS_PKI_SKIP_TARGET_COPY"] = "1"
    result = subprocess.run(
        [BASH, "generate-pki.sh"],
        cwd=BUILD_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"generate-pki.sh failed (exit {result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_generate_pki_is_byte_identical_across_two_runs(tmp_path: Path) -> None:
    out1, out2 = tmp_path / "out1", tmp_path / "out2"
    lock1, lock2 = tmp_path / "lock1.json", tmp_path / "lock2.json"

    _run_generate_pki(out1, lock1)
    _run_generate_pki(out2, lock2)

    mismatches = []
    for rel in COMPARED_FILES:
        p1, p2 = out1 / rel, out2 / rel
        assert p1.is_file(), f"run 1 did not produce {rel}"
        assert p2.is_file(), f"run 2 did not produce {rel}"
        h1, h2 = _sha256(p1), _sha256(p2)
        if h1 != h2:
            mismatches.append((rel, h1, h2))

    assert not mismatches, (
        "generate-pki.sh produced different bytes across two runs for: "
        + ", ".join(f"{rel} ({h1} != {h2})" for rel, h1, h2 in mismatches)
    )

    # The lockfile (role -> fingerprint/serial/notAfter) must match exactly
    # too -- score_run.py joins ground truth through it.
    assert lock1.read_text(encoding="utf-8") == lock2.read_text(encoding="utf-8")


def test_pki_chain_verifies(tmp_path: Path) -> None:
    """Sanity check alongside the reproducibility proof: the deterministic
    chain this script now always produces still actually verifies (root ->
    int-ca-ecc -> pay-edge), i.e. determinism wasn't bought by breaking the
    signatures."""
    out = tmp_path / "out"
    lock = tmp_path / "lock.json"
    _run_generate_pki(out, lock)

    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(out / "root-ca" / "cert.pem"),
            "-untrusted",
            str(out / "int-ca-ecc" / "cert.pem"),
            str(out / "pay-edge" / "cert.pem"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"chain did not verify:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout
