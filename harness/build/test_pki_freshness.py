"""Guard test: fails LOUDLY, with bump instructions, once any generated
harness PKI certificate is within 30 days of its notAfter against real
wall-clock.

Why this exists: generate-pki.sh's validity dates are fixed absolute
strings (required for byte-identical, deterministic cert bytes -- see
README.md "Deterministic PKI"), so unlike a "-days N from now" script they
do NOT silently stay fresh. pay-edge in particular is genuinely short-lived
(90d, harness §6 table) by design intent. Without this test, the PKI could
quietly go stale (or already be expired) with nothing catching it until an
`openssl verify` / live TLS handshake / ecdat lifecycle read failed
mysteriously downstream.

This test regenerates the real harness/build/out/ + pki-lock.generated.json
(the actual build output other tooling reads, not a throwaway tmp copy) so
CI and local runs both see true current expiry, then reads not_after out of
the lockfile for every role.

Run with: python -m pytest harness/build/test_pki_freshness.py
(or just `python -m pytest harness`, which picks this up too).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

BUILD_DIR = Path(__file__).resolve().parent

WARN_WINDOW_DAYS = 30

BUMP_INSTRUCTIONS = """
PKI EXPIRY WARNING -- one or more harness PKI certificates are within
{window} days of expiry (or already expired):
{lines}

FIX -- run, from the repo root:
    harness/build/bump-pki.sh <YYYYMMDD>
(<YYYYMMDD> = today or later; see that script's own header comment for the
full re-record checklist). This is NOT optional cleanup: after bumping, every
ecdat fixture that cites this PKI's exact bytes goes stale and must be
re-recorded by hand with real tools (openssl s_server + real sslyze 6.2.0) --
no hand-editing recorded output (CLAUDE.md). See
ecdat-harness/README.md "Deterministic PKI" and ecdat/docs/open-issues.md
OI-019 for the full precedent (this happened before, on 2026-09-26 and
2026-09-27).
"""


def _find_bash() -> str | None:
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return shutil.which("bash")


BASH = _find_bash()

pytestmark = pytest.mark.skipif(
    BASH is None or shutil.which("openssl") is None,
    reason="generate-pki.sh needs (Git) bash and openssl on PATH",
)


def _parse_not_after(value: str) -> datetime:
    # openssl's "-enddate" text format, e.g. "Dec 26 00:00:00 2026 GMT".
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def test_no_generated_certificate_is_within_30_days_of_expiry(tmp_path: Path) -> None:
    # Regenerate into the REAL out/ + lockfile locations (not a scratch
    # copy): this is meant to reflect what the repo would actually present
    # to `openssl verify`, a live TLS handshake, or ecdat's lifecycle read
    # right now, using generate-pki.sh's current checked-in dates.
    result = subprocess.run(
        [BASH, "generate-pki.sh"],
        cwd=BUILD_DIR,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"generate-pki.sh failed (exit {result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    lockfile = BUILD_DIR / "pki-lock.generated.json"
    assert lockfile.is_file(), f"generate-pki.sh did not write {lockfile}"
    lock = json.loads(lockfile.read_text(encoding="utf-8"))

    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=WARN_WINDOW_DAYS)

    problems = []
    for role, info in lock.items():
        not_after = _parse_not_after(info["not_after"])
        days_left = (not_after - now).days
        if not_after <= threshold:
            status = "EXPIRED" if not_after <= now else "expiring soon"
            problems.append(
                f"  - {role}: not_after={info['not_after']} ({status}, "
                f"{days_left} day(s) from now)"
            )

    assert not problems, BUMP_INSTRUCTIONS.format(
        window=WARN_WINDOW_DAYS, lines="\n".join(problems)
    )
