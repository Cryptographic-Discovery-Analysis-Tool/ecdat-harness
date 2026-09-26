#!/usr/bin/env python3
"""Run real ECDAT scans against the Tier A payment-gateway target, convert
each scan's run document into the shape score_run.py expects, and score it.

This is the first script in this harness that scores REAL ecdat output
instead of a synthetic fixture. It does three things:

1. Locate ECDAT. `ECDAT_REPO` env var, default `../ecdat` relative to this
   harness's repo root (never hardcoded, never assumed to be a sibling
   checkout with any particular absolute path -- Windows paths in this
   environment contain an apostrophe, which is exactly why every path here
   is built with pathlib rather than string-glued).

2. Invoke `python -m ecdat.cli scan ...` as a SUBPROCESS (not an import) for
   each adapter/target pair below, exactly the way a real caller would run
   it from a shell. This intentionally does not import ecdat's Python
   package: ecdat is a separate project with its own CI guard against
   harness identifiers, and this script's job is to drive its CLI the same
   way any external caller would, never to reach into its internals.

3. Convert each adapter's run-document JSON (`_run_document` in ecdat's
   cli.py -- adapter_id, coverage.scanned, findings[].fields[]) into the
   shape score_run.py's `score_run()` reads, and hand the result to
   score_run.py's own scoring function.

Adapters run here, and why (see also README.md's how-to and the final
report this script prints):

  source-semgrep        REPLAY of tests/fixtures/recorded/semgrep/1.99.0/
                         ecdat-rules/tier-a-java.raw.json. This fixture IS a
                         real semgrep 1.99.0 run over this harness's own
                         targets/payments/payment-gateway/src -- it was
                         recorded from the real tool, against the real Tier A
                         files, and CLAUDE.md is explicit that "Replay of a
                         recorded file (--input) is for tests AND SCORING
                         ONLY" -- this is exactly that path, not a
                         live semgrep invocation (semgrep is not installed on
                         this machine; see the honesty note this script
                         prints if it is missing).
  certs-x509  (LIVE)     Reads the real gateway.p12 keystore this harness's
                         own generate-pki.sh just produced. No external tool
                         subprocess is involved -- python-cryptography reads
                         the file directly -- so this is unconditionally a
                         live, non-replay scan of a real artefact.
  config-chain-spring
              (LIVE)     Reads the real application.yml / application-prod.yml
                         under targets/payments/payment-gateway directly off
                         disk. Also no external tool subprocess: this is
                         ecdat's own static resolver running for real.

packages-trivy, images-cbomkit-theia, hsm-pkcs11, kms-aws, binary-yara-readelf
and tls-endpoint are NOT run here: trivy/docker/a PKCS#11 module/an AWS
account/a live TLS listener are not available in this environment, and (see
README.md and this script's own docstring) score_run.py's join only knows
three ground-truth surfaces anyway (source, artifact, configuration) -- see
`_canonical_surface` in score_run.py, which is harness code and out of scope
for this task to extend. Running those adapters' recorded fixtures would
produce findings score_run.py could not join to anything, which would not be
evidence of anything either way.

Usage:
    python harness/eval/run_ecdat.py [--allow-missing-pki] [--keep-out]

Not domain code -- harness eval tooling only.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

HARNESS_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = Path(__file__).resolve().parent
OUT_DIR = EVAL_DIR / "out"
PKI_LOCK = HARNESS_ROOT / "harness" / "build" / "pki-lock.generated.json"

sys.path.insert(0, str(EVAL_DIR))
from ecdat_convert import MalformedRunDocumentError, load_run_document  # noqa: E402
from score_run import (  # noqa: E402
    score_run,
    score_correlation,
    verify_metric_is_live,
    _self_check,
    _print_report,
    _pki_roles,
)


def _ecdat_repo() -> Path:
    """Locate the ecdat checkout. `ECDAT_REPO` env var if set, else
    `../ecdat` relative to this harness repo's own root -- never an absolute
    path baked into this file, so this script works from any checkout
    layout, including CI, where the two repos may not sit under the same
    parent directory ECDAT_REPO points to it."""
    override = os.environ.get("ECDAT_REPO")
    if override:
        return Path(override).resolve()
    return (HARNESS_ROOT / ".." / "ecdat").resolve()


def _run_ecdat_scan(ecdat_repo: Path, adapter: str, argv: list[str], out_path: Path) -> dict[str, Any]:
    """Invoke `python -m ecdat.cli scan --adapter <adapter> ...` as a real
    subprocess and return the parsed run document. Raises RuntimeError with
    the subprocess's own stderr on a nonzero exit -- never silently swallowed,
    per this task's "loud failure" requirement for anything that stops a
    real score from being real."""
    common = [
        "--target-id", f"payment-gateway:{adapter}",
        "--confidence", "0.9",
        "--confidence-justification",
        "harness eval run_ecdat.py: real run against Tier A payment-gateway target",
        "--out", str(out_path),
    ]
    cmd = [sys.executable, "-m", "ecdat.cli", "scan", "--adapter", adapter, *argv, *common]
    result = subprocess.run(
        cmd,
        cwd=str(ecdat_repo),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ecdat scan --adapter {adapter} failed (exit {result.returncode}):\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    print(result.stdout.strip())
    try:
        return load_run_document(str(out_path))
    except MalformedRunDocumentError as exc:
        raise RuntimeError(
            f"ecdat scan --adapter {adapter} wrote a run document score_run.py cannot "
            f"read: {exc}\n(file: {out_path})"
        ) from exc


def _run_ecdat_correlate(ecdat_repo: Path, plan_path: Path, out_path: Path) -> dict[str, Any]:
    """Invoke `python -m ecdat.cli correlate --plan <plan> --out <out>` as a
    real subprocess, same pattern as `_run_ecdat_scan`: never imported,
    always driven exactly the way an external caller would."""
    cmd = [sys.executable, "-m", "ecdat.cli", "correlate", "--plan", str(plan_path), "--out", str(out_path)]
    result = subprocess.run(cmd, cwd=str(ecdat_repo), capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(
            f"ecdat correlate failed (exit {result.returncode}):\n"
            f"cmd: {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    print(result.stdout.strip())
    return json.loads(out_path.read_text(encoding="utf-8"))


def _print_correlation_report(report: dict[str, Any]) -> None:
    print("\n=== combined correlate run: forbidden-edge check (harness §7.4) ===")
    print(f"same-object relationships checked : {report['identity_relationships_checked']}")
    print(f"asset ids resolved to a PKI role  : {len(report['asset_roles_resolved'])}")
    for asset_id, role in sorted(report["asset_roles_resolved"].items()):
        print(f"    {asset_id} -> {role}")
    if report["violations"]:
        print(f"    FORBIDDEN EDGE(S) FOUND: {len(report['violations'])}")
        for v in report["violations"]:
            print(f"    VIOLATION {v['source_role']} <-> {v['target_role']}: {v['forbidden_rule']}")
    else:
        print("forbidden-edge violations         : 0 (checked for real, see roles above)")
    for edge in report["unresolved_edges"]:
        print(
            f"    unresolved same-object edge {edge['source_entity']} <-> "
            f"{edge['target_entity']}: {edge['reason']}"
        )
    for note in report["not_exercised"]:
        print(f"    NOT EXERCISED: {note}")


def _check_pki_lock(allow_missing: bool) -> None:
    """§3 of this task: a missing pki-lock.generated.json must be a loud,
    non-zero-exit failure -- not the silent NOTE score_run.py prints on its
    own -- because every certificate-surface finding in this run silently
    stops being scoreable (the artifact join has nothing to resolve a
    fingerprint to a role against) and a 0/0 recall would otherwise look
    like an honest result instead of a broken build step."""
    if PKI_LOCK.is_file():
        return
    message = (
        f"FATAL: {PKI_LOCK} is missing.\n"
        "Every certificate ('artifact' surface) finding in this run cannot be "
        "resolved to a harness PKI role without it, which would silently zero "
        "out PAY-004/PAY-005/INF-001 recall instead of reporting a real result.\n"
        "Run harness/build/generate-pki.sh first, or pass --allow-missing-pki "
        "to proceed anyway and accept that those assets will show as out of "
        "reach rather than scored."
    )
    if allow_missing:
        print(f"WARNING (--allow-missing-pki): {message}", file=sys.stderr)
        return
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-pki",
        action="store_true",
        help="proceed even if harness/build/pki-lock.generated.json is missing "
        "(otherwise this is a loud, non-zero-exit failure -- see this script's docstring)",
    )
    parser.add_argument(
        "--keep-out",
        action="store_true",
        help="do not fail if harness/eval/out/ already has content from a previous run "
        "(it is always overwritten either way; this flag only silences the notice)",
    )
    parser.add_argument(
        "--combined",
        action="store_true",
        help="also run `ecdat correlate` over a plan combining every adapter below into one "
        "process, and score the result's same-object relationships against "
        "ground-truth/relationships.yaml's forbidden pairs (harness §7.4). Off by default: "
        "this is a genuinely different kind of run (correlate, not scan) from the five "
        "per-adapter runs above, and this task explicitly asked for it to be separate.",
    )
    args = parser.parse_args(argv)

    _check_pki_lock(args.allow_missing_pki)

    ecdat_repo = _ecdat_repo()
    if not (ecdat_repo / "src" / "ecdat" / "cli.py").is_file():
        print(
            f"FATAL: ECDAT_REPO does not point at a real ecdat checkout: {ecdat_repo}\n"
            "Set the ECDAT_REPO environment variable, or check out ecdat at ../ecdat "
            "relative to this harness repo.",
            file=sys.stderr,
        )
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not args.keep_out and any(OUT_DIR.iterdir()):
        print(f"note: {OUT_DIR} already has content from a previous run; overwriting.")

    payment_gateway = HARNESS_ROOT / "targets" / "payments" / "payment-gateway"
    keystore = payment_gateway / "keystore" / "gateway.p12"
    semgrep_fixture = (
        ecdat_repo
        / "tests" / "fixtures" / "recorded" / "semgrep" / "1.99.0" / "ecdat-rules"
        / "tier-a-java.raw.json"
    )
    # Recorded for real against THIS harness's own edge-lb TLS endpoint
    # (openssl s_server standing in for haproxy, presenting the real
    # generate-pki.sh pay-edge.pem -- see
    # ecdat/tests/fixtures/recorded/sslyze/6.2.0/README.md, "Target: Tier A
    # edge-lb TLS endpoint"). Replay, per CLAUDE.md's "Replay of a recorded
    # file (--input) is for tests and scoring only".
    sslyze_fixture = (
        ecdat_repo / "tests" / "fixtures" / "recorded" / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
    )
    # Recorded for real against THIS harness's own built payment-gateway fat
    # jar (`trivy rootfs --scanners vuln --list-all-pkgs` -- see
    # ecdat/tests/fixtures/recorded/trivy/0.74.0/README.md, "Target: Tier A
    # (payment-gateway, ...)"). Contains org.bouncycastle:bcprov-jdk18on
    # 1.86, PAY-008's planted dependency.
    trivy_fixture = (
        ecdat_repo
        / "tests" / "fixtures" / "recorded" / "trivy" / "0.74.0"
        / "e1_supplemental_payment-gateway-fatjar.raw.json"
    )

    if not keystore.is_file():
        print(
            f"FATAL: {keystore} is missing. Run harness/build/generate-pki.sh first "
            "(it copies the real gateway.p12 into this target).",
            file=sys.stderr,
        )
        return 1
    if not semgrep_fixture.is_file():
        print(
            f"FATAL: recorded semgrep fixture is missing at {semgrep_fixture} -- this "
            "ecdat checkout may be stale or incomplete.",
            file=sys.stderr,
        )
        return 1
    if not sslyze_fixture.is_file():
        print(
            f"FATAL: recorded sslyze fixture is missing at {sslyze_fixture} -- this "
            "ecdat checkout may be stale or incomplete.",
            file=sys.stderr,
        )
        return 1
    if not trivy_fixture.is_file():
        print(
            f"FATAL: recorded trivy fixture is missing at {trivy_fixture} -- this "
            "ecdat checkout may be stale or incomplete.",
            file=sys.stderr,
        )
        return 1

    runs: dict[str, dict[str, Any]] = {}

    print("=== source-semgrep (replay of a real semgrep 1.99.0 run over this harness's own Tier A source) ===")
    runs["source-semgrep"] = _run_ecdat_scan(
        ecdat_repo,
        "source-semgrep",
        ["--input", str(semgrep_fixture)],
        OUT_DIR / "source-semgrep.run.json",
    )

    print("\n=== certs-x509 (LIVE read of the real gateway.p12 keystore) ===")
    runs["certs-x509"] = _run_ecdat_scan(
        ecdat_repo,
        "certs-x509",
        ["--input", str(keystore), "--keystore-password", "changeit"],
        OUT_DIR / "certs-x509.run.json",
    )

    print("\n=== config-chain-spring (LIVE resolution of pay.keywrap.transformation) ===")
    runs["config-chain-spring"] = _run_ecdat_scan(
        ecdat_repo,
        "config-chain-spring",
        ["--input", str(payment_gateway), "--property-key", "pay.keywrap.transformation"],
        OUT_DIR / "config-chain-spring.run.json",
    )

    print(
        "\n=== tls-endpoint (replay of a real sslyze 6.2.0 run against this harness's own "
        "edge-lb TLS endpoint) ==="
    )
    runs["tls-endpoint"] = _run_ecdat_scan(
        ecdat_repo,
        "tls-endpoint",
        [
            "--sslyze-input", str(sslyze_fixture),
            "--host", "edge-lb",
            "--port", "8443",
            "--sni", "pay-edge",
            "--vantage", "harness-eval-replay",
            "--consent",
        ],
        OUT_DIR / "tls-endpoint.run.json",
    )

    print(
        "\n=== packages-trivy (replay of a real trivy 0.74.0 rootfs run against this "
        "harness's own built payment-gateway fat jar) ==="
    )
    runs["packages-trivy"] = _run_ecdat_scan(
        ecdat_repo,
        "packages-trivy",
        ["--input", str(trivy_fixture)],
        OUT_DIR / "packages-trivy.run.json",
    )

    overall_ok = True
    for name, run in runs.items():
        report = score_run(run)
        _print_report(name, report)
        if not report["pki_lock_available"]:
            print(
                "    NOTE: harness/build/pki-lock.generated.json is missing, so no "
                "certificate can be resolved to a planted role. Run "
                "harness/build/generate-pki.sh."
            )
        message, ok = _self_check(report, verify_metric_is_live(run))
        print(message)
        overall_ok = overall_ok and ok

    if args.combined:
        plan = [
            {
                "adapter": "source-semgrep",
                "target_id": "payment-gateway:source-semgrep",
                "confidence": 0.9,
                "confidence_justification": "harness eval run_ecdat.py --combined",
                "input": str(semgrep_fixture),
            },
            {
                "adapter": "certs-x509",
                "target_id": "payment-gateway:certs-x509",
                "confidence": 0.9,
                "confidence_justification": "harness eval run_ecdat.py --combined",
                "input": str(keystore),
                "keystore_password": "changeit",
            },
            {
                "adapter": "config-chain-spring",
                "target_id": "payment-gateway:config-chain-spring",
                "confidence": 0.9,
                "confidence_justification": "harness eval run_ecdat.py --combined",
                "input": str(payment_gateway),
                "property_key": ["pay.keywrap.transformation"],
            },
            {
                "adapter": "tls-endpoint",
                "target_id": "payment-gateway:tls-endpoint",
                "confidence": 0.9,
                "confidence_justification": "harness eval run_ecdat.py --combined",
                "sslyze_input": str(sslyze_fixture),
                "host": "edge-lb",
                "port": 8443,
                "sni": "pay-edge",
                "vantage": "harness-eval-replay",
                "consent": True,
            },
            {
                "adapter": "packages-trivy",
                "target_id": "payment-gateway:packages-trivy",
                "confidence": 0.9,
                "confidence_justification": "harness eval run_ecdat.py --combined",
                "input": str(trivy_fixture),
            },
        ]
        plan_path = OUT_DIR / "combined.plan.json"
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

        print(
            "\n=== ecdat correlate (all 5 adapters above, one process -- harness §7.4 "
            "forbidden-edge check) ==="
        )
        try:
            correlate_doc = _run_ecdat_correlate(ecdat_repo, plan_path, OUT_DIR / "combined.correlate.json")
        except RuntimeError as exc:
            print(f"FATAL: {exc}", file=sys.stderr)
            return 1

        roles = _pki_roles()
        correlation_report = score_correlation(correlate_doc, roles)
        _print_correlation_report(correlation_report)
        if correlation_report["violations"]:
            overall_ok = False

    print(f"\nrun documents written to {OUT_DIR}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
