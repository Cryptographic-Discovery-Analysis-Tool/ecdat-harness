#!/usr/bin/env python3
"""Scores ECDAT output against ground truth (harness §8.1-8.2).

Implemented in the order the 2026-09-17 task asked for:
1. false_certainty_rate -- the headline trust metric (§8.2: "Target: 0.").
2. per_surface_recall -- "never one global number" (Directive 3).
3. forbidden_edge_violations -- the Part-5 over-merge hard failures (§7.4).
4. secret_leak_scan -- Directive 10 / TRAP-09 (§8.2 "Security of ECDAT" row).

Inputs are plain dicts/lists (JSON- or YAML-loadable), not tied to any
specific ECDAT output schema yet -- no adapters exist to produce real output
(ecdat/src/ecdat/adapters/ is still empty stubs), so this module is
structural and exercised here only against synthetic fixtures in
`_selftest()`. Wiring it to a real ECDAT run is future work.

Not domain code -- harness eval tooling only.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any


# --- 1. False-certainty rate (§8.2, headline metric) ------------------------

ELIGIBLE_FOR_FALSE_CERTAINTY = {"UNKNOWN", "INFERRED", "DECLARED"}


def false_certainty_rate(
    ecdat_fields: list[dict[str, Any]],
    expected_states: dict[tuple[str, str], str],
) -> dict[str, Any]:
    """§8.2: "# fields reported KNOWN where expected state in {UNKNOWN,
    INFERRED, DECLARED} / total such fields." Target: 0.

    ecdat_fields: [{"asset_id": ..., "field": ..., "epistemic_state": ...}]
    expected_states: {(asset_id, field): expected_epistemic_state}
    """
    total_eligible = 0
    false_certainty_count = 0
    offenders: list[dict[str, Any]] = []

    for obs in ecdat_fields:
        key = (obs["asset_id"], obs["field"])
        expected = expected_states.get(key)
        if expected not in ELIGIBLE_FOR_FALSE_CERTAINTY:
            continue
        total_eligible += 1
        if obs["epistemic_state"] == "KNOWN":
            false_certainty_count += 1
            offenders.append({**obs, "expected_state": expected})

    rate = false_certainty_count / total_eligible if total_eligible else None
    return {
        "false_certainty_count": false_certainty_count,
        "total_eligible": total_eligible,
        "rate": rate,
        "offenders": offenders,
    }


# --- 2. Per-surface recall (§8.2: "Never one global number", Directive 3) --


def per_surface_recall(
    ecdat_findings: list[dict[str, Any]],
    ground_truth_findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Both lists of {"finding_id": ..., "surface": ...}.

    Returns {surface: {"found": n, "total": n, "recall": found/total}}.
    """
    gt_by_surface: dict[str, set[str]] = defaultdict(set)
    for f in ground_truth_findings:
        gt_by_surface[f["surface"]].add(f["finding_id"])

    found_by_surface: dict[str, set[str]] = defaultdict(set)
    for f in ecdat_findings:
        found_by_surface[f["surface"]].add(f["finding_id"])

    result: dict[str, dict[str, Any]] = {}
    for surface, expected_ids in gt_by_surface.items():
        found_ids = found_by_surface.get(surface, set()) & expected_ids
        result[surface] = {
            "found": len(found_ids),
            "total": len(expected_ids),
            "recall": len(found_ids) / len(expected_ids) if expected_ids else None,
        }
    return result


# --- 3. Forbidden-edge check (§7.4 Part-5 over-merge tests, hard failure) --


def forbidden_edge_violations(
    ecdat_edges: list[dict[str, Any]],
    ground_truth_relationships: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """§7.4: "Any ECDAT output containing them scores as a correlation
    failure regardless of other results." ecdat_edges: [{"from", "type",
    "to"}]. ground_truth_relationships: entries from relationships.yaml,
    only those with forbidden: true are checked.
    """
    violations = []
    for forbidden in ground_truth_relationships:
        if not forbidden.get("forbidden"):
            continue
        allowed_types = {t.strip() for t in str(forbidden.get("type", "")).split("/")}
        for edge in ecdat_edges:
            if (
                edge.get("from") == forbidden.get("from")
                and edge.get("to") == forbidden.get("to")
                and edge.get("type") in allowed_types
            ):
                violations.append({"forbidden_rule": forbidden, "found_edge": edge})
    return violations


# --- 4. Secret-leak grep (§8.2 "Security of ECDAT" row; Directive 10) ------

_PEM_PRIVATE_KEY_MARKER = b"PRIVATE KEY"
_LONG_BASE64_BLOB = re.compile(rb"(?:[A-Za-z0-9+/]{4}){20,}={0,2}")  # >=80 chars


def secret_leak_scan(paths: list[Path]) -> list[dict[str, Any]]:
    """Greps DB dumps / CBOM / UI HTML / logs for `-----BEGIN ... PRIVATE
    KEY`, and long base64 blobs (candidate key material). This is a coarse
    heuristic (harness §8.2 literally says "grep ... for -----BEGIN, base64
    key blobs") -- it is not a certificate-vs-key classifier, so a
    legitimate long base64-encoded certificate would also be flagged;
    reviewing hits is still a human/CI step, this only surfaces candidates.
    """
    findings: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"-----BEGIN" in data and _PEM_PRIVATE_KEY_MARKER in data:
            findings.append({"path": str(path), "reason": "PEM private-key marker found"})
        for m in _LONG_BASE64_BLOB.finditer(data):
            findings.append(
                {
                    "path": str(path),
                    "reason": f"long base64 blob ({len(m.group())} chars) -- candidate key material",
                }
            )
    return findings


def _selftest() -> None:
    """Synthetic fixtures only -- no real ECDAT output exists yet
    (adapters are unbuilt). Demonstrates each function's contract; run with
    `python score.py --selftest`.
    """
    # 1. false_certainty_rate
    expected = {
        ("PAY-001", "algorithm"): "INFERRED",
        ("PAY-002", "algorithm"): "KNOWN",
    }
    honest = [
        {"asset_id": "PAY-001", "field": "algorithm", "epistemic_state": "INFERRED"},
        {"asset_id": "PAY-002", "field": "algorithm", "epistemic_state": "KNOWN"},
    ]
    dishonest = [
        {"asset_id": "PAY-001", "field": "algorithm", "epistemic_state": "KNOWN"},
        {"asset_id": "PAY-002", "field": "algorithm", "epistemic_state": "KNOWN"},
    ]
    r_honest = false_certainty_rate(honest, expected)
    r_dishonest = false_certainty_rate(dishonest, expected)
    assert r_honest["rate"] == 0.0, r_honest
    assert r_dishonest["rate"] == 1.0, r_dishonest
    print("false_certainty_rate: OK", r_honest, r_dishonest)

    # 2. per_surface_recall
    gt_findings = [
        {"finding_id": "PAY-001", "surface": "source"},
        {"finding_id": "PAY-001", "surface": "configuration"},
        {"finding_id": "PAY-002", "surface": "source"},
    ]
    ecdat_findings = [
        {"finding_id": "PAY-001", "surface": "source"},
        {"finding_id": "PAY-002", "surface": "source"},
    ]
    recall = per_surface_recall(ecdat_findings, gt_findings)
    assert recall["source"]["recall"] == 1.0, recall
    assert recall["configuration"]["recall"] == 0.0, recall
    print("per_surface_recall: OK", recall)

    # 3. forbidden_edge_violations
    relationships = [
        {
            "from": "PAY-004 (app keystore)",
            "type": "serves / presents",
            "to": "edge-lb endpoint",
            "forbidden": True,
        }
    ]
    bad_edges = [{"from": "PAY-004 (app keystore)", "type": "serves", "to": "edge-lb endpoint"}]
    good_edges = [{"from": "edge-lb", "type": "terminates-tls-for", "to": "payment-gateway"}]
    assert len(forbidden_edge_violations(bad_edges, relationships)) == 1
    assert len(forbidden_edge_violations(good_edges, relationships)) == 0
    print("forbidden_edge_violations: OK")

    # 4. secret_leak_scan
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        leaky = Path(tmp) / "cbom.json"
        leaky.write_bytes(b'{"key": "-----BEGIN EC PRIVATE KEY-----\\nabc\\n-----END EC PRIVATE KEY-----"}')
        clean = Path(tmp) / "clean.json"
        clean.write_bytes(b'{"algorithm": "AES-256-GCM"}')
        findings = secret_leak_scan([leaky, clean])
        assert any(f["path"] == str(leaky) for f in findings)
        assert not any(f["path"] == str(clean) for f in findings)
    print("secret_leak_scan: OK")

    print("\nall score.py self-tests passed (synthetic fixtures only)")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
    else:
        print(__doc__)
