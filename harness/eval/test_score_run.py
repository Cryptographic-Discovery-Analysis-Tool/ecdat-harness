"""Fixture-based tests for score_run.py's `tls`/`dependency` joins and the
`score_correlation` forbidden-edge check -- no ecdat subprocess, no real
`ecdat correlate` run, no generated PKI lockfile needed.

These exercise exactly the two extensions this task added:
1. `_canonical_surface` / `_match` / `_in_reach` now recognise the `tls` and
   `dependency` ground-truth surfaces (score_run.py's own docstring explains
   why each is joined the way it is).
2. `score_correlation` -- the harness-side scorer for an `ecdat correlate`
   report's `same-object` relationships against ground-truth/relationships.yaml's
   forbidden pairs (translated to PKI roles in `_FORBIDDEN_ROLE_PAIRS`).

Run with: python -m pytest harness/eval/test_score_run.py
"""
from __future__ import annotations

import pytest

from score_run import (
    _canonical_surface,
    _surfaces_run,
    score_correlation,
    score_run,
)

# --- minimal synthetic run documents -----------------------------------


def _field(name: str, value, state: str = "KNOWN") -> dict:
    return {"field": name, "value": value, "epistemic_state": state, "evidence_refs": []}


def _tls_run() -> dict:
    """Shaped exactly like a real `ecdat scan --adapter tls-endpoint` replay
    of tests/fixtures/recorded/sslyze/6.2.0/tier_a_edge_lb.raw.json: one
    finding at surface `tls:edge-lb:8443`, one coverage entry ending with
    that same host:port (the adapter's own `coverage.scanned` convention,
    e.g. "sslyze edge-lb:8443")."""
    return {
        "adapter_id": "tls-endpoint",
        "outcome": "completed",
        "failure_reason": None,
        "coverage": {"scanned": ["sslyze edge-lb:8443"], "skipped": []},
        "visibility": [],
        "findings": [
            {
                "finding_id": "tls-endpoint:tls:edge-lb:8443",
                "surface": "tls:edge-lb:8443",
                "evidence_refs": [],
                "fields": [
                    _field("requested_host", "edge-lb"),
                    _field("port", 8443),
                    _field("negotiated_group", None, "UNKNOWN"),
                ],
            }
        ],
    }


def _dependency_run(package_name: str = "org.bouncycastle:bcprov-jdk18on") -> dict:
    """Shaped like a real `ecdat scan --adapter packages-trivy` replay of the
    recorded fat-jar fixture: `coverage.scanned == ["."]` (trivy's own
    ArtifactName for that invocation), surface `packages:.`, one finding per
    package with a `name` field."""
    return {
        "adapter_id": "packages-trivy",
        "outcome": "completed",
        "failure_reason": None,
        "coverage": {"scanned": ["."], "skipped": []},
        "visibility": [],
        "findings": [
            {
                "finding_id": "packages-trivy:0",
                "surface": "packages:.",
                "evidence_refs": [],
                "fields": [
                    _field("name", package_name),
                    _field("version", "1.86"),
                    _field("purl", f"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.86"),
                ],
            }
        ],
    }


# --- _canonical_surface --------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("tls:edge-lb:8443", "tls"),
        ("tls:example.com:443", "tls"),
        ("packages:.", "dependency"),
        ("packages:/some/rootfs", "dependency"),
        ("source", "source"),
        ("certdir:some/dir", "artifact"),
        ("config:root:some.key", "configuration"),
        ("something-unrecognised", None),
    ],
)
def test_canonical_surface_mapping(raw, expected):
    assert _canonical_surface(raw) == expected


# --- _surfaces_run ---------------------------------------------------------


def test_surfaces_run_includes_dependency_even_with_zero_findings():
    """TRAP-07-shaped case: trivy ran (adapter_id says so) but found nothing.
    coverage.scanned is still non-empty (harness §7.3: "silence != scanned"),
    and the dependency surface must still count as run, not as never-run."""
    run = {"adapter_id": "packages-trivy", "coverage": {"scanned": ["."]}, "findings": []}
    assert "dependency" in _surfaces_run(run)


def test_surfaces_run_from_findings_alone():
    run = _tls_run()
    assert _surfaces_run(run) == {"tls"}


# --- tls surface: one wire finding matches all three planted "logical"
# assets at that endpoint (PAY-005/006/007) -----------------------------


def test_tls_finding_matches_all_three_planted_assets_at_that_endpoint():
    report = score_run(_tls_run())
    recall = report["per_surface_recall"]["tls"]
    assert recall["found"] == 3
    assert recall["total"] == 3
    assert recall["recall"] == 1.0
    # No expectation table entry exists for the tls surface on purpose (see
    # PAY-005.yaml's own comment) -- so every field on the matched finding
    # is a documented gap, never a silently-dropped or fabricated score.
    assert report["expectation_gaps"], "tls fields should show up as expectation_gaps, not vanish"
    assert all(gap["surface"] == "tls" for gap in report["expectation_gaps"])


def test_tls_finding_at_an_unplanted_endpoint_is_unmatched_not_a_miss():
    run = _tls_run()
    run["findings"][0]["surface"] = "tls:unplanted-host:9999"
    run["coverage"]["scanned"] = ["sslyze unplanted-host:9999"]
    report = score_run(run)
    assert report["per_surface_recall"] == {}
    labels = [u["label"] for u in report["findings_not_matched_to_a_planted_asset"]]
    assert "tls:unplanted-host:9999" in labels


# --- dependency surface: joined by package name, reachability by adapter,
# not by ground truth's pom.xml path ------------------------------------


def test_dependency_finding_matches_planted_package_by_name():
    report = score_run(_dependency_run())
    recall = report["per_surface_recall"]["dependency"]
    assert recall == {"found": 1, "total": 1, "recall": 1.0}


def test_dependency_surface_never_reachable_by_path_alone():
    """The whole point of the dependency join: ground truth's PAY-008 path is
    payments/payment-gateway/pom.xml, which trivy's own coverage.scanned
    (the built-artifact scan root, ".") never suffix-matches. Reachability
    for this surface must come from `adapter_id`/finding presence, not path,
    or this would score PAY-008 as permanently out of reach even when a real
    trivy run did observe it (as the assertion above proves it does)."""
    run = _dependency_run()
    run["coverage"]["scanned"] = ["."]
    assert not any(
        candidate.endswith("payments/payment-gateway/pom.xml".lower())
        for candidate in [c.lower() for c in run["coverage"]["scanned"]]
    )
    report = score_run(run)
    assert report["per_surface_recall"]["dependency"]["total"] == 1


def test_unplanted_package_is_unmatched_not_silently_dropped():
    report = score_run(_dependency_run(package_name="some.other:library"))
    labels = [u["label"] for u in report["findings_not_matched_to_a_planted_asset"]]
    assert "some.other:library" in labels
    # PAY-008 is in reach (trivy ran) but was not found -- a real miss.
    assert report["per_surface_recall"]["dependency"] == {"found": 0, "total": 1, "recall": 0.0}


# --- score_correlation: forbidden-edge check over a correlate report ----


def _asset(asset_id: str, der_sha256: str | None) -> dict:
    fields = []
    if der_sha256 is not None:
        fields.append({"field": "der_sha256", "value": der_sha256, "epistemic_state": "KNOWN"})
    return {"asset_id": asset_id, "fields": fields}


def _relationship(source: str, target: str, rel_type: str = "same-object") -> dict:
    return {
        "type": rel_type,
        "source_entity": source,
        "target_entity": target,
        "evidence_basis": "content_identity",
        "epistemic_state": "KNOWN",
        "rule_id": "IDENTITY-CERT-DER-001",
        "evidence_refs": [],
    }


_ROLES = {"aaaa": "gateway-p12", "bbbb": "pay-edge", "cccc": "int-ca-ecc"}


def test_score_correlation_reports_zero_violations_when_no_same_object_edge_exists():
    """The real, expected shape of a combined run over this harness: two
    different real certificates (gateway-p12, pay-edge) with two different
    der_sha256 hashes, so ecdat's own correlation engine never links them --
    there is no relationship for this check to even look at."""
    document = {
        "assets": [_asset("a1", "aaaa"), _asset("a2", "bbbb")],
        "relationships": [],
    }
    report = score_correlation(document, _ROLES)
    assert report["violations"] == []
    assert report["identity_relationships_checked"] == 0
    assert report["asset_roles_resolved"] == {"a1": "gateway-p12", "a2": "pay-edge"}


def test_score_correlation_is_live_and_catches_a_forbidden_pair():
    """Metric self-check, the same spirit as score_run.py's own
    verify_metric_is_live: if this test's deliberately-bad input (the exact
    forbidden merge relationships.yaml names -- gateway-p12 same-object
    pay-edge) does NOT get flagged, the check is not measuring anything."""
    document = {
        "assets": [_asset("a1", "aaaa"), _asset("a2", "bbbb")],
        "relationships": [_relationship("a1", "a2")],
    }
    report = score_correlation(document, _ROLES)
    assert len(report["violations"]) == 1
    violation = report["violations"][0]
    assert {violation["source_role"], violation["target_role"]} == {"gateway-p12", "pay-edge"}


def test_score_correlation_does_not_flag_a_permitted_identity_pair():
    """Two findings of the SAME real certificate (e.g. the same pay-edge
    cert read from two different files) are a legitimate same-object claim,
    not a forbidden one -- the forbidden pairs table only knows about the
    two specific role pairs ground truth names."""
    document = {
        "assets": [_asset("a1", "bbbb"), _asset("a2", "bbbb")],
        "relationships": [_relationship("a1", "a2")],
    }
    report = score_correlation(document, _ROLES)
    assert report["violations"] == []


def test_score_correlation_reports_unresolved_edges_instead_of_silently_passing():
    """An asset that never resolves to a harness PKI role (e.g. from a
    surface the pki-lock doesn't cover) must not be silently treated as
    'not forbidden, therefore fine' -- that would be exactly the kind of
    manufactured pass this whole harness exists to avoid."""
    document = {
        "assets": [_asset("a1", "aaaa"), _asset("a2", "unknown-hash")],
        "relationships": [_relationship("a1", "a2")],
    }
    report = score_correlation(document, _ROLES)
    assert report["violations"] == []
    assert len(report["unresolved_edges"]) == 1


def test_score_correlation_always_names_the_structurally_unreachable_pair():
    """PAY-001 (source) vs PAY-004 (keystore) can never be checked this way
    -- source-semgrep emits no der_sha256 -- and that must be reported, not
    quietly absent from the output."""
    report = score_correlation({"assets": [], "relationships": []}, _ROLES)
    assert report["not_exercised"]
    assert "PAY-001" in report["not_exercised"][0]
