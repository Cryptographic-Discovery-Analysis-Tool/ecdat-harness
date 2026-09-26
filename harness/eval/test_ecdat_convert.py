"""Fixture-based tests for ecdat_convert.py -- no ecdat subprocess needed.

Runs against a small, hand-written run document shaped exactly like
`ecdat.cli._run_document`'s real output (see run_ecdat.py's docstring for
why the two shapes already match), so this test never has to invoke ecdat
itself to prove the converter's validation logic works.

Run with: python -m pytest harness/eval/test_ecdat_convert.py
"""
from __future__ import annotations

import json

import pytest

from ecdat_convert import MalformedRunDocumentError, parse_run_document

VALID_DOCUMENT = {
    "adapter_id": "certs-x509",
    "support_level": "partial",
    "target_id": "t",
    "outcome": "completed",
    "failure_reason": None,
    "observed_at": "2026-09-26T00:00:00+00:00",
    "coverage": {"scanned": ["keystore/gateway.p12"], "skipped": []},
    "visibility": [],
    "evidence": [],
    "raw_captures": [],
    "findings": [
        {
            "finding_id": "certs-x509:abc:0",
            "surface": "certdir:keystore/gateway.p12",
            "evidence_refs": [],
            "fields": [
                {
                    "field": "der_sha256",
                    "value": "deadbeef",
                    "epistemic_state": "KNOWN",
                    "evidence_refs": [],
                }
            ],
        }
    ],
}


def test_valid_document_round_trips_unchanged():
    parsed = parse_run_document(json.dumps(VALID_DOCUMENT))
    assert parsed == VALID_DOCUMENT


def test_not_json_is_rejected():
    with pytest.raises(MalformedRunDocumentError, match="not valid JSON"):
        parse_run_document("{not json")


def test_top_level_list_is_rejected():
    with pytest.raises(MalformedRunDocumentError, match="top level"):
        parse_run_document("[]")


@pytest.mark.parametrize("missing_key", ["adapter_id", "outcome", "coverage", "findings"])
def test_missing_top_level_key_is_rejected(missing_key):
    document = {k: v for k, v in VALID_DOCUMENT.items() if k != missing_key}
    with pytest.raises(MalformedRunDocumentError, match=missing_key):
        parse_run_document(json.dumps(document))


def test_coverage_without_scanned_is_rejected():
    document = {**VALID_DOCUMENT, "coverage": {"skipped": []}}
    with pytest.raises(MalformedRunDocumentError, match="coverage.scanned"):
        parse_run_document(json.dumps(document))


def test_coverage_scanned_must_be_a_list():
    document = {**VALID_DOCUMENT, "coverage": {"scanned": "not-a-list"}}
    with pytest.raises(MalformedRunDocumentError, match="coverage.scanned"):
        parse_run_document(json.dumps(document))


def test_finding_missing_surface_is_rejected():
    finding = {"finding_id": "x", "fields": []}
    document = {**VALID_DOCUMENT, "findings": [finding]}
    with pytest.raises(MalformedRunDocumentError, match="surface"):
        parse_run_document(json.dumps(document))


def test_finding_without_fields_list_is_rejected():
    finding = {"finding_id": "x", "surface": "source"}
    document = {**VALID_DOCUMENT, "findings": [finding]}
    with pytest.raises(MalformedRunDocumentError, match="fields"):
        parse_run_document(json.dumps(document))


@pytest.mark.parametrize("missing_key", ["field", "value", "epistemic_state"])
def test_field_missing_required_key_is_rejected(missing_key):
    field = {
        k: v
        for k, v in {"field": "algorithm", "value": "RSA", "epistemic_state": "KNOWN"}.items()
        if k != missing_key
    }
    finding = {"finding_id": "x", "surface": "source", "fields": [field]}
    document = {**VALID_DOCUMENT, "findings": [finding]}
    with pytest.raises(MalformedRunDocumentError, match=missing_key):
        parse_run_document(json.dumps(document))


def test_empty_findings_list_is_valid():
    """A run that completed but found nothing is a real, honest result --
    not a malformed document. score_run.py's own metric self-check is what
    flags an all-empty run as not evidence of anything; the converter's job
    is only structural validation."""
    document = {**VALID_DOCUMENT, "findings": []}
    parsed = parse_run_document(json.dumps(document))
    assert parsed["findings"] == []
