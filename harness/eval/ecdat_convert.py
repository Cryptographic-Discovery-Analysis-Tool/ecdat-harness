"""Converts a real `ecdat scan` run document (as written by cli.py's
`_run_document`, and read back off disk here) into the shape
`score_run.py`'s `score_run()` requires, validating it on the way in.

Why this module exists even though the two shapes turn out to be the same
today: `score_run.py` was written against ecdat's documented run-document
schema before any adapter had ever actually been run end-to-end for this
harness (see the stale docstring `run_ecdat.py`'s README fixes). This module
is the one seam where that assumption is checked for real, so a future
ecdat schema change (a renamed key, a finding missing `fields`) fails here,
loudly, with a message naming the exact problem -- instead of failing
silently inside score_run.py's dict lookups (a missing `"findings"` key
would otherwise just score as "0 findings", which reads as a clean run
rather than a broken adapter).

Not domain code -- harness eval tooling only.
"""
from __future__ import annotations

import json
from typing import Any


class MalformedRunDocumentError(ValueError):
    """Raised when a run document is not shaped the way score_run.py needs.
    Always names the exact field and what was found instead."""


_REQUIRED_TOP_LEVEL = ("adapter_id", "outcome", "coverage", "findings")
_REQUIRED_FIELD_KEYS = ("field", "value", "epistemic_state")


def parse_run_document(raw_text: str) -> dict[str, Any]:
    """Parse and validate one `ecdat scan --out <path>` run document.

    Returns the same dict `score_run.score_run()` expects: a top-level dict
    with `coverage: {"scanned": [...]}` and `findings: [{"surface": ...,
    "fields": [{"field", "value", "epistemic_state", ...}]}]`. Raises
    `MalformedRunDocumentError` (not a bare KeyError/TypeError) with a
    message pointing at the exact structural problem, before score_run.py
    ever sees the document.
    """
    try:
        document = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise MalformedRunDocumentError(f"not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise MalformedRunDocumentError(
            f"expected a JSON object at the top level, got {type(document).__name__}"
        )

    for key in _REQUIRED_TOP_LEVEL:
        if key not in document:
            raise MalformedRunDocumentError(f"missing required top-level key {key!r}")

    coverage = document["coverage"]
    if not isinstance(coverage, dict) or "scanned" not in coverage:
        raise MalformedRunDocumentError(
            "coverage.scanned is required (score_run.py's _in_reach() reads it to decide "
            "which planted assets this run could have seen)"
        )
    if not isinstance(coverage["scanned"], list):
        raise MalformedRunDocumentError("coverage.scanned must be a list of scanned paths")

    findings = document["findings"]
    if not isinstance(findings, list):
        raise MalformedRunDocumentError("findings must be a list")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise MalformedRunDocumentError(f"findings[{index}] is not an object")
        if "surface" not in finding:
            raise MalformedRunDocumentError(f"findings[{index}] is missing 'surface'")
        if "fields" not in finding or not isinstance(finding["fields"], list):
            raise MalformedRunDocumentError(f"findings[{index}].fields must be a list")
        for field_index, field in enumerate(finding["fields"]):
            if not isinstance(field, dict):
                raise MalformedRunDocumentError(
                    f"findings[{index}].fields[{field_index}] is not an object"
                )
            for required in _REQUIRED_FIELD_KEYS:
                if required not in field:
                    raise MalformedRunDocumentError(
                        f"findings[{index}].fields[{field_index}] is missing {required!r}"
                    )

    return document


def load_run_document(path: str) -> dict[str, Any]:
    """Same as `parse_run_document`, reading from a file path (what
    `run_ecdat.py` actually calls after `ecdat scan --out <path>` writes it)."""
    with open(path, encoding="utf-8") as handle:
        return parse_run_document(handle.read())
