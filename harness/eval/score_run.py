#!/usr/bin/env python3
"""Score a real ECDAT run document against Tier A planted truth.

This is the join `score.py` was missing: it takes what ECDAT emitted, matches
each finding to a planted asset by location, and hands the per-field epistemic
states to the metric functions.

The join lives here, on the harness side, and never inside ECDAT. ECDAT is given
a target and a scan config and nothing else (§8.6: "No harness-conditional code
paths"), so it cannot be tuned against the answer key it is being scored on.

Usage:
    python harness/eval/score_run.py <run.json> [<run.json> ...]

Not domain code -- harness eval tooling only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import false_certainty_rate, per_surface_recall  # noqa: E402

HARNESS_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = HARNESS_ROOT / "ground-truth"

#: Epistemic states a field may hold where claiming direct observation would be
#: an over-claim. Mirrors score.ELIGIBLE_FOR_FALSE_CERTAINTY.
ELIGIBLE = {"UNKNOWN", "INFERRED", "DECLARED"}


def _load_assets() -> list[dict[str, Any]]:
    assets = []
    for path in sorted((GROUND_TRUTH / "assets").glob("*.yaml")):
        assets.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return assets


def _load_traps() -> list[dict[str, Any]]:
    return yaml.safe_load((GROUND_TRUTH / "traps.yaml").read_text(encoding="utf-8")) or []


def _source_locations() -> dict[str, str]:
    """asset_id -> the source file that asset is planted in.

    File-level, not line-level: a planted asset occupies one file on the source
    surface, and the recorded line ranges in ground truth were written against
    an earlier revision of those files. Matching on the file avoids scoring a
    correct finding as a miss because a line moved.
    """
    locations: dict[str, str] = {}
    for asset in _load_assets():
        if asset.get("tier") != "A":
            continue
        for location in asset.get("locations") or ():
            if location.get("surface") == "source":
                locations[asset["id"]] = location["path"]
    for trap in _load_traps():
        location = trap.get("location")
        if isinstance(location, str) and location.endswith(".java"):
            locations[trap["id"]] = location
    return locations


def _expected_states() -> dict[tuple[str, str], str]:
    """(asset_id, field) -> expected epistemic state on the source surface.

    Read from each asset's `expected_observation.field_states.source`, which is
    the machine-readable encoding of that asset's own must_be / must_not prose.
    """
    expected: dict[tuple[str, str], str] = {}
    for asset in _load_assets():
        states = ((asset.get("expected_observation") or {}).get("field_states") or {}).get(
            "source"
        ) or {}
        for field, state in states.items():
            expected[(asset["id"], field)] = state
    # TRAP-01 is recorded in traps.yaml rather than as an asset. Its stated
    # expectation is "reachable: UNKNOWN or false"; Lock §7 OQ-5 settles that as
    # UNKNOWN, because nothing in scope performs reachability analysis.
    expected[("TRAP-01", "reachable")] = "UNKNOWN"
    return expected


def _match_asset(path: str, locations: dict[str, str]) -> str | None:
    normalised = path.replace("\\", "/")
    for asset_id, location in locations.items():
        if normalised.endswith(location):
            return asset_id
    return None


def score_run(run: dict[str, Any]) -> dict[str, Any]:
    locations = _source_locations()
    expected = _expected_states()

    observed_fields: list[dict[str, Any]] = []
    matched_findings: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []

    for finding in run.get("findings", ()):
        fields = {f["field"]: f for f in finding.get("fields", ())}
        path = (fields.get("path") or {}).get("value") or ""
        asset_id = _match_asset(str(path), locations)
        if asset_id is None:
            unmatched.append(
                {
                    "finding_id": finding["finding_id"],
                    "path": path,
                    "fields": {
                        name: entry.get("value")
                        for name, entry in fields.items()
                        if name not in ("path", "line")
                    },
                }
            )
            continue
        matched_findings.append({"finding_id": asset_id, "surface": finding["surface"]})
        for name, entry in fields.items():
            observed_fields.append(
                {
                    "asset_id": asset_id,
                    "field": name,
                    "epistemic_state": entry["epistemic_state"],
                }
            )

    ground_truth_findings = [
        {"finding_id": asset_id, "surface": "source"} for asset_id in locations
    ]

    false_certainty = false_certainty_rate(observed_fields, expected)
    recall = per_surface_recall(matched_findings, ground_truth_findings)

    # §8.2 "Under-claiming rate": fields reported UNKNOWN where the answer key
    # says KNOWN. Tolerable, but tracked -- an all-UNKNOWN tool scores a perfect
    # false-certainty rate and is useless, so the headline metric is meaningless
    # without this one beside it.
    under_claimed = [
        field
        for field in observed_fields
        if field["epistemic_state"] == "UNKNOWN"
        and expected.get((field["asset_id"], field["field"])) == "KNOWN"
    ]
    expected_known = [key for key, state in expected.items() if state == "KNOWN"]

    return {
        "false_certainty": false_certainty,
        "per_surface_recall": recall,
        "under_claiming": {
            "count": len(under_claimed),
            "total_expected_known": len(expected_known),
            "rate": len(under_claimed) / len(expected_known) if expected_known else None,
            "offenders": under_claimed,
        },
        "findings_not_matched_to_a_planted_asset": unmatched,
        "coverage": run.get("coverage", {}),
        "visibility": run.get("visibility", []),
    }


def _print_report(name: str, report: dict[str, Any]) -> None:
    print(f"\n=== {name} ===")

    fc = report["false_certainty"]
    rate = fc["rate"]
    print(
        f"false-certainty rate : {rate if rate is not None else 'n/a'}  "
        f"({fc['false_certainty_count']} of {fc['total_eligible']} eligible fields)"
    )
    for offender in fc["offenders"]:
        print(
            f"    OVER-CLAIM {offender['asset_id']}.{offender['field']}: "
            f"reported KNOWN, expected {offender['expected_state']}"
        )

    print("per-surface recall   :")
    for surface, numbers in sorted(report["per_surface_recall"].items()):
        print(
            f"    {surface:<14} {numbers['found']}/{numbers['total']}"
            f"  = {numbers['recall']}"
        )

    uc = report["under_claiming"]
    print(
        f"under-claiming rate  : {uc['rate']}  "
        f"({uc['count']} of {uc['total_expected_known']} fields expected KNOWN)"
    )
    for offender in uc["offenders"]:
        print(f"    UNDER-CLAIM {offender['asset_id']}.{offender['field']}")

    scanned = report["coverage"].get("scanned", [])
    print(f"files examined       : {len(scanned)}")
    for entry in report["visibility"]:
        print(f"visibility           : [{entry['dimension']}] {entry['detail']}")

    unmatched = report["findings_not_matched_to_a_planted_asset"]
    if unmatched:
        print(f"unmatched findings   : {len(unmatched)} (not a planted asset; judge each)")
        for item in unmatched:
            print(f"    {item['path'].split('/')[-1]}: {item['fields']}")


def verify_metric_is_live(run: dict[str, Any]) -> dict[str, Any]:
    """Prove the headline metric can still fail, using this same run.

    A false-certainty rate of 0 is only meaningful if a rate above 0 was
    reachable. A join that silently stopped matching findings to assets, or an
    expectation table that lost its entries, would also report 0 -- and would
    look like success. So every scoring run re-scores a deliberately dishonest
    copy of itself: every field that could be over-claimed is set to KNOWN. If
    that does not push the rate up, the metric is not measuring anything and the
    run's real score should not be believed.
    """
    mutated = json.loads(json.dumps(run))
    for finding in mutated.get("findings", ()):
        for field in finding.get("fields", ()):
            field["epistemic_state"] = "KNOWN"
    return score_run(mutated)["false_certainty"]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    exit_code = 0
    for arg in argv:
        path = Path(arg)
        run = json.loads(path.read_text(encoding="utf-8"))
        report = score_run(run)
        _print_report(path.name, report)

        control = verify_metric_is_live(run)
        if not control["total_eligible"] or not control["false_certainty_count"]:
            print(
                "    METRIC NOT LIVE: an all-KNOWN copy of this run scored "
                f"{control['false_certainty_count']}/{control['total_eligible']} -- "
                "the join or the expectation table is broken, so the score above "
                "is not evidence of anything."
            )
            exit_code = 1
        else:
            print(
                f"metric self-check     : an all-KNOWN copy of this run scores "
                f"{control['false_certainty_count']}/{control['total_eligible']} "
                f"(rate {control['rate']}) -- the metric can fail, and this run did not"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
