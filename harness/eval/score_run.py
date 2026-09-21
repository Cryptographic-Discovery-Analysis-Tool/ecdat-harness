#!/usr/bin/env python3
"""Score a real ECDAT run document against Tier A planted truth.

This is the join `score.py` was missing: it takes what ECDAT emitted, matches
each finding to a planted asset, and hands the per-field epistemic states to
the metric functions.

Each surface is joined on the identifier that surface actually carries, because
a location is not the same kind of fact on every surface:

    source         a file path (suffix-matched -- ground truth records the file,
                   not the line, so a moved line is not scored as a miss)
    artifact       a certificate's DER SHA-256, resolved to a harness PKI ROLE
                   through harness/build/pki-lock.generated.json. Ground truth
                   names roles and never fingerprints (H3), so regenerating the
                   PKI never requires editing the answer key.
    configuration  a property key

The join lives here, on the harness side, and never inside ECDAT. ECDAT is given
a target and a scan config and nothing else (§8.6: "No harness-conditional code
paths"), so it cannot be tuned against the answer key it is being scored on.
pki-lock.generated.json is build output, not ground truth: it carries no
expectations, only the fingerprints this build happened to produce.

Denominators are scoped to what the run could have seen: a planted asset counts
against a run only if one of its ground-truth locations is among the files the
run reports as scanned. A run over the keystore is not charged with missing the
source surface -- it is reported as out of reach, with the count, so a narrow
run cannot be mistaken for a complete one.

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
PKI_LOCK = HARNESS_ROOT / "harness" / "build" / "pki-lock.generated.json"

#: Epistemic states a field may hold where claiming direct observation would be
#: an over-claim. Mirrors score.ELIGIBLE_FOR_FALSE_CERTAINTY.
ELIGIBLE = {"UNKNOWN", "INFERRED", "DECLARED"}


# --- ground truth ----------------------------------------------------------


def _load_assets() -> list[dict[str, Any]]:
    assets = []
    for path in sorted((GROUND_TRUTH / "assets").glob("*.yaml")):
        assets.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return assets


def _load_traps() -> list[dict[str, Any]]:
    return yaml.safe_load((GROUND_TRUTH / "traps.yaml").read_text(encoding="utf-8")) or []


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lower()


def _locations() -> list[dict[str, Any]]:
    """Every place a Tier A planted asset can be observed, flattened.

    Each entry: {asset_id, surface, path, key, pki_role}. `surface` is the
    canonical ground-truth surface name, which is also the key under which that
    asset's expected field states are recorded.
    """
    flat: list[dict[str, Any]] = []
    for asset in _load_assets():
        if asset.get("tier") != "A":
            continue
        for location in asset.get("locations") or ():
            flat.append(
                {
                    "asset_id": asset["id"],
                    "surface": location.get("surface"),
                    "path": location.get("path"),
                    "key": location.get("key"),
                    "pki_role": location.get("pki_role"),
                }
            )
    for trap in _load_traps():
        location = trap.get("location")
        if isinstance(location, str) and location.endswith(".java"):
            flat.append(
                {
                    "asset_id": trap["id"],
                    "surface": "source",
                    "path": location,
                    "key": None,
                    "pki_role": None,
                }
            )
    return flat


def _expected_states() -> dict[tuple[str, str, str], str]:
    """(asset_id, surface, field) -> expected epistemic state.

    Read from each asset's `expected_observation.field_states.<surface>`, the
    machine-readable encoding of that asset's own must_be / must_not prose. A
    surface with no entry is deliberate: it means nothing in ground truth states
    an expectation for that asset there, and the scorer says so rather than
    inventing one.
    """
    expected: dict[tuple[str, str, str], str] = {}
    for asset in _load_assets():
        by_surface = (asset.get("expected_observation") or {}).get("field_states") or {}
        for surface, states in by_surface.items():
            for field, state in (states or {}).items():
                expected[(asset["id"], surface, field)] = state
    # TRAP-01 is recorded in traps.yaml rather than as an asset. Its stated
    # expectation is "reachable: UNKNOWN or false"; Lock §7 OQ-5 settles that as
    # UNKNOWN, because nothing in scope performs reachability analysis.
    expected[("TRAP-01", "source", "reachable")] = "UNKNOWN"
    return expected


def _pki_roles() -> dict[str, str]:
    """DER SHA-256 -> harness PKI role, from the generated lockfile.

    Build output, gitignored, regenerated by harness/build/generate-pki.sh. It
    is the only thing that can connect a fingerprint on disk to the role that
    ground truth names (H3).
    """
    if not PKI_LOCK.is_file():
        return {}
    lock = json.loads(PKI_LOCK.read_text(encoding="utf-8"))
    return {
        entry["sha256_fingerprint_der"].lower(): role
        for role, entry in lock.items()
        if entry.get("sha256_fingerprint_der")
    }


# --- surfaces --------------------------------------------------------------


def _canonical_surface(surface: str) -> str | None:
    """ECDAT's per-run surface string -> the ground-truth surface name.

    ECDAT scopes a surface to the thing it scanned (`certdir:<dir>`,
    `config:<root>:<key>`), which is why its surface strings are not the
    ground-truth names. The mapping happens here and not in ECDAT.
    """
    if surface == "source":
        return "source"
    if surface.startswith("certdir:"):
        return "artifact"
    if surface.startswith("config:"):
        return "configuration"
    return None


def _property_key(surface: str) -> str | None:
    """`config:<scan root>:<property key>` -> the property key.

    The scan root is an absolute path that may itself contain a colon, so the
    key is taken from the right-hand end, not by splitting from the left.
    """
    if not surface.startswith("config:"):
        return None
    tail = surface.rsplit(":", 1)[-1]
    return tail or None


# --- scoping ---------------------------------------------------------------


def _in_reach(locations: list[dict[str, Any]], run: dict[str, Any]) -> list[dict[str, Any]]:
    """The planted locations this run actually had the chance to observe.

    A location is in reach if one of the files the run reports as scanned ends
    with that location's recorded path. Locations with no on-disk path (the
    `tls` surface is a host:port, not a file) are never in reach of a run that
    only reads files, and are reported as such rather than scored as misses.
    """
    scanned = [_norm(p) for p in (run.get("coverage") or {}).get("scanned", ())]
    reached = []
    for location in locations:
        path = location.get("path")
        if not path:
            continue
        needle = _norm(path)
        if any(candidate.endswith(needle) for candidate in scanned):
            reached.append(location)
    return reached


# --- the join --------------------------------------------------------------


def _match(
    finding: dict[str, Any],
    fields: dict[str, dict[str, Any]],
    surface: str,
    reachable: list[dict[str, Any]],
    roles: dict[str, str],
) -> tuple[str | None, str]:
    """Return (asset_id, why) for one finding. `why` explains a non-match."""
    candidates = [loc for loc in reachable if loc["surface"] == surface]

    if surface == "source":
        path = _norm((fields.get("path") or {}).get("value") or "")
        if not path:
            return None, "no path field on a source finding"
        for location in candidates:
            if path.endswith(_norm(location["path"])):
                return location["asset_id"], ""
        return None, "source file is not a planted asset"

    if surface == "artifact":
        fingerprint = str((fields.get("der_sha256") or {}).get("value") or "").lower()
        if not fingerprint:
            return None, "no der_sha256 to resolve against the PKI lockfile"
        role = roles.get(fingerprint)
        if role is None:
            return None, "certificate is not from the harness PKI (unknown fingerprint)"
        for location in candidates:
            if location.get("pki_role") == role:
                return location["asset_id"], ""
        return None, f"harness PKI role '{role}' is not a Tier A planted asset"

    if surface == "configuration":
        key = _property_key(finding["surface"])
        if not key:
            return None, "config finding carries no property key"
        for location in candidates:
            if location.get("key") == key:
                return location["asset_id"], ""
        return None, f"property key '{key}' is not a planted asset"

    return None, f"no join defined for surface '{surface}'"


def _unmatched_label(
    finding: dict[str, Any], fields: dict[str, dict[str, Any]], surface: str
) -> str:
    if surface == "source":
        raw = str((fields.get("path") or {}).get("value") or "")
        return raw.replace("\\", "/").split("/")[-1] or finding["finding_id"]
    if surface == "artifact":
        return str((fields.get("subject") or {}).get("value") or finding["finding_id"])
    if surface == "configuration":
        return _property_key(finding["surface"]) or finding["finding_id"]
    return finding["finding_id"]


def score_run(run: dict[str, Any]) -> dict[str, Any]:
    all_locations = _locations()
    reachable = _in_reach(all_locations, run)
    expected_by_surface = _expected_states()
    roles = _pki_roles()

    observed_fields: list[dict[str, Any]] = []
    matched_findings: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    #: (asset_id, surface, field) triples a run reported that the answer key has
    #: no entry for. A gap here means the expectation table, not the tool, is
    #: incomplete -- and a score computed over an incomplete table is not
    #: evidence of anything.
    expectation_gaps: list[dict[str, Any]] = []
    surfaces_seen: set[str] = set()

    for finding in run.get("findings", ()):
        fields = {f["field"]: f for f in finding.get("fields", ())}
        surface = _canonical_surface(finding["surface"])
        if surface is None:
            unmatched.append(
                {
                    "finding_id": finding["finding_id"],
                    "label": finding["surface"],
                    "reason": "unrecognised surface",
                    "fields": {},
                }
            )
            continue
        surfaces_seen.add(surface)
        asset_id, why = _match(finding, fields, surface, reachable, roles)
        if asset_id is None:
            unmatched.append(
                {
                    "finding_id": finding["finding_id"],
                    "label": _unmatched_label(finding, fields, surface),
                    "reason": why,
                    "fields": {
                        name: entry.get("value")
                        for name, entry in fields.items()
                        if name not in ("path", "line")
                    },
                }
            )
            continue

        matched_findings.append({"finding_id": asset_id, "surface": surface})
        for name, entry in fields.items():
            if (asset_id, surface, name) not in expected_by_surface:
                # No stated expectation for this field on this surface. This is
                # the same rule the original scorer used for the source surface:
                # administrative/locator fields (path, line, evidence pointers)
                # and content fields ground truth simply never commented on are
                # not scored, silently -- adding an expectation nothing in the
                # ground-truth prose asked for would invent a metric. Recorded
                # for visibility only; it never fails the run (see
                # `expectation_gaps` in the report, and the self-check below,
                # which verifies liveness structurally instead).
                expectation_gaps.append(
                    {"asset_id": asset_id, "surface": surface, "field": name}
                )
                continue
            observed_fields.append(
                {
                    # score.py keys on (asset_id, field); the surface is folded
                    # into the id so the same asset seen on two surfaces is
                    # scored against the right expectations on each.
                    "asset_id": f"{asset_id}@{surface}",
                    "field": name,
                    "epistemic_state": entry["epistemic_state"],
                }
            )

    expected_flat = {
        (f"{asset_id}@{surface}", field): state
        for (asset_id, surface, field), state in expected_by_surface.items()
    }

    # Recall denominators: only surfaces this run reached, and on each only the
    # assets it could have seen. Everything else is reported as out of reach,
    # never as a zero -- a zero would read as a miss.
    ground_truth_findings = [
        {"finding_id": location["asset_id"], "surface": location["surface"]}
        for location in reachable
        if location["surface"] in surfaces_seen
    ]
    reached_pairs = {(loc["surface"], loc["asset_id"]) for loc in reachable}
    out_of_reach: dict[str, set[str]] = {}
    for location in all_locations:
        pair = (location["surface"], location["asset_id"])
        if pair in reached_pairs and location["surface"] in surfaces_seen:
            continue
        out_of_reach.setdefault(location["surface"], set()).add(location["asset_id"])

    false_certainty = false_certainty_rate(observed_fields, expected_flat)
    recall = per_surface_recall(matched_findings, ground_truth_findings)

    # §8.2 "Under-claiming rate": fields reported UNKNOWN where the answer key
    # says KNOWN. Tolerable, but tracked -- an all-UNKNOWN tool scores a perfect
    # false-certainty rate and is useless, so the headline metric is meaningless
    # without this one beside it. Scoped to the surfaces this run reached, for
    # the same reason recall is.
    under_claimed = [
        field
        for field in observed_fields
        if field["epistemic_state"] == "UNKNOWN"
        and expected_flat.get((field["asset_id"], field["field"])) == "KNOWN"
    ]
    scoped_ids = {
        f"{location['asset_id']}@{location['surface']}"
        for location in reachable
        if location["surface"] in surfaces_seen
    }
    expected_known = [
        key for key, state in expected_flat.items() if state == "KNOWN" and key[0] in scoped_ids
    ]

    return {
        "false_certainty": false_certainty,
        "per_surface_recall": recall,
        "surfaces_out_of_reach": {k: sorted(v) for k, v in sorted(out_of_reach.items())},
        "expectation_gaps": expectation_gaps,
        "matched_count": len(matched_findings),
        "finding_count": len(run.get("findings", ())),
        "under_claiming": {
            "count": len(under_claimed),
            "total_expected_known": len(expected_known),
            "rate": len(under_claimed) / len(expected_known) if expected_known else None,
            "offenders": under_claimed,
        },
        "findings_not_matched_to_a_planted_asset": unmatched,
        "coverage": run.get("coverage", {}),
        "visibility": run.get("visibility", []),
        "outcome": run.get("outcome"),
        "failure_reason": run.get("failure_reason"),
        "pki_lock_available": bool(roles),
    }


# --- reporting -------------------------------------------------------------


def _print_report(name: str, report: dict[str, Any]) -> None:
    print(f"\n=== {name} ===")

    if report["outcome"] != "completed":
        print(
            f"run outcome          : {report['outcome']} ({report['failure_reason']}) "
            "-- nothing was observed, so there is nothing to score"
        )

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
    if not report["per_surface_recall"]:
        print("    (none -- this run reached no planted asset on any surface)")
    for surface, numbers in sorted(report["per_surface_recall"].items()):
        print(
            f"    {surface:<14} {numbers['found']}/{numbers['total']}  = {numbers['recall']}"
        )
    for surface, assets in report["surfaces_out_of_reach"].items():
        print(
            f"    {surface:<14} not scored: {len(assets)} planted asset(s) outside "
            f"this run's scanned scope ({', '.join(assets)})"
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
            print(f"    {item['label']}: {item['reason']}")


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
    return score_run(mutated)


def _self_check(report: dict[str, Any], control: dict[str, Any]) -> tuple[str, bool]:
    """Say whether this run's score is evidence of anything, and why.

    Returns (message, ok). Each branch below rules out one way a 0 could be
    fake, in the order in which it would fool a reader: a run that observed
    nothing, a join that matched nothing, and finally the original control --
    an all-KNOWN copy of the run that must score worse than the run itself.

    A field with no entry in the expectation table (`expectation_gaps` in the
    report) is not treated as a failure here: that mirrors the source surface's
    original behaviour, where locator/administrative fields (path, line,
    evidence pointers) and content fields ground truth simply never commented
    on are skipped rather than scored. Those gaps are printed for a human to
    read, but a scorer that failed the run over every uncommented field would
    make the ground-truth authors write an expectation for every field any
    adapter might ever emit, which is not what §8.2 asks for.

    The one non-failing branch that reports no rate is the surface where every
    field the run emitted IS in the expectation table and is expected KNOWN
    (a direct artefact read). That is not the join silently dropping fields --
    fields silently dropped would show up as `total_eligible == 0` too, but so
    would a genuinely all-KNOWN surface, so this case is reported as "not
    applicable" rather than a pass. Recall above is unaffected either way.
    """
    fc = control["false_certainty"]

    if report["outcome"] != "completed":
        return (
            "metric self-check     : not applicable -- the run did not complete, so "
            "no score was produced to check",
            True,
        )

    if report["finding_count"] == 0:
        return (
            "    METRIC NOT LIVE: the run completed but emitted no findings, so "
            "neither recall nor false-certainty was computed from anything.",
            False,
        )

    if report["matched_count"] == 0:
        return (
            f"    METRIC NOT LIVE: none of the {report['finding_count']} finding(s) "
            "joined to a planted asset, so the score above is not evidence of "
            "anything. The join, not the tool, is what failed.",
            False,
        )

    if not fc["total_eligible"]:
        return (
            "false-certainty       : not applicable on this run -- every field it "
            "reports is expected KNOWN (a direct read of an artefact), so there is "
            "nothing here that could be over-claimed. Recall above is still live.",
            True,
        )

    if not fc["false_certainty_count"]:
        return (
            "    METRIC NOT LIVE: an all-KNOWN copy of this run scored "
            f"{fc['false_certainty_count']}/{fc['total_eligible']} -- the join or the "
            "expectation table is broken, so the score above is not evidence of "
            "anything.",
            False,
        )

    return (
        "metric self-check     : an all-KNOWN copy of this run scores "
        f"{fc['false_certainty_count']}/{fc['total_eligible']} (rate {fc['rate']}) -- "
        "the metric can fail, and this run did not",
        True,
    )


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

        if not report["pki_lock_available"]:
            print(
                "    NOTE: harness/build/pki-lock.generated.json is missing, so no "
                "certificate can be resolved to a planted role. Run "
                "harness/build/generate-pki.sh."
            )
        message, ok = _self_check(report, verify_metric_is_live(run))
        print(message)
        if not ok:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
