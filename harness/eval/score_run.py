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
    python harness/eval/score_run.py [--allow-missing-pki] <run.json> [<run.json> ...]

A missing harness/build/pki-lock.generated.json is a loud, non-zero-exit
failure by default (every certificate finding would otherwise silently score
as "out of reach" instead of failing the way a broken build step should);
pass --allow-missing-pki to score anyway.

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
    `config:<root>:<key>`, `tls:<host>:<port>`, `packages:<scanned_target>`),
    which is why its surface strings are not the ground-truth names. The
    mapping happens here and not in ECDAT.
    """
    if surface == "source":
        return "source"
    if surface.startswith("certdir:"):
        return "artifact"
    if surface.startswith("config:"):
        return "configuration"
    if surface.startswith("k8ssecret:"):
        return "configuration"
    if surface.startswith("tls:"):
        return "tls"
    if surface.startswith("packages:"):
        return "dependency"
    return None


def _property_key(surface: str) -> str | None:
    """`config:<scan root>:<property key>` or `k8ssecret:<manifest
    path>:<data/stringData key>` -> the trailing key.

    ecdat's k8s-secret adapter (DEV-014) emits `k8ssecret:<path>:<source
    field>.<key>` (e.g. "k8ssecret:.../pay-tls-secret.yaml:data.tls.key"),
    the same shape config-chain-spring's own `config:<root>:<property key>`
    already uses -- both are joined here as ground truth's `configuration`
    surface, keyed on whatever ground truth's own `key` field names (a
    Spring property key for one adapter, "data.tls.key" for the other). The
    scan root/manifest path is an absolute path that may itself contain a
    colon (a Windows drive letter), so the key is taken from the right-hand
    end, not by splitting from the left.
    """
    if not (surface.startswith("config:") or surface.startswith("k8ssecret:")):
        return None
    tail = surface.rsplit(":", 1)[-1]
    return tail or None


# --- scoping ---------------------------------------------------------------


def _in_reach(
    locations: list[dict[str, Any]], run: dict[str, Any], surfaces_run: set[str]
) -> list[dict[str, Any]]:
    """The planted locations this run actually had the chance to observe.

    A location is in reach if one of the files/endpoints the run reports as
    scanned ends with that location's recorded path (`tls`'s "path" is a
    host:port string, e.g. "edge-lb:8443", not a file -- the tls-endpoint
    adapter's own `coverage.scanned` entries ("sslyze edge-lb:8443", "openssl
    s_client edge-lb:8443") end with exactly that string, so this needs no
    special case).

    `dependency` is the one surface where path-suffix matching would be
    dishonest rather than merely inapplicable: ground truth's PAY-008
    location names `payments/payment-gateway/pom.xml` -- the SOURCE
    declaration -- but `packages-trivy` (this harness's only dependency
    adapter) observes the dependency by inventorying the BUILT artifact
    (`trivy rootfs` on the fat jar), whose own `coverage.scanned` is
    whatever trivy's `ArtifactName` happened to report for that invocation
    (the recorded fixture: "."). No path-suffix rule connects those two
    honestly. So a dependency location counts as in reach if this run ran a
    dependency-surface scan at all (`surfaces_run` contains "dependency") --
    scoped to "did a packages adapter run", not "did it read this exact
    file", because that is the actual granularity a package-manifest
    inventory operates at. Recall is still computed per planted package (by
    name/purl, see `_match`), so a trivy run that ran but did not report
    bcprov-jdk18on still scores a real miss, not a free pass.
    """
    scanned = [_norm(p) for p in (run.get("coverage") or {}).get("scanned", ())]
    reached = []
    for location in locations:
        if location["surface"] == "dependency":
            if "dependency" in surfaces_run:
                reached.append(location)
            continue
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

    if surface == "dependency":
        # packages-trivy's "name" field is trivy's own package Name, which
        # for a Maven package is literally "groupId:artifactId" -- the exact
        # string ground truth records as the dependency's `key` (see
        # PAY-008.yaml: key: org.bouncycastle:bcprov-jdk18on). No purl
        # normalisation needed; trivy already reports it in the same shape.
        name = str((fields.get("name") or {}).get("value") or "")
        if not name:
            return None, "no name field on a dependency finding"
        for location in candidates:
            if location.get("key") == name:
                return location["asset_id"], ""
        return None, f"package '{name}' is not a planted asset"

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
    if surface == "dependency":
        return str((fields.get("name") or {}).get("value") or finding["finding_id"])
    if surface == "tls":
        return finding["surface"]
    return finding["finding_id"]


def _surfaces_run(run: dict[str, Any]) -> set[str]:
    """Which ground-truth surfaces this run actually exercised, independent
    of whether any finding on that surface matched a planted asset. Used by
    `_in_reach` for the `dependency` surface (see its docstring) and to keep
    that scoping decision in one place rather than re-deriving it twice."""
    surfaces = {
        canonical
        for canonical in (_canonical_surface(f.get("surface", "")) for f in run.get("findings", ()))
        if canonical
    }
    # A trivy run that finds zero packages (e.g. TRAP-07's no-crypto-service)
    # still ran the dependency surface -- coverage.scanned says so even with
    # no findings (harness §7.3: "silence != scanned") -- so this is also
    # keyed off adapter_id, not just finding presence.
    if str(run.get("adapter_id", "")).startswith("packages-"):
        surfaces.add("dependency")
    return surfaces


def score_run(run: dict[str, Any]) -> dict[str, Any]:
    all_locations = _locations()
    surfaces_run = _surfaces_run(run)
    reachable = _in_reach(all_locations, run, surfaces_run)
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

        if surface == "tls":
            # One wire probe is evidence for several planted "logical"
            # assets at once: PAY-005 (the certificate identity), PAY-006
            # (the negotiated key-agreement group(s)) and PAY-007 (the
            # cipher suites) all share the SAME ground-truth location
            # (surface: tls, path: "edge-lb:8443") because they are three
            # different algorithm-family facts about one observed endpoint,
            # not three different places. ECDAT itself also emits exactly
            # one Finding per probe (adapters/tls/adapter.py). So this is
            # the one surface where a single finding matches every reachable
            # location at that path, not just one -- anything else would
            # under-count recall for two of the three assets purely because
            # score_run.py's join is per-finding-per-asset everywhere else.
            candidates = [loc for loc in reachable if loc["surface"] == "tls"]
            path = _norm(finding["surface"][len("tls:") :])
            path_matches = [loc for loc in candidates if path.endswith(_norm(loc["path"]))]
            if not path_matches:
                unmatched.append(
                    {
                        "finding_id": finding["finding_id"],
                        "label": finding["surface"],
                        "reason": "tls endpoint is not a planted asset location",
                        "fields": {},
                    }
                )
                continue
            for location in path_matches:
                asset_id = location["asset_id"]
                matched_findings.append({"finding_id": asset_id, "surface": surface})
                for name, entry in fields.items():
                    if (asset_id, surface, name) not in expected_by_surface:
                        expectation_gaps.append(
                            {"asset_id": asset_id, "surface": surface, "field": name}
                        )
                        continue
                    observed_fields.append(
                        {
                            "asset_id": f"{asset_id}@{surface}",
                            "field": name,
                            "epistemic_state": entry["epistemic_state"],
                        }
                    )
            continue

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


# --- forbidden-edge scoring of an `ecdat correlate` report ------------------

#: harness §7.4 / ground-truth/relationships.yaml's `forbidden: true` rows,
#: translated once, here, from the free-text entity names a human reads
#: ("PAY-004 (app keystore)", "edge-lb endpoint") to the harness PKI roles
#: those entities resolve to (H3: ground truth never names a fingerprint, but
#: it does name a role -- PAY-004.yaml `role: gateway-p12`, PAY-005.yaml
#: `role: pay-edge`). This is an interpretation of relationships.yaml living
#: in harness code, not an edit to ground truth: relationships.yaml itself is
#: untouched, and this table only exists because `ecdat correlate`'s
#: `same-object` relationships name CryptoAsset ids, not the prose labels
#: ground truth uses, so *something* has to bridge the two to make the check
#: automatic instead of a human re-reading the JSON every time.
_FORBIDDEN_ROLE_PAIRS: dict[frozenset[str], str] = {
    frozenset({"gateway-p12", "pay-edge"}): (
        "relationships.yaml: 'PAY-004 (app keystore) serves/presents edge-lb endpoint' "
        "-- forbidden because the LB actually serves pay-edge (PAY-005), a different "
        "certificate; gateway-p12 and pay-edge must never be asserted same-object."
    ),
}

#: The other forbidden pair in relationships.yaml ('PAY-001 RSA key (source)
#: same-object/shares-public-key PAY-004 RSA key (keystore)') is recorded
#: here, not in _FORBIDDEN_ROLE_PAIRS, because it can never be checked this
#: way: PAY-001 is a source-code RSA-OAEP transformation string
#: (source-semgrep), which carries no der_sha256/spki_sha256 field at all --
#: there is no hash on that side to resolve to a role, or to compare, no
#: matter what a correlate run contains. `ecdat.correlation.engine`'s own
#: docstring confirms this is structural, not a gap in this harness's plan:
#: it only ever computes identity from `der_sha256`/`spki_sha256` fields, and
#: no adapter in this harness's reach emits either for source-code findings.
_STRUCTURALLY_UNREACHABLE_FORBIDDEN_EDGE = (
    "relationships.yaml: 'PAY-001 RSA key (source) same-object/shares-public-key "
    "PAY-004 RSA key (keystore)' -- NOT exercised by this check: PAY-001 (source-semgrep) "
    "carries no der_sha256/spki_sha256 field, so no hash exists on that side for "
    "ecdat.correlation.engine's identity rule (IDENTITY-CERT-DER-001, the only one it acts "
    "on) to ever compare or resolve to a role. This is a structural gap in the current "
    "adapter set, not a verified absence -- reported honestly rather than silently passed."
)


def _asset_known_field(asset: dict[str, Any], field_name: str) -> str | None:
    for field in asset.get("fields", ()):
        if field.get("field") == field_name and field.get("epistemic_state") == "KNOWN":
            value = field.get("value")
            return str(value) if value else None
    return None


def score_correlation(document: dict[str, Any], roles: dict[str, str]) -> dict[str, Any]:
    """Score one `ecdat correlate --format report` document (see
    `_correlate_document` in ecdat's cli.py) against the forbidden pairs in
    `_FORBIDDEN_ROLE_PAIRS`.

    `ecdat.correlation.engine.correlate()` only ever emits a `same-object`
    relationship when two assets share a KNOWN `der_sha256` value (its own
    docstring: "ONLY that"), and only between assets that carry the field at
    all. So this check resolves each `same-object` relationship's two
    endpoints to a harness PKI role the same way score_run.py's `artifact`
    join does (der_sha256 -> pki-lock -> role), and flags a violation only if
    the resolved role pair is one ground truth forbids. A relationship whose
    endpoints do not both resolve to a role (e.g. an asset from a surface
    this harness's PKI lock does not cover) is not checked -- silently
    passing it would be exactly the kind of manufactured pass this harness
    exists to avoid, so it is instead surfaced under `unresolved_edges`.
    """
    asset_roles: dict[str, str] = {}
    for asset in document.get("assets", ()):
        der = _asset_known_field(asset, "der_sha256")
        if der:
            role = roles.get(der.lower())
            if role:
                asset_roles[asset["asset_id"]] = role

    violations: list[dict[str, Any]] = []
    unresolved_edges: list[dict[str, Any]] = []
    identity_relationships = [
        rel for rel in document.get("relationships", ()) if rel.get("type") == "same-object"
    ]
    for rel in identity_relationships:
        source_role = asset_roles.get(rel.get("source_entity"))
        target_role = asset_roles.get(rel.get("target_entity"))
        if source_role is None or target_role is None:
            unresolved_edges.append(
                {
                    "source_entity": rel.get("source_entity"),
                    "target_entity": rel.get("target_entity"),
                    "reason": "one or both endpoints did not resolve to a harness PKI role",
                }
            )
            continue
        pair = frozenset({source_role, target_role})
        note = _FORBIDDEN_ROLE_PAIRS.get(pair)
        if note is not None:
            violations.append(
                {
                    "relationship": rel,
                    "source_role": source_role,
                    "target_role": target_role,
                    "forbidden_rule": note,
                }
            )

    return {
        "identity_relationships_checked": len(identity_relationships),
        "asset_roles_resolved": asset_roles,
        "violations": violations,
        "unresolved_edges": unresolved_edges,
        "not_exercised": [_STRUCTURALLY_UNREACHABLE_FORBIDDEN_EDGE],
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
    allow_missing_pki = "--allow-missing-pki" in argv
    run_paths = [a for a in argv if a != "--allow-missing-pki"]

    if not run_paths:
        print(__doc__)
        return 2

    # Loud failure by default (unless --allow-missing-pki): a missing
    # pki-lock.generated.json silently zeroes out every certificate
    # ('artifact' surface) finding's chance of being scored, which would
    # otherwise read as a real 0/0-recall result instead of a broken build
    # step. Checked once, before scoring any run, rather than per-run inside
    # the loop below, because it is the same fatal precondition for all of
    # them.
    if not PKI_LOCK.is_file() and not allow_missing_pki:
        print(
            f"FATAL: {PKI_LOCK} is missing.\n"
            "Every certificate ('artifact' surface) finding in every run below would "
            "silently score as out of reach instead of being resolved to a planted PKI "
            "role, which is not a real result.\n"
            "Run harness/build/generate-pki.sh first, or pass --allow-missing-pki to "
            "score anyway and accept that those assets will not be scored.",
            file=sys.stderr,
        )
        return 1

    exit_code = 0
    for arg in run_paths:
        path = Path(arg)
        run = json.loads(path.read_text(encoding="utf-8"))
        report = score_run(run)
        _print_report(path.name, report)

        if not report["pki_lock_available"]:
            print(
                "    NOTE: harness/build/pki-lock.generated.json is missing, so no "
                "certificate can be resolved to a planted role. Run "
                "harness/build/generate-pki.sh (or this run was scored with "
                "--allow-missing-pki)."
            )
        message, ok = _self_check(report, verify_metric_is_live(run))
        print(message)
        if not ok:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
