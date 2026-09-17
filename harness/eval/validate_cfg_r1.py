#!/usr/bin/env python3
"""Lock §6 CFG-R1: "Run payment-gateway states B, C, D (with profile), F,
[H] -- read the actual bound value at runtime -- to confirm the actual
runtime winner matches the expected column. The harness answer key must
itself be validated against the runtime, not against the docs." (harness
§14.4 test 1 names B, C, D, F; harness §14.6 adds state H.)

Runs states A, B, C, D, E, F, H against a real, locally built Spring Boot
jar (state G is not run -- see overlays/README.md: an unreferenced Helm
values.yaml key has zero runtime effect by construction, nothing to
validate). Requires `mvn` and `java` on PATH; prints exact commands used and
the real captured stdout for each state so results are reproducible, per
CLAUDE.md's anti-hallucination rules (no runtime value here is asserted from
memory or from Spring docs alone).

Not domain code -- harness build/eval tooling only.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY_DIR = HERE.parent.parent / "targets" / "payments" / "payment-gateway"
OUT_DIR = HERE / "out"

LOG_PATTERN = re.compile(r"CFG-R1 pay\.keywrap\.transformation=(.*)")


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> str:
    # shutil.which resolves PATHEXT (mvn -> mvn.cmd on Windows) -- a bare
    # subprocess.run(["mvn", ...]) does not do this on Windows.
    resolved = shutil.which(cmd[0], path=(env or {}).get("PATH")) or cmd[0]
    result = subprocess.run(
        [resolved] + cmd[1:], cwd=cwd, env=env, capture_output=True, text=True, timeout=180
    )
    return result.stdout + result.stderr


def extract_value(output: str) -> str | None:
    for line in output.splitlines():
        m = LOG_PATTERN.search(line)
        if m:
            return m.group(1)
    return None


def build_jar(project_dir: Path) -> Path:
    import os

    output = run(["mvn", "-q", "-DskipTests", "package"], cwd=project_dir, env=os.environ.copy())
    jars = list((project_dir / "target").glob("payment-gateway-*.jar"))
    if not jars:
        raise RuntimeError(f"build failed, no jar produced. Maven output:\n{output}")
    return jars[0]


def main() -> int:
    import os

    OUT_DIR.mkdir(exist_ok=True)
    results: dict[str, dict] = {}

    # --- states B, C, D, E, F: base jar, launched differently ---
    base_jar = build_jar(GATEWAY_DIR)
    print(f"built base jar: {base_jar}")

    def run_base(state: str, cmd_suffix: list[str], extra_env: dict):
        env = os.environ.copy()
        env.update(extra_env)
        cmd = ["java", "-jar", str(base_jar)] + cmd_suffix
        output = run(cmd, cwd=GATEWAY_DIR, env=env)
        value = extract_value(output)
        results[state] = {
            "command": " ".join(cmd),
            "env_overrides": extra_env,
            "bound_value": value,
        }
        print(f"state {state}: bound_value={value!r}")

    run_base("B", [], {})
    run_base("C", [], {"PAY_KEYWRAP_TRANSFORMATION": "RSA/ECB/PKCS1Padding"})
    run_base("D", [], {"SPRING_PROFILES_ACTIVE": "prod"})
    run_base(
        "E",
        [],
        {"SPRING_PROFILES_ACTIVE": "prod", "PAY_KEYWRAP_TRANSFORMATION": "RSA/ECB/PKCS1Padding"},
    )
    run_base("F", ["--pay.keywrap.transformation=RSA/ECB/PKCS1Padding"], {})

    # --- state A: overlay application.yml (no pay.keywrap key), separate build ---
    state_a_dir = OUT_DIR / "state-A-project"
    if state_a_dir.exists():
        shutil.rmtree(state_a_dir)
    shutil.copytree(GATEWAY_DIR, state_a_dir, ignore=shutil.ignore_patterns("target", "overlays"))
    overlay_yml = GATEWAY_DIR / "overlays" / "state-A" / "application.yml"
    shutil.copy(overlay_yml, state_a_dir / "src" / "main" / "resources" / "application.yml")
    state_a_jar = build_jar(state_a_dir)
    output = run(["java", "-jar", str(state_a_jar)], cwd=state_a_dir, env=os.environ.copy())
    value = extract_value(output)
    results["A"] = {
        "command": f"java -jar {state_a_jar} (overlay: state-A/application.yml, no pay.keywrap key)",
        "env_overrides": {},
        "bound_value": value,
    }
    print(f"state A: bound_value={value!r}")

    # --- state H: base jar, run from a working dir with ./config/application.yml ---
    state_h_workdir = OUT_DIR / "state-H-workdir"
    if state_h_workdir.exists():
        shutil.rmtree(state_h_workdir)
    (state_h_workdir / "config").mkdir(parents=True)
    (state_h_workdir / "config" / "application.yml").write_text(
        "pay:\n  keywrap:\n    transformation: \"RSA/ECB/PKCS1Padding\"\n"
    )
    output = run(["java", "-jar", str(base_jar.resolve())], cwd=state_h_workdir, env=os.environ.copy())
    value = extract_value(output)
    results["H"] = {
        "command": f"java -jar {base_jar} (run from workdir with ./config/application.yml = PKCS1)",
        "env_overrides": {},
        "bound_value": value,
    }
    print(f"state H: bound_value={value!r}")

    # state G: not run -- see overlays/README.md
    results["G"] = {
        "command": None,
        "env_overrides": {},
        "bound_value": "<same as B, not run: unreferenced Helm key has no runtime effect>",
    }

    import json

    (OUT_DIR / "cfg_r1_results.json").write_text(json.dumps(results, indent=2))
    print(f"\nwrote {OUT_DIR / 'cfg_r1_results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
