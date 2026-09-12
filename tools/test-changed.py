#!/usr/bin/env python3
"""Run deterministic unit tests plus focused probes for changed rule IDs."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def changed_paths(base: str) -> list[str]:
    result = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMRD", base, "--"],
                            cwd=ROOT, text=True, capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git diff exited {result.returncode}")
    return [line for line in result.stdout.splitlines() if line]


def rule_ids(paths: list[str]) -> list[str]:
    ids = set()
    for value in paths:
        path = Path(value)
        if len(path.parts) == 4 and path.parts[0] in {"rules", "tests", "plans"} \
                and path.suffix == ".yml" and "__snapshots__" not in path.parts:
            ids.add(path.stem)
        elif len(path.parts) == 3 and path.parts[:2] == ("tests", "__snapshots__") \
                and path.parts[2].endswith("-snapshot.yml"):
            ids.add(path.name.removesuffix("-snapshot.yml"))
    return sorted(ids)


def requires_full_suite(paths: list[str]) -> bool:
    prefixes = ("tools/", ".github/workflows/")
    exact = {"package.json", "package-lock.json", "sgconfig.yml",
             "sgconfig.powershell.yml"}
    return any(path.startswith(prefixes) or path.startswith("tests/test_") or path in exact
               for path in paths)


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, cwd=ROOT, timeout=300, check=False,
                            env={**os.environ, **(env or {})})
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("BASE_SHA", "HEAD^"))
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    paths = args.paths or changed_paths(args.base)
    if requires_full_suite(paths):
        run(["npm", "test"])
        run(["npm", "run", "test:mechanics"])
        print("fast gate escalated to full suite for infrastructure changes")
        return 0
    # Inventory enforces whole-pack layout, IDs, fixtures, snapshots and docs.
    # Each focused probe then enforces that rule's diagnostics, exact counts,
    # discovery and arm mutations without rescanning every rule in the pack.
    ids = rule_ids(paths)
    run([sys.executable, "-m", "unittest", "tests.test_inventory",
         "tests.test_diagnostics", "tests.test_coderabbit_provenance"],
        {"ASTGREP_RULE_IDS": ",".join(ids)})
    run([sys.executable, "tools/rule-mechanics.py", "check-plans"])
    for rule_id in ids:
        if any((ROOT / "rules").glob(f"*/*/{rule_id}.yml")):
            run([sys.executable, "tools/rule-probe.py", rule_id])
    print(f"fast gate: {len(ids)} changed rule id(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
