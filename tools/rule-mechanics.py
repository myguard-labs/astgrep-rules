#!/usr/bin/env python3
"""Reproduce plans, validate exact oracles/fixes, and compare scan corpora."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "node_modules" / ".bin" / "ast-grep"
MAX_FILES = 20_000
MAX_FINDINGS = 100_000
MAX_CORPUS_BYTES = 256 * 1024 * 1024


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load tool: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAFFOLD = load_tool("rule-scaffold")
PLAN = load_tool("rule-plan")


def plan_paths() -> list[Path]:
    root = ROOT / "plans"
    return sorted(root.rglob("*.yml")) if root.is_dir() else []


def compile_plan(path: Path, *, preflight: bool = True):
    plan, _matcher, rule_text, fixture_text = PLAN.compile_plan(path, run_checks=preflight)
    expected_plan = ROOT / "plans" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    if path.resolve() != expected_plan.resolve():
        raise RuntimeError(f"PLAN_LAYOUT: expected {expected_plan.relative_to(ROOT)}")
    relative = path.relative_to(ROOT).as_posix()
    marker = f"# Generated from: {relative}\n"
    rule_text = marker + rule_text
    fixture_text = marker + fixture_text
    if preflight:
        check_oracles(plan, yaml.safe_load(rule_text))
    rule_path = ROOT / "rules" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    fixture_path = ROOT / "tests" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    collisions = [candidate for candidate in (ROOT / "rules").glob(f"*/*/{plan['id']}.yml")
                  if candidate != rule_path]
    if collisions:
        raise RuntimeError(f"PLAN_ID_COLLISION: {plan['id']}: {collisions[0]}")
    return rule_path, fixture_path, rule_text, fixture_text


def scan_rule(rule: dict, source: str, engine: Path = ENGINE) -> list[dict]:
    result = subprocess.run(
        [str(engine), "scan", "--inline-rules", yaml.safe_dump(rule),
         "--stdin", "--json=compact"], input=source, text=True,
        capture_output=True, timeout=20, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError((result.stderr or result.stdout)[-500:])
    findings = json.loads(result.stdout or "[]")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise RuntimeError("invalid or excessive ast-grep finding output")
    return findings


def check_oracles(plan: dict, rule: dict) -> None:
    for source, expected in plan.get("oracles", {}).items():
        findings = scan_rule(rule, source)
        actual = {
            "count": len(findings),
            "texts": [finding.get("text") for finding in findings],
            "ranges": [[finding["range"]["byteOffset"]["start"],
                        finding["range"]["byteOffset"]["end"]]
                       for finding in findings],
            "message": findings[0].get("message") if findings else None,
            "note": findings[0].get("note") if findings else None,
            "severity": findings[0].get("severity") if findings else None,
            "labels": [label.get("text") for finding in findings
                       for label in finding.get("labels", [])],
        }
        for key, wanted in expected.items():
            if key == "fixed":
                continue
            if actual[key] != wanted:
                raise RuntimeError(f"ORACLE_MISMATCH: {plan['id']} {key}: "
                                   f"expected {wanted!r}, got {actual[key]!r}")


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as output:
            temporary = Path(output.name)
            output.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def plans_command(write: bool) -> int:
    paths = plan_paths()
    drift = []
    updates = []
    for path in paths:
        rule_path, fixture_path, rule_text, fixture_text = compile_plan(path)
        for target, content in ((rule_path, rule_text), (fixture_path, fixture_text)):
            if not target.is_file() or target.read_text(encoding="utf-8") != content:
                drift.append(target.relative_to(ROOT).as_posix())
                if write:
                    owner = f"# Generated from: {path.relative_to(ROOT).as_posix()}\n"
                    if target.exists() and owner not in target.read_text(encoding="utf-8"):
                        raise RuntimeError(f"refusing to overwrite non-generated {target}")
                    updates.append((target, content))
    if write:
        with SCAFFOLD.cli_scaffold_lock():
            for target, content in updates:
                owner = next(line for line in content.splitlines()
                             if line.startswith("# Generated from: ")) + "\n"
                if target.exists() and owner not in target.read_text(encoding="utf-8"):
                    raise RuntimeError(f"refusing to overwrite non-generated {target}")
                write_atomic(target, content)
            count_changed = sync_diagnostic_count(True, {path.stem for path in paths})
    else:
        count_changed = sync_diagnostic_count(False, {path.stem for path in paths})
    if count_changed:
        drift.append("tests/test_diagnostics.py")
    if drift and not write:
        print("generated drift: " + ", ".join(drift), file=sys.stderr)
        return 1
    print(f"{'regenerated' if write else 'verified'} {len(paths)} canonical plan(s)"
          + (f"; {len(drift)} artifact(s) updated" if write else ""))
    return 0


def sync_diagnostic_count(write: bool, planned_ids: set[str]) -> bool:
    """Keep the explicit diagnostic guard reproducible when plans add rules."""
    path = ROOT / "tests/test_diagnostics.py"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"(self\.assertEqual\((?:len\(rules\)|checked), )(\d+)")
    observed = {int(match.group(2)) for match in pattern.finditer(text)}
    if len(observed) != 1:
        raise RuntimeError("diagnostic rule-count guards disagree or are missing")
    existing = {rule.stem for rule in (ROOT / "rules").glob("*/*/*.yml")
                if rule.relative_to(ROOT / "rules").parts[0] != "powershell"}
    desired = len(existing | planned_ids)
    changed = observed != {desired}
    if changed and write:
        write_atomic(path, pattern.sub(lambda match: match.group(1) + str(desired), text))
    return changed


def metamorphic_cases(source: str, language: str) -> list[dict]:
    """Emit review candidates only; no transformation invents an oracle."""
    candidates = []
    stripped = source.strip()
    if "\n" not in stripped:
        comment = "#" if language in {"python", "bash"} else "//"
        candidates.extend([
            {"name": "comment-lookalike", "source": f"{comment} {stripped}"},
            {"name": "string-lookalike", "source": json.dumps(stripped)},
            {"name": "parenthesized", "source": f"({stripped})"},
        ])
    if "(" in stripped and stripped.endswith(")"):
        candidates.append({"name": "extended-arity", "source": stripped[:-1] + ", extra)"})
    return [{**candidate, "expected": "review"} for candidate in candidates]


def metamorph_command(path: Path) -> int:
    plan = PLAN.load_plan(path)
    cases = PLAN.validate_cases(plan["cases"])
    output = {"version": 1, "id": plan.get("id"), "candidates": []}
    for classification in ("invalid", "valid"):
        for index, source in enumerate(cases[classification]):
            for candidate in metamorphic_cases(source, plan["language"]):
                output["candidates"].append(
                    {"from": f"{classification}[{index}]", **candidate})
    print(yaml.safe_dump(output, sort_keys=False), end="")
    return 0


def validate_fix(rule_path: Path, source: str, expected: str | None = None) -> None:
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    if "fix" not in rule:
        return
    extension = {
        "python": "py", "javascript": "js", "bash": "sh", "c": "c", "go": "go",
        "java": "java", "php": "php", "lua": "lua", "cpp": "cpp",
    }[rule["language"]]
    with tempfile.TemporaryDirectory(prefix="rule-fix-") as directory:
        target = Path(directory) / f"source.{extension}"
        target.write_text(source, encoding="utf-8")
        before = target.read_text(encoding="utf-8")
        result = subprocess.run([str(ENGINE), "scan", "--rule", str(rule_path),
                                 "--update-all", str(target)], text=True,
                                capture_output=True, timeout=20, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"FIX_FAILED: {rule['id']}: {result.stderr[-400:]}")
        after = target.read_text(encoding="utf-8")
        if after == before:
            raise RuntimeError(f"FIX_NO_CHANGE: {rule['id']}")
        if expected is not None and after != expected:
            raise RuntimeError(f"FIX_OUTPUT_MISMATCH: {rule['id']}")
        if scan_rule(rule, after):
            raise RuntimeError(f"FIX_RETAINS_FINDING: {rule['id']}")
        second = subprocess.run([str(ENGINE), "scan", "--rule", str(rule_path),
                                 "--update-all", str(target)], text=True,
                                capture_output=True, timeout=20, check=False)
        if second.returncode not in (0, 1) or target.read_text(encoding="utf-8") != after:
            raise RuntimeError(f"FIX_NOT_IDEMPOTENT: {rule['id']}")
        parse = subprocess.run([str(ENGINE), "run", "-l", rule["language"],
                                "--kind", "ERROR", "--json=compact", str(target)],
                               text=True, capture_output=True, timeout=20, check=False)
        try:
            errors = json.loads(parse.stdout or "[]")
        except json.JSONDecodeError as error:
            raise RuntimeError(f"FIX_PARSE_FAILED: {rule['id']}: invalid JSON") from error
        if parse.returncode not in (0, 1) or errors:
            raise RuntimeError(f"FIX_PARSE_FAILED: {rule['id']}")


def fixes_command(rule_id: str | None) -> int:
    paths = (list(ROOT.glob(f"rules/*/*/{rule_id}.yml")) if rule_id else
             sorted((ROOT / "rules").glob("*/*/*.yml")))
    if rule_id and not paths:
        raise RuntimeError(f"unknown rule id: {rule_id}")
    checked = 0
    for path in paths:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "fix" not in rule:
            continue
        fixture = yaml.safe_load((ROOT / "tests" / path.relative_to(ROOT / "rules")).read_text())
        plan_path = ROOT / "plans" / path.relative_to(ROOT / "rules")
        fixed_oracles = {}
        if plan_path.is_file():
            plan = PLAN.load_plan(plan_path)
            fixed_oracles = {candidate: oracle["fixed"]
                             for candidate, oracle in plan.get("oracles", {}).items()
                             if "fixed" in oracle}
        for source in fixture["invalid"]:
            validate_fix(path, source, fixed_oracles.get(source))
            checked += 1
    print(f"validated {checked} fixer fixture(s)")
    return 0


def normalized_findings(engine: Path, config: Path, corpus: Path) -> list[tuple]:
    files = [path for path in corpus.rglob("*") if path.is_file()]
    if len(files) > MAX_FILES:
        raise RuntimeError(f"corpus exceeds {MAX_FILES} files")
    size = sum(path.stat().st_size for path in files)
    if size > MAX_CORPUS_BYTES:
        raise RuntimeError(f"corpus exceeds {MAX_CORPUS_BYTES} bytes")
    result = subprocess.run([str(engine), "scan", "-c", str(config), "--json=compact",
                             "--threads", "1", str(corpus)], text=True,
                            capture_output=True, timeout=300, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr[-500:])
    findings = json.loads(result.stdout or "[]")
    if len(findings) > MAX_FINDINGS:
        raise RuntimeError(f"scan exceeds {MAX_FINDINGS} findings")
    return sorted((finding["ruleId"], finding["file"],
                   finding["range"]["byteOffset"]["start"],
                   finding["range"]["byteOffset"]["end"], finding.get("text"),
                   finding.get("message"), finding.get("severity")) for finding in findings)


def differential_command(old: Path, new: Path, config: Path, corpus: Path) -> int:
    before = normalized_findings(old, config, corpus)
    after = normalized_findings(new, config, corpus)
    before_counts, after_counts = Counter(before), Counter(after)
    removed = [{"finding": finding, "count": count}
               for finding, count in sorted((before_counts - after_counts).items())]
    added = [{"finding": finding, "count": count}
             for finding, count in sorted((after_counts - before_counts).items())]
    print(json.dumps({"old_sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                      "new_sha256": hashlib.sha256(new.read_bytes()).hexdigest(),
                      "before": len(before), "after": len(after),
                      "removed": removed, "added": added}, indent=1))
    return int(bool(removed or added))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-plans")
    sub.add_parser("regenerate-all")
    metamorph = sub.add_parser("metamorph")
    metamorph.add_argument("plan", type=Path)
    fixes = sub.add_parser("validate-fixes")
    fixes.add_argument("--rule-id")
    diff = sub.add_parser("differential")
    diff.add_argument("--old-engine", type=Path, required=True)
    diff.add_argument("--new-engine", type=Path, default=ENGINE)
    diff.add_argument("--config", type=Path, default=ROOT / "sgconfig.yml")
    diff.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "check-plans":
        return plans_command(False)
    if args.command == "regenerate-all":
        return plans_command(True)
    if args.command == "metamorph":
        return metamorph_command(args.plan)
    if args.command == "validate-fixes":
        return fixes_command(args.rule_id)
    return differential_command(args.old_engine, args.new_engine, args.config, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
