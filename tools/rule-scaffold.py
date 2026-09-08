#!/usr/bin/env python3
"""rule-scaffold.py -- create the rule/fixture pair and the inventory bump for one rule.

Why: every new rule needs the same four mechanical edits -- rule YAML in
rules/<lang>/<category>/<id>.yml, a fixture with the same id under tests/, the
explicit rule-count guard in tests/test_diagnostics.py, and a layout that
tests/test_inventory.py accepts. A model retyping those is waste and drifts;
this script does them once so the model only writes the matcher and the
controls. Pipeline: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  rule-scaffold.py --proposal WORK/cluster/proposals.jsonl --id go-x-y \\
                   --category security --claim 'Check bounds before indexing' \\
                   [--matcher matcher.yml] [--dry-run]
  rule-scaffold.py --id c-x-y --language c --category correctness \\
                   --positive 'int f(){...}' --near-miss 'int f(){...}' \\
                   --claim 'Check the return value before use' [--dry-run]

Inputs:  a proposal (by --id from a proposals.jsonl) or explicit flags;
         optional --matcher, a YAML file whose top-level mapping becomes the
         rule's `rule:` body (else a TODO placeholder that will not parse as a
         rule, so an unfinished scaffold cannot pass the suite by accident).
Outputs: the two YAML files; tests/test_diagnostics.py count bumped by one.
Exit:    0 written, 1 refused (id exists, bad id, missing inputs).
Side effects: writes into the repository; --dry-run prints instead.
Limits:  message/note are drafts from the claim; the author rewrites them.
Extend:  CATEGORIES, LANGUAGES.
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("security", "correctness")
LANGUAGES = ("go", "c", "php", "python", "javascript", "java", "lua", "bash")
# Unlike harvest-packets' Go/C proposal grammar, manual scaffolds support all
# LANGUAGES and one defect segment (for example go-check).
KEBAB = re.compile(r"^[a-z]+(-[a-z0-9]+)+$")


class LiteralStr(str):
    """Dump multi-line fixture sources as block scalars for readability."""


def _repr_literal(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


yaml.add_representer(LiteralStr, _repr_literal)


def load_proposal(path: Path, rule_id: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read proposals file {path}: {error}")
    for line in text.splitlines():
        if line.strip():
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                sys.exit(f"malformed proposal line in {path}: {error}")
            if not isinstance(row, dict) or "id" not in row:
                sys.exit(f"proposal row must be an object with id in {path}")
            if row["id"] == rule_id:
                return row
    sys.exit(f"no proposal with id {rule_id!r} in {path}")


def bump_count(dry_run: bool) -> tuple[int, int]:
    """Bump every explicit rule-count guard in tests/test_diagnostics.py.

    The file asserts the count more than once (inventory and checked-count);
    all occurrences must agree, so they are read, checked equal, and rewritten
    together.
    """
    test = ROOT / "tests" / "test_diagnostics.py"
    try:
        with test.open(encoding="utf-8", newline="") as source:
            text = source.read()
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read rule-count guard {test}: {error}")
    pattern = re.compile(r"(self\.assertEqual\((?:len\(rules\)|checked), )(\d+)")
    counts = {int(m.group(2)) for m in pattern.finditer(text)}
    if len(counts) != 1:
        sys.exit(f"rule-count guards disagree or are missing: {sorted(counts)}")
    old = counts.pop()
    new = old + 1
    if not dry_run:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=test.parent,
                                             newline="", delete=False,
                                             prefix=".rule-count-") as output:
                temporary = Path(output.name)
                output.write(pattern.sub(lambda m: m.group(1) + str(new), text))
            temporary.chmod(test.stat().st_mode)
            temporary.replace(test)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return old, new


def prepare_scaffold(args):
    """Resolve proposal fields and reject conflicting destinations before writing."""
    if not KEBAB.fullmatch(args.id):
        sys.exit(f"id {args.id!r} is not kebab-case")
    prop = load_proposal(args.proposal, args.id) if args.proposal else {}
    language = args.language or prop.get("language")
    positive = args.positive or prop.get("positive")
    near_miss = args.near_miss or prop.get("near_miss")
    claim = args.claim or prop.get("claim")
    if not (language and positive and near_miss and claim):
        sys.exit("need language, positive, near-miss and claim (flags or --proposal)")
    if language not in LANGUAGES:
        sys.exit(f"unsupported language {language!r}")
    prefixes = ("c-", "nginx-") if language == "c" else (f"{language}-",)
    if not args.id.startswith(prefixes):
        sys.exit(f"id {args.id!r} must be prefixed with its language")

    rule_path, fixture_path = scaffold_paths(args.id, language, args.category)
    rendered = render_scaffold(args, prop, language, positive, near_miss, claim)
    return rule_path, fixture_path, rendered


def scaffold_paths(rule_id, language, category):
    """Check both output paths and global ID uniqueness before generating files."""
    rule_path = ROOT / "rules" / language / category / f"{rule_id}.yml"
    fixture_path = ROOT / "tests" / language / category / f"{rule_id}.yml"
    for p in (rule_path, fixture_path):
        if p.exists():
            sys.exit(f"refusing to overwrite {p}")
    if any(p.stem == rule_id for p in (ROOT / "rules").rglob("*.yml")):
        sys.exit(f"id {rule_id!r} already exists under another category")
    return rule_path, fixture_path


def render_scaffold(args, prop, language, positive, near_miss, claim):
    """Serialize one rule and fixture, retaining a deliberately invalid TODO matcher."""

    if args.matcher:
        try:
            matcher = yaml.safe_load(args.matcher.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            sys.exit(f"cannot read --matcher {args.matcher}: {error}; "
                     "provide a readable YAML rule body")
        if not isinstance(matcher, dict):
            sys.exit("--matcher must be a YAML mapping (the rule body)")
    else:
        # A string here is rejected by ast-grep as "Cannot parse rule", so an
        # unfinished scaffold fails loudly instead of matching nothing.
        matcher = "TODO: replace with the matcher; see docs/authoring.md"

    rule = {
        "id": args.id, "language": language, "severity": args.severity,
        "message": claim,
        "note": prop.get("rationale", "TODO: when to dismiss, and the semantic limit."),
        "rule": matcher,
    }
    fixture = {"id": args.id,
               "valid": [LiteralStr(near_miss)],
               "invalid": [LiteralStr(positive)]}
    rule_text = yaml.dump(rule, sort_keys=False, width=80, allow_unicode=True)
    fixture_text = yaml.dump(fixture, sort_keys=False, width=1000, allow_unicode=True)
    return rule_text, fixture_text


def create_parent_dirs(directories: tuple[Path, ...], created_dirs: list[Path]) -> None:
    """Create missing ancestors, recording only directories this process owns."""
    for directory in directories:
        missing = []
        cursor = directory
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        for path in reversed(missing):
            try:
                path.mkdir()
            except FileExistsError:
                if not path.is_dir():
                    raise
            else:
                created_dirs.append(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    ap.add_argument("--id", required=True)
    ap.add_argument("--proposal", type=Path, help="proposals.jsonl to read --id from")
    ap.add_argument("--language", choices=LANGUAGES)
    ap.add_argument("--category", choices=CATEGORIES, required=True)
    ap.add_argument("--positive", help="source that must match")
    ap.add_argument("--near-miss", help="source that must not match")
    ap.add_argument("--claim", help="one-sentence syntactic claim (message draft)")
    ap.add_argument("--matcher", type=Path, help="YAML file: the `rule:` body")
    ap.add_argument("--severity", default="warning", choices=("error", "warning", "info"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    rule_path, fixture_path, (rule_text, fixture_text) = prepare_scaffold(args)

    old, new = bump_count(True)
    if args.dry_run:
        print(f"--- {rule_path.relative_to(ROOT)}\n{rule_text}")
        print(f"--- {fixture_path.relative_to(ROOT)}\n{fixture_text}")
        print(f"--- tests/test_diagnostics.py: rule count {old} -> {new}")
        return 0
    created_dirs: list[Path] = []
    created: list[Path] = []
    try:
        create_parent_dirs((rule_path.parent, fixture_path.parent), created_dirs)
        for path, text in ((rule_path, rule_text), (fixture_path, fixture_text)):
            with path.open("x", encoding="utf-8", newline="") as output:
                created.append(path)
                output.write(text)
        old, new = bump_count(False)
    except (OSError, UnicodeError, SystemExit):
        for path in reversed(created):
            path.unlink(missing_ok=True)
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                continue
        raise
    print(f"wrote {rule_path.relative_to(ROOT)}, {fixture_path.relative_to(ROOT)}; "
          f"rule count {old} -> {new}. Next: tools/rule-probe.py {args.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
