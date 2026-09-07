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
                   --category security [--matcher matcher.yml] [--dry-run]
  rule-scaffold.py --id c-x-y --language c --category correctness \\
                   --positive 'int f(){...}' --near-miss 'int f(){...}' [--dry-run]

Inputs:  a proposal (by --id from a proposals.jsonl) or explicit flags;
         optional --matcher, a YAML file whose top-level mapping becomes the
         rule's `rule:` body (else a TODO placeholder that will not parse as a
         rule, so an unfinished scaffold cannot pass the suite by accident).
Outputs: the two YAML files; tests/test_diagnostics.py count bumped by one.
Exit:    0 written, 1 refused (id exists, bad id, missing inputs).
Side effects: writes into the repository; --dry-run prints instead.
Limits:  message/note are drafts from the claim; the author rewrites them.
Extend:  CATEGORIES, EXTENSIONS.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("security", "correctness")
LANGUAGES = ("go", "c", "php", "python", "javascript", "java", "lua", "bash")
KEBAB = re.compile(r"^[a-z]+(-[a-z0-9]+)+$")


class LiteralStr(str):
    """Dump multi-line fixture sources as block scalars for readability."""


def _repr_literal(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


yaml.add_representer(LiteralStr, _repr_literal)


def load_proposal(path: Path, rule_id: str) -> dict:
    for line in path.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
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
    text = test.read_text()
    pattern = re.compile(r"(self\.assertEqual\((?:len\(rules\)|checked), )(\d+)")
    counts = {int(m.group(2)) for m in pattern.finditer(text)}
    if len(counts) != 1:
        sys.exit(f"rule-count guards disagree or are missing: {sorted(counts)}")
    old = counts.pop()
    new = old + 1
    if not dry_run:
        test.write_text(pattern.sub(lambda m: m.group(1) + str(new), text))
    return old, new


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

    if not KEBAB.match(args.id):
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
    if not args.id.startswith(("nginx-" if language == "c" else language, language)):
        sys.exit(f"id {args.id!r} must be prefixed with its language")

    rule_path = ROOT / "rules" / language / args.category / f"{args.id}.yml"
    fixture_path = ROOT / "tests" / language / args.category / f"{args.id}.yml"
    for p in (rule_path, fixture_path):
        if p.exists():
            sys.exit(f"refusing to overwrite {p}")
    if any(p.stem == args.id for p in (ROOT / "rules").rglob("*.yml")):
        sys.exit(f"id {args.id!r} already exists under another category")

    if args.matcher:
        matcher = yaml.safe_load(args.matcher.read_text())
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

    old, new = bump_count(args.dry_run)
    if args.dry_run:
        print(f"--- {rule_path.relative_to(ROOT)}\n{rule_text}")
        print(f"--- {fixture_path.relative_to(ROOT)}\n{fixture_text}")
        print(f"--- tests/test_diagnostics.py: rule count {old} -> {new}")
        return 0
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(rule_text)
    fixture_path.write_text(fixture_text)
    print(f"wrote {rule_path.relative_to(ROOT)}, {fixture_path.relative_to(ROOT)}; "
          f"rule count {old} -> {new}. Next: tools/rule-probe.py {args.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
