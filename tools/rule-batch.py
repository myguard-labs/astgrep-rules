#!/usr/bin/env python3
"""Plan a proposal batch and mechanically scaffold oracle-passing rule seeds.

Why: after proposal review, selecting syntactic/nonduplicate rows, testing seed
viability, scaffolding pairs, and recording the first probe are deterministic.
This tool leaves only matcher generality and semantic value to the drafter and
shipping reviewer. Contract: docs/authoring.md#harvest-and-draft-pipeline.

Usage:
  rule-batch.py --work WORK --category correctness [--dry-run] [--json]
  rule-batch.py --work WORK --category security --apply-seeded

Inputs: WORK/cluster/proposals.jsonl and WORK/dedupe.tsv.
Output: a bounded summary, plus WORK/draft-plan.tsv unless --dry-run. JSON mode
prints only the summary object. Exit 0 when planning/apply succeeds, 1 if any
candidate is blocked or an apply/probe fails, 2 for invalid inputs.
Side effects: default writes only the plan under WORK. --apply-seeded invokes
rule-scaffold.py and rule-draft.py for SEEDED-REVIEW rows. It has no network and
never edits semantic-only, duplicate, already-existing, or unseeded proposals.
Limits: fixture separation is not semantic correctness or shipping approval.
Extend: add routing states in assess(); keep subprocess output captured/bounded.
"""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAFFOLD = ROOT / "tools" / "rule-scaffold.py"
DRAFT = ROOT / "tools" / "rule-draft.py"
PLAN_FIELDS = ("id", "classification", "duplicate", "action", "detail")


class BatchError(ValueError):
    """The batch cannot be assessed safely from its persisted artifacts."""


def read_jsonl(path: Path) -> list[dict]:
    """Read a bounded pipeline artifact or fail with one diagnostic."""
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BatchError(f"cannot read {path}: {error}") from error


def proposal_digest(proposal: dict) -> str:
    """Match the canonical digest emitted by the complete-index dedupe stage."""
    encoded = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_dedupe_rows(path: Path) -> list[dict[str, str]]:
    """Read complete required TSV cells before interpreting the ledger."""
    try:
        with path.open(encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source, delimiter="\t")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise BatchError(f"cannot read {path}: {error}") from error
    required = {"proposal", "proposal_digest", "flag"}
    if not reader.fieldnames or not required <= set(reader.fieldnames):
        raise BatchError(f"invalid dedupe table {path}")
    if any(any(not isinstance(row.get(field), str) for field in required) for row in rows):
        raise BatchError(f"dedupe table {path} has a truncated required field")
    return rows


def duplicate_ids(path: Path, expected: dict[str, str]) -> set[str]:
    """Return flagged IDs only when the dedupe ledger exactly covers proposals."""
    rows = read_dedupe_rows(path)
    ledger_ids = [row.get("proposal") for row in rows]
    if any(not isinstance(rule_id, str) or not rule_id for rule_id in ledger_ids):
        raise BatchError(f"dedupe table {path} has an empty proposal id")
    if len(set(ledger_ids)) != len(ledger_ids):
        raise BatchError(f"dedupe table {path} has duplicate proposal ids")
    if set(ledger_ids) != set(expected):
        raise BatchError(f"dedupe table {path} does not exactly cover current proposals")
    for row in rows:
        if row.get("proposal_digest") != expected[row["proposal"]]:
            raise BatchError(f"dedupe table {path} is stale for {row['proposal']!r}")
    return {row["proposal"] for row in rows if row["flag"]}


def proposal_ids(proposals: list[dict]) -> dict[str, str]:
    """Validate enough proposal identity to reconcile downstream artifacts."""
    ids = []
    for proposal in proposals:
        if not isinstance(proposal, dict) or not isinstance(proposal.get("id"), str):
            raise BatchError("proposal needs a string id")
        ids.append(proposal["id"])
    if any(not rule_id for rule_id in ids) or len(set(ids)) != len(ids):
        raise BatchError("proposal ids must be nonempty and unique")
    return {proposal["id"]: proposal_digest(proposal) for proposal in proposals}


def run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run one repository tool with captured output and a hard timeout."""
    try:
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise BatchError(f"cannot run {Path(command[1]).name}: {error}") from error


def seed_status(proposal: Path, rule_id: str, category: str) -> tuple[str, str]:
    """Dry-run one seed and reduce its output to a review route."""
    if any(path.stem == rule_id for path in (ROOT / "rules").rglob("*.yml")):
        return "EXISTING-REVIEW", "rule id already exists"
    command = [sys.executable, str(SCAFFOLD), "--proposal", str(proposal), "--id", rule_id,
               "--category", category, "--seed", "--contrast", "--assess-seed"]
    try:
        result = run(command)
    except BatchError as error:
        return "BLOCKED", str(error)[:200]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:]
        message = detail[0][:200] if detail else "scaffold returned no diagnostic"
        return "BLOCKED", message
    first = result.stdout.splitlines()[:1]
    if first and first[0].startswith("SEED PASS fixture oracle;"):
        return "SEEDED-REVIEW", "fixture oracle passed; AI reviews claim and generality"
    if first and first[0].startswith("SEED NONE;"):
        return "AI-DRAFT", "no safe seed; AI authors matcher from bounded contrast"
    return "BLOCKED", "scaffold omitted seed verdict"


def assess(proposals: list[dict], duplicates: set[str], proposal_path: Path,
           category: str) -> list[dict[str, str]]:
    """Route each proposal without allowing semantic rows into generation."""
    rows = []
    seen = set()
    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise BatchError("proposal must be an object")
        rule_id = proposal.get("id")
        classification = proposal.get("classification")
        if not isinstance(rule_id, str) or not isinstance(classification, str):
            raise BatchError("proposal needs string id and classification")
        if rule_id in seen:
            raise BatchError(f"duplicate proposal id {rule_id!r}")
        seen.add(rule_id)
        duplicate = "yes" if rule_id in duplicates else "no"
        if duplicate == "yes":
            action, detail = "DUP-REVIEW", "dedupe flagged prior coverage"
        elif classification != "syntactic":
            action, detail = "SEMANTIC-REVIEW", f"{classification} needs rejection/ship judgment"
        else:
            action, detail = seed_status(proposal_path, rule_id, category)
        rows.append({"id": rule_id, "classification": classification,
                     "duplicate": duplicate, "action": action, "detail": detail})
    return rows


def write_plan(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=path.parent, prefix=f".{path.name}.",
                                         delete=False) as output:
            temporary = Path(output.name)
            writer = csv.DictWriter(output, fieldnames=PLAN_FIELDS, delimiter="\t",
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def probe_passed(work: Path, rule_id: str, probe: subprocess.CompletedProcess[str]) -> bool:
    """Require both the bounded CLI verdict and its persisted terminal state."""
    first = probe.stdout.splitlines()[:1]
    if probe.returncode != 0 or not first or f"{rule_id}: PASS " not in first[0]:
        return False
    try:
        state = json.loads((work / "draft" / f"{rule_id}.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(state, dict):
        return False
    attempts = state.get("attempts")
    return state.get("rule") == rule_id and state.get("status") == "PASS" \
        and isinstance(attempts, list) and bool(attempts)


def apply_seeded(rows: list[dict[str, str]], proposal_path: Path, work: Path,
                 category: str) -> int:
    """Generate and probe only rows that already passed the dry-run oracle."""
    failures = 0
    for row in rows:
        if row["action"] != "SEEDED-REVIEW":
            continue
        try:
            scaffold = run([sys.executable, str(SCAFFOLD), "--proposal", str(proposal_path),
                            "--id", row["id"], "--category", category,
                            "--seed", "--contrast"])
        except BatchError as error:
            row["action"] = "APPLY-FAILED"
            row["detail"] = str(error)[:200]
            failures += 1
            continue
        if scaffold.returncode != 0:
            row["action"] = "APPLY-FAILED"
            row["detail"] = (scaffold.stderr or scaffold.stdout).strip()[-200:]
            failures += 1
            continue
        try:
            probe = run([sys.executable, str(DRAFT), row["id"], "--work", str(work)])
        except BatchError as error:
            row["action"] = "PROBE-FAILED"
            row["detail"] = str(error)[:200]
            failures += 1
            continue
        if not probe_passed(work, row["id"], probe):
            row["action"] = "PROBE-FAILED"
            detail = (probe.stderr or probe.stdout).strip()[-160:]
            row["detail"] = "scaffolded pair and rule count retained; " + (
                f"probe/state mismatch: {detail}" if detail
                else "probe/state mismatch without diagnostic")
            failures += 1
        else:
            row["action"] = "SEEDED-PASS"
            row["detail"] = "generated pair passed probe; AI review still required"
    return failures


def main() -> int:
    """Run the plan/apply CLI and emit one bounded status record."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--category", required=True, choices=("security", "correctness"))
    parser.add_argument("--apply-seeded", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.apply_seeded and args.dry_run:
        parser.error("--apply-seeded and --dry-run are mutually exclusive")
    args.work = args.work.resolve()
    proposal_path = args.work / "cluster" / "proposals.jsonl"
    try:
        proposals = read_jsonl(proposal_path)
        rows = assess(proposals, duplicate_ids(args.work / "dedupe.tsv",
                                               proposal_ids(proposals)), proposal_path,
                      args.category)
        failures = apply_seeded(rows, proposal_path, args.work, args.category) \
            if args.apply_seeded else 0
        if not args.dry_run:
            write_plan(args.work / "draft-plan.tsv", rows)
    except (BatchError, OSError, UnicodeError) as error:
        print(f"rule-batch: ERROR: {error}", file=sys.stderr)
        return 2
    counts = Counter(row["action"] for row in rows)
    summary = {"proposals": len(rows), "actions": dict(sorted(counts.items())),
               "failures": failures}
    if args.json:
        print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
    else:
        actions = " ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        print(f"draft-plan: proposals={len(rows)} {actions}; failures={failures}")
    return 1 if failures or counts.get("BLOCKED", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
