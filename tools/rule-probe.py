#!/usr/bin/env python3
"""rule-probe.py -- verify one rule in isolation, with the same gates as the suite.

Why: `npm test` runs every rule and every matcher-arm mutation (~40 s) and its
output is unbounded. A rule being drafted needs a per-rule verdict in seconds,
in a shape a cheap model or a grind loop can act on without reading logs. This
replicates the suite's per-rule contracts -- fixture layout, fixture run,
exact JSON finding counts per fixture, every `any` arm killed by a fixture,
literal diagnostics, and real-file discovery -- and prints one bounded report.
Passing here is necessary, not sufficient: the full suite still runs before
commit. Pipeline: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  rule-probe.py <rule-id>            # report + exit 0/1
  rule-probe.py <rule-id> --json     # machine-readable
  rule-probe.py <rule-id> --sexp     # also dump --debug-query=sexp of each pattern
  rule-probe.py <rule-id> --snapshot # write/refresh this rule's snapshot only,
                                     # then print it for inspection

Inputs:  rules/<lang>/<cat>/<id>.yml, tests/<lang>/<cat>/<id>.yml, optional
         tests/__snapshots__/<id>-snapshot.yml, node_modules/.bin/ast-grep.
Outputs: report on stdout; exit 0 only when every check passed.
Side effects: none, except --snapshot writes tests/__snapshots__/<id>-snapshot.yml
         (scoped with --filter so no other rule's snapshot is touched).
Limits:  arm survivors are reported, not fixed; a survivor needs either a new
         fixture or a witness in tests/arm_coverage.json (see docs/authoring.md).
         Discovery uses one file extension per language (EXTENSIONS).
Extend:  CHECKS order in main(); EXTENSIONS.
"""

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"
EXTENSIONS = {"go": "go", "c": "c", "php": "php", "python": "py", "javascript": "js",
              "java": "java", "lua": "lua", "bash": "sh"}
META = re.compile(r"\$\$?\$?[A-Z_][A-Z0-9_]*")


def find_rule(rule_id: str) -> tuple[Path, Path]:
    hits = [p for p in (ROOT / "rules").rglob("*.yml") if p.stem == rule_id]
    if len(hits) != 1:
        sys.exit(f"expected exactly one rule file for {rule_id!r}, found {len(hits)}")
    rule = hits[0]
    fixture = ROOT / "tests" / rule.relative_to(ROOT / "rules")
    return rule, fixture


def any_arms(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "any" and isinstance(value, list) and len(value) > 1:
                for index in range(len(value)):
                    yield path + (key,), index
            yield from any_arms(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from any_arms(value, path + (index,))


def delete_arm(rule, path, index):
    mutant = copy.deepcopy(rule)
    node = mutant["rule"]
    for component in path:
        node = node[component]
    del node[index]
    return mutant


def scan_stdin(rule: dict, source: str) -> tuple[int | None, str]:
    r = subprocess.run([AST_GREP, "scan", "--inline-rules", yaml.safe_dump(rule),
                        "--stdin", "--json=compact"],
                       input=source, text=True, capture_output=True, timeout=15, check=False)
    try:
        findings = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return None, r.stderr.strip()[:300]
    if any(f["ruleId"] != rule["id"] for f in findings):
        return None, "findings for another rule id"
    return len(findings), ""


class Isolated:
    """A throwaway sgconfig with exactly one rule, fixture and optional snapshot."""

    def __init__(self, rule_path: Path, fixture_path: Path):
        self.tmp = tempfile.TemporaryDirectory(prefix="rule-probe-", dir=ROOT)
        d = Path(self.tmp.name)
        (d / "rules").mkdir()
        (d / "tests" / "__snapshots__").mkdir(parents=True)
        self.rule = d / "rules" / rule_path.name
        self.rule.write_bytes(rule_path.read_bytes())
        (d / "tests" / rule_path.name).write_bytes(fixture_path.read_bytes())
        snap = ROOT / "tests" / "__snapshots__" / f"{rule_path.stem}-snapshot.yml"
        self.has_snapshot = snap.exists()
        if self.has_snapshot:
            (d / "tests" / "__snapshots__" / snap.name).write_bytes(snap.read_bytes())
        self.config = d / "sgconfig.yml"
        self.config.write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")

    def test(self, rule: dict | None = None) -> tuple[int, str]:
        if rule is not None:
            self.rule.write_text(yaml.safe_dump(rule))
        cmd: list[str] = [str(AST_GREP), "test", "-c", str(self.config)]
        if not self.has_snapshot:
            cmd.append("--skip-snapshot-tests")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        return r.returncode, r.stdout + r.stderr

    def close(self):
        self.tmp.cleanup()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    ap.add_argument("rule_id")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sexp", action="store_true")
    ap.add_argument("--snapshot", action="store_true")
    args = ap.parse_args()

    rule_path, fixture_path = find_rule(args.rule_id)
    report: dict = {"rule": str(rule_path.relative_to(ROOT)), "checks": []}
    ok = True

    def check(name: str, passed: bool, detail: str = ""):
        nonlocal ok
        ok &= passed
        report["checks"].append({"name": name, "ok": passed, "detail": detail})

    # 1. layout and parseability -- the inventory test's contract
    rule = yaml.safe_load(rule_path.read_text())
    parts = rule_path.relative_to(ROOT / "rules").parts
    check("layout", len(parts) == 3 and parts[0] == rule.get("language")
          and rule_path.stem == rule.get("id"),
          f"rules/<language>/<category>/<id>.yml with matching id/language; got {parts}")
    check("fixture-exists", fixture_path.is_file(), str(fixture_path.relative_to(ROOT)))
    if not fixture_path.is_file():
        return finish(report, ok, args.json)
    fixture = yaml.safe_load(fixture_path.read_text())
    valid, invalid = fixture.get("valid") or [], fixture.get("invalid") or []
    check("fixture-shape", bool(fixture.get("id") == rule["id"] and valid and invalid
                                and all(isinstance(s, str) and s.strip() for s in valid + invalid)
                                and not set(valid) & set(invalid)),
          f"{len(valid)} valid, {len(invalid)} invalid, no overlap")
    check("matcher-is-mapping", isinstance(rule.get("rule"), dict),
          "the `rule:` body must be a mapping (scaffold TODO placeholder is not)")
    if not isinstance(rule.get("rule"), dict):
        return finish(report, ok, args.json)

    # 2. literal diagnostics -- test_diagnostics compares emitted text to the YAML
    for field in ("message", "note"):
        text = rule.get(field) or ""
        check(f"{field}-literal", bool(text) and not META.search(text),
              "present and no $METAVAR interpolation (snapshots do not store it)")
    check("severity", rule.get("severity") in ("error", "warning", "info"),
          str(rule.get("severity")))

    # 3. exact counts per fixture -- what the snapshot runner cannot assert
    counts = []
    for kind, sources, want in (("invalid", invalid, lambda n: n >= 1),
                                ("valid", valid, lambda n: n == 0)):
        for i, src in enumerate(sources):
            n, err = scan_stdin(rule, src)
            good = n is not None and want(n)
            counts.append(f"{kind}[{i}]={'ERR ' + err if n is None else n}")
            ok &= good
    check("fixture-counts", all(not c.endswith("ERR") for c in counts)
          and ok, "; ".join(counts))
    multi = [c for c in counts if c.startswith("invalid") and c.split("=")[1] not in ("1", "0")]
    if multi:
        report["checks"].append({"name": "multi-match-note", "ok": True,
                                 "detail": "invalid fixtures with >1 finding: " + ", ".join(multi)
                                 + " -- the snapshot keeps only the first; assert counts if they matter"})

    # 4. isolated fixture run, then arm kills -- test_arm_coverage's contract
    iso = Isolated(rule_path, fixture_path)
    try:
        rc, out = iso.test()
        check("fixture-run", rc == 0 and "1 passed; 0 failed" in out,
              ("snapshot present" if iso.has_snapshot else "no snapshot: --skip-snapshot-tests")
              + ("" if rc == 0 else " :: " + out.strip().splitlines()[-1][:200]))
        arms = list(any_arms(rule["rule"]))
        survivors, invalid_mutants = [], []
        for path, index in arms:
            mutant = delete_arm(rule, path, index)
            rc, out = iso.test(mutant)
            ident = f"{'/'.join(map(str, path))}[{index}]"
            if "Cannot parse rule" in out:
                invalid_mutants.append(ident)
            elif rc == 0:
                survivors.append(ident)
        check("arm-kills", not survivors,
              f"{len(arms)} arms; survivors: {survivors or 'none'}"
              + (f"; unparsable mutants (not kills): {invalid_mutants}" if invalid_mutants else "")
              + ("; a survivor needs a distinguishing fixture or an arm_coverage.json witness"
                 if survivors else ""))
    finally:
        iso.close()

    # 5. discovery through a real file and config, not a string fixture
    ext = EXTENSIONS.get(rule["language"])
    with tempfile.TemporaryDirectory(prefix="rule-probe-disc-", dir=ROOT) as name:
        d = Path(name)
        (d / "rules").mkdir()
        (d / "rules" / rule_path.name).write_bytes(rule_path.read_bytes())
        (d / "sgconfig.yml").write_text("ruleDirs: [rules]\n")
        target = d / f"positive.{ext}"
        target.write_text(invalid[0])
        r = subprocess.run([AST_GREP, "scan", "-c", d / "sgconfig.yml", "--json=compact", target],
                           capture_output=True, text=True, timeout=15, check=False)
        try:
            found = len(json.loads(r.stdout or "[]"))
        except json.JSONDecodeError:
            found = -1
        check("discovery", found >= 1, f"positive.{ext} via ruleDirs config: {found} finding(s)")

    # 6. optional pattern S-expressions for the author's eyes
    if args.sexp:
        pats: list[str] = []

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "pattern" and isinstance(v, str):
                        pats.append(v)
                    elif k == "pattern" and isinstance(v, dict) and "context" in v:
                        pats.append(v["context"])
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(rule.get("rule"))
        walk(rule.get("utils"))
        for pat in pats[:6]:
            # An empty stdin prints nothing; any one-byte source makes the
            # pattern's own S-expression appear. ERROR/MISSING nodes are normal
            # for fragments; the thing to read is the root node *kind* -- a
            # call that parses as a type conversion or a declaration is the
            # documented single-argument trap.
            r = subprocess.run([AST_GREP, "run", "-l", rule["language"], "-p", pat,
                                "--debug-query=sexp", "--stdin"], input="x", text=True,
                               capture_output=True, timeout=15, check=False)
            lines = [ln for ln in (r.stderr + r.stdout).splitlines()
                     if ln and not ln.startswith("[warn]") and "postinstall" not in ln]
            report.setdefault("sexp", []).append({"pattern": pat,
                                                  "sexp": "\n".join(lines)[:600]})

    # 7. optional scoped snapshot write
    if args.snapshot:
        r = subprocess.run([AST_GREP, "test", "-c", ROOT / "sgconfig.yml",
                            "--filter", f"^{re.escape(rule['id'])}$", "-U"],
                           capture_output=True, text=True, timeout=60, check=False, cwd=ROOT)
        snap = ROOT / "tests" / "__snapshots__" / f"{rule['id']}-snapshot.yml"
        report["snapshot"] = snap.read_text() if snap.exists() else f"not written: {r.stderr[-300:]}"

    return finish(report, ok, args.json)


def finish(report: dict, ok: bool, as_json: bool) -> int:
    report["ok"] = ok
    if as_json:
        print(json.dumps(report, indent=1))
    else:
        print(f"{report['rule']}: {'PASS' if ok else 'FAIL'}")
        for c in report["checks"]:
            print(f"  [{'ok' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")
        for s in report.get("sexp", []):
            print(f"  sexp {s['pattern']!r}:\n    " + s["sexp"].replace("\n", "\n    "))
        if "snapshot" in report:
            print("  snapshot:\n    " + report["snapshot"].replace("\n", "\n    "))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
