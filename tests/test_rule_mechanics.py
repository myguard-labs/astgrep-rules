"""Contracts for canonical plans and mechanical validation helpers."""

import contextlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLAN = load_tool("rule-plan")
MECHANICS = load_tool("rule-mechanics")
CHANGED = load_tool("test-changed")


def minimal_plan(**updates):
    plan = {
        "version": 1,
        "id": "py-sample",
        "language": "python",
        "category": "security",
        "message": "sample message",
        "note": "sample note",
        "rule": {"pattern": "danger()"},
        "cases": {"invalid": ["danger()"], "valid": ["safe()"]},
    }
    plan.update(updates)
    return plan


class RulePlanTests(unittest.TestCase):
    def test_repository_plan_compiles_and_passes_preflight(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        plan, matcher, rule, fixture = PLAN.compile_plan(path)
        self.assertEqual(plan["id"], "py-tempfile-mktemp")
        self.assertEqual(yaml.safe_load(rule)["rule"], matcher)
        self.assertEqual(yaml.safe_load(fixture)["id"], plan["id"])

    def test_closed_schema_rejects_unknown_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.yml"
            path.write_text(yaml.safe_dump({**minimal_plan(), "surprise": True}))
            with self.assertRaisesRegex(ValueError, "unknown keys: surprise"):
                PLAN.load_plan(path)

    def test_utility_graph_rejects_undefined_cycle_and_unreachable(self):
        cases = [
            ({"rule": {"matches": "missing"}}, "undefined local utilities"),
            ({"rule": {"matches": "a"}, "utils": {
                "a": {"matches": "b"}, "b": {"matches": "a"}}}, "cycle"),
            ({"utils": {"unused": {"pattern": "safe()"}}}, "unreachable"),
        ]
        for update, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                PLAN.validate_plan(minimal_plan(**update))

    def test_constraint_referenced_utility_is_reachable(self):
        plan = minimal_plan(
            rule={"pattern": "danger($ARG)"},
            constraints={"ARG": {"matches": "safe-arg"}},
            utils={"safe-arg": {"kind": "identifier"}},
        )
        matcher, _cases = PLAN.validate_plan(plan)
        self.assertEqual(matcher, plan["rule"])

    def test_surviving_weakening_is_rejected(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "MUTATION_SURVIVED"):
            PLAN.preflight(plan, matcher, cases)

    def test_two_named_branches_reach_both_witness_preflights(self):
        plan = minimal_plan(
            rule=None,
            match={
                "target": {"kind": "call"},
                "any": [
                    {"name": "first", "rule": {"pattern": "first()"},
                     "witness": "first()"},
                    {"name": "second", "rule": {"pattern": "second()"},
                     "witness": "second()"},
                ],
            },
            mutation_limit=0,
            cases={"invalid": ["first()", "second()"], "valid": ["safe()"]},
        )
        del plan["rule"]
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "run_preflight",
                          side_effect=[(True, "ok"), (False, "test-failure"),
                                       (False, "test-failure")]) as preflight:
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(preflight.call_count, 3)

    def test_fixer_requires_fixed_oracle_on_invalid_source(self):
        plan = minimal_plan(
            fix="safe()",
            oracles={"safe()": {"fixed": "safe()"}},
        )
        with self.assertRaisesRegex(ValueError, "fixed output for an invalid source"):
            PLAN.validate_plan(plan)


class RuleMechanicsTests(unittest.TestCase):
    def test_oracle_mismatch_fails_exactly(self):
        plan = minimal_plan(oracles={"danger()": {"count": 2}})
        finding = {"text": "danger()", "range": {"byteOffset": {"start": 0, "end": 8}}}
        with patch.object(MECHANICS, "scan_rule", return_value=[finding]), \
                self.assertRaisesRegex(RuntimeError, "ORACLE_MISMATCH.*count"):
            MECHANICS.check_oracles(plan, {})

    def test_atomic_write_preserves_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.yml"
            path.write_text("old\n")
            path.chmod(0o640)
            MECHANICS.write_atomic(path, "new\n")
            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_regeneration_refuses_unowned_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plans/python/security/py-sample.yml"
            rule_path = root / "rules/python/security/py-sample.yml"
            fixture_path = root / "tests/python/security/py-sample.yml"
            for path in (plan_path, rule_path, fixture_path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("hand authored\n")
            generated = "# Generated from: plans/python/security/py-sample.yml\nid: py-sample\n"
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"), \
                    patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "plan_paths", return_value=[plan_path]), \
                    patch.object(MECHANICS, "compile_plan",
                                 return_value=(rule_path, fixture_path, generated, generated)):
                MECHANICS.plans_command(True)

    def test_fix_output_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "fix.yml"
            rule.write_text(yaml.safe_dump({
                "id": "cpp-fix", "language": "cpp", "fix": "safe()",
                "rule": {"pattern": "danger()"},
            }))

            def run(command, **_kwargs):
                if "--update-all" in command:
                    target = Path(command[-1])
                    before = target.read_text(encoding="utf-8")
                    target.write_text("safe()" if before == "danger()" else before,
                                      encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with self.assertRaisesRegex(RuntimeError, "FIX_OUTPUT_MISMATCH"), \
                    patch.object(MECHANICS.subprocess, "run", side_effect=run), \
                    patch.object(MECHANICS, "scan_rule", return_value=[]):
                MECHANICS.validate_fix(rule, "danger()", "different()")

    def test_fixer_command_checks_every_invalid_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "rules/cpp/security/cpp-fix.yml"
            fixture = root / "tests/cpp/security/cpp-fix.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text(yaml.safe_dump({
                "id": "cpp-fix", "language": "cpp", "fix": "safe()",
                "rule": {"pattern": "danger()"},
            }))
            fixture.write_text(yaml.safe_dump({
                "id": "cpp-fix", "valid": ["safe()"],
                "invalid": ["danger()", "danger();"],
            }))
            with patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "validate_fix") as validate:
                self.assertEqual(MECHANICS.fixes_command("cpp-fix"), 0)
            self.assertEqual([call.args[1] for call in validate.call_args_list],
                             ["danger()", "danger();"])

    def test_differential_is_duplicate_sensitive_and_stable(self):
        finding = ("rule", "x.py", 0, 1, "x", "message", "warning")
        with tempfile.TemporaryDirectory() as directory:
            old, new = Path(directory) / "old", Path(directory) / "new"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            output = io.StringIO()
            with patch.object(MECHANICS, "normalized_findings",
                              side_effect=[[finding, finding], [finding]]), \
                    contextlib.redirect_stdout(output):
                status = MECHANICS.differential_command(old, new, Path("config"), Path("corpus"))
            report = json.loads(output.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(report["removed"][0]["count"], 1)

    def test_corpus_file_bound_fails_before_engine_run(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "a.py").write_text("x")
            with patch.object(MECHANICS, "MAX_FILES", 0), \
                    patch.object(MECHANICS.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "corpus exceeds 0 files"):
                    MECHANICS.normalized_findings(Path("engine"), Path("config"), Path(directory))
                run.assert_not_called()


class ChangedGateTests(unittest.TestCase):
    def test_rule_ids_include_plans_fixtures_rules_and_snapshots(self):
        paths = [
            "plans/python/security/py-one.yml",
            "rules/go/correctness/go-two.yml",
            "tests/php/security/php-three.yml",
            "tests/__snapshots__/py-four-snapshot.yml",
        ]
        self.assertEqual(CHANGED.rule_ids(paths), ["go-two", "php-three", "py-four", "py-one"])

    def test_infrastructure_changes_escalate_but_rule_changes_do_not(self):
        self.assertTrue(CHANGED.requires_full_suite(["tools/rule-plan.py"]))
        self.assertTrue(CHANGED.requires_full_suite(["tests/test_inventory.py"]))
        self.assertFalse(CHANGED.requires_full_suite(["rules/python/security/py-one.yml"]))

    def test_change_discovery_includes_deletions(self):
        result = SimpleNamespace(returncode=0, stdout="tests/test_removed.py\n", stderr="")
        with patch.object(CHANGED.subprocess, "run", return_value=result) as run:
            self.assertEqual(CHANGED.changed_paths("origin/main"), ["tests/test_removed.py"])
        self.assertIn("--diff-filter=ACMRD", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
