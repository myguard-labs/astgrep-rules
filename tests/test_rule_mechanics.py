"""Contracts for canonical plans and mechanical validation helpers."""

import contextlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
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
PROBE = load_tool("rule-probe")


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
    def test_plan_and_probe_cover_every_native_rule_language(self):
        configured = {
            path.name for path in (ROOT / "rules").iterdir()
            if path.is_dir() and path.name != "powershell"
        }
        self.assertEqual(set(PLAN.LANGUAGE_EXTENSIONS), configured)
        self.assertEqual(PROBE.EXTENSIONS, PLAN.LANGUAGE_EXTENSIONS)

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

    def test_plan_id_is_safe_for_preflight_paths(self):
        for rule_id in ("../outside", "/outside", "py/sample", "UPPER"):
            with self.subTest(rule_id=rule_id), \
                    self.assertRaisesRegex(ValueError, "plan id must start"):
                PLAN.validate_plan(minimal_plan(id=rule_id))
        matcher, _cases = PLAN.validate_plan(
            minimal_plan(id="avoid_app_run_with_bad_host-python")
        )
        self.assertEqual(matcher, {"pattern": "danger()"})

    def test_provenance_comments_and_extensions_render_without_overrides(self):
        plan = minimal_plan(
            comments=["License: Example", "Source: https://example.test/rule"],
            extensions={"upstream-pack": True},
        )
        matcher, _cases = PLAN.validate_plan(plan)
        rendered = PLAN.render_rule(plan, matcher)
        self.assertTrue(rendered.startswith(
            "# License: Example\n# Source: https://example.test/rule\n"))
        self.assertTrue(yaml.safe_load(rendered)["upstream-pack"])
        with self.assertRaisesRegex(ValueError, "non-reserved"):
            PLAN.validate_plan(minimal_plan(extensions={"rule": {"pattern": "safe()"}}))
        with self.assertRaisesRegex(ValueError, "single-line"):
            PLAN.validate_plan(minimal_plan(comments=["trusted\rinjected: true"]))

    def test_mutation_limit_cannot_disable_or_truncate_mutations(self):
        with self.assertRaisesRegex(ValueError, "from 1"):
            PLAN.validate_plan(minimal_plan(mutation_limit=0))
        plan = minimal_plan(mutation_limit=1)
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "compiled_mutations",
                          return_value=[("one", "rule"), ("two", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "MUTATION_BUDGET_EXCEEDED"):
            PLAN.preflight(plan, matcher, cases)

    def test_mutation_exclusions_must_exist_and_survive(self):
        matcher, cases = PLAN.validate_plan(minimal_plan())
        unknown = minimal_plan(mutation_exclusions={"missing": "reason"})
        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "UNKNOWN_MUTATION_EXCLUSION"):
            PLAN.preflight(unknown, matcher, cases)
        killed = minimal_plan(mutation_exclusions={"one": "reason"})
        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch",
                             return_value={"one": ("killed", "test-failure")}), \
                self.assertRaisesRegex(RuntimeError, "INVALID_MUTATION_EXCLUSION"):
            PLAN.preflight(killed, matcher, cases)

    def test_mutation_limit_counts_required_mutants_not_exclusions(self):
        plan = minimal_plan(
            mutation_limit=1,
            mutation_exclusions={"excluded-one": "redundant", "excluded-two": "redundant"},
        )
        matcher, cases = PLAN.validate_plan(plan)
        candidates = [("required", "rule"), ("excluded-one", "rule"),
                      ("excluded-two", "rule")]
        outcomes = {
            "required": ("killed", "test-failure"),
            "excluded-one": ("survived", "ok"),
            "excluded-two": ("survived", "ok"),
        }
        with patch.object(PLAN, "compiled_mutations", return_value=candidates), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch", return_value=outcomes) as batch:
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(batch.call_args.args[0], candidates)

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

    def test_qualified_call_patterns_mutate_receiver_and_member(self):
        mutations = dict(PLAN.mutation_candidates(
            {"pattern": "tempfile.mktemp($$$ARGS)"}))
        self.assertEqual(
            set(mutations),
            {"rule.pattern-receiver", "rule.pattern-member"},
        )
        self.assertEqual(mutations["rule.pattern-receiver"]["pattern"],
                         "$_.mktemp($$$ARGS)")

    def test_regex_alternatives_are_independently_mutated(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "^open$|^read$|^write$"}))
        self.assertEqual(
            mutations["rule.regex-alternative[1]-deleted"]["regex"],
            "^open$|^write$",
        )

    def test_regex_split_ignores_escaped_group_and_class_bars(self):
        self.assertEqual(PLAN._regex_alternatives(r"^(a|b)[|]c\|d$|^e$"),
                         [r"^(a|b)[|]c\|d$", "^e$"])

    def test_grouped_regex_alternatives_preserve_anchors_and_wrapper(self):
        cases = {
            "^(?:open|read|write)$": ("^(?:read|write)$", 3),
            "^(?i:open|read)+$": ("^(?i:read)+$", 2),
            "(open|read){2}": ("(read){2}", 2),
            "(open|read){2,4}?": ("(read){2,4}?", 2),
            "(?x:open # ignored | bar\n|read)": ("(?x:read)", 2),
        }
        for pattern, (expected, expected_count) in cases.items():
            with self.subTest(pattern=pattern):
                mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
                self.assertEqual(
                    mutations["rule.regex-alternative[0]-deleted"]["regex"], expected)
                alternative_keys = [key for key in mutations if "regex-alternative" in key]
                self.assertEqual(len(alternative_keys), expected_count)

    def test_grouped_regex_mutants_are_engine_valid_with_exact_text(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "^(?:open|read|write)$"}))
        rows = (("^(?:read|write)$", "read"), ("^(?:open|write)$", "open"),
                ("^(?:open|read)$", "open"))
        for index, (expected, witness) in enumerate(rows):
            regex = mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"]
            self.assertEqual(regex, expected)
            rule = yaml.safe_dump({
                "id": f"regex-{index}", "language": "python", "message": "x",
                "severity": "warning", "rule": {"kind": "identifier", "regex": regex},
            })
            passed, detail = PLAN.run_preflight(
                rule, {"invalid": [witness], "valid": ["closed"]}, f"regex-{index}")
            self.assertTrue(passed, detail)

    def test_claim_matrix_requires_each_pairwise_combination(self):
        plan = minimal_plan(
            cases={"invalid": ["a()", "b()"], "valid": ["safe()"]},
            claims={
                "api": {"a": ["a()"], "b": ["b()"]},
                "operator": {"call": ["a()", "b()"]},
            },
        )
        PLAN.validate_plan(plan)
        plan["claims"]["operator"]["call"] = ["a()"]
        with self.assertRaisesRegex(ValueError, "CLAIM_PAIR_UNCOVERED.*api.b"):
            PLAN.validate_plan(plan)

    def test_claim_matrix_rejects_semantic_dimensions_and_valid_witnesses(self):
        with self.assertRaisesRegex(ValueError, "syntax-only"):
            PLAN.validate_plan(minimal_plan(claims={"runtime-type": {"file": ["danger()"]}}))
        with self.assertRaisesRegex(ValueError, "non-invalid witnesses"):
            PLAN.validate_plan(minimal_plan(claims={"api": {"safe": ["safe()"]}}))
        with self.assertRaisesRegex(ValueError, "dimension names must be strings"):
            PLAN.validate_plan(minimal_plan(claims={1: {"api": ["danger()"]}}))

    def test_declared_metamorphic_cases_preserve_or_change_outcome(self):
        plan = minimal_plan(metamorphic=[
            {"source": "danger()", "transform": "callee-parenthesized",
             "outcome": "equivalent"},
            {"source": "safe()", "transform": "parenthesized", "outcome": "different"},
        ])
        matcher, cases = PLAN.validate_plan(plan)
        self.assertEqual(matcher, {"pattern": "danger()"})
        expanded = PLAN.expanded_cases(plan, cases)
        self.assertIn("(danger)()", expanded["invalid"])
        self.assertIn("(safe())", expanded["invalid"])

    def test_metamorphic_rejects_unknown_or_inapplicable_transforms(self):
        with self.assertRaisesRegex(ValueError, "invalid metamorphic"):
            PLAN.validate_plan(minimal_plan(metamorphic=[
                {"source": "danger()", "transform": "rename-symbol",
                 "outcome": "equivalent"},
            ]))
        plan = minimal_plan(language="c", metamorphic=[
            {"source": "danger()", "transform": "format-width", "outcome": "equivalent"},
        ])
        _matcher, cases = PLAN.validate_plan(plan)
        with self.assertRaisesRegex(ValueError, "not applicable"):
            PLAN.expanded_cases(plan, cases)
        with self.assertRaisesRegex(ValueError, "must be strings"):
            PLAN.validate_plan(minimal_plan(metamorphic=[{
                "source": ["danger()"], "transform": "parenthesized",
                "outcome": "equivalent",
            }]))
        with self.assertRaisesRegex(ValueError, "does not support bash"):
            PLAN.validate_plan(minimal_plan(language="bash", metamorphic=[
                {"source": "danger()", "transform": "member-access-swap",
                 "outcome": "equivalent"},
            ]))

    def test_metamorphic_derives_required_syntax_families(self):
        cases = {
            ("obj->field", "member-access-swap"): "obj.field",
            ("ns::call()", "qualified-name"): "::ns::call()",
            ('log("value")', "literal-concatenation"): 'log("value" "")',
            ('log("%s", value)', "format-width"): 'log("%20s", value)',
            ('log("%s", value)', "format-precision"): 'log("%.3s", value)',
            ("danger()", "parenthesized"): "(danger())",
        }
        for (source, transform), expected in cases.items():
            with self.subTest(transform=transform):
                self.assertEqual(PLAN._metamorphic_source(source, transform), expected)

    def test_format_transforms_skip_escaped_percent_and_existing_fields(self):
        transformed = [
            ('log("%% literal: %s", value)', "format-width",
             'log("%% literal: %20s", value)'),
            ('log("%%%s", value)', "format-precision", 'log("%%%.3s", value)'),
        ]
        for source, transform, expected in transformed:
            with self.subTest(source=source, transform=transform):
                self.assertEqual(PLAN._metamorphic_source(source, transform), expected)
        unchanged = [("%20s", "format-width"), ("%*s", "format-width"),
                     ("%.2s", "format-precision"), ("%.*s", "format-precision"),
                     ("%%", "format-width")]
        for source, transform in unchanged:
            with self.subTest(source=source, transform=transform), \
                    self.assertRaisesRegex(ValueError, "not applicable"):
                PLAN._metamorphic_source(source, transform)

    def test_compiled_plan_ir_matches_compatibility_artifacts(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        ir = PLAN.compile_plan_ir(path, run_checks=False)
        legacy = PLAN.compile_plan(path, run_checks=False)
        self.assertEqual(legacy, (PLAN.thaw(ir.plan), PLAN.thaw(ir.matcher),
                                  ir.rule_text, ir.fixture_text))

    def test_compiled_plan_ir_is_recursively_immutable(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        ir = PLAN.compile_plan_ir(path, run_checks=False)
        with self.assertRaises(TypeError):
            ir.plan["cases"]["invalid"][0] = "changed()"
        with self.assertRaises(TypeError):
            ir.matcher["kind"] = "identifier"

    def test_compiled_plan_ir_freezes_yaml_sets_and_thaws_compatibly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.yml"
            path.write_text(yaml.safe_dump(minimal_plan(
                extensions={"tags": {"one", "two"}})), encoding="utf-8")
            ir = PLAN.compile_plan_ir(path, run_checks=False)
        self.assertIsInstance(ir.plan["extensions"]["tags"], frozenset)
        self.assertEqual(PLAN.thaw(ir.plan)["extensions"]["tags"], {"one", "two"})

    def test_relation_only_mutants_are_not_counted_as_kills(self):
        matcher = {"all": [{"kind": "call"}, {"not": {"has": {"kind": "string"}}}]}
        plan = minimal_plan(rule=matcher)
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("rule.all[0]-deleted", paths)

    def test_affirmative_relation_only_mutant_is_not_a_candidate(self):
        matcher = {"all": [{"kind": "call"}, {"has": {"kind": "identifier"}}]}
        plan = minimal_plan(rule=matcher)
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("rule.all[0]-deleted", paths)

    def test_constraint_any_arm_deletions_are_mutation_candidates(self):
        matcher = {"pattern": "danger($ARG)"}
        plan = minimal_plan(
            rule=matcher,
            constraints={"ARG": {"not": {"any": [
                {"kind": "string_literal"}, {"kind": "concatenated_string"},
            ]}}},
        )
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertEqual(paths, [
            "constraints.ARG-deleted",
            "constraints.ARG.not.any[0]-deleted",
            "constraints.ARG.not.any[1]-deleted",
        ])

    def test_referenced_utilities_are_not_whole_deletion_candidates(self):
        matcher = {"matches": "danger-call"}
        plan = minimal_plan(
            rule=matcher,
            utils={"danger-call": {"pattern": "danger()"}},
        )
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("utils.danger-call-deleted", paths)

    def test_preflight_calls_share_one_cumulative_deadline(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        deadlines = []

        def batch(_items, _cases, _rule_id, deadline, _telemetry):
            deadlines.append(deadline)
            return {"one": ("killed", "test-failure")}

        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "perf_counter", return_value=10.0), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")) as run, \
                patch.object(PLAN, "_run_mutant_batch", side_effect=batch):
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["deadline"], 10.0 + PLAN.MAX_PREFLIGHT_SECONDS)
        self.assertEqual(deadlines, [10.0 + PLAN.MAX_PREFLIGHT_SECONDS])

    def test_exhausted_preflight_budget_fails_before_engine_run(self):
        with patch.object(PLAN, "perf_counter", side_effect=[5.0, 6.0]), \
                patch.object(PLAN, "run_engine") as run:
            passed, detail = PLAN.run_preflight(
                "id: sample\n", {"invalid": ["x"], "valid": ["y"]}, "sample",
                deadline=5.5,
            )
        self.assertFalse(passed)
        self.assertEqual(detail, "engine-error=preflight budget exhausted")
        run.assert_not_called()

    def test_invalid_mutant_is_skipped(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch", return_value={
                    path: ("invalid", "bad rule")
                    for path, _rule in PLAN.compiled_mutations(plan, matcher)
                }):
            PLAN.preflight(plan, matcher, cases)

    def test_mutants_share_one_engine_process_with_per_mutant_outcomes(self):
        output = "PASS sample-mutant-0  ..\nFAIL sample-mutant-1  NM\nError: test failed."
        result = SimpleNamespace(returncode=4, stdout=output, stderr="")
        telemetry = PLAN.PhaseTelemetry()
        rules = [
            ("survivor", yaml.safe_dump({"id": "sample", "language": "python",
                                         "message": "x", "severity": "warning",
                                         "rule": {"pattern": "$_"}})),
            ("killed", yaml.safe_dump({"id": "sample", "language": "python",
                                       "message": "x", "severity": "warning",
                                       "rule": {"pattern": "danger()"}})),
        ]
        with patch.object(PLAN, "run_engine", return_value=result) as run:
            outcomes = PLAN._run_mutant_batch(
                rules, {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), telemetry)
        self.assertEqual(outcomes["survivor"][0], "survived")
        self.assertEqual(outcomes["killed"][0], "killed")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(telemetry.engine_processes, 1)

    def test_batch_runner_uses_one_process_for_two_valid_mutants(self):
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        rule = yaml.safe_dump({
            "id": "sample", "language": "python", "message": "x", "severity": "warning",
            "rule": {"pattern": "danger()"},
        })
        with patch.object(PLAN, "run_engine", return_value=result) as run:
            PLAN._run_mutant_batch(
                [("one", rule), ("two", rule)],
                {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), PLAN.PhaseTelemetry())
        self.assertEqual(run.call_count, 1)

    def test_unloadable_mutant_is_bisected_and_attributed(self):
        load_error = SimpleNamespace(
            returncode=2, stdout="", stderr="file is not a valid ast-grep rule")
        passed = SimpleNamespace(returncode=0, stdout="PASS sample-mutant-0 ..", stderr="")
        telemetry = PLAN.PhaseTelemetry()
        valid_rule = yaml.safe_dump({
            "id": "sample", "language": "python", "message": "x", "severity": "warning",
            "rule": {"pattern": "danger()"},
        })
        with patch.object(PLAN, "run_engine",
                          side_effect=[load_error, passed, load_error]):
            outcomes = PLAN._run_mutant_batch(
                [("valid", valid_rule), ("invalid", yaml.safe_dump({
                    "id": "sample", "language": "python", "message": "x",
                    "severity": "warning", "rule": {},
                }))],
                {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), telemetry)
        self.assertEqual(outcomes["valid"][0], "survived")
        self.assertEqual(outcomes["invalid"][0], "invalid")
        self.assertEqual(telemetry.engine_processes, 3)

    def test_telemetry_separates_deterministic_counts_from_wall_clock(self):
        telemetry = PLAN.PhaseTelemetry(engine_processes=2, mutants=9, wall_ms=37)
        report = telemetry.report()
        self.assertEqual(report["counts"]["engine_processes"], 2)
        self.assertEqual(report["counts"]["mutants"], 9)
        self.assertEqual(report["wall_clock_ms_informational"]["batched_engine"], 37)

    def test_metamorphic_parser_errors_fail_before_contrast_preflight(self):
        plan = minimal_plan(metamorphic=[
            {"source": "danger()", "transform": "parenthesized", "outcome": "equivalent"},
        ])
        matcher, cases = PLAN.validate_plan(plan)
        malformed = SimpleNamespace(returncode=0, stdout="(ERROR)", stderr="")
        with patch.object(PLAN, "run_engine", return_value=malformed), \
                patch.object(PLAN, "run_preflight") as contrast, \
                self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.preflight(plan, matcher, cases)
        contrast.assert_not_called()

    def test_metamorphic_parser_checks_actual_derived_cst(self):
        good = minimal_plan(metamorphic=[
            {"source": "danger()", "transform": "parenthesized", "outcome": "equivalent"},
        ])
        _matcher, good_cases = PLAN.validate_plan(good)
        PLAN.validate_derived_syntax(
            good, good_cases, float("inf"), PLAN.PhaseTelemetry())

        bad = minimal_plan(
            cases={"invalid": ["danger("], "valid": ["safe()"]},
            metamorphic=[
                {"source": "danger(", "transform": "parenthesized",
                 "outcome": "equivalent"},
            ],
        )
        _matcher, bad_cases = PLAN.validate_plan(bad)
        with self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.validate_derived_syntax(
                bad, bad_cases, float("inf"), PLAN.PhaseTelemetry())

    def test_literal_concatenation_is_limited_to_adjacent_literal_grammars(self):
        for language in ("javascript", "typescript", "java"):
            with self.subTest(language=language), \
                    self.assertRaisesRegex(ValueError, f"does not support {language}"):
                PLAN.validate_plan(minimal_plan(language=language, metamorphic=[{
                    "source": "danger()", "transform": "literal-concatenation",
                    "outcome": "equivalent",
                }]))

    def test_engine_timeout_terminates_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid = Path(directory) / "child.pid"
            ready = Path(directory) / "ready"
            child_program = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).write_text('ready', encoding='utf-8'); "
                "time.sleep(60)"
            )
            program = (
                "import pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child_program!r}], "
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                f"ready=pathlib.Path({str(ready)!r}); "
                "deadline=time.monotonic()+2; "
                "exec(\"while not ready.exists() and time.monotonic() < deadline:\\n"
                " time.sleep(0.01)\"); "
                f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8'); "
                "time.sleep(60)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                PLAN.run_engine([sys.executable, "-c", program], timeout=0.5)
            self.assertTrue(ready.is_file())
            pid = int(child_pid.read_text(encoding="utf-8"))
            status = Path(f"/proc/{pid}/status")
            for _attempt in range(100):
                if (not status.exists()
                        or "\nState:\tZ" in status.read_text(encoding="utf-8")):
                    break
                time.sleep(0.01)
            self.assertTrue(
                not status.exists()
                or "\nState:\tZ" in status.read_text(encoding="utf-8"))

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
            cases={"invalid": ["first()", "second()"], "valid": ["safe()"]},
        )
        del plan["rule"]
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "compiled_mutations", return_value=[]), \
                patch.object(PLAN, "run_preflight",
                          side_effect=[(True, "ok"), (False, "test-failure"),
                                       (False, "test-failure")]) as preflight:
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(preflight.call_count, 3)


class RulePlanFixTests(unittest.TestCase):
    def test_fixer_requires_fixed_oracle_on_invalid_source(self):
        plan = minimal_plan(
            fix="safe()",
            oracles={"safe()": {"fixed": "safe()"}},
        )
        with self.assertRaisesRegex(ValueError, "fixed output for every invalid source"):
            PLAN.validate_plan(plan)

    def test_fixer_requires_exact_output_for_each_invalid_source(self):
        plan = minimal_plan(
            fix="safe()",
            cases={"invalid": ["danger()", "danger(1)"], "valid": ["safe()"]},
            oracles={"danger()": {"fixed": "safe()"}},
        )
        with self.assertRaisesRegex(ValueError, "every invalid source"):
            PLAN.validate_plan(plan)

    def test_valid_fixed_oracle_may_expect_no_change(self):
        plan = minimal_plan(
            fix="safe()",
            cases={"invalid": ["danger()"], "valid": ["safe()"]},
            oracles={
                "danger()": {"fixed": "safe()"},
                "safe()": {"fixed": "safe()"},
            },
        )
        with patch.object(MECHANICS.PLAN, "load_plan", return_value=plan), \
                patch.object(MECHANICS, "validate_fix") as validate:
            self.assertEqual(MECHANICS.validate_plan_fixes([Path("plan.yml")]), 2)
        self.assertFalse(validate.call_args_list[0].kwargs["allow_no_change"])
        self.assertTrue(validate.call_args_list[1].kwargs["allow_no_change"])


class RulePlanCliTests(unittest.TestCase):
    def test_cli_writes_end_to_end_phase_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            telemetry = Path(directory) / "telemetry.json"
            result = subprocess.run(
                [sys.executable, ROOT / "tools/rule-plan.py",
                 ROOT / "plans/python/security/py-tempfile-mktemp.yml",
                 "--telemetry", telemetry],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(telemetry.read_text(encoding="utf-8"))
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["plan"], "py-tempfile-mktemp")
        self.assertEqual(report["counts"], {
            "engine_processes": 2,
            "mutants": 9,
            "survived": 4,
            "invalid": 0,
            "errors": 0,
        })
        self.assertIn("preflight", report["wall_clock_ms_informational"])

    def test_rule_plan_help_is_clean(self):
        result = subprocess.run(
            [sys.executable, ROOT / "tools/rule-plan.py", "--help"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)
        self.assertIn("PLAN.yml", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_readme_documents_the_actual_plan_commands_and_guides(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("rule-scaffold.py --plan", readme)
        self.assertNotIn("docs/complex-rules.md", readme)
        for text in ("python3 tools/rule-plan.py", "npm run generate:check",
                     "npm run generate", "docs/authoring.md", "plans/README.md"):
            self.assertIn(text, readme)


class RuleMechanicsTests(unittest.TestCase):
    def test_plan_transaction_compiles_each_plan_once(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        original = MECHANICS.PLAN.compile_plan_ir
        with patch.object(MECHANICS, "plan_paths", return_value=[path]), \
                patch.object(MECHANICS.PLAN, "compile_plan_ir", wraps=original) as compile_ir, \
                patch.object(MECHANICS.PLAN, "preflight"), \
                patch.object(MECHANICS, "stale_generated_artifacts", return_value=[]), \
                patch.object(MECHANICS, "_changed_plan_artifacts", return_value=([], [])), \
                patch.object(MECHANICS, "validate_plan_fixes", return_value=0), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(MECHANICS._plans_command(False), 0)
        self.assertEqual(compile_ir.call_count, 1)

    def test_write_mode_locks_before_plan_transaction(self):
        events = []

        @contextlib.contextmanager
        def lock():
            events.append("lock-enter")
            yield
            events.append("lock-exit")

        def transaction(write):
            self.assertTrue(write)
            self.assertEqual(events, ["lock-enter"])
            events.append("transaction")
            return 0

        with patch.object(MECHANICS.SCAFFOLD, "cli_scaffold_lock", return_value=lock()), \
                patch.object(MECHANICS, "_plans_command", side_effect=transaction):
            self.assertEqual(MECHANICS.plans_command(True), 0)
        self.assertEqual(events, ["lock-enter", "transaction", "lock-exit"])

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
                    patch.object(MECHANICS, "validate_plan_id_ownership"), \
                    patch.object(MECHANICS.PLAN, "compile_plan_ir",
                                 return_value=SimpleNamespace(plan=minimal_plan())), \
                    patch.object(MECHANICS, "_compiled_plan_artifacts", return_value=
                                 MECHANICS.RenderedPlan(
                                     minimal_plan(), rule_path,
                                     fixture_path, generated, generated)):
                MECHANICS.plans_command(True)

    def test_regeneration_validates_candidate_fixes_before_writing(self):
        target = ROOT / "rules/python/security/py-sample.yml"
        updates = [(target, "id: py-sample\n", "owner")]
        compiled = SimpleNamespace(plan=minimal_plan())
        artifacts = MECHANICS.RenderedPlan(
            minimal_plan(), target, target, "id: py-sample\n", "id: py-sample\n")
        with patch.object(MECHANICS, "plan_paths", return_value=[Path("plan.yml")]), \
                patch.object(MECHANICS.PLAN, "compile_plan_ir",
                             return_value=compiled), \
                patch.object(MECHANICS, "_compiled_plan_artifacts",
                             return_value=artifacts), \
                patch.object(MECHANICS, "validate_plan_id_ownership"), \
                patch.object(MECHANICS, "stale_generated_artifacts", return_value=[]), \
                patch.object(MECHANICS, "_changed_plan_artifacts",
                             return_value=(["rule"], updates)), \
                patch.object(MECHANICS, "validate_plan_fixes",
                             side_effect=RuntimeError("FIX_PARSE_FAILED")) as validate, \
                patch.object(MECHANICS, "_write_plan_artifacts") as write, \
                self.assertRaisesRegex(RuntimeError, "FIX_PARSE_FAILED"):
            MECHANICS.plans_command(True)
        self.assertEqual(validate.call_args.args[1], {target.resolve(): "id: py-sample\n"})
        self.assertEqual(validate.call_args.args[2], {Path("plan.yml"): artifacts})
        write.assert_not_called()

    def test_embedded_generation_marker_does_not_claim_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rule.yml"
            path.write_text(
                "id: hand-authored\n# Generated from: plans/python/security/claimed.yml\n",
                encoding="utf-8",
            )
            self.assertIsNone(MECHANICS.generated_owner(path))

    def test_deleted_plan_is_reported_as_stale_generated_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "rules/python/security/py-removed.yml"
            fixture = root / "tests/python/security/py-removed.yml"
            for path in (rule, fixture):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "# Generated from: plans/python/security/py-removed.yml\nid: py-removed\n",
                    encoding="utf-8",
                )
            with patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "plan_paths", return_value=[]), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(MECHANICS.plans_command(False), 1)

    def test_duplicate_plan_ids_are_rejected_before_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for language in ("python", "javascript"):
                path = root / f"plans/{language}/security/shared.yml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(yaml.safe_dump(minimal_plan(id="shared", language=language)))
                paths.append(path)
            with patch.object(MECHANICS, "ROOT", root), \
                    self.assertRaisesRegex(RuntimeError, "PLAN_ID_COLLISION"):
                MECHANICS.validate_plan_id_ownership(paths)

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
                    patch.object(MECHANICS.PLAN, "run_engine", side_effect=run), \
                    patch.object(MECHANICS, "scan_rule", return_value=[]):
                MECHANICS.validate_fix(rule, "danger()", "different()")

    def test_fixer_rejects_missing_node_only_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "fix.yml"
            rule.write_text(yaml.safe_dump({
                "id": "cpp-missing-fix", "language": "cpp", "fix": "if () {}",
                "rule": {"pattern": "danger()"},
            }))
            with self.assertRaisesRegex(RuntimeError,
                                        "FIX_PARSE_FAILED: cpp-missing-fix"):
                MECHANICS.validate_fix(rule, "danger()")

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

    def test_versioned_corpus_rejects_behavior_drift(self):
        finding = ("rule", "sample.py", 0, 1, "x", "message", "warning")
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expected.json"
            expected.write_text(json.dumps({"version": 1, "findings": []}),
                                encoding="utf-8")
            with patch.object(MECHANICS, "normalized_findings", return_value=[finding]), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = MECHANICS.baseline_command(
                    Path("config"), Path("corpus"), expected, False)
            self.assertEqual(status, 1)

    def test_versioned_corpus_rejects_malformed_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expected.json"
            expected.write_text("[]", encoding="utf-8")
            with patch.object(MECHANICS, "normalized_findings", return_value=[]), \
                    self.assertRaisesRegex(RuntimeError, "version 1"):
                MECHANICS.baseline_command(
                    Path("config"), Path("corpus"), expected, False)

    def test_corpus_file_bound_fails_before_engine_run(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "a.py").write_text("x")
            with patch.object(MECHANICS, "MAX_FILES", 0), \
                    patch.object(MECHANICS, "bounded_scan_output",
                                 return_value=b"[]") as engine_run:
                with self.assertRaisesRegex(RuntimeError, "corpus exceeds 0 files"):
                    MECHANICS.normalized_findings(Path("engine"), Path("config"), Path(directory))
                engine_run.assert_not_called()

    def test_normalized_findings_rejects_non_list_json(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(MECHANICS, "bounded_scan_output", return_value=b"{}"), \
                self.assertRaisesRegex(TypeError, "expected a finding list"):
            MECHANICS.normalized_findings(
                Path("engine"), Path("config"), Path(directory))

    def test_normalized_findings_rejects_malformed_entry(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(MECHANICS, "bounded_scan_output", return_value=b"[{}]"), \
                self.assertRaisesRegex(RuntimeError, "malformed.*finding"):
            MECHANICS.normalized_findings(
                Path("engine"), Path("config"), Path(directory))

    def test_normalized_finding_rejects_invalid_byte_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "sample.py"
            target.write_text("x", encoding="utf-8")
            for start, end in ((-1, 0), (2, 1)):
                finding = {
                    "ruleId": "sample",
                    "file": str(target),
                    "range": {"byteOffset": {"start": start, "end": end}},
                }
                with self.subTest(start=start, end=end), \
                        self.assertRaisesRegex(RuntimeError, "malformed.*finding"):
                    MECHANICS._normalize_finding(finding, root)

    def test_scan_output_bound_terminates_oversized_output(self):
        with patch.object(MECHANICS, "MAX_SCAN_OUTPUT_BYTES", 10), \
                self.assertRaisesRegex(RuntimeError, "scan output exceeds"):
            MECHANICS.bounded_scan_output(
                [sys.executable, "-c", "print('x' * 100)"])

    def test_scan_output_bound_terminates_stalled_process(self):
        with self.assertRaisesRegex(RuntimeError, "scan exceeded"):
            MECHANICS.bounded_scan_output(
                [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)


class ChangedGateTests(unittest.TestCase):
    def test_powershell_script_runs_built_parser_arm_coverage(self):
        scripts = json.loads((ROOT / "package.json").read_text())["scripts"]
        command = scripts["test:powershell"]
        self.assertIn(
            "tests.test_arm_coverage.ArmCoverageTests."
            "test_current_matcher_arm_inventory_powershell",
            command,
        )
        self.assertIn(
            "tests.test_arm_coverage.ArmCoverageTests."
            "test_classified_arms_have_distinguishing_counts_powershell",
            command,
        )

    def test_workflow_runs_full_suites_on_pull_requests_only(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"))
        self.assertEqual(workflow.get("on", workflow.get(True)), ["pull_request"])
        steps = {step.get("name"): step for step in workflow["jobs"]["test"]["steps"]}
        self.assertEqual(steps["Full native suite"].get("run"), "npm test")
        self.assertNotIn("if", steps["Full native suite"])
        self.assertEqual(
            steps["Generated artifacts and fixers"].get("run"),
            "npm run test:mechanics",
        )
        self.assertNotIn("if", steps["Generated artifacts and fixers"])

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
        self.assertTrue(CHANGED.requires_full_suite(["tests/arm_coverage.json"]))
        self.assertTrue(CHANGED.requires_full_suite(
            ["tests/arm_coverage_powershell.json"]))
        self.assertFalse(CHANGED.requires_full_suite(["rules/python/security/py-one.yml"]))

    def test_infrastructure_fast_gate_runs_mechanics_once_and_marks_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            with patch.object(CHANGED, "run") as run, \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    patch("sys.argv", ["test-changed.py", "tools/rule-plan.py"]):
                self.assertEqual(CHANGED.main(), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "mechanics_ran=true\n")
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["npm", "test"], ["npm", "run", "test:mechanics"],
        ])

    def test_focused_gate_runs_inventory_and_each_changed_probe(self):
        paths = ["rules/python/security/py-one.yml"]
        with patch.object(CHANGED, "rule_ids", return_value=["py-one"]), \
                patch.object(CHANGED, "run") as run, \
                patch.object(Path, "glob", return_value=iter([Path("rule.yml")])), \
                patch("sys.argv", ["test-changed.py", *paths]):
            self.assertEqual(CHANGED.main(), 0)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn([CHANGED.sys.executable, "-m", "unittest", "tests.test_inventory",
                       "tests.test_diagnostics", "tests.test_coderabbit_provenance"],
                      commands)
        self.assertIn([CHANGED.sys.executable, "tools/rule-probe.py", "py-one"], commands)
        diagnostic = next(call for call in run.call_args_list
                          if "tests.test_diagnostics" in call.args[0])
        self.assertEqual(diagnostic.args[1], {"ASTGREP_RULE_IDS": "py-one"})

    def test_change_discovery_includes_deletions(self):
        result = SimpleNamespace(returncode=0, stdout="tests/test_removed.py\n", stderr="")
        with patch.object(CHANGED.subprocess, "run", return_value=result) as run:
            self.assertEqual(CHANGED.changed_paths("origin/main"), ["tests/test_removed.py"])
        self.assertIn("--diff-filter=ACMRD", run.call_args.args[0])
        self.assertIn("--no-renames", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
