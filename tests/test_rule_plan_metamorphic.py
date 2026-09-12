from tests.mechanics_test_support import (
    PLAN,
    ROOT,
    Path,
    minimal_plan,
    tempfile,
    unittest,
    yaml,
)


class RulePlanMetamorphicTests(unittest.TestCase):
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
                language = "python" if transform == "parenthesized" else "c"
                self.assertEqual(
                    PLAN._metamorphic_source(source, transform, language), expected)

    def test_metamorphic_transforms_skip_lexical_lookalikes(self):
        cases = {
            ('["fake()", danger()]', "callee-parenthesized", "python"):
                '["fake()", (danger)()]',
            ('"obj.field"; obj.field', "member-access-spacing", "javascript"):
                '"obj.field"; obj . field',
            ('# fake()\ndanger()', "callee-parenthesized", "python"):
                '# fake()\n(danger)()',
            ('// "fake"\nlog("real")', "literal-concatenation", "c"):
                '// "fake"\nlog("real" "")',
            ('// %s\nlog("%s", value)', "format-width", "c"):
                '// %s\nlog("%20s", value)',
            ('[/obj.field/, obj.field]', "member-access-spacing", "javascript"):
                '[/obj.field/, obj . field]',
            ('x // y; danger()', "callee-parenthesized", "python"):
                'x // y; (danger)()',
            ('function f(){ return /obj.field/; } obj.field;',
             "member-access-spacing", "javascript"):
                'function f(){ return /obj.field/; } obj . field;',
            ('# $fake->field\n$obj->field;', "member-access-spacing", "php"):
                '# $fake->field\n$obj -> field;',
            ('void f() { danger(); }', "callee-parenthesized", "cpp"):
                'void f() { (danger)(); }',
            ('obj->danger()', "callee-parenthesized", "cpp"):
                '(obj->danger)()',
            ('ns::danger()', "callee-parenthesized", "cpp"):
                '(ns::danger)()',
            ('obj.danger()', "callee-parenthesized", "javascript"):
                '(obj.danger)()',
            ('obj?.field', "member-access-spacing", "javascript"):
                'obj ?. field',
            ('$obj?->field', "member-access-spacing", "php"):
                '$obj ?-> field',
        }
        for (source, transform, language), expected in cases.items():
            with self.subTest(transform=transform):
                self.assertEqual(
                    PLAN._metamorphic_source(source, transform, language), expected)

    def test_format_transforms_skip_escaped_percent_and_existing_fields(self):
        transformed = [
            ('log("%% literal: %s", value)', "format-width",
             'log("%% literal: %20s", value)'),
            ('log("%%%s", value)', "format-precision", 'log("%%%.3s", value)'),
        ]
        for source, transform, expected in transformed:
            with self.subTest(source=source, transform=transform):
                self.assertEqual(PLAN._metamorphic_source(source, transform, "c"), expected)
        unchanged = [("%20s", "format-width"), ("%*s", "format-width"),
                     ("%.2s", "format-precision"), ("%.*s", "format-precision"),
                     ("%%", "format-width")]
        for source, transform in unchanged:
            with self.subTest(source=source, transform=transform), \
                    self.assertRaisesRegex(ValueError, "not applicable"):
                PLAN._metamorphic_source(source, transform, "c")

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
