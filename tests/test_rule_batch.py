import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rule_batch", ROOT / "tools/rule-batch.py")
assert SPEC and SPEC.loader
BATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BATCH)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class RuleBatchTests(unittest.TestCase):
    def test_header_only_dedupe_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            path.write_text("proposal\tproposal_digest\tflag\n", encoding="utf-8")
            self.assertEqual(BATCH.duplicate_ids(path, {}), set())

    def test_dedupe_must_exactly_cover_current_proposals(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            digest = "a" * 64
            for rows in (f"go-one\t{digest}\t\n",
                         f"go-one\t{digest}\t\ngo-one\t{digest}\tDUP?\n",
                         f"go-one\t{digest}\t\ngo-stale\t{digest}\t\n"):
                with self.subTest(rows=rows):
                    path.write_text("proposal\tproposal_digest\tflag\n" + rows,
                                    encoding="utf-8")
                    with self.assertRaisesRegex(BATCH.BatchError, "dedupe table"):
                        BATCH.duplicate_ids(path, {"go-one": digest, "go-two": digest})

    def test_dedupe_rejects_stale_proposal_content(self):
        proposal = {"id": "go-one", "classification": "syntactic", "claim": "new"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            path.write_text("proposal\tproposal_digest\tflag\n"
                            f"go-one\t{'0' * 64}\t\n", encoding="utf-8")
            with self.assertRaisesRegex(BATCH.BatchError, "stale"):
                BATCH.duplicate_ids(path, BATCH.proposal_ids([proposal]))

    def test_dedupe_rejects_truncated_row_but_accepts_empty_flag(self):
        proposal = {"id": "go-one", "classification": "syntactic"}
        digest = BATCH.proposal_digest(proposal)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            header = "proposal\tproposal_digest\tflag\n"
            path.write_text(header + f"go-one\t{digest}\n", encoding="utf-8")
            with self.assertRaisesRegex(BATCH.BatchError, "truncated"):
                BATCH.duplicate_ids(path, {"go-one": digest})
            path.write_text(header + f"go-one\t{digest}\t\n", encoding="utf-8")
            self.assertEqual(BATCH.duplicate_ids(path, {"go-one": digest}), set())

    def test_assess_routes_duplicates_and_semantic_rows_without_scaffolding(self):
        proposals = [
            {"id": "go-duplicate-rule", "classification": "syntactic"},
            {"id": "go-dataflow-rule", "classification": "taint"},
            {"id": "go-syntax-rule", "classification": "syntactic"},
        ]
        with patch.object(BATCH, "seed_status", return_value=("AI-DRAFT", "contrast")) as seed:
            rows = BATCH.assess(proposals, {"go-duplicate-rule"}, Path("proposals"),
                                "correctness")
        self.assertEqual([row["action"] for row in rows],
                         ["DUP-REVIEW", "SEMANTIC-REVIEW", "AI-DRAFT"])
        seed.assert_called_once_with(Path("proposals"), "go-syntax-rule", "correctness")

    def test_assess_rejects_malformed_and_duplicate_proposals(self):
        for proposals, message in (([[]], "object"),
                                   ([{"id": "go-x", "classification": 1}], "string"),
                                   ([{"id": "go-x", "classification": "noise"},
                                     {"id": "go-x", "classification": "noise"}], "duplicate")):
            with self.subTest(message=message), self.assertRaisesRegex(BATCH.BatchError, message):
                BATCH.assess(proposals, set(), Path("proposals"), "correctness")

    def test_seed_status_requires_explicit_oracle_verdict(self):
        cases = (
            (completed(stdout="SEED PASS fixture oracle; review\n"), "SEEDED-REVIEW"),
            (completed(stdout="SEED NONE; author matcher\n"), "AI-DRAFT"),
            (completed(stdout="no verdict\n"), "BLOCKED"),
            (completed(1, stderr="invalid proposal\n"), "BLOCKED"),
        )
        for result, expected in cases:
            with self.subTest(expected=expected), patch.object(BATCH, "run", return_value=result):
                action, _ = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
                self.assertEqual(action, expected)
        with patch.object(BATCH, "run", side_effect=BATCH.BatchError("scaffold timed out")):
            action, detail = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
        self.assertEqual(action, "BLOCKED")
        self.assertIn("timed out", detail)

    def test_seed_status_uses_only_the_first_output_line(self):
        spoofed = completed(stdout=("SEED NONE; author matcher\n"
                                    "CONTRAST near-only=[\"SEED PASS fixture oracle\"]\n"))
        with patch.object(BATCH, "run", return_value=spoofed):
            action, _ = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
        self.assertEqual(action, "AI-DRAFT")

    def test_seed_status_short_circuits_existing_rule_without_subprocess(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(BATCH, "ROOT", Path(directory)):
            rule = Path(directory) / "rules/go/security/go-test-rule.yml"
            rule.parent.mkdir(parents=True)
            rule.write_text("id: go-test-rule\n")
            with patch.object(BATCH, "run") as runner:
                action, _ = BATCH.seed_status(Path("p"), "go-test-rule", "security")
            self.assertEqual(action, "EXISTING-REVIEW")
            runner.assert_not_called()

    def test_apply_seeded_records_probe_pass_and_bounds_failures(self):
        rows = [
            {"id": "go-seeded-rule", "action": "SEEDED-REVIEW", "detail": ""},
            {"id": "go-manual-rule", "action": "AI-DRAFT", "detail": ""},
        ]
        with patch.object(BATCH, "run", side_effect=[
                completed(stdout="wrote pair\n"),
                completed(stdout="go-seeded-rule: PASS 1/4\n")]) as runner, \
                patch.object(BATCH, "probe_passed", return_value=True):
            self.assertEqual(BATCH.apply_seeded(rows, Path("p"), Path("w"), "correctness"), 0)
        self.assertEqual(runner.call_args_list, [
            call([sys.executable, str(BATCH.SCAFFOLD), "--proposal", "p",
                  "--id", "go-seeded-rule", "--category", "correctness",
                  "--seed", "--contrast"]),
            call([sys.executable, str(BATCH.DRAFT), "go-seeded-rule", "--work", "w"]),
        ])
        self.assertEqual(rows[0]["action"], "SEEDED-PASS")
        self.assertEqual(rows[1]["action"], "AI-DRAFT")

        rows[0]["action"] = "SEEDED-REVIEW"
        with patch.object(BATCH, "run", side_effect=[completed(), completed(stdout="")]), \
                patch.object(BATCH, "probe_passed", return_value=False):
            self.assertEqual(BATCH.apply_seeded(rows, Path("p"), Path("w"), "correctness"), 1)
        self.assertEqual(rows[0]["action"], "PROBE-FAILED")
        self.assertIn("scaffolded pair and rule count retained", rows[0]["detail"])

    def test_apply_seeded_records_subprocess_exceptions_per_candidate(self):
        for results, expected in (
                ([BATCH.BatchError("scaffold timed out")], "APPLY-FAILED"),
                ([completed(stdout="wrote pair\n"), BATCH.BatchError("probe timed out")],
                 "PROBE-FAILED")):
            rows = [{"id": "go-seeded-rule", "action": "SEEDED-REVIEW", "detail": ""}]
            with self.subTest(expected=expected), patch.object(
                    BATCH, "run", side_effect=results):
                failures = BATCH.apply_seeded(
                    rows, Path("p"), Path("w"), "correctness")
            self.assertEqual(failures, 1)
            self.assertEqual(rows[0]["action"], expected)
            self.assertIn("timed out", rows[0]["detail"])

    def test_probe_pass_requires_matching_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            state = work / "draft/go-test-rule.json"
            state.parent.mkdir()
            verdict = completed(stdout="go-test-rule: PASS 1/4\n")
            state.write_text(json.dumps({"rule": "go-test-rule", "status": "PASS",
                                         "attempts": [{}]}))
            self.assertTrue(BATCH.probe_passed(work, "go-test-rule", verdict))
            state.write_text(json.dumps({"rule": "go-test-rule", "status": "RETRY",
                                         "attempts": [{}]}))
            self.assertFalse(BATCH.probe_passed(work, "go-test-rule", verdict))
            for malformed in ([], None, "state"):
                with self.subTest(malformed=malformed):
                    state.write_text(json.dumps(malformed), encoding="utf-8")
                    self.assertFalse(BATCH.probe_passed(work, "go-test-rule", verdict))

    def test_relative_work_is_resolved_before_child_tools_run(self):
        proposal = {"id": "go-relative-work-rule", "language": "go",
                    "claim": "Report bad calls", "classification": "syntactic",
                    "positive": "package p\nfunc f(){ bad(x) }",
                    "near_miss": "package p\nfunc f(){ good(x) }",
                    "rationale": "syntactic contrast", "supporting": ["abc123"],
                    "overlaps": []}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            work = parent / "work"
            (work / "cluster").mkdir(parents=True)
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            digest = BATCH.proposal_digest(proposal)
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-relative-work-rule\t{digest}\t\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/rule-batch.py"), "--work", "work",
                 "--category", "correctness", "--dry-run"], cwd=parent,
                capture_output=True, text=True, check=False, timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_main_dry_run_json_is_bounded_and_does_not_write_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            proposals = work / "cluster/proposals.jsonl"
            proposals.parent.mkdir()
            proposals.write_text(json.dumps({
                "id": "go-test-rule", "classification": "syntactic"}) + "\n")
            proposal = {"id": "go-test-rule", "classification": "syntactic"}
            digest = BATCH.proposal_digest(proposal)
            (work / "dedupe.tsv").write_text(
                f"proposal\tproposal_digest\tflag\ngo-test-rule\t{digest}\t\n")
            args = ["rule-batch", "--work", str(work), "--category", "correctness",
                    "--dry-run", "--json"]
            with patch("sys.argv", args), patch.object(
                    BATCH, "seed_status", return_value=("SEEDED-REVIEW", "passed")), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(BATCH.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["actions"], {"SEEDED-REVIEW": 1})
            self.assertFalse((work / "draft-plan.tsv").exists())

    def test_write_plan_is_reproducible(self):
        rows = [{"id": "go-test-rule", "classification": "syntactic", "duplicate": "no",
                 "action": "AI-DRAFT", "detail": "needs matcher"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "draft-plan.tsv"
            BATCH.write_plan(path, rows)
            first = path.read_bytes()
            BATCH.write_plan(path, rows)
            self.assertEqual(path.read_bytes(), first)

    def test_main_bounds_plan_write_failure(self):
        argv = ["rule-batch", "--work", "work", "--category", "correctness"]
        with patch("sys.argv", argv), \
                patch.object(BATCH, "read_jsonl", return_value=[]), \
                patch.object(BATCH, "proposal_ids", return_value=set()), \
                patch.object(BATCH, "duplicate_ids", return_value=set()), \
                patch.object(BATCH, "assess", return_value=[]), \
                patch.object(BATCH, "write_plan", side_effect=OSError("read only")), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(BATCH.main(), 2)
        self.assertIn("rule-batch: ERROR: read only", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
