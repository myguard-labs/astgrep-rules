"""Contracts for offline harvest inputs, reply gates, and rule scaffolding."""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
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


HISTORY = load_tool("harvest-history")
PACKETS = load_tool("harvest-packets")
PROBE = load_tool("rule-probe")
SCAFFOLD = load_tool("rule-scaffold")


@contextlib.contextmanager
def ascii_text_defaults():
    """Exercise implicit encodings independently of the developer's UTF-8 locale."""
    original_open = Path.open
    original_temporary = tempfile.NamedTemporaryFile

    def open_path(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding in (None, "locale"):
            encoding = "ascii"
        return original_open(path, mode, buffering, encoding, errors, newline)

    def temporary(*args, **kwargs):
        if "b" not in kwargs.get("mode", "w+b"):
            kwargs.setdefault("encoding", "ascii")
        return original_temporary(*args, **kwargs)

    with patch.object(Path, "open", open_path), \
            patch.object(tempfile, "NamedTemporaryFile", temporary):
        yield


@contextlib.contextmanager
def coverage_cases(cases):
    """Provide actual witness JSON without changing the shared JSON decoder."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tests").mkdir()
        (root / "tests/arm_coverage.json").write_text(
            json.dumps({"cases": cases}), encoding="utf-8")
        with patch.object(PROBE, "ROOT", root):
            yield


class HistoryTests(unittest.TestCase):
    def test_dedupe_sha_aliases_preserve_first_repo_and_packet_uniqueness(self):
        for phase in ("show", "patch-id"):
            for order in (("fast", "slow"), ("slow", "fast"), ("fast", "alias", "slow")):
                with self.subTest(phase=phase, order=order):
                    candidates = [{"repo": repo,
                                   "sha": ("a" if repo == "fast" and len(order) == 3
                                           else "b") * 40,
                                   "short": ("a" if repo == "fast" and len(order) == 3
                                             else "b") * 12,
                                   "subject": "fix bounds", "files": ["x.c"],
                                   "diff": "-old\n+new"} for repo in order]

                    def show(repo, *_args, target=phase):
                        if repo.name == "slow" and target == "show":
                            raise subprocess.TimeoutExpired(["git", "show"], 60)
                        return repo.name

                    def patch_id(command, *, target=phase, **kwargs):
                        if kwargs["input"] == b"slow" and target == "patch-id":
                            raise subprocess.TimeoutExpired(command, 60)
                        return subprocess.CompletedProcess(command, 0, b"same-patch\n")

                    with patch.object(HISTORY, "run", side_effect=show), \
                            patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                            contextlib.redirect_stderr(io.StringIO()):
                        result = HISTORY.dedupe_by_patch_id(ROOT, candidates)
                    self.assertEqual(len(result), 1)
                    self.assertIs(result[0], candidates[0])
                    self.assertEqual(result[0]["repo"], order[0])
                    self.assertEqual(result[0]["also_in"], list(order[1:]))
                    packets = PACKETS.label_packets(result)
                    self.assertEqual(len(packets), 1)
                    self.assertEqual(next(iter(packets.values()))["repo"], order[0])

    def test_dedupe_timeouts_preserve_candidates_with_sha_identity(self):
        for phase in ("show", "patch-id"):
            with self.subTest(phase=phase):
                candidates = [{"repo": repo, "sha": sha * 40}
                              for repo, sha in (("first", "a"), ("slow", "b"),
                                                ("last", "c"), ("fork", "b"))]

                def show(repo, *_args, target=phase):
                    if repo.name in ("slow", "fork") and target == "show":
                        raise subprocess.TimeoutExpired(["git", "show"], 60)
                    return repo.name

                def patch_id(command, *, target=phase, **kwargs):
                    if kwargs["input"] in (b"slow", b"fork") and target == "patch-id":
                        raise subprocess.TimeoutExpired(command, 60)
                    return subprocess.CompletedProcess(command, 0, kwargs["input"] + b"\n")

                with patch.object(HISTORY, "run", side_effect=show), \
                        patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    result = HISTORY.dedupe_by_patch_id(ROOT, candidates)
                self.assertEqual([row["repo"] for row in result], ["first", "slow", "last"])
                self.assertIs(result[1], candidates[1])
                self.assertEqual(result[1]["also_in"], ["fork"])
                self.assertIn("using SHA fallback", stderr.getvalue())
                # The fork's known SHA bypasses a second identity lookup and timeout.
                self.assertIn("timed-out-candidates=1", stderr.getvalue())

    def test_history_listing_timeout_reports_incomplete_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "slow", "last"):
                (root / name / ".git").mkdir(parents=True)

            def history(repo, *_args):
                if repo.name == "slow":
                    raise subprocess.TimeoutExpired(["git", "log"], 60)
                sha = "a" * 40 if repo.name == "first" else "c" * 40
                return sha + "\x1ffix bounds\x1f2026-09-08"

            with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                    patch.object(HISTORY, "run", side_effect=history), \
                    patch.object(HISTORY, "changed_source_files", return_value=[
                        HISTORY.SourceChange("x.c", 1, 1)]), \
                    patch.object(HISTORY, "diff_body", return_value="-old\n+new"), \
                    patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                    patch.object(HISTORY, "dedupe_by_patch_id", side_effect=lambda _, rows: rows), \
                    patch("sys.argv", ["harvest", "--root", str(root), "--repos",
                                       "first", "slow", "last"]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(HISTORY.main(), 1)
            self.assertEqual([json.loads(line)["repo"]
                              for line in stdout.getvalue().splitlines()], ["first", "last"])
            self.assertIn("incomplete harvest", stderr.getvalue())
            self.assertIn("timed-out-repos=1", stderr.getvalue())
            self.assertIn("skip slow", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_per_commit_timeouts_preserve_same_repo_neighbors(self):
        history = "\n".join(char * 40 + "\x1ffix bounds\x1f2026-09-08" for char in "abc")
        for phase in ("source-files", "diff", "file-content"):
            with self.subTest(phase=phase):
                def source_files(_repo, sha, target=phase):
                    if sha == "b" * 40 and target == "source-files":
                        raise subprocess.TimeoutExpired(["git", "show", "--numstat"], 60)
                    return [HISTORY.SourceChange("x.c", 1, 1)]

                def diff(_repo, sha, _paths, target=phase):
                    if sha == "b" * 40 and target == "diff":
                        raise subprocess.TimeoutExpired(["git", "show"], 60)
                    return "-old\n+new"

                def cosmetic(_repo, sha, _changes, target=phase):
                    if sha == "b" * 40 and target == "file-content":
                        raise subprocess.TimeoutExpired(["git", "show", "revision:x.c"], 60)
                    return False

                with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                        patch.object(HISTORY, "run", return_value=history), \
                        patch.object(HISTORY, "changed_source_files", side_effect=source_files), \
                        patch.object(HISTORY, "diff_body", side_effect=diff), \
                        patch.object(HISTORY, "cosmetic_commit", side_effect=cosmetic), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    rows = HISTORY.harvest(ROOT, "sample", 3, 60, None)
                self.assertEqual([row["sha"] for row in rows], ["a" * 40, "c" * 40])
                self.assertRegex(stderr.getvalue(), r"timed-out-commits=\s*1")
                self.assertIn("skip sample:" + "b" * 40, stderr.getvalue())

    def test_timeouts_retain_candidates_and_report_incomplete_repos(self):
        for phase in ("harvest", "show", "patch-id"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ("first", "slow", "last"):
                    (root / name / ".git").mkdir(parents=True)

                def harvest(_repo, name, *_args, target=phase):
                    if name == "slow" and target == "harvest":
                        raise subprocess.TimeoutExpired(["git", "log"], 60)
                    return [{"repo": name, "sha": name, "signals": [], "churn": 1}]

                def show(repo, *_args, target=phase):
                    if repo.name == "slow" and target == "show":
                        raise subprocess.TimeoutExpired(["git", "show"], 60)
                    return repo.name

                def patch_id(command, *, target=phase, **kwargs):
                    if kwargs["input"] == b"slow" and target == "patch-id":
                        raise subprocess.TimeoutExpired(command, 60)
                    return subprocess.CompletedProcess(command, 0, kwargs["input"] + b"\n")

                with patch.object(HISTORY, "harvest", side_effect=harvest), \
                        patch.object(HISTORY, "run", side_effect=show), \
                        patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                        patch("sys.argv", ["harvest", "--root", str(root), "--repos",
                                           "first", "slow", "last"]), \
                        contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(HISTORY.main(), int(phase == "harvest"))
                self.assertEqual([json.loads(line)["repo"]
                                  for line in stdout.getvalue().splitlines()],
                                 ["first", "last"] if phase == "harvest"
                                 else ["first", "slow", "last"])
                counter = "repos" if phase == "harvest" else "candidates"
                self.assertIn(f"timed-out-{counter}=1", stderr.getvalue())
                self.assertIn("skip slow" if phase == "harvest" else "retain slow",
                              stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_output_stages_preserve_legacy_subject_bytes(self):
        raw_subject = "fix café ".encode() + b"\xff"
        candidate = {"short": "abc", "sha": "a" * 40, "repo": "sample",
                     "subject": raw_subject.decode("utf-8", "surrogateescape"),
                     "churn": 1, "signals": [], "url": "", "diff": "+new\udcfe\n"}
        for file_output in (False, True):
            with self.subTest(file_output=file_output), \
                    tempfile.TemporaryDirectory() as directory, \
                    io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict") as stdout:
                root = Path(directory)
                (root / "sample/.git").mkdir(parents=True)
                index, output = root / "index.md", root / "corpus.jsonl"
                argv = ["harvest", "--root", str(root), "--repos", "sample", "--index", str(index)]
                if file_output:
                    argv += ["--out", str(output)]
                with patch.object(HISTORY, "harvest", return_value=[dict(candidate)]), \
                        patch.object(HISTORY, "dedupe_by_patch_id",
                                     side_effect=lambda _, rows: rows), \
                        patch("sys.argv", argv), ascii_text_defaults(), \
                        contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(UnicodeEncodeError):
                        stdout.write("☃")
                    self.assertEqual(HISTORY.main(), 0)
                stdout.flush()
                payload = (output.read_bytes().decode("ascii") if file_output
                           else stdout.buffer.getvalue().decode("ascii"))
                row = json.loads(payload)
                self.assertEqual(row["subject"].encode("utf-8", "surrogateescape"), raw_subject)
                self.assertEqual(row["diff"], candidate["diff"])
                self.assertIn(raw_subject, index.read_bytes())

    def test_git_subprocesses_have_bounded_timeouts(self):
        def timeout(command, **kwargs):
            self.assertGreater(kwargs.get("timeout", 0), 0, "Git invocation must be bounded")
            self.assertLessEqual(kwargs["timeout"], 60)
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with self.subTest(command="git"), \
                patch.object(HISTORY.subprocess, "run", side_effect=timeout), \
                self.assertRaises(subprocess.TimeoutExpired):
            HISTORY.run(ROOT, "log")
        with self.subTest(command="patch-id"), \
                patch.object(HISTORY, "run", return_value="diff"), \
                patch.object(HISTORY.subprocess, "run", side_effect=timeout), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(HISTORY.dedupe_by_patch_id(
                ROOT, [{"repo": "sample", "sha": "a" * 40}]),
                [{"repo": "sample", "sha": "a" * 40}])
            self.assertIn("timed-out-candidates=1", stderr.getvalue())

    def test_unattributable_commit_does_not_abort_other_commits_or_repos(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "second"):
                (root / name / ".git").mkdir(parents=True)

            def log(repo, *_args):
                shas = ("a" * 40, "b" * 40) if repo.name == "first" else ("c" * 40,)
                return "\n".join(sha + "\x1ffix bounds\x1f2026-09-08" for sha in shas)

            with patch.object(HISTORY, "run", side_effect=log), \
                    patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                    patch.object(HISTORY, "changed_source_files", return_value=[
                        HISTORY.SourceChange("x.c", 1, 1)]), \
                    patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                    patch.object(HISTORY, "diff_body", side_effect=("", "-a\n+b", "-b\n+c")), \
                    patch.object(HISTORY, "dedupe_by_patch_id", side_effect=lambda _, rows: rows), \
                    patch("sys.argv", ["harvest", "--root", str(root),
                                       "--repos", "first", "second"]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(HISTORY.main(), 0)
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual([(row["repo"], row["sha"]) for row in rows],
                             [("first", "b" * 40), ("second", "c" * 40)])
            self.assertRegex(stderr.getvalue(), r"no-diff-skipped=\s*1")

    def test_origin_userinfo_never_reaches_published_urls(self):
        # Inert markers exercise URL credential forms; assertions never print them.
        for userinfo in ("fixture-token", "fixture-user:fixture-password",
                         "fixture-user:fixture%40password", ":fixture-password"):
            with self.subTest(form="password" if ":" in userinfo else "token"):
                with patch.object(HISTORY, "run", return_value=(
                        "https://" + userinfo + "@example.test/owner/project.git")):
                    prefix = HISTORY.commit_url_prefix(ROOT, None)
                candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                             "churn": 1, "density": 1, "signals": [], "url": prefix + "abc"}
                with tempfile.TemporaryDirectory() as directory:
                    index = Path(directory) / "index.md"
                    HISTORY.write_index(index, [candidate])
                    for rendered in (json.dumps(candidate), index.read_text()):
                        self.assertFalse(userinfo in rendered, "origin userinfo reached output")
                        self.assertTrue(
                            "https://example.test/owner/project/commit/abc" in rendered,
                            "published commit URL must use only host and repository path")

    def test_blank_line_changes_preserve_line_sensitive_semantics(self):
        for source in ("int line = __LINE__;\n", "#define SITE __LINE__\nint line = SITE;\n",
                       "int line = __builtin_LINE();\n", "int line = EXTERNAL_LINE_MACRO;\n"):
            with self.subTest(source=source):
                self.assertFalse(HISTORY.is_cosmetic(source, "\n" + source))
        # Moving a blank line keeps the line count but still changes __LINE__.
        self.assertFalse(HISTORY.is_cosmetic("\nint line = __LINE__;\nint x;\n",
                                             "int line = __LINE__;\n\nint x;\n"))
        self.assertTrue(HISTORY.is_cosmetic(" int line = __LINE__;\n", "\tint line = __LINE__;\n"))

    def test_diff_paths_are_literal_git_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args, source=None):
                return subprocess.run(["git", "-C", str(root), *args], input=source,
                                      capture_output=True, check=True, timeout=10).stdout.decode()

            git("init", "-q")
            for name, value in ((":odd.c", "colon"), ("glob[1].c", "bracket"),
                                ("glob1.c", "decoy")):
                blob = git("hash-object", "-w", "--stdin",
                           source=f"int {value} = 1;\n".encode()).strip()
                git("update-index", "--add", "--cacheinfo", f"100644,{blob},{name}")
            tree = git("write-tree").strip()
            # An inert object fixture exercises git-show without creating a branch/ref.
            commit = git("hash-object", "-t", "commit", "-w", "--stdin", source=(
                f"tree {tree}\nauthor Test <test@example.test> 0 +0000\n"
                "committer Test <test@example.test> 0 +0000\n\nfixture\n").encode()).strip()
            nested = root / "nested"
            nested.mkdir()
            for repo in (root, nested):
                for name, wanted, excluded in ((":odd.c", "colon", "bracket"),
                                                ("glob[1].c", "bracket", "decoy")):
                    with self.subTest(repo=repo, path=name):
                        diff = HISTORY.diff_body(repo, commit, [name])
                        self.assertIn(f"int {wanted} = 1;", diff)
                        self.assertNotIn(f"int {excluded} = 1;", diff)

    def test_non_utf8_diff_preserves_bytes_and_patch_identity(self):
        raw = b"diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-old\xff\n+new\xfe\n"
        with patch.object(HISTORY.subprocess, "run", return_value=SimpleNamespace(stdout=raw)):
            diff = HISTORY.diff_body(ROOT, "HEAD", ["x.c"])
        self.assertEqual(diff.encode("utf-8", "surrogateescape"), raw)
        self.assertEqual(json.loads(json.dumps(diff)), diff)
        real_run = subprocess.run
        expected = real_run(["git", "patch-id", "--stable"], input=raw,
                            capture_output=True, check=True).stdout
        with patch.object(HISTORY, "run", return_value=diff), \
                patch.object(HISTORY.subprocess, "run", wraps=real_run) as runner:
            candidate = {"repo": "sample", "sha": "a" * 40}
            self.assertEqual(HISTORY.dedupe_by_patch_id(ROOT, [candidate]), [candidate])
        self.assertEqual(runner.call_args.kwargs["input"], raw)
        self.assertTrue(expected.strip(), "control patch must have a real patch-id")

    def test_source_filter_excludes_binary_tests_and_docs(self):
        numstat = "1\t1\tmain.go\0" "2\t0\tmain_test.go\0-\t-\timage.c\0" "1\t0\tREADME.md\0"
        with patch.object(HISTORY, "run", return_value=numstat):
            self.assertEqual(HISTORY.changed_source_files(ROOT, "HEAD"),
                             [HISTORY.SourceChange("main.go", 1, 1)])

    def test_cosmetic_boundary(self):
        self.assertTrue(HISTORY.is_cosmetic("  x = 1\n", "\tx = 1\n"))
        self.assertFalse(HISTORY.is_cosmetic("// old\nx = 1", "// revised\nx = 1"))
        for before, after in (("*p = 1;", "*p = 2;"), ("int x;", "intx;"),
                              ('x = "a b";', 'x = "ab";'),
                              ("first();\nsecond();", "second();\nfirst();"),
                              ("a > > b", "a >> b"), ("x\r\n", "x\n"),
                              ("#define X \\\n  x", "#define X \\\n x")):
            with self.subTest(before=before):
                self.assertFalse(HISTORY.is_cosmetic(before, after))

    def test_raw_string_context_far_outside_changed_lines_is_retained(self):
        before = 'value := `\n' + 'unchanged\n' * 20 + '  // literal\n`'
        after = before.replace('  // literal', ' // literal')
        self.assertFalse(HISTORY.is_cosmetic(before, after))

    def test_pool_vocabulary(self):
        for spelling in ("sync.Pool{}", "p.Reset()", "p.Put(x)", "newTransaction()"):
            with self.subTest(spelling=spelling):
                self.assertIn("pool-reuse", HISTORY.signal_terms(spelling, "fix"))

    def test_directive_comments_and_indentation_are_retained(self):
        for directive in ("//go:build linux", "// +build linux", "//line source.go:5"):
            before = directive + "\n\npackage x\n"
            self.assertFalse(HISTORY.is_cosmetic(before, before.replace("linux", "windows")))
            self.assertFalse(HISTORY.is_cosmetic(before, " " + before))

    def test_rename_uses_real_paths_and_preserves_small_edit_churn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args, source=None):
                return subprocess.run(["git", "-C", str(root), *args], input=source,
                    capture_output=True, check=True, timeout=10).stdout.decode()

            git("init", "-q")
            original = "".join(f"int value_{index} = {index};\n" for index in range(100))
            blob = git("hash-object", "-w", "--stdin", source=original.encode()).strip()
            git("update-index", "--add", "--cacheinfo", f"100644,{blob},old.c")
            tree = git("write-tree").strip()
            git("update-index", "--force-remove", "old.c")
            edited = original.replace("value_99 = 99", "value_99 = 100")
            blob = git("hash-object", "-w", "--stdin", source=edited.encode()).strip()
            target = "new\tname.c"
            git("update-index", "--add", "--cacheinfo", f"100644,{blob},{target}")
            numstat = git("diff", "--cached", "--find-renames", "--numstat", "-z", tree)
            with patch.object(HISTORY, "run", return_value=numstat):
                changes = HISTORY.changed_source_files(root, "unused")
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes, [HISTORY.SourceChange(target, 1, 1, "old.c")])
            diff = git("diff", "--cached", "--find-renames", tree, "--", "old.c", target)
            self.assertIn("-int value_99 = 99;", diff)
            self.assertIn("+int value_99 = 100;", diff)
            self.assertLess(sum(change.added + change.deleted for change in changes), 60)
            self.assertFalse(HISTORY.cosmetic_commit(root, "unused", changes))

    def test_subject_with_separator_keeps_subject_and_date(self):
        record = "a" * 40 + "\x1ffix: a\x1fb\x1f2026-09-07 12:00:00 +0200"
        with patch.object(HISTORY, "run", return_value=record), \
                patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                patch.object(HISTORY, "changed_source_files",
                             return_value=[HISTORY.SourceChange("x.c", 1, 1)]), \
                patch.object(HISTORY, "diff_body", return_value="-x\n+y"), \
                patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                contextlib.redirect_stderr(io.StringIO()):
            rows = HISTORY.harvest(ROOT, "sample", 3, 60, None)
        self.assertEqual(rows[0]["subject"], "fix: a\x1fb")
        self.assertEqual(rows[0]["date"], "2026-09-07")

    def test_origin_url_and_missing_origin(self):
        for origin in ("git@github.com:example/project.git", "https://github.com/example/project.git"):
            with self.subTest(origin=origin), patch.object(HISTORY, "run", return_value=origin):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, None),
                                 "https://github.com/example/project/commit/")
        with patch.object(HISTORY, "run", side_effect=subprocess.CalledProcessError(2, "git")):
            self.assertEqual(HISTORY.commit_url_prefix(ROOT, "fallback/"), "fallback/")


class ReplyTests(unittest.TestCase):
    def test_proposals_require_at_least_one_supporting_commit(self):
        proposal = self.proposal()
        proposal["supporting"] = []
        self.assertIn("supporting", PACKETS.validate_proposal(proposal, {"abc"}) or "")
        proposal["supporting"] = ["abc"]
        self.assertIsNone(PACKETS.validate_proposal(proposal, {"abc"}))
        self.assertEqual(PACKETS.validate_cluster(
            {"cluster": "go-bounds", "proposals": []}, "go-bounds", {"abc"}, "go"), (None, []))

    def test_cluster_emit_requires_current_validated_label_replies(self):
        for mutation in ("class", "summary", "language", "deleted", "malformed", "labels"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, \
                    contextlib.redirect_stderr(io.StringIO()):
                root = Path(directory)
                args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl",
                                       chunk=12, min_size=1)
                PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                    "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                    "signals": ["bounds"], "density": 1, "url": ""}])
                self.assertEqual(PACKETS.label_emit(args), 0)
                reply_path = root / "label/replies/abc.json"
                reply_path.write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
                labels_path = root / "label/labels.jsonl"
                originals = {p: p.read_bytes() for p in (reply_path, labels_path)}
                if mutation == "deleted":
                    reply_path.unlink()
                elif mutation == "malformed":
                    reply_path.write_text("{")
                elif mutation == "labels":
                    labels = PACKETS.read_jsonl(labels_path)
                    labels[0]["summary"] = "edited aggregate"
                    PACKETS.write_jsonl(labels_path, labels)
                else:
                    reply = self.label()
                    reply[mutation] = {"class": "logic", "summary": "edited reply",
                                       "language": "c"}[mutation]
                    reply_path.write_text(json.dumps(reply))
                before = labels_path.read_bytes()
                self.assertEqual(PACKETS.cluster_emit(args), 1)
                self.assertFalse((root / "cluster").exists())
                self.assertEqual(labels_path.read_bytes(), before)
                for path, content in originals.items():
                    path.write_bytes(content)
                self.assertEqual(PACKETS.cluster_emit(args), 0)

    def test_prompt_bytes_survive_platform_text_defaults(self):
        original_open = Path.open

        def platform_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
            # Model a legacy locale and Windows text-mode newline translation.
            if "b" not in mode and "w" in mode:
                encoding = "cp1252" if encoding in (None, "locale") else encoding
                newline = "\r\n" if newline is None else newline
            return original_open(path, mode, buffering, encoding, errors, newline)

        for stage_name in ("label", "cluster"):
            with self.subTest(stage=stage_name), tempfile.TemporaryDirectory() as directory, \
                    patch.object(Path, "open", platform_open):
                stage = Path(directory) / stage_name
                prompt = "Classify café.\nRetain exact bytes.\n"
                packets = {"sample": {"id": "sample"}}
                self.assertTrue(PACKETS.emit_packets(stage, packets, prompt))
                self.assertEqual((stage / "PROMPT.md").read_bytes(), prompt.encode("utf-8"))
                self.assertTrue(PACKETS.packet_state(stage, packets, prompt))
                self.assertTrue(PACKETS.emit_packets(stage, packets, prompt))

    def test_prompt_changes_refuse_stale_replies_without_overwriting_evidence(self):
        for stage_name, constant in (("label", "LABEL_PROMPT"), ("cluster", "CLUSTER_PROMPT")):
            with self.subTest(stage=stage_name), tempfile.TemporaryDirectory() as directory, \
                    contextlib.redirect_stderr(io.StringIO()):
                root = Path(directory)
                args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=12, min_size=1)
                PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                    "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                    "signals": ["bounds"], "density": 1, "url": ""}])
                self.assertEqual(PACKETS.label_emit(args), 0)
                (root / "label/replies/abc.json").write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
                if stage_name == "cluster":
                    self.assertEqual(PACKETS.cluster_emit(args), 0)
                    (root / "cluster/replies/go-bounds.json").write_text(json.dumps(
                        {"cluster": "go-bounds", "proposals": []}))
                emit = getattr(PACKETS, f"{stage_name}_emit")
                ingest = getattr(PACKETS, f"{stage_name}_ingest")
                self.assertEqual(ingest(args), 0)
                stage = root / stage_name
                before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*")
                          if p.is_file()}
                with patch.object(PACKETS, constant, getattr(PACKETS, constant) + "\nchanged"):
                    self.assertEqual(ingest(args), 1)
                    self.assertEqual(emit(args), 1)
                self.assertEqual({p.relative_to(stage): p.read_bytes() for p in stage.rglob("*")
                                  if p.is_file()}, before)
                self.assertEqual(ingest(args), 0)
                prompt = stage / "PROMPT.md"
                original = prompt.read_bytes()
                prompt.write_bytes(original + b"\nchanged")
                self.assertEqual(ingest(args), 1)
                self.assertEqual(emit(args), 1)
                self.assertEqual(prompt.read_bytes(), original + b"\nchanged")
                for path, content in before.items():
                    if path.parts[0] == "replies":
                        self.assertEqual((stage / path).read_bytes(), content)
                prompt.write_bytes(original)
                self.assertEqual(ingest(args), 0)
                self.assertEqual(emit(args), 0)

    def test_proposal_language_must_match_emitted_cluster(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=12, min_size=1)
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            self.assertEqual(PACKETS.label_emit(args), 0)
            (root / "label/replies/abc.json").write_text(json.dumps(self.label()))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertEqual(PACKETS.cluster_emit(args), 0)
            reply = root / "cluster/replies/go-bounds.json"
            reply.write_text(json.dumps({"cluster": "go-bounds", "proposals": [
                {**self.proposal(), "id": "c-index-check", "language": "c"}]}))
            self.assertEqual(PACKETS.cluster_ingest(args), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl"), [])
            self.assertIn("language", errors.getvalue())
            reply.write_text(json.dumps({"cluster": "go-bounds", "proposals": [self.proposal()]}))
            self.assertEqual(PACKETS.cluster_ingest(args), 0)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl")[0]["language"], "go")

    def test_label_language_must_match_corpus(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.c"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            self.assertEqual(PACKETS.label_emit(args), 0)
            reply = root / "label/replies/abc.json"
            reply.write_text(json.dumps(self.label()))
            self.assertEqual(PACKETS.label_ingest(args), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "label/labels.jsonl"), [])
            self.assertIn("language", errors.getvalue())
            reply.write_text(json.dumps({**self.label(), "language": "c"}))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertTrue(PACKETS.read_jsonl(root / "label/labels.jsonl")[0]["agreed"])

    def test_duplicate_proposal_ids_rejected_across_replies(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            stage = root / "cluster"
            packets = {name: {"language": "go", "candidates": [{"short": short}]}
                       for name, short in (("go-bounds-1", "abc"), ("go-bounds-2", "def"))}
            self.assertTrue(PACKETS.emit_packets(stage, packets, PACKETS.CLUSTER_PROMPT))
            for name, packet in packets.items():
                proposal = {**self.proposal(), "supporting": [packet["candidates"][0]["short"]]}
                (stage / "replies" / f"{name}.json").write_text(json.dumps(
                    {"cluster": name, "proposals": [proposal]}))
            self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 1)
            self.assertIn("duplicate proposal id", errors.getvalue())
            proposals_path = stage / "proposals.jsonl"
            self.assertEqual(PACKETS.read_jsonl(proposals_path), [])
            with self.assertRaisesRegex(SystemExit, "no proposal"):
                SCAFFOLD.load_proposal(proposals_path, self.proposal()["id"])
            second = stage / "replies/go-bounds-2.json"
            reply = json.loads(second.read_text())
            reply["proposals"][0]["id"] = "go-second-check"
            second.write_text(json.dumps(reply))
            self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 0)
            self.assertEqual({tuple(p["supporting"]) for p in PACKETS.read_jsonl(proposals_path)},
                             {("abc",), ("def",)})

    def test_cluster_chunk_change_refused_and_manifest_requires_all_packets(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=1, min_size=1)
            corpus = [{"short": name, "repo": "sample", "subject": "fix", "files": ["x.go"],
                       "diff": "+x[i]", "signals": ["bounds"], "density": 1, "url": ""}
                      for name in ("abc", "def")]
            PACKETS.write_jsonl(args.corpus, corpus)
            self.assertEqual(PACKETS.label_emit(args), 0)
            for name in ("abc", "def"):
                (root / f"label/replies/{name}.json").write_text(json.dumps({**self.label(), "id": name}))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertEqual(PACKETS.cluster_emit(args), 0)
            packets = root / "cluster/packets"
            before = {p.name: p.read_bytes() for p in packets.glob("*.json")}
            self.assertEqual(len(before), 2)
            args.chunk = 3
            self.assertEqual(PACKETS.cluster_emit(args), 1)
            self.assertEqual({p.name: p.read_bytes() for p in packets.glob("*.json")}, before)
            for name in before:
                (root / "cluster/replies" / name).write_text(json.dumps(
                    {"cluster": Path(name).stem, "proposals": []}))
            self.assertEqual(PACKETS.cluster_ingest(args), 0)
            next(packets.glob("*.json")).unlink()
            self.assertEqual(PACKETS.cluster_ingest(args), 1)

    def test_pool_label_uses_producer_signal(self):
        self.assertIn(PACKETS.TAXONOMY["pool-reset"], HISTORY.signal_terms("p.Reset()", "fix"))

    def test_packet_lifecycle_preserves_stale_work_and_rejects_missing_state(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            stage = Path(directory) / "label"
            original = {"abc": {"id": "abc", "diff": "old"}}
            self.assertFalse(PACKETS.packet_state(stage, original, "prompt"))
            self.assertTrue(PACKETS.emit_packets(stage, original, "prompt"))
            reply = stage / "replies/abc.json"
            reply.write_text('{"id":"abc"}')
            before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*") if p.is_file()}
            for changed in ({}, {"abc": {"id": "abc", "diff": "new"}},
                            {**original, "def": {"id": "def"}}):
                self.assertFalse(PACKETS.emit_packets(stage, changed, "prompt"))
                after = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*") if p.is_file()}
                self.assertEqual(before, after)
            self.assertTrue(PACKETS.emit_packets(stage, original, "prompt"))

    def test_nonempty_corpus_without_packets_cannot_ingest(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.go"], "diff": "x"}])
            self.assertEqual(PACKETS.label_ingest(args), 1)
            self.assertFalse((root / "label/labels.jsonl").exists())
            self.assertEqual(PACKETS.cluster_ingest(args), 1)

    def test_shipped_message_yaml_styles(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PACKETS, "ROOT", Path(directory)):
            rules = Path(directory) / "rules/go/security"
            rules.mkdir(parents=True)
            for name, scalar in (("plain", "Check the index"), ("quoted", '"Check the index"'),
                                 ("folded", ">-\n  Check the index"),
                                 ("literal", "|\n  Check the index")):
                (rules / f"{name}.yml").write_text(f"message: {scalar}\n")
            self.assertEqual([row["message"] for row in PACKETS.shipped_rules("go")],
                             ["Check the index"] * 4)
            (rules / "incomplete.yml").write_text("")
            with self.assertRaisesRegex(SystemExit, "expected a YAML mapping"):
                PACKETS.shipped_rules("go")

    def test_missing_stage_input_refused(self):
        with tempfile.TemporaryDirectory() as directory, \
                self.assertRaisesRegex(SystemExit, "preceding stage"):
            PACKETS.read_jsonl(Path(directory) / "missing.jsonl")

    @staticmethod
    def label():
        return {"id": "abc", "class": "bounds", "language": "go",
                "confidence": "high", "summary": "Check index before access"}

    @staticmethod
    def proposal():
        return {"id": "go-index-check", "language": "go", "claim": "Check index",
                "classification": "syntactic", "positive": "x[i]", "near_miss": "x[0]",
                "supporting": ["abc"], "overlaps": [], "rationale": "Repeated syntax"}

    def test_label_types_and_boundaries(self):
        self.assertIsNone(PACKETS.validate_label(self.label(), "abc"))
        for field, value in (("class", []), ("class", "unknown"), ("id", "wrong"),
                             ("summary", ""), ("summary", "x" * 161),
                             ("language", None), ("confidence", "maybe")):
            with self.subTest(field=field, value=value):
                self.assertIsNotNone(PACKETS.validate_label({**self.label(), field: value}, "abc"))
        self.assertIsNone(PACKETS.validate_label({**self.label(), "summary": "x" * 160}, "abc"))

    def test_cluster_rejects_wrong_types_and_foreign_support(self):
        valid = {"cluster": "go-bounds", "proposals": [self.proposal()]}
        self.assertEqual(PACKETS.validate_cluster(valid, "go-bounds", {"abc"}, "go"),
                         (None, valid["proposals"]))
        for field, value in (("id", 12), ("language", "python"), ("positive", None),
                             ("near_miss", "x[i]"), ("claim", ""), ("supporting", [[]]),
                             ("supporting", ["foreign"]), ("overlaps", "rule"),
                             ("rationale", "x" * 301)):
            reply = {"cluster": "go-bounds", "proposals": [{**self.proposal(), field: value}]}
            with self.subTest(field=field, value=value):
                error, props = PACKETS.validate_cluster(reply, "go-bounds", {"abc"}, "go")
                self.assertIsNotNone(error)
                self.assertEqual(props, [])

    def test_label_ingest_missing_malformed_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix index", "files": ["x.go"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(PACKETS.label_emit(args), 0)
                self.assertEqual(PACKETS.label_ingest(args), 1)
                reply = root / "label/replies/abc.json"
                reply.write_text("{")
                self.assertEqual(PACKETS.label_ingest(args), 1)
                self.assertEqual(PACKETS.read_jsonl(root / "label/labels.jsonl"), [])
                reply.write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertIn("MISSING abc", errors.getvalue())
            self.assertIn("REJECT abc: invalid JSON", errors.getvalue())
            labels = PACKETS.read_jsonl(root / "label/labels.jsonl")
            self.assertEqual([(row["id"], row["agreed"]) for row in labels], [("abc", True)])


class ProbeTests(unittest.TestCase):
    def test_unknown_discovery_extension_returns_explicit_json_failure(self):
        with patch.object(PROBE, "EXTENSIONS", {}), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 1)
        report = json.loads(output.getvalue())
        discovery = next(check for check in report["checks"] if check["name"] == "discovery")
        self.assertFalse(discovery["ok"])
        self.assertIn("unsupported discovery language", discovery["detail"])
        self.assertNotIn("positive.None", discovery["detail"])

    def test_nonstring_diagnostics_return_failed_json_checks(self):
        rule_path, fixture_path = PROBE.find_rule("go-tls-min-version")
        rule = yaml.safe_load(rule_path.read_text())
        fixture = yaml.safe_load(fixture_path.read_text())
        for field in ("message", "note"):
            for value in (42, True, ["text"], {"text": "value"}):
                with self.subTest(field=field, value=value):
                    with patch.object(PROBE, "load_inputs", return_value=(
                            {**rule, field: value}, fixture["valid"], fixture["invalid"])), \
                            patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(PROBE.main(), 1)
                    report = json.loads(output.getvalue())
                    self.assertFalse(report["ok"])
                    diagnostic = next(check for check in report["checks"]
                                      if check["name"] == f"{field}-literal")
                    self.assertFalse(diagnostic["ok"])

    def test_subprocess_timeouts_return_failed_json_checks(self):
        original_run = subprocess.run
        phases = (("fixture-counts", []), ("fixture-run", []), ("arm-kills", []),
                  ("discovery", []), ("pattern-expressions", ["--sexp"]),
                  ("snapshot-update", ["--snapshot"]))
        for phase, options in phases:
            with self.subTest(phase=phase):
                calls = {"tests": 0, "timeouts": 0}

                def run(command, *args, records=calls, target=phase, **kwargs):
                    if command[1] == "test" and "-U" not in command:
                        records["tests"] += 1
                        owner = "fixture-run" if records["tests"] == 1 else "arm-kills"
                    elif command[1] == "scan":
                        owner = "fixture-counts" if "--inline-rules" in command else "discovery"
                    else:
                        owner = "snapshot-update" if "-U" in command else "pattern-expressions"
                    if owner == target:
                        records["timeouts"] += 1
                        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
                    return original_run(command, *args, **kwargs)

                with patch.object(PROBE.subprocess, "run", side_effect=run), \
                        patch("sys.argv", ["probe", "py-jwt-decode-unverified", "--json", *options]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), 1)
                self.assertGreater(calls["timeouts"], 0, "the target subprocess must be reached")
                report = json.loads(output.getvalue())
                self.assertFalse(report["ok"])
                failed = next(check for check in report["checks"] if check["name"] == phase)
                self.assertFalse(failed["ok"])
                self.assertIn("timed out", failed["detail"])
                if phase == "snapshot-update":
                    self.assertNotIn("snapshot", report)

    def test_successful_snapshot_update_with_unreadable_output_is_json_failure(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        original = SimpleNamespace(run=subprocess.run, read_text=Path.read_text)
        for failure in (PermissionError("injected snapshot read failure"),
                        UnicodeError("injected snapshot encoding failure"), None):
            with self.subTest(failure=str(failure)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for source in (source_rule, source_fixture):
                    target = root / source.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                (root / "sgconfig.yml").write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")
                snapshot = root / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
                updates = []

                def run(command, *args, records=updates, **kwargs):
                    result = original.run(command, *args, **kwargs)
                    if "-U" in command:
                        records.append(result.returncode)
                    return result

                def read(path, *args, fail=failure, target=snapshot, records=updates, **kwargs):
                    if fail is not None and path == target and records:
                        raise fail
                    return original.read_text(path, *args, **kwargs)

                with patch.object(PROBE, "ROOT", root), patch.object(Path, "read_text", read), \
                        patch.object(PROBE.subprocess, "run", side_effect=run), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), int(failure is not None))
                self.assertEqual(updates, [0], "the real scoped snapshot update must succeed")
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], failure is None)
                self.assertEqual("snapshot" in report, failure is None)
                update = next(check for check in report["checks"] if check["name"] == "snapshot-update")
                self.assertEqual(update["ok"], failure is None)
                if failure is not None:
                    self.assertIn(str(failure), update["detail"])

    def test_malformed_arm_witness_file_returns_json_failure_and_recovers(self):
        coverage = ROOT / "tests/arm_coverage.json"
        original = SimpleNamespace(read_text=Path.read_text)
        valid_text = coverage.read_text()
        retained = next(case for case in json.loads(valid_text)["cases"]
                        if case["rule"] == "py-jwt-decode-unverified")
        malformed = ["{", "[]", "{}", '{"cases": {}}', '{"cases": [null]}',
                     '{"cases": [{}]}']
        for field in ("rule", "classification", "path", "index", "source", "expected", "deleted_expected"):
            malformed.append(json.dumps({"cases": [{k: v for k, v in retained.items() if k != field}]}))
        for field, value in (("expected", True), ("deleted_expected", 2.0),
                             ("expected", -1), ("index", []), ("source", None),
                             ("classification", "unsupported")):
            malformed.append(json.dumps({"cases": [{**retained, field: value}]}))
        malformed.append(json.dumps({"cases": [retained, {**retained, "expected": 99}]}))
        for text, expected in [*((text, 1) for text in malformed), (valid_text, 0)]:
            def read(path, *args, contents=text, **kwargs):
                return contents if path == coverage else original.read_text(path, *args, **kwargs)

            with self.subTest(contents=text[:80]), patch.object(Path, "read_text", read), \
                    patch("sys.argv", ["probe", "py-jwt-decode-unverified", "--json"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), expected)
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], expected == 0)
                arm = next(check for check in report["checks"] if check["name"] == "arm-kills")
                self.assertEqual(arm["ok"], expected == 0)
                if expected:
                    self.assertTrue(arm["detail"].startswith("invalid arm_coverage.json:"),
                                    arm["detail"])

    def test_orphan_snapshot_key_rejected_and_valid_snapshot_recovers(self):
        rule_path, fixture_path = PROBE.find_rule("go-tls-min-version")
        source_snapshot = ROOT / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in (rule_path, fixture_path, source_snapshot):
                target = root / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            snapshot = root / source_snapshot.relative_to(ROOT)
            document = yaml.safe_load(snapshot.read_text())
            document["snapshots"]["orphan input"] = next(iter(document["snapshots"].values()))
            cases = ((yaml.safe_dump(document), 1, "snapshot-keys"),
                     ("[]\n", 1, "snapshot-shape"),
                     ("snapshots: []\n", 1, "snapshot-keys"),
                     (source_snapshot.read_text(), 0, "snapshot-keys"))
            for text, expected, check_name in cases:
                snapshot.write_text(text)
                with self.subTest(snapshot=text[:40]), patch.object(PROBE, "ROOT", root), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), expected)
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], expected == 0)
                checks = {item["name"]: item for item in report["checks"]}
                self.assertEqual(checks[check_name]["ok"], expected == 0)

    def test_probe_mapping_read_errors_return_json_failure(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / source_rule.relative_to(ROOT)
            fixture = root / source_fixture.relative_to(ROOT)
            for target, source in ((rule, source_rule), (fixture, source_fixture)):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            original = SimpleNamespace(read_text=Path.read_text)
            for failure in ("encoding", "permission"):
                rule.write_bytes(b"\xff" if failure == "encoding" else source_rule.read_bytes())

                def read(path, *args, fail=failure, **kwargs):
                    if fail == "permission" and path == rule:
                        raise PermissionError("injected unreadable rule")
                    return original.read_text(path, *args, **kwargs)

                with self.subTest(failure=failure), patch.object(PROBE, "ROOT", root), \
                        patch.object(Path, "read_text", read), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), 1)
                    report = json.loads(output.getvalue())
                    self.assertFalse(report["ok"])
                    self.assertTrue(any(check["name"] == "rule-shape" and not check["ok"]
                                        for check in report["checks"]))

    def test_snapshot_update_failure_cannot_return_old_snapshot(self):
        real_run = subprocess.run
        updates = []

        def fail_update(command, *args, **kwargs):
            if "-U" in command:
                updates.append(command)
                return subprocess.CompletedProcess(command, 2, "", "injected snapshot write failure")
            return real_run(command, *args, **kwargs)

        snapshot = ROOT / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
        original = snapshot.read_bytes()
        with patch.object(PROBE.subprocess, "run", side_effect=fail_update), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = PROBE.main()
        self.assertEqual(len(updates), 1)
        self.assertEqual(snapshot.read_bytes(), original)
        self.assertEqual(result, 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["ok"])
        self.assertNotIn("snapshot", report)
        self.assertIn("injected snapshot write failure", output.getvalue())
        checks = {item["name"]: item["ok"] for item in report["checks"]}
        for name in ("fixture-counts", "fixture-run", "arm-kills", "discovery"):
            self.assertTrue(checks[name], name)

    def test_jwt_witnesses_validate_each_deleted_arm(self):
        rule_path, fixture_path = PROBE.find_rule("py-jwt-decode-unverified")
        rule = yaml.safe_load(rule_path.read_text())
        cases = [case for case in json.loads((ROOT / "tests/arm_coverage.json").read_text())["cases"]
                 if case["rule"] == rule["id"]]
        self.assertEqual(len(cases), 2)
        for case in cases:
            with self.subTest(index=case["index"]):
                path = tuple(int(part) if part.isdigit() else part for part in case["path"].split("/"))
                self.assertEqual(PROBE.scan_stdin(rule, case["source"]), (1, ""))
                self.assertEqual(PROBE.scan_stdin(PROBE.delete_arm(rule, path, case["index"]),
                                                 case["source"]), (2, ""))
        iso = PROBE.Isolated(rule_path, fixture_path)
        try:
            passed, detail = PROBE.check_arms(iso, rule)
        finally:
            iso.close()
        self.assertTrue(passed, detail)
        for case in cases:
            self.assertIn(f"{case['path']}[{case['index']}]: 1 -> 2", detail)

    def test_witness_classification_is_closed(self):
        case = {"rule": "test-rule", "path": "any", "index": 0,
                "classification": "weak-count-oracle", "source": "inert",
                "expected": 1, "deleted_expected": 2}
        for classification in ("missing-fixture", "weak-count-oracle"):
            PROBE.validate_witness_case({**case, "classification": classification})
        PROBE.validate_witness_case({"rule": "test-rule", "classification": "equivalent"})
        for classification in ("unsupported", "Equivalent", "weak-count-oracle "):
            with self.subTest(classification=classification), \
                    self.assertRaisesRegex(ValueError, "classification"):
                PROBE.validate_witness_case({**case, "classification": classification})

    def test_duplicate_witness_identities_are_rejected(self):
        case = {"rule": "test-rule", "path": "any", "index": 0,
                "classification": "weak-count-oracle", "source": "inert",
                "expected": 1, "deleted_expected": 2}
        for duplicate in (dict(case), {**case, "expected": 99}):
            for cases in ([case, duplicate], [duplicate, case]):
                with self.subTest(cases=cases), \
                        coverage_cases(cases), \
                        self.assertRaisesRegex(ValueError, "duplicate witness"):
                    self.assertEqual(json.loads('{"control": true}'), {"control": True})
                    PROBE.arm_witnesses({"id": "test-rule"})
        cases = [case, {**case, "rule": "other-rule"}, {**case, "path": "other/any"},
                 {**case, "index": 1}, {"rule": "test-rule", "classification": "equivalent"}]
        with coverage_cases(cases):
            self.assertEqual(set(PROBE.arm_witnesses({"id": "test-rule"})),
                             {("any", 0), ("other/any", 0), ("any", 1)})

    def test_witness_counts_must_match_both_expected_results(self):
        rule = {"id": "test-rule", "rule": {"any": [{"pattern": "a"}, {"pattern": "b"}]}}
        cases = [{"rule": "test-rule", "path": "any", "index": index,
                  "classification": "weak-count-oracle", "source": "inert",
                  "expected": 1, "deleted_expected": 2} for index in (0, 1)]
        iso = SimpleNamespace(test=lambda _rule: (0, "test result: ok. 1 passed; 0 failed;"))
        for counts, expected in (([(1, ""), (2, "")] * 2, True),
                                 ([(1, ""), (1, "")] * 2, False),
                                 ([(0, ""), (2, "")] * 2, False),
                                 ([(None, "failed"), (2, "")] * 2, False),
                                 ([(1, ""), (None, "failed")] * 2, False)):
            with self.subTest(counts=counts), \
                    coverage_cases(cases), \
                    patch.object(PROBE, "scan_stdin", side_effect=counts):
                self.assertEqual(json.loads('{"control": true}'), {"control": True})
                self.assertEqual(PROBE.check_arms(iso, rule)[0], expected)

    def test_snapshot_refresh_and_missing_output(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        real_run = subprocess.run
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                rule = root / source_rule.relative_to(ROOT)
                fixture = root / source_fixture.relative_to(ROOT)
                for target, source in ((rule, source_rule), (fixture, source_fixture)):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                (root / "sgconfig.yml").write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")
                snapshot = root / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
                if not failure:
                    snapshot.parent.mkdir()
                    snapshot.write_text("id: go-tls-min-version\nsnapshots: {}\n")

                def update(command, *args, fail=failure, **kwargs):
                    if fail and "-U" in command:
                        return subprocess.CompletedProcess(command, 2, "", "injected missing snapshot")
                    return real_run(command, *args, **kwargs)

                with patch.object(PROBE, "ROOT", root), \
                        patch.object(PROBE.subprocess, "run", side_effect=update), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), int(failure))
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], not failure)
                self.assertEqual("snapshot" in report, not failure)
                if failure:
                    self.assertFalse(snapshot.exists())
                    self.assertIn("injected missing snapshot", output.getvalue())
                else:
                    self.assertTrue(yaml.safe_load(report["snapshot"])["snapshots"])

    def test_real_probe_uses_running_interpreter_with_different_path(self):
        # A second environment on PATH must not choose the test's child runtime.
        with tempfile.TemporaryDirectory() as directory:
            shadow = Path(directory) / "python3"
            shadow.write_text("#!/bin/sh\necho wrong-PATH-interpreter >&2\nexit 97\n")
            shadow.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                control = subprocess.run(["python3", "--version"], capture_output=True,
                                         text=True, check=False, timeout=10)
                self.assertEqual(control.returncode, 97)
                self.assertIn("wrong-PATH-interpreter", control.stderr)
                self.test_real_rule_passes_all_probe_phases()

    def test_missing_binary_has_json_failure(self):
        with patch.object(PROBE, "AST_GREP", ROOT / "missing-ast-grep"), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 1)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertIn("npm ci", output.getvalue())

    def test_empty_failed_fixture_run_has_json_failure(self):
        with patch.object(PROBE.Isolated, "test", return_value=(-9, "")), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 1)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertIn("no output, exit -9", output.getvalue())
    def test_only_fixture_failure_counts_as_arm_kill(self):
        rule = {"rule": {"any": [{"pattern": "a"}, {"pattern": "b"}]}}
        for rc, output, expected in ((8, "Cannot parse rule", False), (2, "tool failure", False),
                                     (4, "Error: test failed.", True), (4, "", False),
                                     (0, "test result: ok. 1 passed; 0 failed;", False)):
            with self.subTest(rc=rc, output=output):
                iso = SimpleNamespace(test=lambda _rule, status=rc, text=output: (status, text))
                self.assertEqual(PROBE.check_arms(iso, rule)[0], expected)

    def test_malformed_fixture_returns_failed_report(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PROBE, "ROOT", Path(directory)):
            root = Path(directory)
            rule = root / "rules/go/security/go-test.yml"
            fixture = root / "tests/go/security/go-test.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text("id: go-test\nlanguage: go\nrule: {pattern: bad($X)}\n")
            for text in ("", "scalar", "[", "id: go-test\nvalid: [safe]\n",
                         "id: go-test\nvalid: [safe]\ninvalid: [null]\n"):
                fixture.write_text(text)
                checks = []
                result = PROBE.load_inputs(rule, fixture, lambda *args, rows=checks: rows.append(args))
                self.assertIsNone(result, text)
                self.assertTrue(any(not item[1] for item in checks), text)

    def test_real_rule_passes_all_probe_phases(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/rule-probe.py"), "go-tls-min-version", "--json"],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        checks = {item["name"]: item["ok"] for item in report["checks"]}
        for name in ("fixture-counts", "fixture-run", "arm-kills", "discovery"):
            self.assertTrue(checks[name], name)

    def test_fixture_counts_reject_missing_positive_and_matching_negative(self):
        with patch.object(PROBE, "scan_stdin", side_effect=[(0, ""), (1, "")]):
            passed, detail, multiple = PROBE.fixture_counts({}, ["safe"], ["bad"])
        self.assertFalse(passed)
        self.assertEqual(detail, "invalid[0]=0; valid[0]=1")
        self.assertEqual(multiple, [])

    def test_scan_rejects_tool_failure_and_malformed_output(self):
        rule = {"id": "probe"}
        for rc, stdout in ((2, ""), (0, "{"), (0, "{}"), (0, '[{"ruleId":"other"}]')):
            with self.subTest(rc=rc, stdout=stdout), patch.object(PROBE.subprocess, "run",
                    return_value=SimpleNamespace(returncode=rc, stdout=stdout, stderr="error")):
                self.assertIsNone(PROBE.scan_stdin(rule, "inert")[0])
        for rc, stdout, count in ((0, "[]", 0), (1, '[{"ruleId":"probe"}]', 1)):
            with patch.object(PROBE.subprocess, "run",
                    return_value=SimpleNamespace(returncode=rc, stdout=stdout, stderr="")):
                self.assertEqual(PROBE.scan_stdin(rule, "inert"), (count, ""))

    def test_nested_arm_removal_preserves_original(self):
        rule = {"rule": {"all": [{"any": [{"pattern": "a"}, {"pattern": "b"}]}]}}
        arms = list(PROBE.any_arms(rule["rule"]))
        self.assertEqual(arms, [(("all", 0, "any"), 0), (("all", 0, "any"), 1)])
        mutant = PROBE.delete_arm(rule, *arms[0])
        self.assertEqual(mutant["rule"]["all"][0]["any"], [{"pattern": "b"}])
        self.assertEqual(len(rule["rule"]["all"][0]["any"]), 2)


class ScaffoldTests(unittest.TestCase):
    def test_count_update_preserves_utf8_source_under_ascii_defaults(self):
        original = ("# café 🧪\nself.assertEqual(len(rules), 3)\n"
                    "self.assertEqual(checked, 3)\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tests/test_diagnostics.py"
            path.parent.mkdir()
            path.write_bytes(original)
            with patch.object(SCAFFOLD, "ROOT", root), ascii_text_defaults():
                self.assertEqual(SCAFFOLD.bump_count(True), (3, 4))
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(SCAFFOLD.bump_count(False), (3, 4))
            self.assertEqual(path.read_bytes(), original.replace(b", 3)", b", 4)"))

    def test_missing_matcher_is_controlled_refusal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            args = SimpleNamespace(id="go-test-rule", language="go", proposal=None,
                                   positive="bad(x)", near_miss="good(x)", claim="Check",
                                   category="security", matcher=root / "missing.yml", severity="warning")
            with self.assertRaisesRegex(SystemExit, r"cannot read --matcher.*missing.yml"):
                SCAFFOLD.prepare_scaffold(args)
            self.assertFalse((root / "rules").exists())

    def test_language_prefix_boundary(self):
        for language, rule_id, valid in (("go", "golang-test-rule", False),
                ("c", "cast-test-rule", False), ("java", "javascript-test-rule", False),
                ("go", "go-check", True), ("c", "c-check", True), ("c", "nginx-check", True)):
            args = SimpleNamespace(id=rule_id, language=language, proposal=None,
                                   positive="bad(x)", near_miss="good(x)", claim="Check",
                                   category="security", matcher=None, severity="warning")
            with self.subTest(language=language, rule_id=rule_id):
                if valid:
                    self.assertEqual(SCAFFOLD.prepare_scaffold(args)[0].stem, rule_id)
                else:
                    with self.assertRaisesRegex(SystemExit, "prefixed"):
                        SCAFFOLD.prepare_scaffold(args)

    def test_scaffold_dry_run_write_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n")
            matcher = root / "matcher.yml"
            matcher.write_text("pattern: bad($X)\n")
            argv = ["rule-scaffold", "--id", "go-test-rule", "--language", "go",
                    "--category", "security", "--positive", "bad(x)", "--near-miss", "good(x)",
                    "--claim", "Check call", "--matcher", str(matcher)]
            with contextlib.redirect_stdout(io.StringIO()):
                with patch("sys.argv", [*argv, "--dry-run"]):
                    self.assertEqual(SCAFFOLD.main(), 0)
                self.assertFalse((root / "rules").exists())
                original_open = Path.open

                def fail_rule_write(path, mode="r", *values, **kwargs):
                    if path.name == "go-test-rule.yml" and mode in ("x", "w"):
                        raise OSError("injected output failure")
                    return original_open(path, mode, *values, **kwargs)

                with patch("sys.argv", argv), patch.object(Path, "open", fail_rule_write), \
                        self.assertRaisesRegex(OSError, "injected output failure"):
                    SCAFFOLD.main()
                self.assertEqual(guard.read_text().count(", 3)"), 2)

                def fail_fixture_write(path, mode="r", *values, **kwargs):
                    if path == root / "tests/go/security/go-test-rule.yml" and mode in ("x", "w"):
                        raise OSError("injected fixture failure")
                    return original_open(path, mode, *values, **kwargs)

                original_bump = SCAFFOLD.bump_count

                def fail_count_write(dry_run):
                    if not dry_run:
                        raise OSError("injected count failure")
                    return original_bump(dry_run)

                for failure in (patch.object(Path, "open", fail_fixture_write),
                                patch.object(SCAFFOLD, "bump_count", fail_count_write),
                                patch.object(Path, "replace", side_effect=OSError("count failure"))):
                    with patch("sys.argv", argv), failure, self.assertRaises(OSError):
                        SCAFFOLD.main()
                    self.assertFalse((root / "rules/go/security/go-test-rule.yml").exists())
                    self.assertFalse((root / "tests/go/security/go-test-rule.yml").exists())
                    self.assertEqual(guard.read_text().count(", 3)"), 2)
                with patch("sys.argv", argv):
                    self.assertEqual(SCAFFOLD.main(), 0)
                with patch("sys.argv", argv), self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                    SCAFFOLD.main()
            rule = yaml.safe_load((root / "rules/go/security/go-test-rule.yml").read_text())
            fixture = yaml.safe_load((root / "tests/go/security/go-test-rule.yml").read_text())
            self.assertEqual(rule["rule"], {"pattern": "bad($X)"})
            self.assertEqual(fixture, {"id": "go-test-rule", "valid": ["good(x)"], "invalid": ["bad(x)"]})
            self.assertEqual(guard.read_text().count(", 4)"), 2)

    def test_counts_update_together_and_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(SCAFFOLD, "ROOT", Path(directory)):
            path = Path(directory) / "tests/test_diagnostics.py"
            path.parent.mkdir()
            original = "self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n"
            path.write_text(original)
            self.assertEqual(SCAFFOLD.bump_count(True), (3, 4))
            self.assertEqual(path.read_text(), original)
            self.assertEqual(SCAFFOLD.bump_count(False), (3, 4))
            self.assertEqual(path.read_text(), original.replace(", 3)", ", 4)"))
            path.write_text(original.replace("checked, 3", "checked, 2"))
            with self.assertRaisesRegex(SystemExit, "disagree"):
                SCAFFOLD.bump_count(False)

    def test_missing_proposal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proposals.jsonl"
            with self.assertRaisesRegex(SystemExit, "cannot read proposals"):
                SCAFFOLD.load_proposal(path, "go-index-check")
            path.write_text('{"id": "go-other-rule"}\n')
            with self.assertRaisesRegex(SystemExit, "no proposal"):
                SCAFFOLD.load_proposal(path, "go-index-check")
            for text in ("{", "{}", "[]"):
                path.write_text(text)
                with self.assertRaises(SystemExit):
                    SCAFFOLD.load_proposal(path, "go-index-check")
