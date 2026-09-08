#!/usr/bin/env python3
"""harvest-history.py -- stage 1 of a rule harvest: build the candidate corpus.

Why: mining a project's fix history for ast-grep rules is a recurring task
(Snuffleupagus, nginx-zstd, coraza). Reading every commit with a model is the
expensive way; this script removes everything that is provably not a candidate
so the model stages see a small, ranked corpus. It makes no judgement about
whether a fix generalises -- that is the packet stage
(harvest-packets.py). Pipeline: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  harvest-history.py --root DIR --repos coraza coraza-nginx --out candidates.jsonl
  harvest-history.py --root DIR --repos x --index docs/harvest/x-candidates.md
  harvest-history.py ... --max-files 3 --max-lines 60   # defaults

Inputs:  DIR/<repo>/.git for each repo; commit URLs come from `origin`
         (GitHub/GitLab style) or --url-prefix.
Outputs: JSONL (one candidate per line, with the full diff) to --out or stdout;
         optional Markdown reading-order index to --index; summary on stderr.
         Fork duplicates are collapsed by `git patch-id --stable`; the earlier
         repo in --repos order wins and later ones are listed in `also_in`.
Exit:    0; a repo without .git is reported and skipped.
Side effects: none beyond the files named above. No network.
Limits:  Go and C only (SOURCE_SUFFIX). Ranking is a reading order, not a
         quality score: a one-line fix carries little vocabulary and can rank
         low while being the best candidate. Downstream reads the whole corpus.
Extend:  FIX_SUBJECT, EXCLUDE_PATH, SOURCE_SUFFIX, and the `terms` dict in
         signal_terms().
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

# Commits whose subject matches these are fixes worth reading. Kept broad on
# purpose: precision comes from the diff filters below, not from commit prose,
# which is unreliable across five repositories with different conventions.
FIX_SUBJECT = re.compile(
    r"""^(fix|bug)\b|\bfix(es|ed)?\b|\bpanic|\bnil\s|\bcrash|\bleak
        |\boverflow|\bunderflow|\brace\b|\bdeadlock|\bbypass|\bCVE-
        |\bsecurity\b|\binjection|\btraversal|\bunbounded|\bexhaust
        |\buse-after|\bdouble[- ]free|\bout[- ]of[- ]bounds|\bOOB\b""",
    re.IGNORECASE | re.VERBOSE,
)

# Source we can write rules against. Anything else is build plumbing or docs.
SOURCE_SUFFIX = {".go", ".c", ".h"}

# Paths that produce fixes which never generalise into a rule about product
# code: test bodies assert behaviour rather than exhibit it, and build/CI files
# are not scanned by the pack at all.
EXCLUDE_PATH = re.compile(
    r"(^|/)(vendor|third_party|testdata|examples?|fuzz)/"
    r"|(^|/)cmd/(testsuite|ftw)/"
    r"|(^|/)magefile\.go$"
    r"|_test\.go$"
    r"|\.pb\.go$"
    r"|(^|/)mage/",
)

# A fix that only moves whitespace or renames an identifier teaches nothing.
# Detected structurally below rather than by message, because "fix: apply mage
# format" and "fix: reset pooled field" are indistinguishable as prose.


def run(repo: Path, *args: str) -> str:
    """Decode Git losslessly; JSON escapes legacy bytes and patch-id restores them."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=True,
    ).stdout.decode("utf-8", "surrogateescape")


class SourceChange(NamedTuple):
    """One logical change, including both real paths when Git detects a rename."""
    path: str
    added: int
    deleted: int
    old_path: str | None = None


def changed_source_files(repo: Path, sha: str) -> list[SourceChange]:
    """Parse NUL-delimited numstat without treating display paths as filenames."""
    out = run(repo, "show", "--find-renames", "--numstat", "-z", "--format=", sha)
    files = []
    records = iter(out.split("\0"))
    for record in records:
        parts = record.split("\t", 2)
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        old_path = None
        if not path:
            old_path, path = next(records), next(records)
        if added == "-" or deleted == "-":  # binary
            continue
        if Path(path).suffix not in SOURCE_SUFFIX:
            continue
        if EXCLUDE_PATH.search(path):
            continue
        files.append(SourceChange(path, int(added), int(deleted), old_path))
    return files


def diff_body(repo: Path, sha: str, paths: list[str]) -> str:
    """Select literal repository-root paths even when repo is a subdirectory."""
    return run(repo, "show", "--find-renames", "--format=", "--unified=6", sha, "--",
               *(f":(top,literal){path}" for path in paths))


def is_cosmetic(before: str, after: str) -> bool:
    """Compare complete files, preserving statement order and token boundaries.

    Only outer indentation is ignored; blank-line positions can affect line
    macros even when their definitions come from another file. Literal, comment and
    continuation syntax makes equivalence
    uncertain without a lexer, so those files remain candidates. Whole-file
    context is essential: a raw-string delimiter can be far outside a hunk.
    """
    if any(marker in source for source in (before, after)
           for marker in ('"', "'", "`", "\\", "\r", "//", "/*", "*/")):
        return False

    def lines(source):
        return [line.strip() for line in source.splitlines()]

    return lines(before) == lines(after)


def cosmetic_commit(repo: Path, sha: str, changes: list[SourceChange]) -> bool:
    """Retain added/deleted files and any file whose equivalence is uncertain."""
    for change in changes:
        if change.old_path is not None:
            return False  # filenames can carry build constraints, too
        path = change.path
        try:
            before = run(repo, "show", f"{sha}^:{path}")
            after = run(repo, "show", f"{sha}:{path}")
        except (subprocess.CalledProcessError, UnicodeError):
            return False
        if not is_cosmetic(before, after):
            return False
    return True


def signal_terms(diff: str, subject: str) -> list[str]:
    """Defect vocabulary present in the change, used to rank candidates.

    These are hints for the stage-2 reader, not a classification. A candidate
    with no signal term is still emitted; it just sorts lower.
    """
    hay = (diff + "\n" + subject).lower()
    terms = {
        "panic": r"\bpanic\(",
        "nil-deref": r"!=\s*nil|==\s*nil",
        "bounds": r"\blen\(|\bcap\(|\[[a-z_]+\s*[-+]\s*1\]",
        "int-cast": r"\bu?int(8|16|32|64)?\(",
        "pool-reuse": r"sync\.Pool|\.Reset\(|Put\(|newTransaction",
        "unchecked-err": r"_,\s*(err|_)\s*[:=]|_ =",
        "concurrency": r"\bgo func|sync\.|atomic\.|mutex|lock",
        "alloc": r"make\(|malloc|calloc|realloc|ngx_p?alloc",
        "free": r"\bfree\(|ngx_pfree",
        "memcpy": r"mem(cpy|move|set)|ngx_cpymem|ngx_memcpy",
        "string-len": r"strlen|\.len\b|ngx_str",
        "encoding": r"decode|unescape|normalis|normaliz|utf8|url",
    }
    return sorted(k for k, pat in terms.items() if re.search(pat, hay, re.IGNORECASE))


def commit_url_prefix(repo: Path, fallback: str | None) -> str | None:
    """Derive a credential-free HTTPS commit URL from origin, else use fallback."""
    try:
        origin = run(repo, "remote", "get-url", "origin").strip()
    except subprocess.CalledProcessError:
        origin = ""
    if origin.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return fallback
        path = parsed.path.rstrip("/").removesuffix(".git")
        if parsed.hostname and path:
            return f"https://{parsed.netloc.rsplit('@', 1)[-1]}{path}/commit/"
        return fallback
    m = re.match(r"git@([^:/]+)[:/](.+?)(?:\.git)?/?$", origin)
    if m and not origin.startswith("/"):
        return f"https://{m.group(1)}/{m.group(2)}/commit/"
    return fallback


def harvest(repo: Path, name: str, max_files: int, max_lines: int,
            url_prefix: str | None) -> list[dict]:
    prefix = commit_url_prefix(repo, url_prefix)
    shas = run(repo, "log", "--format=%H\x1f%s\x1f%ci", "--no-merges").splitlines()
    candidates = []
    stats = {"total": 0, "subject": 0, "source": 0, "sized": 0, "cosmetic": 0}

    for line in shas:
        sha, rest = line.split("\x1f", 1)
        subject, date = rest.rsplit("\x1f", 1)
        stats["total"] += 1
        if not FIX_SUBJECT.search(subject):
            continue
        stats["subject"] += 1

        files = changed_source_files(repo, sha)
        if not files:
            continue
        stats["source"] += 1

        churn = sum(change.added + change.deleted for change in files)
        if len(files) > max_files or churn > max_lines:
            continue
        stats["sized"] += 1

        paths = list(dict.fromkeys(path for change in files
                                   for path in (change.old_path, change.path) if path is not None))
        diff = diff_body(repo, sha, paths)
        if not diff.strip():
            raise ValueError(f"no attributable diff for {sha}: {paths!r}")
        if cosmetic_commit(repo, sha, files):
            stats["cosmetic"] += 1
            continue

        candidates.append({
            "repo": name,
            "sha": sha,
            "short": sha[:12],
            "subject": subject,
            "date": date[:10],
            "files": [change.path for change in files],
            "churn": churn,
            "signals": signal_terms(diff, subject),
            "url": f"{prefix}{sha}" if prefix else "",
            "diff": diff,
        })

    print(
        f"{name:18s} commits={stats['total']:5d} "
        f"fix-subject={stats['subject']:4d} touches-source={stats['source']:4d} "
        f"in-size={stats['sized']:4d} cosmetic-dropped={stats['cosmetic']:3d} "
        f"=> candidates={len(candidates):3d}",
        file=sys.stderr,
    )
    return candidates


def dedupe_by_patch_id(root: Path, candidates: list[dict]) -> list[dict]:
    """Collapse the same change seen through a fork; first repo in order wins."""
    seen: dict[str, dict] = {}
    out = []
    for c in candidates:
        show = run(root / c["repo"], "show", c["sha"])
        pid = subprocess.run(["git", "patch-id", "--stable"],
                             input=show.encode("utf-8", "surrogateescape"),
                             capture_output=True, check=True).stdout.decode("ascii").split()
        key = pid[0] if pid else c["sha"]
        if key in seen:
            seen[key].setdefault("also_in", []).append(c["repo"])
            continue
        seen[key] = c
        out.append(c)
    return out


def write_index(path: Path, candidates: list[dict]) -> None:
    repos = sorted({c["repo"] for c in candidates})
    lines = [
        "<!-- markdownlint-disable MD013 MD060 -->",
        "<!-- generated by tools/harvest-history.py; subjects quoted verbatim -->",
        "# Harvest candidate corpus\n",
        f"{len(candidates)} unique fix commits across {', '.join(repos)}, after",
        "dropping test/vendor/example/harness paths, cosmetic-only diffs, and fork",
        "duplicates (git patch-id). Ranked by defect-vocabulary density per changed",
        "line: a reading order, not a quality score. Diffs live in the JSONL output",
        "of tools/harvest-history.py, which is regenerable and not checked in.\n",
        "Cosmetic exclusion compares complete files in order. Files containing",
        "literal, comment or continuation syntax remain candidates because",
        "their equivalence cannot be established by the conservative filter.\n",
        "| # | density | repo | commit | churn | signals | subject |",
        "|---|---------|------|--------|-------|---------|---------|",
    ]
    for i, c in enumerate(candidates, 1):
        subj = c["subject"].replace("|", "\\|")[:88]
        link = f"[`{c['short']}`]({c['url']})" if c["url"] else f"`{c['short']}`"
        lines.append(f"| {i} | {c['density']:.3f} | {c['repo']} | {link} | {c['churn']} | "
                     f"{','.join(c['signals'])} | {subj} |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path,
                    help="directory holding the cloned repositories")
    ap.add_argument("--repos", nargs="+", required=True)
    ap.add_argument("--max-files", type=int, default=3)
    ap.add_argument("--max-lines", type=int, default=60)
    ap.add_argument("--out", type=Path, help="write JSONL here instead of stdout")
    ap.add_argument("--index", type=Path, help="also write a Markdown reading-order index")
    ap.add_argument("--url-prefix", help="commit URL prefix when a repo has no origin")
    args = ap.parse_args()

    all_candidates = []
    for name in args.repos:
        repo = args.root / name
        if not (repo / ".git").exists():
            print(f"skip {name}: not a git checkout", file=sys.stderr)
            continue
        all_candidates.extend(harvest(repo, name, args.max_files, args.max_lines,
                                      args.url_prefix))

    all_candidates = dedupe_by_patch_id(args.root, all_candidates)

    # Rank by signal density per line changed, so a tight diff carrying several
    # defect terms outranks a long one that merely accumulates vocabulary by
    # chance. Ties break toward the smaller diff.
    for c in all_candidates:
        c["density"] = round(len(c["signals"]) / max(c["churn"], 1), 4)
    all_candidates.sort(key=lambda c: (-c["density"], c["churn"]))

    if args.index:
        write_index(args.index, all_candidates)

    sink = args.out.open("w") if args.out else sys.stdout
    for c in all_candidates:
        sink.write(json.dumps(c) + "\n")
    if args.out:
        sink.close()

    print(f"\ntotal candidates: {len(all_candidates)}", file=sys.stderr)
    hist: dict[str, int] = {}
    for c in all_candidates:
        for s in c["signals"]:
            hist[s] = hist.get(s, 0) + 1
    for term, n in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"  {term:16s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
