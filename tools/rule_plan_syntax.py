"""Pinned-engine CST targeting and recovery validation for rule plans."""

import json
import re
import tempfile
from itertools import pairwise
from pathlib import Path

CST_TARGET_KINDS: dict[str, dict[str, str | tuple[str, ...]]] = {
    "callee-parenthesized": {
        "c": "call_expression", "cpp": "call_expression",
        "javascript": "call_expression", "typescript": "call_expression",
        "python": "call", "java": "method_invocation",
    },
    "member-access-spacing": {
        "c": "field_expression", "cpp": "field_expression",
        "javascript": "member_expression", "typescript": "member_expression",
        "java": "field_access", "go": "selector_expression",
        "php": ("member_access_expression", "nullsafe_member_access_expression"),
    },
    "qualified-name-spacing": {
        "javascript": "member_expression", "typescript": "member_expression",
        "python": "attribute", "java": "method_invocation",
        "php": ("member_call_expression", "member_access_expression",
                "nullsafe_member_call_expression", "nullsafe_member_access_expression"),
    },
    "member-access-swap": {"c": "field_expression", "cpp": "field_expression"},
}


def target_kind(transform: str, language: str) -> str | tuple[str, ...] | None:
    return CST_TARGET_KINDS.get(transform, {}).get(language)


def syntax_spans(source: str, language: str, kind: str | tuple[str, ...], extension: str,
                 invoke) -> list[tuple[int, int]]:
    """Return character spans for full-source CST nodes of one target kind."""
    with tempfile.TemporaryDirectory(prefix="rule-plan-target-") as directory:
        path = Path(directory) / f"source.{extension}"
        path.write_text(source, encoding="utf-8")
        results = [invoke(
            ["run", "-l", language, "-k", candidate,
             "--json=compact", str(path)])
            for candidate in ((kind,) if isinstance(kind, str) else kind)]
    failed = next((result for result in results if result.returncode not in (0, 1)), None)
    if failed:
        raise RuntimeError(f"METAMORPHIC_TARGET_ERROR: {failed.stderr[-500:]}")
    findings = [row for result in results for row in json.loads(result.stdout or "[]")]
    encoded = source.encode("utf-8")
    return [
        (len(encoded[:row["range"]["byteOffset"]["start"]].decode("utf-8")),
         len(encoded[:row["range"]["byteOffset"]["end"]].decode("utf-8")))
        for row in findings
    ]


def literal_gap_spans(source: str, language: str, extension: str, invoke):
    """Return whitespace gaps bounded by two distinct string-literal CST nodes."""
    kind = "string" if language == "python" else "string_literal"
    literals = sorted(syntax_spans(source, language, kind, extension, invoke))
    return [(left[1], right[0]) for left, right in pairwise(literals)
            if source[left[1]:right[0]].isspace()
            and "\n" not in source[left[1]:right[0]]]


def callee_spans(source: str, language: str, extension: str,
                 invoke) -> list[tuple[int, int]]:
    """Return exact `$CALLEE` child spans from CST call-expression matches."""
    with tempfile.TemporaryDirectory(prefix="rule-plan-callee-") as directory:
        path = Path(directory) / f"source.{extension}"
        path.write_text(source, encoding="utf-8")
        query = (["-p", "void __f(){ $CALLEE($$$ARGS); }", "--selector",
                  "call_expression"] if language == "c" else
                 ["-p", "$CALLEE($$$ARGS)"])
        result = invoke(
            ["run", "-l", language, *query, "--json=compact", str(path)])
    if result.returncode not in (0, 1):
        raise RuntimeError(f"METAMORPHIC_TARGET_ERROR: {result.stderr[-500:]}")
    encoded = source.encode("utf-8")
    findings = json.loads(result.stdout or "[]")
    return [
        (len(encoded[:row["metaVariables"]["single"]["CALLEE"]["range"]
                     ["byteOffset"]["start"]].decode("utf-8")),
         len(encoded[:row["metaVariables"]["single"]["CALLEE"]["range"]
                     ["byteOffset"]["end"]].decode("utf-8")))
        for row in findings
    ]


def validate_full_source(source: str, language: str, extension: str,
                         deadline: float, invoke) -> None:
    """Parse a program file and reject tree-sitter ERROR or MISSING recovery."""
    with tempfile.TemporaryDirectory(prefix="rule-plan-source-") as directory:
        path = Path(directory) / f"derived.{extension}"
        path.write_text(source, encoding="utf-8")
        result = invoke(
            ["run", "-l", language, "-k", "ERROR", "--json=compact", str(path)],
            deadline=deadline)
        cst = invoke(
            ["run", "-l", language, "-p", source, "--debug-query=sexp", "--stdin"],
            deadline=deadline, input_text="")
    errors = json.loads(result.stdout or "[]")
    recovery = cst.stdout + cst.stderr
    if (result.returncode not in (0, 1) or not isinstance(errors, list) or errors
            or re.search(r"\((?:ERROR|MISSING)\b", recovery)):
        raise RuntimeError("METAMORPHIC_PARSE_ERROR: derived source is malformed")
