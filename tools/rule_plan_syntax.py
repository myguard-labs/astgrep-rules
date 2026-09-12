"""Pinned-engine CST targeting and recovery validation for rule plans."""

import json
import re
import tempfile
from pathlib import Path

CST_TARGET_KINDS = {
    "callee-parenthesized": {
        "c": "call_expression", "cpp": "call_expression",
        "javascript": "call_expression", "typescript": "call_expression",
        "python": "call", "java": "method_invocation",
    },
    "member-access-spacing": {
        "c": "field_expression", "cpp": "field_expression",
        "javascript": "member_expression", "typescript": "member_expression",
        "java": "field_access", "go": "selector_expression",
        "php": "member_access_expression",
    },
    "member-access-swap": {"c": "field_expression", "cpp": "field_expression"},
}


def target_kind(transform: str, language: str) -> str | None:
    return CST_TARGET_KINDS.get(transform, {}).get(language)


def syntax_spans(source: str, language: str, kind: str, extension: str,
                 invoke) -> list[tuple[int, int]]:
    """Return character spans for full-source CST nodes of one target kind."""
    with tempfile.TemporaryDirectory(prefix="rule-plan-target-") as directory:
        path = Path(directory) / f"source.{extension}"
        path.write_text(source, encoding="utf-8")
        result = invoke(
            ["run", "-l", language, "-k", kind, "--json=compact", str(path)])
    if result.returncode not in (0, 1):
        raise RuntimeError(f"METAMORPHIC_TARGET_ERROR: {result.stderr[-500:]}")
    findings = json.loads(result.stdout or "[]")
    encoded = source.encode("utf-8")
    return [
        (len(encoded[:row["range"]["byteOffset"]["start"]].decode("utf-8")),
         len(encoded[:row["range"]["byteOffset"]["end"]].decode("utf-8")))
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
            deadline)
        cst = invoke(
            ["run", "-l", language, "-p", source, "--debug-query=sexp", "--stdin"],
            deadline, input_text="")
    errors = json.loads(result.stdout or "[]")
    recovery = cst.stdout + cst.stderr
    if (result.returncode not in (0, 1) or not isinstance(errors, list) or errors
            or re.search(r"\((?:ERROR|MISSING)\b", recovery)):
        raise RuntimeError("METAMORPHIC_PARSE_ERROR: derived source is malformed")
