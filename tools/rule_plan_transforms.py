"""Syntax-aware source transforms and regex mutation helpers for rule plans."""

import re

FORMAT_CONVERSION = re.compile(
    r"%(?!%)(?P<flags>[-+ #0]*)(?P<width>\d+|\*)?"
    r"(?P<precision>\.(?:\d+|\*))?(?P<length>hh|ll|[hljztL])?"
    r"(?P<conversion>[diuoxXfFeEgGaAcspn])")


def _lexical_kinds(source: str) -> list[str]:
    """Classify source characters conservatively as code, string, or comment."""
    kinds = ["code"] * len(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index) or source[index] == "#":
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            kinds[index:end] = ["comment"] * (end - index)
            index = end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = len(source) if end < 0 else end + 2
            kinds[index:end] = ["comment"] * (end - index)
            index = end
        elif source[index] in "'\"`":
            quote = source[index]
            delimiter = quote * 3 if source.startswith(quote * 3, index) else quote
            end = index + len(delimiter)
            while end < len(source):
                if source.startswith(delimiter, end):
                    end += len(delimiter)
                    break
                if source[end] == "\\":
                    end += 2
                else:
                    end += 1
            kinds[index:end] = ["string"] * (end - index)
            index = end
        else:
            index += 1
    return kinds


def _replace_first(source: str, expression: re.Pattern, replacement,
                   allowed: set[str]) -> tuple[str, int]:
    kinds = _lexical_kinds(source)
    for match in expression.finditer(source):
        if set(kinds[match.start():match.end()]) <= allowed:
            value = replacement(match) if callable(replacement) else match.expand(replacement)
            return source[:match.start()] + value + source[match.end():], 1
    return source, 0


def metamorphic_source(source: str, transform: str) -> str:
    """Apply one transform only to a token of the intended lexical class."""
    if transform == "parenthesized":
        return f"({source})"
    if transform == "callee-parenthesized":
        changed, count = _replace_first(
            source, re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()"),
            r"(\1)", {"code"})
    elif transform in {"qualified-name-spacing", "member-access-spacing"}:
        changed, count = _replace_first(
            source, re.compile(r"\s*(->|\.)\s*"), r" \1 ", {"code"})
    elif transform == "qualified-name":
        changed, count = _replace_first(
            source, re.compile(r"(?<!:)\b([A-Za-z_]\w*::)"), r"::\1", {"code"})
    elif transform == "member-access-swap":
        changed, count = _replace_first(
            source, re.compile(r"->|\."),
            lambda match: "." if match[0] == "->" else "->", {"code"})
    elif transform == "literal-concatenation":
        changed, count = _replace_first(
            source, re.compile(r'"([^"\\]+)"'),
            lambda match: f'"{match[1]}" ""', {"string"})
    elif transform == "literal-spacing":
        changed, count = _replace_first(
            source, re.compile(r"(['\"])\s+(['\"])"), r"\1   \2",
            {"code", "string"})
    elif transform == "format-width":
        changed, count = _transform_format_conversion(source, precision=False)
    elif transform == "format-precision":
        changed, count = _transform_format_conversion(source, precision=True)
    else:
        raise ValueError(f"unsupported metamorphic transform: {transform}")
    if count != 1 or changed == source:
        raise ValueError(f"metamorphic transform {transform} is not applicable")
    return changed


def _transform_format_conversion(source: str, *, precision: bool) -> tuple[str, int]:
    kinds = _lexical_kinds(source)
    match = next((candidate for candidate in FORMAT_CONVERSION.finditer(source)
                  if set(kinds[candidate.start():candidate.end()]) == {"string"}
                  and _preceding_percent_count(source, candidate.start()) % 2 == 0), None)
    if match is None:
        return source, 0
    parts = match.groupdict(default="")
    if precision:
        if parts["precision"]:
            return source, 0
        parts["precision"] = ".3"
    else:
        if parts["width"]:
            return source, 0
        parts["width"] = "20"
    replacement = (f"%{parts['flags']}{parts['width']}{parts['precision']}"
                   f"{parts['length']}{parts['conversion']}")
    return source[:match.start()] + replacement + source[match.end():], 1


def _preceding_percent_count(source: str, offset: int) -> int:
    count = 0
    while offset > count and source[offset - count - 1] == "%":
        count += 1
    return count


def regex_alternatives(pattern: str, *, verbose: bool = False) -> list[str]:
    """Split only top-level regex alternatives, preserving all syntax verbatim."""
    global_verbose = bool(re.match(r"^\(\?[aiLmsux-]*x[aiLmsux-]*\)", pattern))
    scan = _mask_verbose_comments(pattern) if verbose or global_verbose else pattern
    parts, start, depth, escaped, in_class = [], 0, 0, False, False
    for index, character in enumerate(scan):
        escaped, in_class, depth, separator = _regex_state(
            character, escaped, in_class, depth)
        if separator:
            parts.append(pattern[start:index])
            start = index + 1
    parts.append(pattern[start:])
    return parts if len(parts) > 1 and all(parts) else []


def _mask_verbose_comments(pattern: str) -> str:
    output, escaped, in_class, in_comment = [], False, False, False
    for character in pattern:
        if in_comment:
            output.append("\n" if character == "\n" else " ")
            in_comment = character != "\n"
        else:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "[":
                in_class = True
            elif character == "]":
                in_class = False
            elif character == "#" and not in_class:
                in_comment = True
    return "".join(output)


def _regex_state(character: str, escaped: bool, in_class: bool,
                 depth: int) -> tuple[bool, bool, int, bool]:
    if escaped:
        return False, in_class, depth, False
    if character == "\\":
        return True, in_class, depth, False
    if character == "[":
        return False, True, depth, False
    if character == "]" and in_class:
        return False, False, depth, False
    if not in_class and character == "(":
        return False, in_class, depth + 1, False
    if not in_class and character == ")":
        return False, in_class, max(0, depth - 1), False
    return False, in_class, depth, not in_class and depth == 0 and character == "|"
