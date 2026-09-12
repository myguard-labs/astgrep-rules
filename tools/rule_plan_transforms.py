"""Syntax-aware source transforms and regex mutation helpers for rule plans."""

import re
from dataclasses import dataclass, field

FORMAT_CONVERSION = re.compile(
    r"%(?!%)(?P<flags>[-+ #0]*)(?P<width>\d+|\*)?"
    r"(?P<precision>\.(?:\d+|\*))?(?P<length>hh|ll|[hljztL])?"
    r"(?P<conversion>[diuoxXfFeEgGaAcspn])")


def _lexical_kinds(source: str, language: str) -> list[str]:
    """Classify source characters conservatively as code, string, or comment."""
    kinds = ["code"] * len(source)
    index = 0
    while index < len(source):
        end = _comment_end(source, index, language)
        if end is not None:
            kinds[index:end] = ["comment"] * (end - index)
            index = end
        elif source[index] in "'\"`":
            end = _quoted_end(source, index)
            kinds[index:end] = ["string"] * (end - index)
            index = end
        elif language in {"javascript", "typescript"} and source[index] == "/":
            end = _javascript_regex_end(source, index)
            if end is not None:
                kinds[index:end] = ["string"] * (end - index)
                index = end
                continue
            index += 1
        else:
            index += 1
    return kinds


def _comment_end(source: str, index: int, language: str) -> int | None:
    slash_comments = language not in {"python", "bash", "ruby"}
    hash_comments = language in {"python", "bash", "ruby"}
    if ((slash_comments and source.startswith("//", index))
            or (hash_comments and source[index] == "#")):
        newline = source.find("\n", index)
        return len(source) if newline < 0 else newline
    if slash_comments and source.startswith("/*", index):
        close = source.find("*/", index + 2)
        return len(source) if close < 0 else close + 2
    return None


def _quoted_end(source: str, index: int) -> int:
    quote = source[index]
    delimiter = quote * 3 if source.startswith(quote * 3, index) else quote
    end = index + len(delimiter)
    while end < len(source) and not source.startswith(delimiter, end):
        end += 2 if source[end] == "\\" else 1
    return min(len(source), end + len(delimiter))


def _javascript_regex_end(source: str, index: int) -> int | None:
    previous = next((character for character in reversed(source[:index])
                     if not character.isspace()), "")
    if previous and previous not in "([=,:;!&|?{}":
        return None
    end, escaped, in_class = index + 1, False, False
    while end < len(source):
        character = source[end]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            in_class = True
        elif character == "]":
            in_class = False
        elif character == "/" and not in_class:
            end += 1
            while end < len(source) and source[end].isalpha():
                end += 1
            return end
        end += 1
    return None


def _replace_first(source: str, expression: re.Pattern, replacement,
                   language: str, target) -> tuple[str, int]:
    allowed, syntax_spans = target
    kinds = _lexical_kinds(source, language)
    for match in expression.finditer(source):
        in_syntax = syntax_spans is None or any(
            start <= match.start() and match.end() <= end for start, end in syntax_spans)
        if in_syntax and set(kinds[match.start():match.end()]) <= allowed:
            value = replacement(match) if callable(replacement) else match.expand(replacement)
            return source[:match.start()] + value + source[match.end():], 1
    return source, 0


def _parenthesize_callee(source: str,
                         syntax_spans: list[tuple[int, int]] | None) -> tuple[str, int]:
    if not syntax_spans:
        return source, 0
    start, end = syntax_spans[0]
    return source[:start] + f"({source[start:end]})" + source[end:], 1


def metamorphic_source(source: str, transform: str, language: str,
                       syntax_spans: list[tuple[int, int]] | None = None) -> str:
    """Apply one transform only to a token of the intended lexical class."""
    if transform == "parenthesized":
        return f"({source})"
    if transform == "callee-parenthesized":
        changed, count = _parenthesize_callee(source, syntax_spans)
    elif transform in {"qualified-name-spacing", "member-access-spacing"}:
        changed, count = _replace_first(
            source, re.compile(r"\s*(\?->|\?\.|->|\.)\s*"), r" \1 ", language,
            ({"code"}, syntax_spans))
    elif transform == "qualified-name":
        changed, count = _replace_first(
            source, re.compile(r"(?<!:)\b([A-Za-z_]\w*::)"), r"::\1", language,
            ({"code"}, None))
    elif transform == "member-access-swap":
        changed, count = _replace_first(
            source, re.compile(r"->|\."),
            lambda match: "." if match[0] == "->" else "->", language,
            ({"code"}, syntax_spans))
    elif transform == "literal-concatenation":
        changed, count = _replace_first(
            source, re.compile(r'"([^"\\]+)"'),
            lambda match: f'"{match[1]}" ""', language, ({"string"}, None))
    elif transform == "literal-spacing":
        changed, count = _space_literal_gap(source, syntax_spans)
    elif transform == "format-width":
        changed, count = _transform_format_conversion(source, language, precision=False)
    elif transform == "format-precision":
        changed, count = _transform_format_conversion(source, language, precision=True)
    else:
        raise ValueError(f"unsupported metamorphic transform: {transform}")
    if count != 1 or changed == source:
        raise ValueError(f"metamorphic transform {transform} is not applicable")
    return changed


def _space_literal_gap(source: str,
                       syntax_spans: list[tuple[int, int]] | None) -> tuple[str, int]:
    if not syntax_spans:
        return source, 0
    start, end = syntax_spans[0]
    return source[:start] + "   " + source[end:], 1


def _transform_format_conversion(source: str, language: str,
                                 *, precision: bool) -> tuple[str, int]:
    kinds = _lexical_kinds(source, language)
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
    """Split real top-level alternatives while preserving original regex bytes."""
    parts, start = [], 0
    for index in _top_level_bars(pattern, verbose):
        parts.append(pattern[start:index])
        start = index + 1
    parts.append(pattern[start:])
    return parts if len(parts) > 1 and all(parts) else []


INLINE_FLAGS = re.compile(r"\(\?([aiLmsuxUR]*)(?:-([aiLmsuxUR]*))?([:)])")


def inline_verbose(fragment: str, inherited: bool = False) -> bool:
    """Apply supported inline enable/disable flags to inherited verbose mode."""
    flags = INLINE_FLAGS.match(fragment)
    if not flags:
        return inherited
    enabled, disabled, _terminator = flags.groups()
    return (inherited or "x" in enabled) and "x" not in (disabled or "")


@dataclass
class _RegexState:
    modes: list[bool]
    escaped: bool = False
    in_class: bool = False
    in_comment: bool = False
    bars: list[int] = field(default_factory=list)

    def advance(self, pattern: str, index: int) -> int:
        character = pattern[index]
        if self.in_comment:
            self.in_comment = character != "\n"
        elif self.escaped:
            self.escaped = False
        elif character == "\\":
            self.escaped = True
        elif self.in_class:
            self.in_class = character != "]"
        elif character == "[":
            self.in_class = True
        elif self.modes[-1] and character == "#":
            self.in_comment = True
        elif character == "(":
            index = self._open_group(pattern, index)
        elif character == ")" and len(self.modes) > 1:
            self.modes.pop()
        elif character == "|" and len(self.modes) == 1:
            self.bars.append(index)
        return index + 1

    def _open_group(self, pattern: str, index: int) -> int:
        flags = INLINE_FLAGS.match(pattern, index)
        if not flags:
            self.modes.append(self.modes[-1])
            return index
        _enabled, _disabled, terminator = flags.groups()
        mode = inline_verbose(pattern[index:], self.modes[-1])
        if terminator == ":":
            self.modes.append(mode)
        else:
            self.modes[-1] = mode
        return flags.end() - 1


def _top_level_bars(pattern: str, verbose: bool) -> list[int]:
    """Track escape, class, nesting, scoped flags, and verbose-comment state.

    Escapes and character classes suppress structural punctuation. Each group
    inherits its parent's verbose mode unless scoped flags change it. A `#`
    starts a comment only while that active scope is verbose; parentheses and
    bars inside the comment remain inert until the newline.
    """
    state = _RegexState([verbose])
    index = 0
    while index < len(pattern):
        index = state.advance(pattern, index)
    return state.bars
