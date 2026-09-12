"""Execution and result classification for batched rule-plan mutants."""

import re
import subprocess


def batch_error(paths, malformed, detail: str):
    outcomes = {path: ("error", detail) for path in paths}
    outcomes.update(malformed)
    return outcomes


def raise_batch_error(outcomes):
    """Fail on attributed engine errors before interpreting mutant semantics."""
    for path in sorted(outcomes):
        outcome, detail = outcomes[path]
        if outcome == "error":
            raise RuntimeError(f"MUTATION_PREFLIGHT_ERROR: {path}: {detail}")


def classify(result, id_to_path, malformed):
    output = result.stdout + result.stderr
    if result.returncode != 0 and "Error: test failed." not in output:
        return None
    failed_ids = set(re.findall(r"^FAIL\s+(\S+)", output, flags=re.MULTILINE))
    outcomes = {
        path: (("killed", "test-failure") if mutant_id in failed_ids
               else ("survived", "ok"))
        for mutant_id, path in id_to_path.items()
    }
    outcomes.update(malformed)
    return outcomes


def execute(id_to_path, malformed, invoke):
    """Execute one materialized batch and return its result or attributed errors."""
    try:
        result = invoke()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return None, batch_error(
            id_to_path.values(), malformed, f"engine-error={error}")
    return result, None


def unloadable_outcome(result, item, malformed):
    output = result.stdout + result.stderr
    detail = " | ".join(output.splitlines()[-6:])[:600]
    kind = "invalid" if "file is not a valid ast-grep rule" in output else "error"
    return {**malformed, item[0]: (kind, detail)}
