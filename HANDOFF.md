# Mechanics validation handoff

- Branch: `feat/mechanics-validation-throughput`
- Current head: the signed delivery commit containing this handoff (`HEAD`)
- Fixed: metamorphic selection is bound to actual rule finding ranges;
  char/raw-string lookalikes cannot precede a matched format conversion.
- Cleanups: dead callee target map removed, method separation restored, and
  claim value names reject padding, whitespace-only, and control characters.
- Focused: 33 tests passed.
- Full: 357 Python tests passed (9 skipped); 450 ast-grep tests passed.
- Mechanics: 3 canonical plans, 3 exact fix oracles, differential baseline
  with 3 findings.
- Next: review the exact pushed head; do not merge from this handoff alone.
