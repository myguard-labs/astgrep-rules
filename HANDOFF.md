# Mechanics validation handoff

- Branch: `feat/mechanics-validation-throughput`
- Current head: the signed delivery commit containing this handoff (`HEAD`)
- Fixed: full CST validation rejects ERROR/MISSING recovery; structural target
  spans stay distinct from empty matches and remain bound to rule findings.
- Format mutations are restricted to language-specific string literal nodes;
  qualified-name mutations preserve finding spans and PHP floats remain inert.
- Focused: 35 tests passed.
- Full: 359 Python tests passed (9 skipped); 450 ast-grep tests passed.
- Mechanics: 3 canonical plans, 3 exact fix oracles, differential baseline
  with 3 findings.
- Next: review the exact pushed head; do not merge from this handoff alone.
