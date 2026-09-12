# Mechanics validation handoff

- Branch: `feat/mechanics-validation-throughput`
- Current head: the signed delivery commit containing this handoff (`HEAD`)
- Fixed: fixer output uses full-source CST validation, including multi-statement
  acceptance and ERROR/MISSING rejection; HTML uses its document root.
- Regex classes preserve leading `]` and POSIX-class pipes; legal Python and
  C++ raw literal forms retain delimiters and CST-bounded transformations.
- Preflight coverage is split below the 20-method threshold; immutable outcome
  initialization and top-level spacing satisfy their deterministic checks.
- Focused: 81 tests passed.
- Full: 362 Python tests passed (9 skipped); 450 ast-grep tests passed.
- Mechanics: 3 canonical plans, 3 exact fix oracles, differential baseline
  with 3 findings.
- Next: review the exact pushed head; do not merge from this handoff alone.
