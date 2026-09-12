# Mechanics validation handoff

- Branch: `feat/mechanics-validation-throughput`
- Current head: the signed delivery commit containing this handoff (`HEAD`)
- Fixed: failed full-source CST queries now fail closed through a successful
  root-selector scan; format width/precision skip qualified conversions and
  mutate the first later eligible conversion.
- Focused: 33 tests passed.
- Full: 357 Python tests passed (9 skipped); 450 ast-grep tests passed.
- Mechanics: 3 canonical plans, 3 exact fix oracles, differential baseline
  with 3 findings.
- Next: review the exact pushed head; do not merge from this handoff alone.
