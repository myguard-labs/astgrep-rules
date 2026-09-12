# Rule refinement plan

This plan governs the incremental improvement of the active rule pack and the
re-evaluation of candidates recorded in [rejected-candidates.md](rejected-candidates.md).
The default is to preserve earned behavior and enrich existing rules. Recreate
a rule only when its matcher structure cannot express the defended claim or its
provenance cannot be migrated losslessly.

## Outcomes

Every reviewed rule or rejected candidate receives exactly one outcome:

- **Enrich** — preserve the matcher and add missing contrasts, boundary cases,
  exact diagnostic or fix oracles, provenance, and mutation coverage.
- **Refine** — narrow or extend the matcher while preserving its identifier and
  documented compatibility contract.
- **Recreate** — replace an indefensible matcher from a newly stated claim and
  retain old fixtures as differential controls. Record intentional diagnostic,
  label, severity, or finding changes before regeneration.
- **Retire or reject** — keep the rule inactive when syntax cannot defend the
  claim, noise remains unacceptable, or another rule fully owns the signal.
  Record fresh evidence and the condition that could justify another review.

No outcome follows from age, origin, or a previous verdict alone.

## Prioritization

Process small, reviewable batches in this order:

1. Active rules with surviving matcher arms, known false positives, broken or
   unbound diagnostics, ineffective constraints, or stale provenance.
2. Active fixers without complete exact-output coverage and high-severity rules
   whose notes concede routine dismissals.
3. Duplicate and overlapping rules where one maintained contract can replace
   several drifting implementations.
4. Rejected and parked candidates whose blocker may have changed.
5. Low-risk metadata, spelling, formatting, and comment debt grouped into the
   normal sweep rather than one PR per rule.

Within a tier, prefer a language-sized batch or one shared matcher family. Do
not mix unrelated semantic changes merely to increase batch size.

## Active-rule workflow

For each selected rule:

1. State the smallest syntactic claim, its severity, routine dismissal, and
   facts that ast-grep cannot establish.
2. Preserve the existing valid/invalid fixtures, snapshots, identifiers,
   diagnostics, labels, URLs, provenance, and vendor extensions as the starting
   compatibility contract.
3. Add a canonical plan when repeatable generation adds value. Imported rules
   keep their license and source headers through `comments` and non-native
   metadata through `extensions`.
4. Add positive, negative, boundary, malformed-input, nested-context, alias,
   literal/comment lookalike, and negative-control fixtures as applicable.
5. Pin exact text, ranges, diagnostics, labels, and every fixed output where
   downstream behavior matters.
6. Run plan contrast and mutation preflight. A mutation exclusion is allowed
   only when the excluded mutant is mechanically shown to be equivalent and the
   plan records why the redundant structure remains.
7. Compare before/after findings on a bounded representative corpus. Read every
   addition and removal; raw count equality is not semantic equivalence.
8. Run the focused probe, mechanics suite, full native suite, applicable custom
   parser suite, deterministic lint, and independent claim review.

If preservation prevents a defensible matcher, choose **recreate** explicitly
and document the intentional compatibility break. Never make regeneration the
default migration mechanism.

## Re-evaluate rejected and parked candidates

Treat every entry in `docs/rejected-candidates.md`, including parked drafts and
language-specific rejection sections, as a review queue rather than a permanent
denylist. Re-evaluate the complete ledger once per engine/toolchain upgrade and
during each language grind.

For each entry:

1. Recover the original claim, rejection reason, counterexample, overlap, and
   any removed draft or corpus measurement.
2. Classify the old blocker: parser support, matcher expressiveness, missing
   semantic fact, false-positive rate, duplicate coverage, fixture failure, or
   unfinished drafting.
3. Check what changed since rejection: ast-grep syntax and parser behavior,
   available canonical-plan features, mutation generation, exact oracles,
   project APIs, upstream fixes, and representative source corpora.
4. Reproduce the old failure or counterexample before drafting. If it no longer
   reproduces, record the engine/toolchain version and the specific capability
   that changed.
5. Attempt the narrowest defensible syntax-only claim. Do not promote a
   semantic-only proposal merely because a matcher can be made to produce hits.
6. Measure the candidate against positive controls, the original counterexample,
   near misses, and a current bounded corpus. Inspect every hit for small
   corpora and a deterministic sample plus category counts for larger ones.
7. Assign one result:
   - **Revived** — promote into the normal plan/rule workflow with complete
     fixtures and provenance.
   - **Still rejected** — refresh the evidence and next reconsideration trigger.
   - **Semantic-tool route** — name the required compiler, CodeQL, Semgrep,
     runtime test, or API-specific analysis instead of weakening the claim.
   - **Superseded** — identify the active rule that owns the signal and prove
     fixture/corpus coverage.
8. Update the rejection entry in the same change so the ledger records the new
   date, versions, evidence, outcome, and next trigger. Never delete historical
   counterexamples when reviving a candidate; move them into negative controls.

## Batch acceptance

A batch is complete only when:

- every selected item has one recorded outcome and no unexplained finding delta;
- generated artifacts are reproducible and have no missing, duplicate, or stale
  owners;
- all matcher arms and documented mutation exclusions have mechanical evidence;
- exact diagnostic and fixer contracts pass;
- focused and full suites pass, including PowerShell when that pack changes;
- independent review has dispositioned every finding; and
- `docs/rejected-candidates.md`, `docs/sources.md`, and `docs/limitations.md` are
  updated wherever their claims changed.

Track throughput by defended outcomes, not rules rewritten. A small rejection
with a reproduced counterexample is useful progress; a large generated batch
without reviewed claims is not.

## Practical sequence

1. Start with known active-rule debt such as `null-library-function-cpp` and
   other rules already exposing probe or fixture weaknesses.
2. Migrate one representative rule family per language to establish reusable
   plan patterns without forcing all rules through immediate conversion.
3. Work through `rejected-candidates.md` section by section, beginning with
   parked drafts and parser/matcher limitations most likely changed by the new
   framework.
4. After each language pass, run a duplicate/overlap sweep and refresh the
   corresponding rejection entries.
5. Repeat after ast-grep, custom parser, or corpus upgrades; these are explicit
   triggers to reconsider prior rejections.
