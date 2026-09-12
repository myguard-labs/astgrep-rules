# Canonical rule plans

New mechanically generated rules keep their versioned source plan under
`plans/<language>/<category>/<id>.yml`. The mirrored rule and fixture remain
ordinary ast-grep YAML for downstream compatibility.

Run `npm run generate:check` to preflight plans, exact oracles, mutations, and
generated-file drift. Run `npm run generate` to update only artifacts owned by
plans. Existing handcrafted rules can be migrated independently.

Imported rules preserve required license and source comments through the
single-line `comments` list. Non-native top-level metadata belongs under
`extensions`; reserved ast-grep configuration keys cannot be overridden there.
Structurally redundant mutations retained for diagnostic-label compatibility
may be named under `mutation_exclusions`; each needs a reviewable rationale.

Plans may declare a syntax-only coverage matrix under `claims`. Its dimensions
are `api`, `callee`, `operator`, `argument-position`, `literal-form`, and
`syntax`; each named value lists invalid fixture sources that witness it. Every
value and every cross-dimension pair must share a witness, so a broad claim
cannot ride on disconnected examples. Runtime types, reachability, ownership,
and trust are deliberately outside this schema and need a semantic analyzer.

The optional `metamorphic` list classifies derived syntax explicitly. Each row
names a fixture `source`, one supported `transform`, and whether its detection
outcome is `equivalent` or `different`. Supported transforms cover
parenthesization, qualified-name variants, pointer/member-access swaps and
spacing, literal concatenation/spacing, and printf-style width or precision.
Inapplicable or contradictory transforms fail
before the engine runs; generated candidates never invent their own oracle.

Mutation preflight batches all loadable candidates into one pinned-engine test
process. An engine-load failure is bisected only far enough to attribute the
invalid or erroneous candidate; ordinary killed and surviving mutants retain
their stable mutation paths. All batches share the plan's cumulative deadline.
`rule-plan.py PLAN --telemetry FILE.json` records deterministic engine-process
and mutant counts alongside explicitly informational wall-clock phase timings.
The compiler validates and renders one immutable plan representation, which is
then shared by generation, preflight, and compatibility callers.
