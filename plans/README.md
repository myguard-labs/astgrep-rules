# Canonical rule plans

New mechanically generated rules keep their versioned source plan under
`plans/<language>/<category>/<id>.yml`. The mirrored rule and fixture remain
ordinary ast-grep YAML for downstream compatibility.

Run `npm run generate:check` to preflight plans, exact oracles, mutations, and
generated-file drift. Run `npm run generate` to update only artifacts owned by
plans. Existing handcrafted rules can be migrated independently.
