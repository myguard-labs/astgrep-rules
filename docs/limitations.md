# Detection boundaries

These migrated rules primarily identify review candidates. Tests demonstrate
syntax coverage; they do not prove all variants of a bug are detected.

- `c-prctl-set-dumpable` recognizes decimal `1` with optional `U`/`L`
  suffixes (either order and case), not computed values, aliases, or other
  integer spellings. Zero remains excluded.
- `c-memcpy-sizeof-pointer` also matches valid fixed-array and struct copies:
  ast-grep cannot resolve the identifier's type. Keep it advisory.
- Allocation, slab, response-header, reload, and intervention rules flag sites;
  they cannot prove a missing guard, initialization, or cleanup on every path.
- `c-format-string` checks format arguments in its listed libc calls; aliases
  and wrappers need separate rules. The ctype rule excludes a direct
  `unsigned char` cast, but cannot infer already-safe integer ranges, EOF, or
  typedefs. A cast elsewhere inside an expression does not make its result safe.
- `php-sql-string-interp` recognizes its listed function names and query
  positions, not database member calls or aliases. No interprocedural SQL or
  command dataflow is modeled.
- `php-extract-superglobal` recognizes a direct superglobal as the first
  positional argument. Named arguments, aliases and transformed arrays need
  separate analysis. A superglobal used only to compute flags or a prefix is
  not the extracted array.
- `php-exec-sink` inventories selected calls, including ordinary assertions.
  String evaluation by `assert` was deprecated in PHP 7.2 and removed in PHP 8.0;
  an assertion match is not a code-execution diagnosis on modern PHP. See the
  [PHP assertion contract](https://www.php.net/manual/en/function.assert.php).
- The Python YAML rule recognizes SafeLoader/CSafeLoader spellings, including
  `yaml.` qualification. Aliases and positional loaders require review; their
  safety cannot be inferred from names. Modern PyYAML requires a Loader, so a
  missing one can be an API error rather than unsafe deserialization.
- `go-exec-sprintf` flags formatted executable and argv expressions for review,
  while excluding `CommandContext`'s context argument. Go's `exec.Command`
  does not invoke a shell automatically; formatting alone is not proof of
  command injection. Inspect the executable, arguments, and whether a shell runs.
- `go-sql-sprintf` checks the documented query position for ordinary and
  context-aware methods. Syntax cannot distinguish a DB or transaction receiver
  from a prepared statement, whose Query/Exec arguments are bound values, so a
  formatted first argument on a statement remains an advisory candidate.
- `c-shell-exec` inventories its listed shell and direct-execution APIs.
  Exec arguments remain separate argv elements, but the selected program can
  interpret them. The `*p` variants can also invoke a shell after an `ENOEXEC`
  failure; see [exec(3)](https://man7.org/linux/man-pages/man3/exec.3.html).
  Executable selection, option handling and PATH lookup still need review.
  The inventory is not exhaustive: `execve` remains outside this rule.
- `nginx-shm-exists-reload-test` identifies `shm.exists` references within an
  `if` condition, including compound conditions. It excludes ordinary writes
  and argument uses outside conditions; it does not prove that the condition
  is the sole reload guard or cover every possible control-flow form.
- `c-snprintf-return-advance` covers direct compound assignments. Separately
  stored return values require another analysis; nginx formatting functions
  have different return contracts from libc.

The original alignment experiment under `candidates/` was rejected for false
positives. Its dated measurements are historical evidence, not current counts.
Use type/alignment diagnostics and executed-path sanitizers for that question.

The time truncation rule covers explicit casts and direct integer declarations.
It includes qualifiers, signed/unsigned forms, and individual declarators in a
multi-declaration. Assignments to previously declared variables need type
resolution and remain outside this matcher.

## Added rules

- `go-tls-insecure-skip-verify` and `py-requests-verify-false` match a literal
  `true`/`False`. A value supplied through a variable, config field or build flag
  is not detected; that path needs configuration review.
- `go-defer-in-loop` uses the nearest enclosing function as the boundary, so a
  defer inside a closure or goroutine within the loop is correctly excluded. It
  does not model whether the loop is bounded or the resource cheap, and it does
  not cover a helper called in the loop that defers internally.
- `py-hardcoded-tempfile` is lexical: it matches `/tmp/` and `/var/tmp/` string
  prefixes anywhere, including read-only paths and paths later replaced. It
  cannot see `TMPDIR` overrides or a path already produced by `mkdtemp`.
- `php-file-inclusion-variable` fires when a variable, subscript, call or
  interpolated string reaches the included path. A path built only from
  literals, constants and `__DIR__` does not match. It does not model taint, so
  an internal, non-request variable still matches and needs review.
- `c-strncat-size-misuse` keys on `sizeof`/`strlen` appearing as the length
  argument itself; the correct remaining-space forms subtract and do not match.
  It cannot confirm the sizeof operand is the same object as the destination,
  and an array passed as a pointer parameter makes `sizeof` wrong for reasons
  this rule does not diagnose.

`c-strncat-size-misuse` snapshots show `sizeof(dst)` as a secondary label twice:
the nested `has` annotates the same range at the argument-list and operand
levels. Scan output reports a single finding per call; the duplicate is a label
artifact, not a double match.

## Second batch

- `go-http-no-timeout` keys on field names in the literal. A client configured
  after construction, or one whose Transport carries its own deadlines, is not
  detected; a literal naming any `*Timeout` field is treated as handled even if
  the value is zero.
- `go-error-swallowed` cannot tell an error from any other discarded return, so
  it approximates: an assignment binding `err*`, `e` or `ok*` is excluded, as
  are discards of the common cleanup calls (Close/Flush/Sync/Kill/Wait/Remove/
  Set*Deadline). Measured on labs/gozer, labs/gyzor and labs/mailstrix, most
  raw matches came from vendored dependencies; scope scans to first-party
  directories. Test files legitimately discard results and dominate the rest.
- `py-jwt-decode-unverified` matches any `.decode` call carrying the disabling
  argument, so a non-JWT `decode` with a `verify` keyword would also match. It
  does not detect verification disabled through a variable or a prebuilt options
  dict.
- `py-mutable-default-arg` flags the literal default. It cannot tell whether the
  parameter is ever mutated, so a read-only default still matches; the fix is
  cheap either way.
- `php-weak-crypto` is a call inventory. md5/sha1 over non-secret data is a
  legitimate use and matches; the rule cannot see what the argument holds.
- `c-return-stack-address` binds the returned identifier to a same-function
  declaration without a storage class, so a `static` local does not match. It
  does not resolve shadowing, so a name also declared in an inner scope, or one
  that is a parameter pointer, still needs the declaration checked.

## Third batch

Rules chosen against the 2025 CWE Top 25 (CISA/MITRE, published 2025-12-11,
scored over 39,080 CVE records) after mapping the existing pack for gaps.
See <https://cwe.mitre.org/data/definitions/1435.html>.

- `php-echo-superglobal-xss` covers CWE-79, rank 1. It matches a superglobal
  reaching echo/print and clears the match when a recognised escaper wraps the
  value in the same statement. An escaper applied earlier and stored in a
  variable is not visible to it, and a value echoed into a non-HTML response is
  a legitimate dismissal.
- `php-upload-unvalidated-name` covers CWE-434. `nthChild: 2` restricts the
  match to the destination argument, so the legitimate
  `$_FILES[...]["tmp_name"]` source does not fire. It cannot see validation
  performed earlier in the function.
- `go-zip-slip` covers CWE-22. It matches a `.Name` field read inside
  filepath.Join, the archive-entry shape, and excludes a `.Name()` method call
  because `os.DirEntry` over a local directory cannot carry traversal — that
  distinction came from a false positive on
  labs/mailstrix/internal/mailstrix/scanner.go. A containment check on a later
  line is not seen; Go 1.24+ `os.OpenRoot` is the recommended fix and all
  first-party Go modules here are 1.24 or newer.
- `py-ssrf-request-fstring` covers CWE-918 and flags an interpolated URL, not a
  proven SSRF. An interpolated path under a fixed host is the common benign
  shape.
- `py-mark-safe-interpolation` covers CWE-79 in Django: interpolation happens
  before `mark_safe` marks the result, so the payload is already embedded.
  `format_html` is the fix. `mark_safe` over a constant does not match.
- `c-free-without-null` is hygiene for CWE-416/CWE-415, not a use-after-free
  finding: ast-grep models no dataflow, so it cannot prove a later use. It is
  `info` severity because short-lived scopes legitimately free without
  clearing — measured zero hits under labs/nginx-http-shield-module/src and 124
  across its ci/tests and ci/fuzz harnesses.

## Fourth batch

Selected against the OWASP Top 10:2025 (announced November 2025, final
January 2026), which added two categories the pack had no coverage for:
A03 Software Supply Chain Failures and A10 Mishandling of Exceptional
Conditions. SSRF was absorbed into A01 Broken Access Control in this edition.
See <https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/>.

- `py-bare-except` and `py-except-pass` cover A10/CWE-396/CWE-390. Both exclude
  a clause that re-raises, the documented cleanup idiom; ruff E722 and flake8
  differ on that case, and PEP 760 proposed removing the bare form outright.
  `py-except-pass` is `info` because narrow typed clauses that deliberately
  ignore an error are common and legitimate: all 34 first-party hits measured
  were typed (BrokenPipeError, SystemExit, OSError), mostly CI tooling.
  `py-bare-except` stays `warning` — it catches KeyboardInterrupt and
  SystemExit, so it is the form that actually fails open.
- `go-unchecked-type-assertion` covers CWE-476. It distinguishes `v := x.(T)`
  from `v, ok := x.(T)` by the arity of the left expression list, so comma-ok
  and type switches do not match. It cannot tell whether the dynamic type is
  already guaranteed, so an assertion immediately after a type switch still
  matches. Measured 6 first-party hits, all genuine single-value assertions.
- `nginx-unchecked-array-push` checks for the guard rather than inventorying
  call sites as `nginx-unchecked-palloc` does: it matches only when no
  comparison of the assigned name follows in the same block. It does not
  confirm the comparison is against NULL, and a guard in a called helper is
  invisible. Measured zero hits across the nginx modules here, which check
  every push; upstream nginx tracks the same omission in nginx/nginx#526.
- `php-strcmp-loose-compare` and `php-hash-loose-compare` cover CWE-697 type
  juggling. The first is an authentication bypass before PHP 8, where an array
  argument makes strcmp return NULL and NULL == 0 holds; PHP 8 raises a
  TypeError instead, but the comparison stays wrong on any pre-8 deployment.
  The second covers magic hashes, where two 0e-prefixed digit strings compare
  equal. Neither rule can tell whether the compared value is a secret, so a
  loose comparison of non-security hashes also matches.

## Fifth batch

Adds `bash` as a fifth language, closing OWASP A03:2025 Software Supply Chain
Failures — the remaining 2025 category with no coverage. Most of A03 is
registry, SBOM and provenance territory that no AST matcher can reach; these
two rules cover only its code-level slice.

- `sh-curl-pipe-shell` matches a fetch piped into an interpreter. An interpreter
  given an inline script (`python3 -c`, `perl -e`) is excluded: stdin there is
  data, not the code being run. That exclusion came from a false positive on
  tools/ollama-ask.sh, which pipes JSON into `python3 -c`. It cannot see whether
  a checksum is verified elsewhere in the script.
- `sh-tls-verify-disabled` matches the flag, not the intent. `--cacert`/`--cert`
  pointing at a private CA is the correct alternative and does not match.
- `go-context-cancel-leak` fires only when cancel is assigned to the blank
  identifier. A bound cancel that is never deferred is the more common defect
  and is invisible to this matcher; `go vet` does catch the lostcancel case.
- `php-insecure-cookie-flags` checks the options-array form and calls too short
  to carry flags. The seven-argument positional form is deliberately NOT
  checked: its flags are unnamed booleans, so a syntactic matcher cannot tell a
  flagged call from an unflagged one. The fixture carries that case under
  `valid` with a comment marking it a known gap rather than an endorsement.
- `py-tarfile-extractall` covers CWE-22. Per PEP 706, Python 3.12-3.13 emit a
  DeprecationWarning but still extract with the `fully_trusted` filter, so a
  match on those versions is exploitable; 3.14+ defaults to `data` and a match
  there is already safe. Check the interpreter floor before dismissing. Found
  one true positive outside this repo, at tools/patch-management.py:36.
- `c-scanf-unbounded-string` matches a `%s` or `%[` conversion with no field
  width in the scanf family. It reads the format literal, so a format passed
  through a variable is not seen.

## Sixth batch

Mined from the git and memory history of the owned submodules (2026-09-05),
selecting shapes with a measured hit rate on this codebase rather than from a
generic catalog.

- `nginx-unchecked-module-ctx` checks for the guard rather than inventorying
  call sites: a match means no NULL comparison or truthiness test of the
  assigned name precedes the first member access in the same block. Measured
  34 hits across `modules/nginx/*/src` and 1 in first-party code, against 274
  total fetch sites — the check is selective, not a census. All 34 third-party
  hits were confirmed to have no guard within 25 lines. It cannot prove the
  site is reachable with a NULL context: the single first-party hit
  (`ngx_stream_label_autoconf_module.c`, the `nla_stream_remember_pick`
  post-condition) is safe and carries a comment stating the invariant, which is
  the documented way to dismiss a match. A handler installed only after the
  context exists is the common benign shape.
- `c-send-without-nosignal` reads only the flags argument, so a program that
  installs `signal(SIGPIPE, SIG_IGN)` at startup or sets `SO_NOSIGPIPE` on the
  socket is safe and still matches. It does not model which of the three
  defences is present. Measured 3 first-party hits, all in
  `labs/nginx-label-autoconf-module` active health probes, where that module
  has no `SIGPIPE`, `MSG_NOSIGNAL` or `SO_NOSIGPIPE` reference anywhere — the
  shape the recurring-findings catalog flags as worst, since the crash lands on
  exactly the peer-closes case a prober exists to exercise. `write()` to a
  socket carries the same hazard and is deliberately out of scope: it is not
  distinguishable from ordinary file I/O at the AST level.

## Seventh batch

Derived from the nginx development guide's documented return conventions
(2026-09-05), then filtered by measured hit rate on `modules/nginx/*` and
`labs/nginx-*` (18010 C files). Shapes with no measured defects were dropped
rather than shipped: `ngx_cpymem`/`ngx_movemem` with a discarded return matched
0 sites, and the `ngx_sprintf` family's "return value used as a length" defect
is not separable at the AST level from the documented `p = ngx_sprintf(p, ...)`
chaining idiom, which accounts for all 394 assignment sites sampled.

- `nginx-atoi-unchecked` matches an ngx_atoi-family assignment with no binary
  comparison of the assigned name anywhere in the enclosing function. The
  function-wide guard search is deliberate: an earlier draft that demanded a
  literal `NGX_ERROR` comparison, or that searched only sibling statements,
  produced 55 hits with 13 first-party matches that were all false positives —
  code correctly validating by range (`if (first < 100)`) or guarding after an
  enclosing if/else. The shipped shape measures 9 hits across 260 call sites
  with zero first-party matches. Two were confirmed real:
  `http-let/ngx_http_let_module.c:179` adds an unvalidated offset to a pointer,
  so `NGX_ERROR` underflows `ret->data` on attacker-shaped substring arguments,
  and `nchan/.../redis_nodeset_parser.c:61` stores `NGX_ERROR` directly into
  `r->min`/`r->max`. The trade is false negatives: a comparison on an unrelated
  path still suppresses the match, and the rule cannot see validation performed
  in a callee.
- `nginx-send-header-return-ignored` matches the call as a bare expression
  statement. It does not model whether a body follows, so a handler that sends
  only headers and finalizes is harmless and still matches. Measured 17 hits,
  all third-party, zero first-party — the first-party modules already use the
  `rc == NGX_ERROR || rc > NGX_OK || r->header_only` idiom.
  `http-js-challenge/ngx_http_js_challenge.c:239` was confirmed: it calls
  `ngx_http_output_filter` unconditionally afterwards, which emits a body for a
  HEAD request and writes after a filter has already finalized the request.

## Eighth batch: measured rejections, no rules shipped

A second research pass (2026-09-05) mined the
[nginx security advisories](https://nginx.org/en/security_advisories.html)
rather than the development guide, on the theory that CVE root causes would
suggest shapes the API-contract pass missed. Every candidate was rejected on
measurement against `modules/nginx/*` and `labs/nginx-*`. The measurements are
recorded here so the same seams are not re-mined.

- `ngx_palloc(pool, sizeof(ngx_buf_t))` without a following `ngx_memzero`, the
  uninitialised-flags shape behind several memory-disclosure CVEs: 1 site in the
  whole corpus. Modules use `ngx_calloc_buf` and `ngx_create_temp_buf` (117
  sites), which zero or fully initialise the structure.
- `ngx_list_push(&r->headers_out.headers)` with no `->hash` assignment, which
  silently drops the header because iteration skips `hash == 0`: 7 raw hits, all
  false positives. Every one assigned the whole struct with `*ho = *h`, which
  carries `hash` from the source header. With struct copy, `ngx_memcpy` and
  `ngx_memzero` added as dismissals the rule measures 0.
- `ngx_strlchr`/`ngx_strnstr`/`ngx_strcasestrn` result used with no guard, a NULL
  dereference on crafted input: 4 raw hits, all on attacker-controlled data
  (`tc_url`, `unparsed_uri`), and all false positives — each site guards with
  `if (p)`, a truthiness test rather than a comparison. With `!$V` and the
  parenthesised-condition forms added, the rule measures 0.
- Allocation size computed by multiplication is already covered by
  `c-alloc-mul-overflow`, which carries the nginx pool allocators alongside
  `malloc`; a separate nginx rule would duplicate it.
- Three shapes were too broad to be selective and were not narrowed further:
  `ngx_cpymem`/`ngx_memcpy` whose length argument is a pointer subtraction (326
  hits), `$A->len - $B` underflow arithmetic (170), and pool allocation with a
  multiplied size (219, and already covered). At those rates the rule would
  flag mostly correct code.

The recurring false-positive mechanism across both research passes is the same:
a guard expressed as a truthiness test, a range check, or a struct copy rather
than the literal comparison the first draft of a matcher expects. Measure every
candidate against the corpus and read the hits before shipping; a raw count is
not a defect count.

## Ninth batch: ngx_log_debugN arity is not expressible in ast-grep

Mined from 305 C-touching `fix` commits across the owned `labs/nginx-*` modules
(2026-09-05), on the theory that bugs already fixed here recur. Commit
`e09f571`, "fix: correct ngx_log_debug macro argument count", suggested a rule:
`ngx_log_debugN` encodes its vararg count in the macro name, so a call whose
argument count disagrees with `N` passes an argument the varargs machinery never
reads, and the format directive prints an adjacent stack slot.

The class is real and it recurred: a string-aware argument counter over the
2522 `ngx_log_debugN` calls in `modules/nginx/*` and `labs/nginx-*` finds
exactly one mismatch, `labs/nginx-skeleton-module/src/ngx_http_skel_module.c:271`,
where an `ngx_log_debug2` passes three varargs.

It is nonetheless not expressible as an ast-grep rule. The check is arithmetic
over a capture — "the argument count must equal the digit in the callee name" —
so the only encoding is nine explicit alternatives keyed on `nthChild`. That
encoding does not work, and the reason is worth recording: `nthChild` over an
`argument_list` does not index arguments. A correct five-argument
`ngx_log_debug2` reports a child at `nthChild: 6`, and so does the genuinely
defective six-argument call, so true and false positives are indistinguishable
by count. Adjacent-macro concatenation (`FOO_BASENAME FOO_EXT`) is one source of
the extra child while still matching a five-metavariable pattern, and a
preprocessor conditional inside the argument list is another. An intermediate
draft that excluded `concatenated_string` outright also suppressed the one true
positive, whose format string is split across adjacent literals.

Use a script for this check, not a rule. Shift-width truncation
(`1u << s` assigned to an `ngx_uint_t`, from commit `d1488a8`) was rejected
separately: 297 sites, nearly all constant shifts such as `1u << 20` that are
correct, and the defective form is only defective when the destination is
64-bit, which is a type question ast-grep cannot answer.

## Tenth batch: mined from quality-lint catalogs

Previous passes mined CVE, CWE Top 25, OWASP, the nginx development guide and
this codebase's own fix history — all security-shaped. This pass (2026-09-05)
mined the correctness/nit catalogs instead: staticcheck's SA/S checks and
ruff's flake8-bugbear (B) rules, on the theory that the pack's `correctness`
category was thin — 11 of 69 rules, and every one of the third-party packs the
superrepo consumer vendors alongside this one is security-only, so a plain
quality defect has no lens at all. Every candidate was measured against
first-party code before shipping;
`labs/build_psol/src` is upstream pagespeed and was excluded from the counts.

- `py-raise-without-from` covers ruff B904/CWE-390. Measured 16 hits across 347
  first-party Python files, all genuine: 12 in `tools/mariadb-mcp`, 2 in
  `tools/wp_mcp_client.py`, 2 in `labs/nginx-http-sentinel-module`. Every one
  interpolates the caught exception into the message while dropping the
  explicit chain. It excludes `from None`, the documented suppression idiom,
  and a bare re-raise. It requires the raised expression to be a call, so
  `raise SomeError` (a class, no call) is a false negative; `raise SomeError()`
  and `raise mod.SomeError("x")` both match, so the gap is narrow. A raise
  inside a function, lambda or class body defined within the handler is
  excluded — that code runs later, with no active exception, where `from e`
  would be wrong and the `as e` binding is already deleted. A raise inside a
  `with` block in the handler still runs under the active exception and does
  match.
- `py-zip-without-strict` covers ruff B905/PEP 618. Measured 9 first-party
  hits; three are alignment invariants where truncation would corrupt output
  rather than crash — `eilandert/mailstrix-yara-gen/src/schedule.py:156` pairs
  cron fields with their ranges, `eilandert/mailstrix-yara-gen/src/classifier.py:216`
  pairs feature names with importances, and
  `tools/mariadb-mcp/src/server.py:829` zips three parallel
  lists. It is `info` because shortest-wins is sometimes deliberate. The
  `nthChild: 2` clause on the argument list is what excludes single-argument
  `zip()`, which cannot mismatch. A `.zip()` method call is excluded by the
  anchored `^zip$` regex, which sees the attribute node's full text `obj.zip`;
  the `kind: identifier` beside it is redundant and kept only as a guard
  against a future loosening of that anchor. A locally shadowed `zip` still
  matches — the rule resolves no bindings. Snapshots show the second argument
  as a duplicated secondary label, the same nested-`has` artifact recorded for
  `c-strncat-size-misuse`.

Measured rejections, recorded so the seams are not re-mined:

- A `requests`/session call with no `timeout=` argument: 0 first-party hits.
  Every call site in `tools/website-tester` and `labs/webtester` already passes
  one. The `go-http-no-timeout` analogue stays the only timeout rule.
- Go was measured clean on the classic staticcheck shapes across 2366
  first-party non-vendor files: `time.Tick` 0, `signal.Notify` 0, `rand.Seed`
  0, `time.Now().Sub` 0, `fmt.Sprintf("%s", x)` 0, `x == true` 0, defer in a
  range loop 0. golangci-lint already runs on those modules, so the shapes a
  Go linter covers are not worth re-encoding here.
- `in_array($needle, $haystack)` without the strict flag: 43 raw hits, 41 in
  `labs/vimbadmin/vendor` and the rest third-party, against 240 already-strict
  calls. First-party PHP does not carry the defect.
- Bash shapes (`cd $D` 1653, `rm -rf $V` 496) are too broad to narrow into a
  selective matcher at this corpus size; shellcheck already covers them.

The parse trap worth recording: a rule whose `all` array contains only `kind`
plus `not`/`inside` clauses is rejected with "Rule must have one positive
matcher" — `kind` alone does not satisfy it. Adding a positive `has` fixes it.
The `not: {has: {field: cause}}` spelling for excluding `raise ... from` also
failed to compose; `not: {pattern: 'raise $EXC($$$ARGS) from $CAUSE'}` works
and was verified against both forms on 0.45.2.

The splat case was caught in review: `zip(*rows)` is a single `list_splat`
argument that expands to many iterables, so the `nthChild: 2` clause alone
made the common transpose idiom a false negative. The shipped rule matches
either a second argument or a `list_splat`.
