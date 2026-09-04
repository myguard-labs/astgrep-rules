# Detection boundaries

These migrated rules primarily identify review candidates. Tests demonstrate
syntax coverage; they do not prove all variants of a bug are detected.

- `c-memcpy-sizeof-pointer` also matches valid fixed-array and struct copies:
  ast-grep cannot resolve the identifier's type. Keep it advisory.
- Allocation, slab, response-header, reload, and intervention rules flag sites;
  they cannot prove a missing guard, initialization, or cleanup on every path.
- `c-format-string` checks format arguments in its listed libc calls; aliases
  and wrappers need separate rules. The ctype rule excludes a direct
  `unsigned char` cast, but cannot infer already-safe integer ranges, EOF, or
  typedefs. A cast elsewhere inside an expression does not make its result safe.
- `php-sql-string-interp` currently matches function calls, not all database
  member-call AST shapes. No interprocedural SQL or command dataflow is modeled.
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
- `go-exec-sprintf` flags formatted arguments for review. Go's `exec.Command`
  does not invoke a shell automatically; formatting alone is not proof of
  command injection. Inspect the executable, arguments, and whether a shell runs.
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
Assignments to previously declared variables need type resolution and remain
outside this matcher.

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
