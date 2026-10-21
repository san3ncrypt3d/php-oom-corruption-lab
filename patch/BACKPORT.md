# The real fix, and how to apply it when you build PHP yourself

> TL;DR - the only complete fix is the upstream patch. Upgrade to **8.2.35 /
> 8.3.36 / 8.4.27 / 8.5.12** or newer. The `mitigations.ini` + `guard.php` in
> this folder only shrink the attack surface; they do **not** repair the Zend
> OOM state-corruption core.

## 1. The obvious fix: upgrade

| Branch | First fixed release | Status |
|--------|--------------------|--------|
| 8.5    | 8.5.12  | supported |
| 8.4    | 8.4.27  | supported |
| 8.3    | 8.3.36  | supported |
| 8.2    | 8.2.35  | supported |
| ≤ 8.1  | *none*  | **EOL - no fix will ship. Migrate.** |

Distro packages (Debian/Ubuntu `php8.*`, RHEL `php:remi`, Alpine) carry the fix
as a backported patch without changing the version string, so
`apt upgrade php8.3` is usually enough - verify with `php -v` against the table.

## 2. What the upstream patch actually changes

Fix commit: **`3584a98bda`** - *"Avoid state corruption via bailout"* - fixing
`GHSA-w8hw-w9fx-j79w` (CVE-2026-109618) and `GHSA-6wmf-4rv5-p3rp`
(CVE-2026-109619). It touches ~300 files but the mechanism is two ideas:

### (a) Stop `longjmp`-ing out of an out-of-memory condition - CVE-2026-109618

Historically, hitting `memory_limit` triggered a `zend_bailout()` (a
`longjmp`). If that fired *during request startup* - before `init_executor()`
ran - the `longjmp` skipped initialisation and jumped straight to shutdown, so
shutdown ran against half-initialised, corrupt engine state. The patch replaces
the immediate bailout with a **delayed, soft OOM** that is handled at a safe
point after execution instead of unwinding the C stack:

```c
/* Zend/zend.c - zend_execute_scripts() */
 zend_execute(op_array, retval);
+if (ZEND_HAS_OOM()) {
+    zend_handle_delayed_oom();
+}
```

A new `EG(delayed_oom)` record carries the condition, and `zend_error_zstr_at()`
learns to stand down while an OOM is being handled:

```c
-if (EG(exception)) {
+if (EG(exception) && EXPECTED(EG(delayed_oom).state != ZEND_OOM_STATE_HANDLING)) {
```

### (b) Reset globals that shutdown may read before init - CVE-2026-109619

On a SAPI that reuses a worker (PHP-FPM, FrankenPHP), a request that died early
could leave executor globals (`EG(...)`) pointing at freed memory from the
previous request. The next request's startup - which under an upload runs the
`rfc1867` handler *before* basic init - then read that stale state. The patch
explicitly clears the dangerous fields in `zend_shutdown_executor_values()`:

```c
+/* may be used by zend_error_zstr_at before init_executor */
+ZVAL_UNDEF(&EG(user_error_handler));
+ZVAL_UNDEF(&EG(user_exception_handler));
+EG(record_errors) = false;
+EG(num_errors)    = 0;
+EG(errors)        = NULL;
+EG(error_handling)= EH_NORMAL;
+EG(exception)     = NULL;
...
+EG(objects_store).object_buckets = NULL;
+EG(objects_store).top = 1;
```

## 3. If you build PHP from source and cannot jump versions

Cherry-pick the upstream commit onto your branch, then rebuild:

```bash
git clone https://github.com/php/php-src && cd php-src
git checkout PHP-8.3.35                 # your current tag
git cherry-pick 3584a98bda             # the fix
# resolve the handful of conflicts (mostly new OOM-reset lines in ext/*)
./buildconf --force && ./configure $(php-config --configure-options) && make -j
make test TESTS="Zend/tests/oom_request_parsing.phpt ext/session/tests/rfc1867_no_user_code.phpt"
```

The commit ships its own regression tests
(`Zend/tests/oom_request_parsing.phpt`, `ext/session/tests/rfc1867_*`); a clean
run of those is your proof the backport took. The sibling session-fixation
hardening is tracked separately in PHP PR **#22113** (adds a
`!PS(use_only_cookies)` guard to the `MULTIPART_EVENT_FORMDATA` handler) - pull
it too if you rely on `use_only_cookies` as a boundary.
```
