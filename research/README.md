# Research artifacts

Reproducible scripts behind the technical sections of the write-up.

- `build_asan.sh` — builds PHP 8.3.35 and 8.3.36 with AddressSanitizer
  (`-fsanitize=address`) in a throwaway `debian:bookworm` container, CLI + CGI.
- `asan_oom_trigger.sh` — drives an ASan `php-cgi` with the faithful
  CVE-2026-109618 trigger: a POST body of deeply-nested variable names
  (`a[][b]…×63=c` ×1000, ~195 KB) that exhausts memory during request parsing,
  before any user code. Mirrors upstream `Zend/tests/oom_request_parsing.phpt`.
- `splfixedarray_oom.php` — the SplFixedArray OOM-during-`unserialize` case from
  upstream `oom_SplFixedArray___unserialize.phpt`; OOM lands inside `unserialize`.

## Findings (honest scope)

- The startup/parse OOM window is reproducible under ASan on 8.3.35, pre-auth,
  zero application dependency (`... in Unknown on line 0`).
- On PHP-FPM, vulnerable 8.3.35 crashes the worker (`exit code 70`) on this
  trigger; patched 8.3.36 survives. EOL 8.1.34 behaves like 8.3.35.
- A clean ASan **use-after-free** report was **not** produced here: the
  documented `var_destroy` UAF needs an OOM landing at a precise point in
  unserialize cleanup — exploit-grade heap grooming, which is the weaponisation
  the upstream researcher withholds and this repo deliberately does not pursue.

See [`../backport/`](../backport) for the EOL mitigation built on these findings.
