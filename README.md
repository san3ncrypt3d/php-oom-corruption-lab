# php-oom-corruption-lab

Research lab, verification tooling and an **EOL backport** for two critical,
pre-authentication PHP vulnerabilities disclosed 2026-10-21:

| CVE | GHSA | Summary | Fixed in |
|-----|------|---------|----------|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM state corruption (`longjmp` past `init_executor`) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state on a reused worker | same |

**Write-up:** https://san3ncrypt3d.com/2026/10/21/php-oom-corruption/

The bug reaches back to PHP 5.4, but **only 8.2-8.5 were patched** - everything
≤ 8.1 is end-of-life and will never receive the fix. This repo is built around
that gap.

> **Defensive research, not a weapon.** The RCE demonstrated here is a known
> object-injection class driven over HTTP with benign proof payloads. The repo
> ships **no** weaponised memory-corruption exploit and **no** command shell.
> Everything runs against the bundled local lab, on a host you own.

## What's here

- **`backport/`** - the headline contribution: a surgical, fail-closed
  `zend_mm_safe_error()` patch for EOL PHP (≤ 8.1), **built and proven on
  8.1.34**. Neutralises the startup-OOM corruption while leaving in-script OOMs
  catchable.
- **`research/`** - reproducible AddressSanitizer build of 8.3.35/8.3.36 and the
  faithful OOM trigger (a 195 KB nested-variable POST that exhausts memory during
  request parsing, mirroring upstream `oom_request_parsing.phpt`).
- **`lab/`** - Docker lab (Apache mod_php + nginx/php-fpm) pinned to vulnerable
  PHP 8.3.35, two SAPIs because they fail differently.
- **`poc/`** - read-only detection, the two injection primitives, and
  `rce_handler_confusion.py` (pre-auth RCE over HTTP via serialize-handler
  confusion - no LFI, no planting).
- **`patch/`** - interim mitigations (`mitigations.ini`, an `auto_prepend`
  runtime guard) for supported versions you cannot upgrade yet.
- **`docs/`** - root-cause notes (`ANALYSIS.md`) and a step-by-step
  `REPRODUCE.md`. Full narrative write-up: [san3ncrypt3d.com](https://san3ncrypt3d.com/2026/10/21/php-oom-corruption/).

## Quick start

```bash
cd lab && podman compose up -d        # or: docker compose up -d
for c in oomlab-fpm oomlab-apache; do
  podman exec -u root $c sh -c 'mkdir -p /var/www/html/data; \
    chown -R www-data:www-data /var/lib/php/sessions /var/www/html/data; \
    chmod 1733 /var/lib/php/sessions'
done
#   Apache mod_php : http://127.0.0.1:18081
#   nginx -> FPM   : http://127.0.0.1:18080

cd ..
python3 poc/probe_conditions.py --url http://127.0.0.1:18080   # detection only
python3 poc/rce_handler_confusion.py --sid demoA               # pre-auth RCE (lab)
./poc/run_demo.sh fpm                                          # full chain
```

## Mitigate / patch

- **Supported branch** → upgrade (table above). Only complete fix.
- **Can't upgrade yet** → [`patch/mitigations.ini`](patch/mitigations.ini) +
  [`patch/guard.php`](patch/guard.php) (`auto_prepend_file`).
- **EOL PHP (≤ 8.1, no official fix)** → [`backport/`](backport) - surgical
  fail-closed OOM guard, built and proven on 8.1.34.
- **Build from source** → [`patch/BACKPORT.md`](patch/BACKPORT.md) (cherry-pick
  `3584a98bda`).

## Write-up

Full walkthrough with screenshots: **[san3ncrypt3d.com/2026/10/21/php-oom-corruption](https://san3ncrypt3d.com/2026/10/21/php-oom-corruption/)**

In this repo: [`docs/ANALYSIS.md`](docs/ANALYSIS.md) - root cause ·
[`docs/REPRODUCE.md`](docs/REPRODUCE.md) - HTTP-only repro.

## Honest scope

This reproduces the OOM trigger faithfully (pre-auth, confirmed under ASan),
shows the vulnerable/patched worker-crash difference, and ships a working EOL
backport. It does **not** include a clean ASan use-after-free: the documented
`var_destroy` UAF needs an OOM landing at a precise point in unserialize cleanup
- exploit-grade heap grooming - which this repo deliberately does not pursue.

## References (primary sources)

- php-src fix commit [`3584a98bda`](https://github.com/php/php-src/commit/3584a98bda) - "Avoid state corruption via bailout"
- Advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- PHP PR [#22113](https://github.com/php/php-src/pull/22113) - rfc1867 session-fixation hardening
- Upstream regression tests: `Zend/tests/oom_request_parsing.phpt`, `ext/session/tests/rfc1867_*`

## Teardown

```bash
cd lab && podman compose down -v
```
