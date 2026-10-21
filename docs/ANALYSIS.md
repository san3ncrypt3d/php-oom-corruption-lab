# Technical analysis — CVE-2026-109618 & CVE-2026-109619

> Scope note: this repo is a **verification lab**, not a weaponised exploit. It
> demonstrates the *primitives* (attacker bytes reaching session storage, and an
> attacker-controlled object destructor executing pre-auth) that the CVEs make
> reachable. It does not include a memory-corruption-to-shell chain.

## The two CVEs

| CVE | GHSA | Class | One-line |
|-----|------|-------|----------|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | state corruption via bailout | An OOM during request *startup* `longjmp`s past `init_executor`, so shutdown runs on corrupt engine state. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | stale global state | A worker that survives an early-request failure carries freed `EG()`/session state into the next request. |

Both were published 2026-10-21 and fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
by commit `3584a98bda`. Affected range is roughly PHP 5.4 → 8.5.11.

## Why `session.upload_progress` is the way in

`session.upload_progress.enabled` is **On by default**. When a multipart POST
carries a field named `PHP_SESSION_UPLOAD_PROGRESS`, PHP's `rfc1867` upload
handler writes progress data — including the **raw, unsanitised upload
filename** — into the session file, and it does this *very early* in request
handling, before most of the engine is initialised and with no authentication.

That gives an unauthenticated attacker two things at once:

1. **A write primitive into server-side session storage** (the filename bytes).
2. **Code that runs during the fragile early-request window** that the OOM bug
   corrupts.

## The primitives this lab demonstrates

### Primitive 1 — session-file injection (`poc/demo_injection.py`)

A single ordinary multipart POST places attacker-chosen bytes into
`sess_<id>`. Observed in the lab (`session.upload_progress.cleanup` left On by
default is defeated by a slow/raced upload; the lab sets it Off for a
deterministic demo):

```
upload_progress_demo|a:5:{...;s:4:"name";s:27:"INJECTED_MARK_<?=marker?>";...}
```

The marker is stored verbatim — no escaping, no validation.

### Primitive 2 — object destructor reachability (`poc/demo_destruct.py`)

With `session.serialize_handler = php`, a session record of the form
`key|O:...` is **deserialised into a live object** on the next
`session_start()`, and its `__destruct()` runs at request shutdown — with no
call to `unserialize()` anywhere in the application. The lab proves this with a
benign canary gadget:

```
DestructProbe::__destruct fired marker=rce-proof
```

On a real target the attacker substitutes an application/framework class whose
destructor is dangerous. See Primitive 3.

### Primitive 3 — object injection to RCE via a file-write gadget (`poc/demo_rce.py`)

No LFI/RFI required. A `__destruct()` that flushes buffered content to a path is
an extremely common gadget shape (template/view caches, compiled configs, log
buffers):

```php
class CacheFlush {
    public $cacheFile; public $html;
    public function __destruct() { if ($this->cacheFile) file_put_contents($this->cacheFile, $this->html); }
}
```

Injecting a serialised `CacheFlush` with `cacheFile` in the webroot and PHP in
`html` gives arbitrary file write, then code execution on the next request to the
dropped file. The lab proves it with a benign payload:

```
$ curl .../data/rce_proof.php
RCE-PROOF user=www-data host=... php=8.3.35
```

RFI is intentionally not demonstrated: `include "http://..."` requires
`allow_url_include=On`, off by default, so it is not a realistic path. The lab
ships the proof payload only, not a command shell.

## How the public chains compose these

- **session-file inclusion** (injection → LFI): filename bytes are PHP code; an app-level local
  file include of the session file executes them. Covered widely elsewhere; this
  lab intentionally does **not** re-demonstrate LFI.
- **serialize-handler confusion** (handler mismatch): a `php_serialize`-written session read back by
  the `php` handler lets `|` split a record so the tail deserialises as an
  object → Primitive 2 without needing LFI.
- **the startup-OOM core** (the novel core): the OOM bug corrupts engine/`EG()` state with
  **no application-specific precondition** on mod_php / FrankenPHP (D), or across
  two requests on a surviving FPM worker (E). This is the "zero-dependency"
  escalation and the reason ini mitigations are only partial.

## The OOM core, observed (`poc/demo_oom.py`)

With a low `memory_limit`, a body larger than the limit makes PHP OOM during
request startup, pre-auth, with no app code involved:

```
Allowed memory size of 2097152 bytes exhausted ... in Unknown on line 0
```

`Unknown:0` = before any script line. On FPM the vulnerable/patched difference is
visible in the worker log under identical load:

```
php:8.3.35  child exited with code 70   (worker killed, respawns — bailout corrupts state)
php:8.3.36  ready to handle connections (worker survives — delayed soft-OOM)
```

Escalating that corrupted-state window to code execution is heap/build-dependent
and intentionally not implemented here.

## Why mitigations are only partial

Turning off `upload_progress` closes Primitives 1/2's *pre-auth* delivery, but
CVE-2026-109618's corruption lives in the Zend allocator/executor, reachable by
any path that exhausts memory during startup. Only the engine patch removes it.
See `../patch/BACKPORT.md`.
