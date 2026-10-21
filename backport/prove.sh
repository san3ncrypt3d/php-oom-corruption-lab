#!/usr/bin/env bash
# Build the oom-guard-patched PHP 8.1.34 and prove the before/after on the
# faithful startup-OOM trigger. Self-contained (podman). First run compiles
# (~15-20 min); the binary is cached in /tmp/oomlab-backport afterwards.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE=/tmp/oomlab-backport
mkdir -p "$CACHE"

if [ ! -x "$CACHE/php-cgi-patched" ]; then
  echo "[*] building patched PHP 8.1.34 (one-time, ~15-20 min)..."
  podman run --rm -v "$CACHE:/out" docker.io/library/debian:bookworm bash -c '
    set -e; export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq build-essential pkg-config libxml2-dev libsqlite3-dev curl ca-certificates >/dev/null
    cd /tmp; curl -fsSLO https://www.php.net/distributions/php-8.1.34.tar.gz
    tar xf php-8.1.34.tar.gz; cd php-8.1.34
    # capture the startup phase at function entry, before error handling runs
    perl -0pi -e "s/(static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error\(zend_mm_heap \*heap,.*?size_t size\)\n\{\n)/\$1\tint oom_in_startup = (EG(current_execute_data) == NULL);\n/s" Zend/zend_alloc.c
    # fail closed in that window instead of longjmp-ing on corrupt state
    perl -0pi -e "s/\theap->overflow = 0;\n\tzend_bailout\(\);\n\texit\(1\);/\theap->overflow = 0;\n\tif (oom_in_startup) {\n\t\tfprintf(stderr, \"oom-guard: startup-window OOM -> fail-closed exit (bailout skipped)\\n\");\n\t\tfflush(stderr);\n\t\t_exit(70);\n\t}\n\tzend_bailout();\n\texit(1);/" Zend/zend_alloc.c
    grep -q oom-guard Zend/zend_alloc.c || { echo PATCH-FAILED; exit 2; }
    ./configure --disable-all --enable-cli --enable-cgi --enable-session >/dev/null
    make -j"$(nproc)" >/dev/null 2>&1
    cp sapi/cgi/php-cgi /out/php-cgi-patched
    echo "[*] build done"'
fi

python3 -c "open('/tmp/nested.bin','w').write('&'.join(['a[]'+'[b]'*63+'=c']*1000))"

podman run --rm -v "$CACHE:/cache:ro" -v /tmp/nested.bin:/nested.bin:ro docker.io/library/php:8.1.34-cli bash -c '
  echo "<?php echo \"ran user code\n\";" > /tmp/t.php
  run() {
    REQUEST_METHOD=POST CONTENT_TYPE=application/x-www-form-urlencoded CONTENT_LENGTH=$(wc -c </nested.bin) \
      SCRIPT_FILENAME=/tmp/t.php REDIRECT_STATUS=1 "$1" -n -d memory_limit=16M -d max_input_vars=100000 < /nested.bin 2>&1
    echo "  exit code: ${PIPESTATUS:-$?}"
  }
  echo "### UNPATCHED 8.1.34 (official, EOL) -> bailout ###"
  { run /usr/local/bin/php-cgi; } | sed "s/<[^>]*>//g" | grep -iE "memory size|oom-guard|exit code"
  echo
  echo "### PATCHED 8.1.34 (oom-guard backport) -> fail closed ###"
  { run /cache/php-cgi-patched; } | sed "s/<[^>]*>//g" | grep -iE "memory size|oom-guard|exit code"'
