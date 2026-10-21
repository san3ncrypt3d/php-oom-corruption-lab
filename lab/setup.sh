#!/usr/bin/env bash
# One-shot lab bring-up + session-dir perm fix.
set -euo pipefail
cd "$(dirname "$0")"
${COMPOSE:-podman compose} up -d
sleep 3
for c in oomlab-fpm oomlab-apache; do
  podman exec -u root "$c" sh -c \
    'chown -R www-data:www-data /var/lib/php/sessions /var/www/html/data && chmod 1733 /var/lib/php/sessions' || true
done
echo "Apache: http://127.0.0.1:18081   nginx->FPM: http://127.0.0.1:18080"
