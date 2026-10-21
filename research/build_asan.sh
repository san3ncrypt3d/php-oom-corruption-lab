#!/bin/bash
set -e
cd /build
echo "[*] apt deps"; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq build-essential pkg-config libxml2-dev libsqlite3-dev curl ca-certificates >/dev/null
for ver in 8.3.35 8.3.36; do
  echo "[*] fetch php-$ver"
  curl -fsSL "https://www.php.net/distributions/php-$ver.tar.gz" -o php-$ver.tar.gz
  tar xf php-$ver.tar.gz
  cd php-$ver
  echo "[*] configure $ver (ASan)"
  CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O0" \
  LDFLAGS="-fsanitize=address" \
  ./configure --disable-all --enable-cli --enable-cgi --enable-session \
    --enable-debug >/dev/null
  echo "[*] make $ver"
  make -j"$(nproc)" >/dev/null 2>&1
  cp sapi/cli/php /build/php-$ver-asan
  cp sapi/cgi/php-cgi /build/php-cgi-$ver-asan
  cd /build
  echo "[+] built $ver -> /build/php-$ver-asan"
done
echo "[DONE]"
