#!/usr/bin/env python3
# Read-only exposure check. Reads /info.php and prints a verdict. No attack traffic.
import argparse
import json
import sys
import urllib.request


def fetch(url):
    with urllib.request.urlopen(url.rstrip("/") + "/info.php", timeout=10) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    args = ap.parse_args()

    info = fetch(args.url)
    v = info["version_vulnerable"]
    c = info["conditions"]

    print(f"  target        : {args.url}  ({info['sapi']})")
    print(f"  php version   : {info['php_version']}  (branch {info['branch']}, "
          f"fixed in {info['fixed_version_for_branch']})")
    print(f"  version vuln  : {'YES' if v else 'no' if v is False else 'UNKNOWN'}")
    print(f"  upload_progress enabled : {c['upload_progress_enabled']}")
    print(f"  use_only_cookies        : {c['use_only_cookies']}")
    print(f"  use_strict_mode         : {c['use_strict_mode']}")
    print(f"  memory_limit            : {c['memory_limit']}")

    print()
    if v and c["upload_progress_enabled"]:
        print("  VERDICT: VULNERABLE core + session attack surface reachable.")
        print("           Patch to the fixed version. If you cannot, see patch/.")
    elif v:
        print("  VERDICT: core is vulnerable but upload_progress is off "
              "(one attack surface closed; still patch).")
    else:
        print("  VERDICT: version appears patched for this branch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
