#!/usr/bin/env python3
"""Audit every copy of the Memphis passkey runtime on this machine against SDK main.

The rule (Sep 13, 2026): every `passkey.js` and `memphis-connect.js` an app ships is a
copy of `thebes-sdk/runtime/`, never a fork. A copy that drifts silently keeps a bug the
SDK has already fixed; Proofly kept `pubKeyCredParams: [{alg: -7}]` for a day after the
algorithm fix and its users could not sign in. This script finds such copies before a
person does.

    python3 tools/passkey-copies-audit.py [--roots /workspace /home] [--json]
    python3 tools/passkey-copies-audit.py --live [tools/live-passkey-cids.txt]

`--live` fetches passkey.js (and memphis-connect.js where present) from every deployed
web contract listed in the cid file, through the boundary, and applies the same test to
the bytes a browser actually loads. That is the check that would have caught Proofly.

Exit status 0 when every copy is current, 1 when any copy is stale or carries a known
bad pattern. A copy is CURRENT when its bytes equal the SDK file; OLD-LINEAGE when its
bytes differ AND it carries a pattern the SDK has retired; DRIFT when it differs but
carries no retired pattern (a local edit; read it). Built outputs (dist/, out/, bundle/)
are reported too, because the built copy is the one a browser loads.
"""
import argparse, hashlib, json, os, re, sys

SDK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime")
FILES = ["passkey.js", "memphis-connect.js"]
RETIRED = {
    "passkey.js": [
        (re.compile(r"pubKeyCredParams:\s*\[\s*\{\s*type:\s*\"public-key\",\s*alg:\s*-7\s*\}\s*\]"), "ES256 only (pre Sep 13 algorithms fix)"),
        (re.compile(r"timeout:\s*60000"), "60 s ceremony timeout (pre Sep 14 cross-device fix)"),
        (re.compile(r"authenticatorSelection:\s*\{\s*userVerification"), "no residentKey (pre Aug 29 discoverable fix)"),
        (re.compile(r"const deadline = Date\.now\(\) \+ 8000;"), "8 s receipt budget, no submission retry, no resumable registration (pre Sep 15 new-user fix)"),
    ],
    "memphis-connect.js": [
        (re.compile(r"function finish\(fn, arg\)\s*\{"), "popup closed on failure (pre Sep 14 keep-open fix)"),
    ],
}
SKIP_DIRS = {"node_modules", ".git", "target", "target-mayo5", ".cache", "__pycache__"}


def digest(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def classify(fn, text, sdk):
    if hashlib.md5(text.encode("utf-8")).hexdigest() == sdk[fn][0]:
        return "CURRENT", ""
    hits = [w for rx, w in RETIRED[fn] if rx.search(text)]
    return ("OLD-LINEAGE", "; ".join(hits)) if hits else ("DRIFT", "differs from SDK, no retired pattern: read it")


def live(a):
    import urllib.request, urllib.error
    sdk = {f: (digest(os.path.join(SDK, f)), None) for f in FILES}
    rows = []
    for line in open(a.live, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cid, _, label = line.partition(" ")
        for fn in FILES:
            url = f"{a.boundary}/_/raw/{cid}/{fn}"
            if cid == "68647104875152":
                url = f"{a.boundary}/connect/{fn}"
            if cid == "224991029478235":
                url = f"https://thebesprotocol.com/assets/{fn}"
            try:
                text = urllib.request.urlopen(url, timeout=40).read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                if e.code == 404 and fn == "memphis-connect.js":
                    continue  # apps on the Memphis host do not ship the broker client
                rows.append({"file": f"{cid} {label} {fn}", "status": "UNREACHABLE", "md5": "", "why": f"HTTP {e.code}"})
                continue
            except Exception as e:  # noqa: BLE001
                rows.append({"file": f"{cid} {label} {fn}", "status": "UNREACHABLE", "md5": "", "why": str(e)[:80]})
                continue
            if "MemphisPasskey" not in text and "memphis" not in text.lower():
                continue
            status, why = classify(fn, text, sdk)
            rows.append({"file": f"{cid} {label} {fn}", "status": status, "md5": hashlib.md5(text.encode()).hexdigest()[:8], "why": why})
    rows.sort(key=lambda r: (r["status"] == "CURRENT", r["file"]))
    bad = [r for r in rows if r["status"] != "CURRENT"]
    if a.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print(f"{r['status']:12s} {r['md5']:8s}  {r['file']}" + (f"   <- {r['why']}" if r["why"] else ""))
        print(f"\n{len(rows)} live copies: {len(rows) - len(bad)} current, {len(bad)} not. SDK: " + ", ".join(f"{f}={sdk[f][0][:8]}" for f in FILES))
    sys.exit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", nargs="+", default=["/workspace", "/home"])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--live", nargs="?", const=os.path.join(os.path.dirname(os.path.abspath(__file__)), "live-passkey-cids.txt"))
    ap.add_argument("--boundary", default="https://memphis.mercaturaforum.com")
    a = ap.parse_args()
    if a.live:
        return live(a)
    sdk = {f: (digest(os.path.join(SDK, f)), open(os.path.join(SDK, f), encoding="utf-8", errors="replace").read()) for f in FILES}
    rows = []
    for root in a.roots:
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                if fn not in FILES:
                    continue
                p = os.path.join(dp, fn)
                if os.path.realpath(p).startswith(os.path.realpath(SDK)):
                    continue
                try:
                    md5 = digest(p)
                    text = open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if "MemphisPasskey" not in text and "memphis" not in text.lower():
                    continue  # an unrelated file with the same name
                if md5 == sdk[fn][0]:
                    status, why = "CURRENT", ""
                else:
                    hits = [w for rx, w in RETIRED[fn] if rx.search(text)]
                    status, why = ("OLD-LINEAGE", "; ".join(hits)) if hits else ("DRIFT", "differs from SDK, no retired pattern: read it")
                rows.append({"file": p, "status": status, "md5": md5[:8], "why": why})
    rows.sort(key=lambda r: (r["status"] != "OLD-LINEAGE", r["status"] != "DRIFT", r["file"]))
    bad = [r for r in rows if r["status"] != "CURRENT"]
    if a.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print(f"{r['status']:12s} {r['md5']}  {r['file']}" + (f"   <- {r['why']}" if r["why"] else ""))
        print(f"\n{len(rows)} copies: {len(rows) - len(bad)} current, {len(bad)} stale. SDK: " + ", ".join(f"{f}={sdk[f][0][:8]}" for f in FILES))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
