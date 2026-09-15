#!/usr/bin/env python3
"""New-user battery for the Memphis passkey runtime: sign up, sign in, sign out, sign in again.

    python3 tools/e2e-new-user.py [--connect URL] [--attempts N] [--out DIR]
                                  [--local-connect-dir DIR] [--delay-pending SECONDS]
                                  [--algorithms -7,-257,-8]

What one attempt is, per algorithm (ES256 -7, RS256 -257, EdDSA -8):
  1. sign-up   an app on its own origin (served by this script, nothing deployed) opens the
               connect window; a fresh virtual authenticator, restricted to that one algorithm,
               completes the three-factor "Create a new identity" ceremony for a fresh handle
  2. sign-in   the app forgets the session; the connect window signs the same handle in again
               with the passkey the authenticator holds (same device)
  3. sign-in   a second browser context, whose authenticator was given the same credential
               (a synced passkey, or the phone the QR code reaches), signs the handle in
               (the cross-device shape)

Pass/fail, committed here: every step succeeds, the three sessions name the same anchor,
exactly one `register` call is on the wire per attempt, and `anchor_for_name(handle)` resolves.
Exit status 0 only when every attempt passes.

`--delay-pending S` makes the browser see every update as unconfirmed for S seconds after it
is submitted (the receipt answers "pending"); the chain is untouched. It is the regression gate
for the transport: with the runtime before 2026-09-15 any value above 8 fails every attempt.
`--local-connect-dir DIR` serves connect.html, passkey.js, recovery.js and memphis-connect.js from
DIR at the connect origin, so a candidate runtime is tested before it is deployed.

Requires Playwright with Chromium (`pip install playwright && playwright install chromium`).
"""
import argparse, json, os, sys, time, urllib.request
from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--connect", default="https://memphis.mercaturaforum.com/connect/")
ap.add_argument("--attempts", type=int, default=1)
ap.add_argument("--out", default=None)
ap.add_argument("--local-connect-dir", default=None)
ap.add_argument("--delay-pending", type=float, default=0.0)
ap.add_argument("--algorithms", default="-7,-257,-8")
ap.add_argument("--app-origin", default="https://example-app.test")
ap.add_argument("--bed-node", default=None, help="route every canister call to this node URL instead of the public boundary (a local test chain)")
ap.add_argument("--bed-cid", type=int, default=None, help="the identity canister id on that chain")
ap.add_argument("--discoverable", action="store_true", help="the cross-device step signs in with the passkey alone, no handle typed (needs a canister that lists discoverable_authentication)")
A = ap.parse_args()

CONNECT = A.connect
CONNECT_ORIGIN = CONNECT.split("/connect")[0]
OUT = A.out or ("e2e-new-user-" + time.strftime("%Y%m%dT%H%MZ", time.gmtime()))
os.makedirs(OUT, exist_ok=True)
APP_URL = A.app_origin + "/app"
ALG_NAMES = {-7: "ES256", -257: "RS256", -8: "EdDSA"}


def app_html(module_src, app_name):
    return """<!doctype html><html><body><button id="go">Sign in</button><button id="out">Sign out</button>
<script>%s</script>
<script>
window.__result = null; window.__error = null;
document.getElementById('go').addEventListener('click', function () {
  window.__result = null; window.__error = null;
  memphis.connect({ app: '%s', connectUrl: '%s' })
    .then(function (r) { window.__result = r; })
    .catch(function (e) { window.__error = { message: e.message, code: e.code }; });
});
document.getElementById('out').addEventListener('click', function () { memphis.signOut('%s'); });
</script></body></html>""" % (module_src, app_name, CONNECT, app_name)


ONLY_ALG_INIT = """
(() => {
  const only = %d;
  const orig = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = (opts) => {
    if (opts && opts.publicKey && Array.isArray(opts.publicKey.pubKeyCredParams)) {
      opts.publicKey.pubKeyCredParams = opts.publicKey.pubKeyCredParams.filter(p => p.alg === only);
    }
    return orig(opts);
  };
})();
"""


def authenticator(ctx, page):
    s = ctx.new_cdp_session(page)
    s.send("WebAuthn.enable", {"enableUI": False})
    a = s.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return s, a["authenticatorId"]


def route_to_bed(ctx):
    """The runtime speaks to the public boundary by absolute URL; on a bed every one of those
    requests is re-addressed to the local node (call, receipt, next_nonce, and the v1 query shape,
    whose base64 reply the node answers in hex)."""
    import base64 as b64mod
    bed, cid = A.bed_node.rstrip("/"), A.bed_cid
    def handler(route, request):
        url = request.url
        path = url.split(CONNECT_ORIGIN, 1)[1]
        api = ctx.request
        try:
            if path.startswith("/api/call"):
                body = json.loads(request.post_data or "{}"); body["canister_id"] = cid
                r = api.post(bed + "/api/call", data=json.dumps(body), headers={"content-type": "application/json"})
                route.fulfill(status=r.status, content_type="application/json", body=r.body())
            elif path.startswith("/api/receipt") or path.startswith("/api/next_nonce"):
                r = api.get(bed + path)
                route.fulfill(status=r.status, content_type="application/json", body=r.body())
            elif "/query" in path:
                body = json.loads(request.post_data or "{}")
                arg_hex = b64mod.b64decode(body.get("arg", "")).hex()
                r = api.post(bed + "/api/query", data=json.dumps({"canister_id": cid, "method": body.get("method"), "arg": arg_hex, "sender": ""}), headers={"content-type": "application/json"})
                j = r.json()
                if j.get("status") == "success" and j.get("reply") is not None:
                    j["reply"] = b64mod.b64encode(bytes.fromhex(j["reply"])).decode()
                route.fulfill(status=200, content_type="application/json", body=json.dumps(j))
            else:
                route.continue_()
        except Exception as e:
            route.fulfill(status=502, content_type="application/json", body=json.dumps({"status": "error", "error": "bed route: " + str(e)}))
    ctx.route(CONNECT_ORIGIN + "/api/**", handler)


def query_anchor(handle):
    import base64
    if A.bed_node:
        n = handle.encode()
        def uleb(x):
            o = bytearray()
            while True:
                b = x & 0x7f; x >>= 7
                if x == 0:
                    o.append(b); return bytes(o)
                o.append(b | 0x80)
        arg = b"DIDL\x00\x01\x71" + uleb(len(n)) + n
        req = urllib.request.Request(A.bed_node.rstrip("/") + "/api/query",
            data=json.dumps({"canister_id": A.bed_cid, "method": "anchor_for_name", "arg": arg.hex(), "sender": ""}).encode(),
            headers={"content-type": "application/json"})
        r = json.load(urllib.request.urlopen(req, timeout=30))
        rep = bytes.fromhex(r.get("reply", "")) if r.get("status") == "success" else b""
        return rep[-32:].hex() if len(rep) > 40 and rep[-34] == 1 and rep[-33] == 0x20 else None
    n = handle.encode()
    def uleb(x):
        o = bytearray()
        while True:
            b = x & 0x7f; x >>= 7
            if x == 0:
                o.append(b); return bytes(o)
            o.append(b | 0x80)
    arg = b"DIDL\x00\x01\x71" + uleb(len(n)) + n
    req = urllib.request.Request(CONNECT_ORIGIN + "/api/v1/canister/921/query",
        data=json.dumps({"method": "anchor_for_name", "arg": base64.b64encode(arg).decode(), "sender": ""}).encode(),
        headers={"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=30))
    rep = base64.b64decode(r.get("reply", "")) if r.get("status") == "success" else b""
    # opt blob, present: ... 0x01 (some) 0x20 (length 32) then the 32-byte anchor
    return rep[-32:].hex() if len(rep) > 40 and rep[-34] == 1 and rep[-33] == 0x20 else None


class Rig:
    def __init__(self, p, alg, rec):
        self.p, self.alg, self.rec = p, alg, rec
        self.module_src = (open(os.path.join(A.local_connect_dir, "memphis-connect.js")).read() if A.local_connect_dir
                           else urllib.request.urlopen(CONNECT + "memphis-connect.js", timeout=30).read().decode())

    def context(self):
        b = self.p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1280, "height": 900})
        ctx.add_init_script(ONLY_ALG_INIT % self.alg)
        if A.bed_node:
            route_to_bed(ctx)
        if A.local_connect_dir:
            def serve(route, request):
                name = request.url.split("?")[0].rstrip("/").split("/")[-1] or "connect.html"
                if name == "connect":
                    name = "connect.html"
                path = os.path.join(A.local_connect_dir, name)
                if os.path.exists(path):
                    ct = "text/html" if name.endswith(".html") else "application/javascript"
                    route.fulfill(status=200, content_type=ct, body=open(path, "rb").read())
                else:
                    route.continue_()
            ctx.route("**/connect/**", serve)
            ctx.route("**/connect/", serve)
        pg = ctx.new_page()
        body = app_html(self.module_src, "new-user-e2e")
        pg.route(APP_URL, lambda route, request: route.fulfill(status=200, content_type="text/html", body=body))
        pg.goto(APP_URL, wait_until="load", timeout=60000)
        authenticator(ctx, pg)
        return b, ctx, pg

    def wire(self, popup, log):
        submitted = {}
        def on_resp(resp):
            r = resp.request
            if "/api/call" in r.url:
                try:
                    m = json.loads(r.post_data or "{}").get("method")
                    h = json.loads(resp.text()).get("message_hash")
                    submitted[h] = (time.time(), m)
                    log.append({"t": round(time.time(), 1), "call": m, "hash": (h or "")[:12]})
                except Exception:
                    pass
        popup.on("response", on_resp)
        popup.on("console", lambda m: log.append({"t": round(time.time(), 1), "console": m.text[:300]}))
        if A.delay_pending > 0:
            def gate(route, request):
                h = request.url.split("hash=")[-1]
                t = submitted.get(h)
                if t and time.time() - t[0] < A.delay_pending:
                    route.fulfill(status=200, content_type="application/json", body=json.dumps({"found": False, "lifecycle": "pending"}))
                else:
                    route.continue_()
            popup.route("**/api/receipt*", gate)

    def ceremony(self, ctx, pg, handle, mode, log, creds=None):
        with ctx.expect_page(timeout=30000) as pi:
            pg.click("#go")
        popup = pi.value
        self.wire(popup, log)
        popup.wait_for_load_state("load", timeout=60000)
        # A virtual authenticator is bound to one target. The popup is a new target every
        # time, so the device's credentials are put back on it: this is the same device.
        s, aid = authenticator(ctx, popup)
        for c in creds or []:
            s.send("WebAuthn.addCredential", {"authenticatorId": aid, "credential": {
                "credentialId": c["credentialId"], "isResidentCredential": True, "rpId": "memphis.mercaturaforum.com",
                "privateKey": c["privateKey"], "userHandle": c.get("userHandle") or "AA==", "signCount": c.get("signCount", 0)}})
        popup.fill("#handle", handle)
        if mode == "create":
            popup.click("#create")
            popup.wait_for_selector("#phraseStep:not([hidden])", timeout=60000)
            popup.check("#phraseOk")
            popup.click("#phraseGo")
        else:
            popup.click("#go")
        # The authenticator lives with the popup and closes with it, so the credentials it
        # minted are read while the ceremony runs; the last reading is the one kept.
        creds = []
        deadline = time.time() + 900
        while time.time() < deadline:
            if not popup.is_closed():
                try:
                    got = s.send("WebAuthn.getCredentials", {"authenticatorId": aid})["credentials"]
                    if got:
                        creds = got
                except Exception:
                    pass
            r = pg.evaluate("()=>window.__result && {name: window.__result.name, anchorId: window.__result.anchorId, hasToken: !!window.__result.token}")
            e = pg.evaluate("()=>window.__error")
            if r or e:
                return r, e, creds
            try:
                pg.wait_for_timeout(500)
            except Exception:
                break
        return None, {"message": "no answer within 900 s"}, creds


def attempt(p, alg, i):
    handle = "e2e%d-%s-%d.thebes" % (int(time.time()) % 100000, ALG_NAMES[alg].lower(), i)
    rec = {"alg": alg, "algorithm": ALG_NAMES[alg], "handle": handle, "steps": {}, "log": []}
    rig = Rig(p, alg, rec)
    b, ctx, pg = rig.context()
    try:
        r1, e1, creds = rig.ceremony(ctx, pg, handle, "create", rec["log"])
        rec["steps"]["signup"] = {"result": r1, "error": e1}
        rec["credentials_on_authenticator"] = len(creds)
        if r1:
            for pgx in ctx.pages:
                if pgx is not pg and not pgx.is_closed():
                    pgx.close()
            pg.click("#out")
            r2, e2, _ = rig.ceremony(ctx, pg, handle, "signin", rec["log"], creds)
            rec["steps"]["signin_same_device"] = {"result": r2, "error": e2}
        else:
            r2 = None
        b2, ctx2, pg2 = rig.context()
        try:
            if r1:
                # The credentials the first context minted, on a second authenticator: a synced
                # passkey, or the phone a QR code reaches. rpId and residency are what the
                # discoverable request needs; the user handle is never read by the service. The
                # ceremony runs in the popup, whose own authenticator is attached when it opens.
                with ctx2.expect_page(timeout=30000) as pi:
                    pg2.click("#go")
                popup = pi.value
                rig.wire(popup, rec["log"])
                popup.wait_for_load_state("load", timeout=60000)
                s3, aid3 = authenticator(ctx2, popup)
                for c in creds:
                    s3.send("WebAuthn.addCredential", {"authenticatorId": aid3, "credential": {
                        "credentialId": c["credentialId"], "isResidentCredential": True, "rpId": "memphis.mercaturaforum.com",
                        "privateKey": c["privateKey"], "userHandle": c.get("userHandle") or "AA==", "signCount": c.get("signCount", 0)}})
                if A.discoverable:
                    popup.wait_for_selector("#device:not([hidden])", timeout=60000)
                    popup.click("#device")
                else:
                    popup.fill("#handle", handle)
                    popup.click("#go")
                deadline = time.time() + 900
                r3, e3 = None, None
                while time.time() < deadline:
                    r3 = pg2.evaluate("()=>window.__result && {name: window.__result.name, anchorId: window.__result.anchorId, hasToken: !!window.__result.token}")
                    e3 = pg2.evaluate("()=>window.__error")
                    if r3 or e3:
                        break
                    pg2.wait_for_timeout(500)
                rec["steps"]["signin_cross_device"] = {"result": r3, "error": e3}
            else:
                r3 = None
        finally:
            b2.close()
    except Exception as e:
        rec["exception"] = repr(e)[:500]
        r1 = r2 = r3 = None
    finally:
        b.close()
    anchors = {x["anchorId"] for x in (r1, r2, r3) if x}
    rec["register_calls_on_wire"] = sum(1 for l in rec["log"] if l.get("call") in ("register", "register_v2"))
    try:
        rec["anchor_on_chain"] = query_anchor(handle)
    except Exception as e:
        rec["anchor_on_chain"] = "query failed: " + str(e)
    rec["pass"] = bool(r1 and r2 and r3 and len(anchors) == 1 and rec["register_calls_on_wire"] == 1
                       and rec["anchor_on_chain"] == r1["anchorId"]
                       and (not A.discoverable or (r3 and r3.get("name") == handle)))
    with open(os.path.join(OUT, "attempt-%s-%d.json" % (ALG_NAMES[alg], i)), "w") as f:
        json.dump(rec, f, indent=1)
    print(json.dumps({"algorithm": ALG_NAMES[alg], "handle": handle, "pass": rec["pass"],
                      "signup": bool(r1), "signin_same_device": bool(r2), "signin_cross_device": bool(r3),
                      "anchors": len(anchors), "register_calls": rec["register_calls_on_wire"],
                      "anchor_on_chain": rec["anchor_on_chain"] == (r1 or {}).get("anchorId"),
                      "errors": [rec["steps"][k]["error"] for k in rec["steps"] if rec["steps"][k].get("error")] or None,
                      "exception": rec.get("exception")}), flush=True)
    return rec["pass"]


def main():
    algs = [int(x) for x in A.algorithms.split(",") if x.strip()]
    print("connect=%s attempts=%d algorithms=%s delay_pending=%.0f local=%s bed=%s discoverable=%s out=%s" % (
        CONNECT, A.attempts, [ALG_NAMES.get(a, a) for a in algs], A.delay_pending, A.local_connect_dir or "-",
        (A.bed_node + " cid " + str(A.bed_cid)) if A.bed_node else "-", A.discoverable, OUT), flush=True)
    total = passed = 0
    with sync_playwright() as p:
        for i in range(A.attempts):
            for alg in algs:
                total += 1
                if attempt(p, alg, i):
                    passed += 1
    print("RESULT %d of %d attempts passed (sign-up, sign-in same device, sign-in cross-device; one anchor, one register, resolvable on chain)" % (passed, total), flush=True)
    with open(os.path.join(OUT, "result.json"), "w") as f:
        json.dump({"passed": passed, "total": total, "delay_pending": A.delay_pending, "connect": CONNECT}, f)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
