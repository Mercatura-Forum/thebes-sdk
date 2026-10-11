// The boundary client's identity and signed transport, run in a VM against a scripted boundary.
//
//   node oracle/boundary.test.mjs
//
// Each case runs the real `runtime/boundary.js` with an in-memory IndexedDB and localStorage that
// can be shared between two "tabs", scripts what /api/call, /api/receipt and /api/query answer,
// and checks every submitted update with node's own Ed25519 against a signing payload built here,
// independently of the runtime. The principal derivation is checked against the souk-deployer
// key, whose principal the chain itself reports (egypt-wasm canister.rs SOUK_DEPLOYER_PRINCIPAL).
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto, createHash, createPublicKey, verify as edVerify } from "node:crypto";

const SRC_PATH = new URL("../runtime/boundary.js", import.meta.url);
const SRC = readFileSync(SRC_PATH, "utf8");
const NOBLE_URL = new URL("../runtime/noble-ed25519-3.1.0.js", import.meta.url).href;

let failures = 0;
function check(name, ok, detail) {
  console.log((ok ? "  PASS  " : "  FAIL  ") + name + (ok ? "" : "   -> " + detail));
  if (!ok) failures++;
}
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const json = (obj, status = 200) => ({ status, json: async () => obj });

// ── an in-memory IndexedDB: one object store, get / add, events fired asynchronously ──
function fakeIndexedDB() {
  const dbs = new Map();
  const later = (fn) => setTimeout(fn, 0);
  return {
    _dbs: dbs,
    open(name) {
      const req = {};
      later(() => {
        let fresh = false;
        if (!dbs.has(name)) { dbs.set(name, new Map()); fresh = true; }
        const stores = dbs.get(name);
        const db = {
          createObjectStore(s) { if (!stores.has(s)) stores.set(s, new Map()); },
          transaction(s, mode) {
            const tx = { pending: 0, failed: null };
            const finish = () => later(() => {
              if (tx.pending > 0) return;
              if (tx.failed) { tx.error = tx.failed; tx.onabort && tx.onabort(); } else { tx.oncomplete && tx.oncomplete(); }
            });
            finish(); // a transaction with no requests commits on its own, as in a browser
            tx.objectStore = () => {
              const store = stores.get(s);
              return {
                get(k) {
                  const r = {}; tx.pending++;
                  later(() => { r.result = store.get(k); tx.pending--; r.onsuccess && r.onsuccess(); finish(); });
                  return r;
                },
                add(v, k) {
                  if (mode !== "readwrite") throw new Error("readonly");
                  const r = {}; tx.pending++;
                  later(() => {
                    tx.pending--;
                    if (store.has(k)) { r.error = tx.failed = Object.assign(new Error("Key already exists"), { name: "ConstraintError" }); r.onerror && r.onerror(); }
                    else { store.set(k, v); r.result = k; r.onsuccess && r.onsuccess(); }
                    finish();
                  });
                  return r;
                },
              };
            };
            return tx;
          },
        };
        req.result = db;
        if (fresh && req.onupgradeneeded) req.onupgradeneeded();
        req.onsuccess && req.onsuccess();
      });
      return req;
    },
  };
}
function fakeLocalStorage(store = new Map()) {
  return { _m: store, getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
}

// One page running boundary.js. `env.idb` / `env.ls` may be shared to model two tabs of one browser.
function page(script, env = {}) {
  const events = [];
  const ctx = {
    console, TextEncoder, TextDecoder, Uint8Array, DataView, Uint32Array, BigInt, Map, Promise, Error, Number, Math, JSON, Object, Array, String, Symbol, RegExp, URL,
    crypto: env.crypto || webcrypto,
    location: { origin: "https://example.thebes.test" },
    localStorage: env.ls || fakeLocalStorage(),
    indexedDB: env.idb === null ? undefined : env.idb || fakeIndexedDB(),
    Date: env.now ? { now: env.now } : Date,
    setTimeout: (fn) => setTimeout(fn, 0), // receipt polling without the 150 ms wait
    fetch: async (url, init) => script(url, init),
    CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init && init.detail; } },
    dispatchEvent: (ev) => { events.push(ev); return true; },
  };
  if (env.scriptSrc) ctx.document = { currentScript: { src: env.scriptSrc } };
  ctx.window = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(SRC, ctx, { importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER });
  return { b: ctx.EgyptBoundary, ctx, events };
}

// The signing payload built here from egypt-state message.rs, not from the runtime.
function payload(cid, method, argBytes, sender, nonce) {
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const lp = (b) => Buffer.concat([u32(b.length), Buffer.from(b)]);
  return Buffer.concat([Buffer.from("egypt-l1-ingress-v1"), Buffer.from([0x02]), u64(cid), lp(Buffer.from(method)), lp(argBytes), lp(sender), u64(nonce)]);
}
function verifies(body) {
  const pub = unhex(body.sender);
  if (pub.length !== 32 || !body.signature || body.signature.length !== 128) return false;
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pub)]), format: "der", type: "spki" });
  return edVerify(null, payload(body.canister_id, body.method, unhex(body.arg), pub, body.nonce), key, Buffer.from(body.signature, "hex"));
}
const principalHere = (pub) => hex(createHash("sha224").update(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pub)])).digest()) + "02";

// A boundary that records submissions and answers each with success unless told otherwise.
function chain(opts = {}) {
  const calls = [], queries = [];
  let n = 0;
  const script = async (url, init) => {
    if (url.endsWith("/api/call")) {
      const body = JSON.parse(init.body); calls.push(body);
      return json({ queued: true, message_hash: (++n).toString(16).padStart(64, "0") });
    }
    if (url.includes("/api/receipt")) {
      const i = Number.parseInt(url.split("hash=")[1], 16) - 1;
      const r = opts.receipt ? opts.receipt(i, calls[i]) : null;
      return json(r || { found: true, status: "success", lifecycle: "success", reply: "4449444c0000" });
    }
    if (url.endsWith("/api/query")) { queries.push(JSON.parse(init.body)); return json({ status: "success", reply: "4449444c0000" }); }
    throw new Error("unexpected " + url);
  };
  return { script, calls, queries };
}

// 1. The derivation the canister sees as msg.caller: SHA-224 vectors and the chain's own souk-deployer principal.
{
  const { b } = page(chain().script);
  const SOUK_PUB = "83e6b23b973fe2bd5235cb4fee94bf64fb8e698722cd4b387818688741ebd149";
  const SOUK_PRINCIPAL = "6e3e7813828df2c7fc7db1ec56d18db5fc84e2de19fbd40579112cd502";
  check("1 principalOf(souk-deployer key) = the principal the chain reports", b.principalOf(SOUK_PUB) === SOUK_PRINCIPAL, b.principalOf(SOUK_PUB));
  let allMatch = true, bad = "";
  for (let i = 0; i < 300; i++) {
    const pub = webcrypto.getRandomValues(new Uint8Array(32));
    if (b.principalOf(pub) !== principalHere(pub)) { allMatch = false; bad = hex(pub); break; }
  }
  check("1b SHA-224 principal matches node:crypto on 300 random keys", allMatch, bad);
}

// 2. First visit: identity() refuses before ready(), then is synchronous, persistent and the key's principal.
{
  const idb = fakeIndexedDB(), ls = fakeLocalStorage();
  const c = chain();
  const { b, events } = page(c.script, { idb, ls });
  let threw = null;
  try { b.identity(); } catch (e) { threw = e.name; }
  // ready() was started by the script itself; on a first visit identity() can only fail until it resolves.
  check("2 identity() before the first ready() names ThebesIdentityNotReady", threw === "ThebesIdentityNotReady", threw);
  const principal = await b.ready();
  check("2b ready() resolves to identity(), a 29-byte self-authenticating principal",
    principal === b.identity() && /^[0-9a-f]{56}02$/.test(principal) && principal === principalHere(unhex(b.publicKey())), principal);
  check("2c the identity event fires once for the new key", events.filter((e) => e.type === "thebes:identity").length === 1, events.length);
  check("2d the key is persistent (IndexedDB) and non-extractable", b.isPersistentIdentity() === true &&
    idb._dbs.get("thebes-boundary").get("keys").get("ed25519-v1").privateKey.extractable === false, "");
  // A reload: same storage, a new page.
  const again = page(c.script, { idb, ls });
  check("2e after a reload identity() answers synchronously before ready()", again.b.identity() === principal, "");
  await again.b.ready();
  check("2f and it is the same key", again.b.publicKey() === b.publicKey() && again.events.length === 0, again.b.publicKey());
}

// 3. Every update is signed by the browser key over the chain's payload; nonces grow; one sender.
{
  const c = chain();
  const { b } = page(c.script);
  await b.ready();
  const arg = hex(b.encodeArgs(["hello", 42n]));
  for (let i = 0; i < 5; i++) await b.callUpdate(7001, "post", arg);
  await b.callUpdate("7002", "ping"); // default empty args, string canister id
  const allSigned = c.calls.every(verifies);
  const oneSender = c.calls.every((x) => x.sender === b.publicKey());
  const growing = c.calls.every((x, i) => i === 0 || x.nonce > c.calls[i - 1].nonce);
  check("3 every update verifies against the key it names, over an independently built payload", allSigned && c.calls.length === 6, JSON.stringify(c.calls[0]));
  check("3b one sender (this browser's key) on every update", oneSender, "");
  check("3c nonces strictly increase", growing, c.calls.map((x) => x.nonce).join(","));
  check("3d the empty-args default and a string canister id are signed as sent", c.calls[5].arg === "4449444c0000" && c.calls[5].canister_id === 7002 && verifies(c.calls[5]), JSON.stringify(c.calls[5]));
  // RED: the check above can fail. The same signature over a different argument does not verify.
  const forged = { ...c.calls[0], arg: hex(b.encodeArgs(["hellp", 42n])) };
  check("3e RED: a signature does not cover a different argument", !verifies(forged), "");
  const relabelled = { ...c.calls[0], nonce: c.calls[0].nonce + 1 };
  check("3f RED: nor a different nonce", !verifies(relabelled), "");
}

// 3g. With the clock standing still (one millisecond, many calls) nonces still grow, and across a reload.
{
  const c = chain(), ls = fakeLocalStorage(), idb = fakeIndexedDB();
  const frozen = () => 1_800_000_000_000;
  const p1 = page(c.script, { now: frozen, ls, idb });
  for (let i = 0; i < 4; i++) await p1.b.callUpdate(7001, "post", "4449444c0000");
  const p2 = page(c.script, { now: frozen, ls, idb });
  for (let i = 0; i < 4; i++) await p2.b.callUpdate(7001, "post", "4449444c0000");
  check("3g nonces grow under a frozen clock, across a reload", c.calls.every((x, i) => i === 0 || x.nonce > c.calls[i - 1].nonce) && c.calls.length === 8,
    c.calls.map((x) => x.nonce).join(","));
}

// 4. A nonce refused as already used is re-signed with a new nonce; a different error is returned as is.
{
  const c = chain({ receipt: (i) => (i === 0 ? { found: true, status: "error", lifecycle: "error", error: "replay: nonce 5 already used (last seen: 9)" } : null) });
  const { b } = page(c.script);
  const r = await b.callUpdate(7001, "post", "4449444c0000");
  check("4 a replayed nonce is resubmitted once with a higher nonce, signed", r.status === "success" && c.calls.length === 2 &&
    c.calls[1].nonce > c.calls[0].nonce && verifies(c.calls[1]), JSON.stringify(c.calls.map((x) => x.nonce)));
  const always = chain({ receipt: () => ({ found: true, status: "error", lifecycle: "error", error: "replay: nonce 5 already used (last seen: 9)" }) });
  const p2 = page(always.script);
  const r2 = await p2.b.callUpdate(7001, "post", "4449444c0000");
  check("4b the retries are bounded (3 submissions), then the error is returned", r2.status === "error" && always.calls.length === 3, always.calls.length);
  const trap = chain({ receipt: () => ({ found: true, status: "error", lifecycle: "error", error: "canister trapped: no" }) });
  const p3 = page(trap.script);
  const r3 = await p3.b.callUpdate(7001, "post", "4449444c0000");
  check("4c any other error is returned without a resubmission", r3.error === "canister trapped: no" && trap.calls.length === 1, trap.calls.length);
}

// 5. No unsigned door: a caller-supplied sender is refused before anything is sent.
{
  const c = chain();
  const { b } = page(c.script);
  await b.ready();
  let name = null;
  try { await b.callUpdate(7001, "admin_only", "4449444c0000", { sender: "6e3e7813828df2c7fc7db1ec56d18db5fc84e2de19fbd40579112cd502" }); } catch (e) { name = e.name; }
  check("5 a foreign sender is refused as ThebesUnsignedSender and nothing is sent", name === "ThebesUnsignedSender" && c.calls.length === 0, name);
  await b.callUpdate(7001, "post", "4449444c0000", { sender: b.publicKey() });
  check("5b naming this browser's own key is allowed (it is what gets signed)", c.calls.length === 1 && verifies(c.calls[0]), "");
}

// 6. Queries name this browser's key, so caller-scoped reads match its updates.
{
  const c = chain();
  const { b } = page(c.script);
  await b.callQuery(7001, "mine");
  check("6 a query names the browser key as sender", c.queries.length === 1 && c.queries[0].sender === b.publicKey(), JSON.stringify(c.queries[0]));
}

// 7. Without WebCrypto Ed25519 the noble file beside boundary.js makes, keeps and signs with the key.
{
  const noEd = {
    getRandomValues: (a) => webcrypto.getRandomValues(a),
    subtle: new Proxy(webcrypto.subtle, {
      get(t, k) {
        if (k === "generateKey" || k === "sign") return async () => { throw new Error("Ed25519 not supported"); };
        const v = t[k]; return typeof v === "function" ? v.bind(t) : v;
      },
    }),
  };
  const idb = fakeIndexedDB(), ls = fakeLocalStorage();
  const c = chain();
  const { b } = page(c.script, { crypto: noEd, idb, ls, scriptSrc: new URL("../runtime/boundary.js", import.meta.url).href });
  await b.callUpdate(7001, "post", "4449444c0000");
  const rec = idb._dbs.get("thebes-boundary").get("keys").get("ed25519-v1");
  check("7 the noble path signs a verifying update", c.calls.length === 1 && verifies(c.calls[0]), JSON.stringify(c.calls[0]));
  check("7b and keeps that key across a reload", rec.kind === "noble" && page(c.script, { crypto: noEd, idb, ls }).b.identity() === b.identity(), rec.kind);
  // Neither WebCrypto Ed25519 nor a URL to load noble from: a typed refusal and no request.
  const none = chain();
  const p2 = page(none.script, { crypto: noEd });
  let name = null;
  try { await p2.b.callUpdate(7001, "post", "4449444c0000"); } catch (e) { name = e.name; }
  check("7c with no way to sign: ThebesUnsupportedBrowser and nothing is sent", name === "ThebesUnsupportedBrowser" && none.calls.length === 0, name);
}

// 8. Two tabs making the first key at once end on one key; a stale cache is corrected; a bad record is never replaced.
{
  const idb = fakeIndexedDB(), ls = fakeLocalStorage();
  const t1 = page(chain().script, { idb, ls }), t2 = page(chain().script, { idb, ls });
  const [p1, p2] = await Promise.all([t1.b.ready(), t2.b.ready()]);
  check("8 two tabs racing on the first key adopt one key", p1 === p2 && t1.b.publicKey() === t2.b.publicKey(), p1 + " " + p2);

  const ls2 = fakeLocalStorage();
  ls2.setItem("thebes_identity_v1", JSON.stringify({ publicKey: "11".repeat(32), principal: "22".repeat(29) }));
  const stale = page(chain().script, { ls: ls2 });
  const before = stale.b.identity();
  const after = await stale.b.ready();
  check("8b a cached identity that is not the key's is replaced by ready(), with an event",
    before === "22".repeat(29) && after !== before && stale.b.identity() === after && stale.events.length === 1, after);

  const idb3 = fakeIndexedDB();
  await page(chain().script, { idb: idb3 }).b.ready();
  const keys = idb3._dbs.get("thebes-boundary").get("keys");
  keys.set("ed25519-v1", { v: 9, kind: "future" });
  const bad = chain();
  const p3 = page(bad.script, { idb: idb3 });
  let name = null;
  try { await p3.b.callUpdate(7001, "post", "4449444c0000"); } catch (e) { name = e.name; }
  check("8c an unusable key record is refused (ThebesIdentityUnavailable), never overwritten, nothing sent",
    name === "ThebesIdentityUnavailable" && keys.get("ed25519-v1").v === 9 && bad.calls.length === 0, name);
}

// 9. No IndexedDB (some private windows): a key for this page only, still signed, and no identity cached.
{
  const ls = fakeLocalStorage(), c = chain();
  const { b } = page(c.script, { idb: null, ls });
  await b.callUpdate(7001, "post", "4449444c0000");
  check("9 without IndexedDB the page key signs, is not persistent, and is not cached",
    verifies(c.calls[0]) && b.isPersistentIdentity() === false && ls.getItem("thebes_identity_v1") === null, "");
}

console.log(failures ? `\n${failures} FAILED` : "\nall passed");
process.exit(failures ? 1 : 0);
