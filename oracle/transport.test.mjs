// The passkey runtime's transport, exercised against a scripted boundary with a virtual clock.
//
//   node oracle/transport.test.mjs
//
// Each case scripts what /api/call, /api/receipt and /api/next_nonce answer, runs the real
// `runtime/passkey.js` in a VM with a clock that jumps instead of waiting, and asserts what the
// runtime does: how long it keeps polling, when it retries a refused submission, how it names
// a lost reply, and that a registration can be resumed without a second `register`.
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const SRC = readFileSync(new URL("../runtime/passkey.js", import.meta.url), "utf8");

function runtime(script) {
  const store = new Map();
  let now = 1_000_000;
  const timers = [];
  const ctx = {
    console, TextEncoder, TextDecoder, Uint8Array, BigInt, Map, Promise, Error, Number, Math, JSON, Object, Array, String, Symbol,
    crypto: webcrypto, btoa: (s) => Buffer.from(s, "binary").toString("base64"), atob: (s) => Buffer.from(s, "base64").toString("binary"),
    location: { origin: "https://memphis.mercaturaforum.com" },
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    sessionStorage: { getItem: (k) => (store.has("s:" + k) ? store.get("s:" + k) : null), setItem: (k, v) => store.set("s:" + k, String(v)), removeItem: (k) => store.delete("s:" + k) },
    // A passkey that answers every assertion request: the bytes are never verified here.
    navigator: { credentials: { get: async () => ({ rawId: new Uint8Array([1, 2, 3, 4]).buffer, response: { authenticatorData: new Uint8Array(37).buffer, clientDataJSON: new Uint8Array([123, 125]).buffer, signature: new Uint8Array(64).buffer } }) } },
    indexedDB: undefined,
    Date: { now: () => now },
    setTimeout: (fn, ms) => { timers.push({ at: now + (ms || 0), fn }); return timers.length; },
    clearTimeout: () => {},
    fetch: async (url, init) => script(url, init, () => now),
  };
  ctx.window = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(SRC, ctx);
  // Drive the virtual clock: run every due timer, jumping to the earliest, until none remain.
  async function settle(promise) {
    let done = false, out, err;
    promise.then((v) => { done = true; out = v; }, (e) => { done = true; err = e; });
    for (let i = 0; i < 100000 && !done; i++) {
      await new Promise((r) => setImmediate(r));
      if (done) break;
      if (timers.length) {
        timers.sort((a, b) => a.at - b.at);
        const t = timers.shift();
        if (t.at > now) now = t.at;
        t.fn();
      }
    }
    if (!done) throw new Error("did not settle");
    if (err) throw err;
    return out;
  }
  return { pk: ctx.MemphisPasskey, settle, store, clock: () => now };
}

const json = (obj, status = 200) => ({ status, json: async () => obj, text: async () => JSON.stringify(obj) });
const HEX_REPLY = "4449444c0000"; // an empty Candid reply is enough for the transport
let failures = 0;
function check(name, ok, detail) {
  console.log((ok ? "  PASS  " : "  FAIL  ") + name + (ok ? "" : "   -> " + detail));
  if (!ok) failures++;
}

// 1. A receipt that stays pending for 30 s is still collected (the old client gave up at 8 s).
{
  let submittedAt = null, polls = 0;
  const { pk, settle, clock } = runtime((url, init, now) => {
    if (url.endsWith("/api/call")) { submittedAt = now(); return json({ queued: true, message_hash: "aa".repeat(32) }); }
    if (url.includes("/api/receipt")) { polls++; return now() - submittedAt < 30000 ? json({ found: false, lifecycle: "pending" }) : json({ found: true, status: "success", lifecycle: "success", reply: HEX_REPLY }); }
    throw new Error("unexpected " + url);
  });
  const t0 = clock();
  const reply = await settle(pk._memphisCallAwait("begin_registration", new Uint8Array([0x44, 0x49, 0x44, 0x4c, 0, 0])));
  check("1 a 30 s confirmation is collected", reply && reply.length === 6 && clock() - t0 >= 30000, `len=${reply && reply.length} waited=${clock() - t0}`);
  check("1b polling backs off to a 2 s cap (fewer than 25 polls in 30 s)", polls < 25 && polls > 10, `polls=${polls}`);
}

// 2. Past the 90 s budget the error is typed, carries the hash, and the hash is remembered.
{
  const { pk, settle, store, clock } = runtime((url) => {
    if (url.endsWith("/api/call")) return json({ queued: true, message_hash: "bb".repeat(32) });
    if (url.includes("/api/receipt")) return json({ found: false, lifecycle: "pending" });
    throw new Error("unexpected " + url);
  });
  const t0 = clock();
  let err = null;
  try { await settle(pk._memphisCallAwait("register", new Uint8Array(6))); } catch (e) { err = e; }
  check("2 budget exhaustion is MemphisReceiptTimeout with the hash", err && err.code === "MemphisReceiptTimeout" && err.messageHash === "bb".repeat(32) && err.method === "register", err && (err.code + " " + err.message));
  check("2b the budget is 90 s, not 8", clock() - t0 >= 90000 && clock() - t0 < 93000, `waited=${clock() - t0}`);
  const pending = JSON.parse(store.get("memphisPendingCallV1") || "null");
  check("2c the pending call is remembered for a later attempt", pending && pending.hash === "bb".repeat(32) && pending.method === "register", JSON.stringify(pending));
}

// 3. A refused submission (back-pressure, then 502) is retried and then accepted.
{
  let attempts = 0, nonceAsked = 0;
  const { pk, settle } = runtime((url) => {
    if (url.endsWith("/api/call")) { attempts++; if (attempts === 1) return json({ status: "error", error: "rss_backpressure" }, 503); if (attempts === 2) return json({ error: "validator unreachable" }, 502); return json({ queued: true, message_hash: "cc".repeat(32) }); }
    if (url.includes("/api/next_nonce")) { nonceAsked++; return json({ next_nonce: 0, is_fresh_sender: true }); }
    if (url.includes("/api/receipt")) return json({ found: true, status: "success", lifecycle: "success", reply: HEX_REPLY });
    throw new Error("unexpected " + url);
  });
  const reply = await settle(pk._memphisCallAwait("begin_authentication", new Uint8Array(6)));
  check("3 back-pressure and 502 are retried until accepted", reply && attempts === 3 && nonceAsked === 2, `attempts=${attempts} nonceAsked=${nonceAsked}`);
}

// 4. A refusal after the sender has executed is never resubmitted: the reply is reported lost.
{
  let attempts = 0;
  const { pk, settle } = runtime((url) => {
    if (url.endsWith("/api/call")) { attempts++; return json({ status: "error", error: "rss_backpressure" }, 503); }
    if (url.includes("/api/next_nonce")) return json({ next_nonce: 1, is_fresh_sender: false });
    throw new Error("unexpected " + url);
  });
  let err = null;
  try { await settle(pk._memphisCallAwait("register", new Uint8Array(6))); } catch (e) { err = e; }
  check("4 an executed sender is not resubmitted (MemphisSubmittedButLost)", err && err.code === "MemphisSubmittedButLost" && attempts === 1, err && (err.code + " attempts=" + attempts));
}

// 5. Every attempt refused: MemphisNetworkBusy after the bounded retries.
{
  let attempts = 0;
  const { pk, settle } = runtime((url) => {
    if (url.endsWith("/api/call")) { attempts++; return json({ status: "error", error: "rss_backpressure" }, 503); }
    if (url.includes("/api/next_nonce")) return json({ next_nonce: 0 });
    throw new Error("unexpected " + url);
  });
  let err = null;
  try { await settle(pk._memphisCallAwait("begin_registration", new Uint8Array(6))); } catch (e) { err = e; }
  check("5 six refusals end in MemphisNetworkBusy", err && err.code === "MemphisNetworkBusy" && attempts === 6, err && (err.code + " attempts=" + attempts));
}

// 6. A receipt saying the nonce was already used means the call ran under another envelope.
{
  const { pk, settle } = runtime((url) => {
    if (url.endsWith("/api/call")) return json({ queued: true, message_hash: "dd".repeat(32) });
    if (url.includes("/api/receipt")) return json({ found: true, status: "error", lifecycle: "error", error: "replay: nonce 0 already used (last seen: 0)" });
    throw new Error("unexpected " + url);
  });
  let err = null;
  try { await settle(pk._memphisCallAwait("register", new Uint8Array(6))); } catch (e) { err = e; }
  check("6 a nonce replay receipt is MemphisSubmittedButLost, not a canister error", err && err.code === "MemphisSubmittedButLost", err && err.code);
}

// 7. A canister refusal is still a canister error, immediately.
{
  const { pk, settle } = runtime((url) => {
    if (url.endsWith("/api/call")) return json({ queued: true, message_hash: "ee".repeat(32) });
    if (url.includes("/api/receipt")) return json({ found: true, status: "error", lifecycle: "error", error: "canister trapped: boom" });
    throw new Error("unexpected " + url);
  });
  let err = null;
  try { await settle(pk._memphisCallAwait("register", new Uint8Array(6))); } catch (e) { err = e; }
  check("7 an execution error is MemphisCanisterError with the detail", err && err.code === "MemphisCanisterError" && /boom/.test(err.detail), err && (err.code + " " + err.detail));
}

// 8. Resume: a registration whose claim_name timed out is finished with the held session and
//    no second register; a registration whose register timed out is finished from its hash.
{
  // Real replies from the chain (2026-09-15): Ok(RegistrationResult) with anchor 7ba0…5fa2, and Ok("nu77615-0.thebes").
  const ANCHOR = "7ba054026f7b38bbcdd9a2e952bcfabf206e607e3ef15cf9aab1a878df675fa2";
  const regOk = "4449444c066b02bc8a0101c5fed201036c049da5f4e10371a5ddb5810602908cb0dc0c02c6c2b7be0e786d7b6b0be5fc9ff60204bec89aca037fa2a3ecff067fa0dcf8aa0805d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac207780100000435666132207ba054026f7b38bbcdd9a2e952bcfabf206e607e3ef15cf9aab1a878df675fa220a85e1bc81e3b2874b8b802e5ab73e9a244c0e82377b361954619f9575a5dbe0f00482e1776850c01";
  const claimOk = "4449444c046b02bc8a0171c5fed201016b0be5fc9ff60202bec89aca037fa2a3ecff067fa0dcf8aa0803d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac20778010000106e7537373631352d302e746865626573";
  let registers = 0, claims = 0, claimFail = true;
  const { pk, settle, store } = runtime((url, init) => {
    if (url.endsWith("/api/call")) {
      const m = JSON.parse(init.body).method;
      if (m === "register") { registers++; return json({ queued: true, message_hash: "01".repeat(32) }); }
      if (m === "claim_name") { claims++; return json({ queued: true, message_hash: "02".repeat(32) }); }
    }
    if (url.includes("/api/receipt?hash=" + "01".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: regOk });
    if (url.includes("/api/receipt?hash=" + "02".repeat(32))) return claimFail ? json({ found: false, lifecycle: "pending" }) : json({ found: true, status: "success", lifecycle: "success", reply: claimOk });
    throw new Error("unexpected " + url);
  });
  let err = null;
  try { await settle(pk.registerWithFactors("nu77615-0.thebes", [])); } catch (e) { err = e; }
  const rec = JSON.parse(store.get("memphisPendingRegistrationV1") || "null");
  check("8 claim_name timeout leaves a 'registered' record with the session", err && err.code === "MemphisReceiptTimeout" && rec && rec.stage === "registered" && rec.session && rec.session.anchor_id_hex === ANCHOR, JSON.stringify({ code: err && err.code, rec }));
  claimFail = false;
  const session = await settle(pk.resumePendingRegistration("nu77615-0.thebes"));
  check("8b resume finishes with the same anchor and no second register", session && session.anchor_id_hex === ANCHOR && registers === 1 && claims === 2 && !store.get("memphisPendingRegistrationV1"), JSON.stringify({ session, registers, claims }));
  const again = await settle(pk.resumePendingRegistration("nu77615-0.thebes"));
  check("8c nothing pending afterwards", again === null, String(again));
}


// ── The Sep-15 canister surface: v2 replies with seq, stale reads retried, recovery ──
const REPLIES = {"register_v2": "4449444c066b02bc8a0101c5fed201036c059fb7de02789da5f4e10371a5ddb5810602908cb0dc0c02c6c2b7be0e786d7b6b0be5fc9ff60204bec89aca037fa2a3ecff067fa0dcf8aa0805d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac207780100005501000000000000046664653820264b651f05863d47807d7643209ad4d1c400c88df61493eabb095e570a5cfde820092e41c30fe0a64f0958382abf06edbd8b69af7fa503cdf2bbf9dbbd14d8e7f0008c3788b51c0000", "claim_name_v2": "4449444c056b02bc8a0101c5fed201026c029fb7de0278cbe4fdc704716b0be5fc9ff60203bec89aca037fa2a3ecff067fa0dcf8aa0804d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac2077801000056010000000000000f73713233363432332e746865626573", "anchor_for_credential": "4449444c036c029fb7de0278f1fee18d03016e026d7b0100560100000000000001209efd862b300a9262335d2386cc6856b5465228ee04a8a9e7a84297d7c1296d72", "authenticate": "4449444c066b02bc8a0101c5fed201036c02908cb0dc0c02c6c2b7be0e786d7b6b0be5fc9ff60204bec89aca037fa2a3ecff067fa0dcf8aa0805d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac20778010000205fbc2e1019345f2f859a0922161e3fd9dd8c274883ba7e08e54fc105af5ec5fe00385b84bc1c0000", "begin_authentication": "4449444c056b02bc8a0101c5fed201026d7b6b0be5fc9ff60203bec89aca037fa2a3ecff067fa0dcf8aa0804d4b4c59a097fa2c6bef1097fbcfbd9b70a7ff4b895a40b71e1d5f2b60e7f8ff6b0dd0e7fe4b7f5e10e7f6c02dbb70171c2b9dbda0a716c01b9a79ac20778010000207fd9c2a60ad2f799fad0ab0399f0c8538a635907980c29d196516a49db98cf7a", "name_for_anchor": "4449444c026c029fb7de0278f1fee18d03016e710100580100000000000000"};
const CAPS = "4449444c016d710100080a616c676f726974686d73037365710b72656769737465725f76320d636c61696d5f6e616d655f763212616e63686f725f666f725f6e616d655f763215616e63686f725f666f725f63726564656e7469616c0f6e616d655f666f725f616e63686f721b646973636f76657261626c655f61757468656e7469636174696f6e";
const b64 = (hex) => Buffer.from(hex, "hex").toString("base64");
const q = (hex) => json({ status: "success", reply: b64(hex) });
const FACTOR = (cred) => ({ credential_id: cred, cose_pub_key_bytes: new Uint8Array(4), authenticator_data: new Uint8Array(37), client_data_json: new Uint8Array(2), signature: new Uint8Array(64), kind: "WebAuthn" });

// 9. With capabilities present, registration goes through register_v2 and claim_name_v2 and the
//    seq of each reply is remembered.
{
  const calls = [];
  const { pk, settle, store } = runtime((url, init) => {
    if (url.includes("/query")) {
      const m = JSON.parse(init.body).method;
      if (m === "capabilities") return q(CAPS);
      throw new Error("unexpected query " + m);
    }
    if (url.endsWith("/api/call")) { const m = JSON.parse(init.body).method; calls.push(m); return json({ queued: true, message_hash: (m === "register_v2" ? "31" : "32").repeat(32) }); }
    if (url.includes("/api/receipt?hash=" + "31".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: REPLIES.register_v2 });
    if (url.includes("/api/receipt?hash=" + "32".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: REPLIES.claim_name_v2 });
    throw new Error("unexpected " + url);
  });
  const session = await settle(pk.registerWithFactors("sq262606.thebes", [FACTOR(new Uint8Array([9, 9]))]));
  check("9 register_v2 and claim_name_v2 are used when the canister lists them", calls.join(",") === "register_v2,claim_name_v2" && session && session.anchor_id_hex.length === 64, calls.join(","));
  check("9b the highest seq seen is remembered (the claim reply seq, 342)", store.get("s:memphisSeqV1") === "342", store.get("s:memphisSeqV1"));
}

// 10. A seq-stamped lookup that answers from behind the remembered seq is retried until a node
//     at or past it answers; the stale miss is never taken as "no identity".
{
  let lookups = 0;
  const { pk, settle } = runtime((url, init) => {
    if (url.includes("/query")) {
      const m = JSON.parse(init.body).method;
      if (m === "capabilities") return q(CAPS);
      if (m === "anchor_for_name_v2") {
        lookups++;
        // Two stale misses (seq 300, no value), then the current answer (seq 339, anchor present).
        if (lookups < 3) return q("4449444c036c029fb7de0278f1fee18d03016e026d7b01002c0100000000000000");
        return q(REPLIES.anchor_for_credential);
      }
      throw new Error("unexpected query " + m);
    }
    if (url.endsWith("/api/call")) return json({ queued: true, message_hash: "33".repeat(32) });
    // begin_authentication answers with a canister refusal so the flow ends right after the lookup.
    if (url.includes("/api/receipt")) return json({ found: true, status: "error", lifecycle: "error", error: "stop here" });
    throw new Error("unexpected " + url);
  });
  pk._noteSeq(339);
  let err = null;
  try { await settle(pk.signIn("sq262606.thebes")); } catch (e) { err = e; }
  check("10 a stale lookup (seq 300 < 339) is retried until current; the flow then continues", lookups === 3 && err && err.code === "MemphisCanisterError" && /stop here/.test(err.detail), `lookups=${lookups} err=${err && (err.code + " " + err.message)}`);
}

// 11. The register_v2 reply is lost (the sender executed): the identity is recovered from the
//     credential alone, with one assertion, and the handle is claimed on it. No second register.
{
  const calls = [];
  const { pk, settle } = runtime((url, init) => {
    if (url.includes("/query")) {
      const m = JSON.parse(init.body).method;
      if (m === "capabilities") return q(CAPS);
      if (m === "anchor_for_credential") return q(REPLIES.anchor_for_credential);
      throw new Error("unexpected query " + m);
    }
    if (url.includes("/api/next_nonce")) return json({ next_nonce: 1 });
    if (url.endsWith("/api/call")) {
      const m = JSON.parse(init.body).method; calls.push(m);
      if (m === "register_v2") return json({ status: "error", error: "rss_backpressure" }, 503);
      return json({ queued: true, message_hash: ("4" + calls.length).repeat(32) });
    }
    if (url.includes("/api/receipt?hash=" + "42".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: REPLIES.begin_authentication });
    if (url.includes("/api/receipt?hash=" + "43".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: REPLIES.authenticate });
    if (url.includes("/api/receipt?hash=" + "44".repeat(32))) return json({ found: true, status: "success", lifecycle: "success", reply: REPLIES.claim_name_v2 });
    throw new Error("unexpected " + url);
  });
  const session = await settle(pk.registerWithFactors("sq262606.thebes", [FACTOR(new Uint8Array([0x9e, 0xfd]))]));
  check("11 a lost register_v2 reply is recovered from the credential: one register, then begin_authentication, authenticate, claim_name_v2",
    calls.join(",") === "register_v2,begin_authentication,authenticate,claim_name_v2" && session && session.anchor_id_hex.startsWith("9efd862b"),
    calls.join(",") + " " + (session && session.anchor_id_hex));
}

console.log(failures ? `\n  ${failures} failing` : "\n  transport: every case holds");
process.exit(failures ? 1 : 0);
