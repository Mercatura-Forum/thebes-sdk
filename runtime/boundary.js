!function(){"use strict";const e=location.origin.includes("memphis.mercaturaforum.com")?"":"https://memphis.mercaturaforum.com",t={NULL:-1,BOOL:-2,NAT:-3,INT:-4,NAT8:-5,NAT16:-6,NAT32:-7,NAT64:-8,INT8:-9,INT16:-10,INT32:-11,INT64:-12,FLOAT32:-13,FLOAT64:-14,TEXT:-15,RESERVED:-16,EMPTY:-17,OPT:-18,VEC:-19,RECORD:-20,VARIANT:-21,FUNC:-22,SERVICE:-23,PRINCIPAL:-24};function n(e){"number"==typeof e&&(e=BigInt(e));const t=[];for(;;){let n=Number(0x7fn&e);if(0n===(e>>=7n))return t.push(n),t;t.push(128|n)}}function r(e){"number"==typeof e&&(e=BigInt(e));const t=[];for(;;){let n=Number(0x7fn&e);const r=!!(64&n);if(0n===(e>>=7n)&&!r||-1n===e&&r)return t.push(n),t;t.push(128|n)}}function o(e,t){let n,r=0n,o=0n;do{n=e[t++],r|=BigInt(127&n)<<o,o+=7n}while(128&n);return[r,t]}function s(e,t){let n,r=0n,o=0n;for(;;)if(n=e[t++],r|=BigInt(127&n)<<o,o+=7n,!(128&n))return o<64n&&64&n&&(r|=-(1n<<o)),[r,t]}const c=new TextEncoder,u=new TextDecoder;function a(e){let t=0n;for(const n of c.encode(e))t=223n*t+BigInt(n)&0xffffffffn;return Number(t)}function i(e){if(e&&"object"==typeof e&&"type"in e)return e;if("string"==typeof e)return{type:"text",value:e};if("boolean"==typeof e)return{type:"bool",value:e};if("bigint"==typeof e)return{type:"nat",value:e};if("number"==typeof e)return{type:"nat",value:BigInt(e)};if(null==e)return{type:"null"};if(Array.isArray(e))return{type:"vec",inner:{type:"text"},value:e};throw new Error("cannot infer Candid type for "+JSON.stringify(e))}function l(e,t){"number"==typeof t&&t<0?e.push(...r(t)):e.push(...n(t))}function f(e,o,s,c){switch((e=i(e)).type){case"null":return t.NULL;case"bool":return t.BOOL;case"nat":return t.NAT;case"int":return t.INT;case"text":return t.TEXT;case"principal":return t.PRINCIPAL;case"opt":{const n=f(e.inner||{type:"text"},o,s,c),u=s.n++;return o.push(...r(t.OPT)),l(o,n),u}case"vec":{const n=f(e.inner||{type:"text"},o,s,c),u=s.n++;return o.push(...r(t.VEC)),l(o,n),u}case"record":{const u=Object.keys(e.fields||{}).map(t=>{const n=i(e.fields[t]);return{name:t,hash:a(t),val:n}}).sort((e,t)=>e.hash-t.hash),p=u.map(e=>f(e.val,o,s,c)),h=s.n++;o.push(...r(t.RECORD)),o.push(...n(u.length));for(let e=0;e<u.length;e++)o.push(...n(u[e].hash)),l(o,p[e]);return e._sortedFields=u,h}default:throw new Error("unknown Candid type: "+e.type)}}function p(e,t){switch((t=i(t)).type){case"null":return;case"bool":return void e.push(t.value?1:0);case"nat":return void e.push(...n(t.value));case"int":return void e.push(...r(t.value));case"text":{const r=c.encode(String(null==t.value?"":t.value));e.push(...n(r.length));for(const t of r)e.push(t);return}case"principal":{e.push(1);const r=d(t.value);e.push(...n(r.length));for(const t of r)e.push(t);return}case"opt":return null===t.value||void 0===t.value?void e.push(0):(e.push(1),void p(e,i(t.value)));case"vec":e.push(...n(t.value.length));for(const n of t.value)p(e,i(n));return;case"record":for(const n of t._sortedFields)p(e,n.val);return;default:throw new Error("unknown Candid value type: "+t.type)}}function h(e){let t="";for(let n=0;n<e.length;n++)t+=e[n].toString(16).padStart(2,"0");return t}function d(e){e.startsWith("0x")&&(e=e.slice(2));const t=new Uint8Array(e.length/2);for(let n=0;n<t.length;n++)t[n]=parseInt(e.substr(2*n,2),16);return t}function y(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),t}const m="4449444c0000";

  // ─── browser identity + signed transport (INV-SENDER-AUTH, V150) ────────────
  // The chain refuses an unsigned call that names a sender. This browser holds
  // ONE Ed25519 key, made on first use and kept in IndexedDB (non-extractable
  // where the browser has WebCrypto Ed25519), and every update is signed with
  // it over egypt-state's Call signing payload. The sender is the key's public
  // key; the node hands the canister the IC self-authenticating principal of
  // that key, SHA-224(DER-SPKI(pk)) ‖ 0x02 (29 bytes), and `identity()` returns
  // exactly that principal, so a page comparing a stored member id with
  // `identity()` compares the same bytes the canister saw as `msg.caller`.
  // The key record is versioned (`ed25519-v1`) so a later Memphis session
  // binding can bind this same key.
  // Where the noble fallback is loaded from: beside this file, or, when a page
  // inlines this file (no src), beside the page.
  const SCRIPT_SRC = (typeof document !== "undefined" && ((document.currentScript && document.currentScript.src) || document.baseURI)) || "";
  const NOBLE_ED25519_FILE = "noble-ed25519-3.1.0.js";
  const IDB_NAME = "thebes-boundary", IDB_STORE = "keys", KEY_ID = "ed25519-v1";
  const CACHE_KEY = "thebes_identity_v1", NONCE_KEY = "thebes_nonce_v1";
  const utf8 = new TextEncoder();

  function typedError(name, message, extra) {
    const err = new Error(message);
    err.name = name;
    if (extra) Object.assign(err, extra);
    return err;
  }
  function concatBytes(...parts) {
    let len = 0;
    for (const p of parts) len += p.length;
    const out = new Uint8Array(len);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }
  function u32be(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v);
    return b;
  }
  function u64be(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v));
    return b;
  }
  function lenPrefixed(b) { return concatBytes(u32be(b.length), b); }
  // egypt-state message.rs IngressMessage::signing_payload() for a Call (tag 0x02).
  function callSigningPayload(canisterId, method, argBytes, senderBytes, nonce) {
    return concatBytes(utf8.encode("egypt-l1-ingress-v1"), Uint8Array.of(0x02), u64be(canisterId),
      lenPrefixed(utf8.encode(method)), lenPrefixed(argBytes), lenPrefixed(senderBytes), u64be(nonce));
  }

  // SHA-224 (FIPS 180-4 §6.3): SHA-256 with its own initial value, truncated to
  // 28 bytes. WebCrypto has no SHA-224 and `identity()` must be synchronous.
  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  function sha224(msg) {
    const H = new Uint32Array([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
    const padded = new Uint8Array(((msg.length + 9 + 63) >> 6) << 6);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(msg.length / 0x20000000));
    view.setUint32(padded.length - 4, (msg.length << 3) >>> 0);
    const W = new Uint32Array(64);
    const rotr = (x, k) => (x >>> k) | (x << (32 - k));
    for (let off = 0; off < padded.length; off += 64) {
      for (let j = 0; j < 16; j++) W[j] = view.getUint32(off + 4 * j);
      for (let j = 16; j < 64; j++) {
        const s0 = rotr(W[j - 15], 7) ^ rotr(W[j - 15], 18) ^ (W[j - 15] >>> 3);
        const s1 = rotr(W[j - 2], 17) ^ rotr(W[j - 2], 19) ^ (W[j - 2] >>> 10);
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
      }
      let [A, B, C, D, E, F, G, HH] = H;
      for (let j = 0; j < 64; j++) {
        const S1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const ch = (E & F) ^ (~E & G);
        const t1 = (HH + S1 + ch + SHA256_K[j] + W[j]) >>> 0;
        const S0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const maj = (A & B) ^ (A & C) ^ (B & C);
        const t2 = (S0 + maj) >>> 0;
        HH = G; G = F; F = E; E = (D + t1) >>> 0; D = C; C = B; B = A; A = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + A) >>> 0; H[1] = (H[1] + B) >>> 0; H[2] = (H[2] + C) >>> 0; H[3] = (H[3] + D) >>> 0;
      H[4] = (H[4] + E) >>> 0; H[5] = (H[5] + F) >>> 0; H[6] = (H[6] + G) >>> 0; H[7] = (H[7] + HH) >>> 0;
    }
    const out = new Uint8Array(28);
    const ov = new DataView(out.buffer);
    for (let j = 0; j < 7; j++) ov.setUint32(4 * j, H[j]);
    return out;
  }
  // egypt-wasm canister.rs ed25519_pubkey_to_principal (= candid Principal::self_authenticating).
  const ED25519_SPKI_PREFIX = Uint8Array.of(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00);
  function principalOf(publicKey) {
    return concatBytes(sha224(concatBytes(ED25519_SPKI_PREFIX, publicKey)), Uint8Array.of(0x02));
  }

  let noblePromise = null;
  function loadNoble() {
    if (!noblePromise) {
      noblePromise = SCRIPT_SRC
        ? import(new URL(NOBLE_ED25519_FILE, SCRIPT_SRC).href)
        : Promise.reject(new Error("the page did not load boundary.js from a URL"));
      noblePromise.catch(() => { noblePromise = null; });
    }
    return noblePromise;
  }
  function unsupported(detail) {
    return typedError("ThebesUnsupportedBrowser",
      "This browser cannot sign requests: it has no Ed25519, and the signing library (" + NOBLE_ED25519_FILE + ") did not load.",
      { detail });
  }
  // A new key record. WebCrypto keys are generated non-extractable; the noble
  // fallback (browsers without WebCrypto Ed25519) has to keep the secret bytes.
  async function newKeyRecord() {
    try {
      const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"]);
      const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
      return { v: 1, kind: "webcrypto", privateKey: kp.privateKey, publicKey };
    } catch (_) { /* no WebCrypto Ed25519: fall through to noble */ }
    let ed;
    try {
      ed = await loadNoble();
    } catch (err) {
      throw unsupported(err && err.message ? err.message : String(err));
    }
    const secretKey = ed.utils.randomSecretKey();
    const publicKey = await ed.getPublicKeyAsync(secretKey);
    return { v: 1, kind: "noble", secretKey, publicKey };
  }
  function validRecord(rec) {
    return !!rec && rec.v === 1 && rec.publicKey instanceof Uint8Array && rec.publicKey.length === 32 &&
      ((rec.kind === "webcrypto" && !!rec.privateKey) || (rec.kind === "noble" && rec.secretKey instanceof Uint8Array && rec.secretKey.length === 32));
  }

  function idbRequest(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function idbOpen() {
    if (typeof indexedDB === "undefined" || !indexedDB) return null;
    try {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => { req.result.createObjectStore(IDB_STORE); };
      return await idbRequest(req);
    } catch (_) {
      return null; // private windows can refuse IndexedDB: the key then lives for this page only
    }
  }
  function idbGet(db) {
    return idbRequest(db.transaction(IDB_STORE, "readonly").objectStore(IDB_STORE).get(KEY_ID));
  }
  // `add`, never `put`: when two tabs make a key at once, the first write wins
  // and the other tab adopts it.
  async function idbAdd(db, rec) {
    try {
      const tx = db.transaction(IDB_STORE, "readwrite");
      const committed = new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
      tx.objectStore(IDB_STORE).add(rec, KEY_ID);
      await committed;
      return true;
    } catch (_) {
      return false;
    }
  }
  async function loadOrCreateKey() {
    const db = await idbOpen();
    if (!db) return { rec: await newKeyRecord(), persistent: false };
    let rec = await idbGet(db);
    if (rec === undefined) {
      const fresh = await newKeyRecord();
      rec = (await idbAdd(db, fresh)) ? fresh : await idbGet(db);
    }
    // A record this file cannot use is never overwritten: replacing it would
    // silently give the browser a new identity.
    if (!validRecord(rec)) {
      throw typedError("ThebesIdentityUnavailable",
        "This browser's Thebes key record (IndexedDB " + IDB_NAME + "/" + KEY_ID + ") is not one this boundary.js can use.");
    }
    return { rec, persistent: true };
  }

  // The last identity this browser had, so `identity()` answers synchronously
  // on every page load after the first. `ready()` checks it against the key.
  function readCache() {
    try {
      const c = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
      if (c && /^[0-9a-f]{64}$/.test(c.publicKey) && /^[0-9a-f]{58}$/.test(c.principal)) return c;
    } catch (_) { /* no storage */ }
    return null;
  }
  let cached = readCache(), keyRecord = null, persistentKey = false, readyPromise = null;
  function ready() {
    if (!readyPromise) {
      readyPromise = loadOrCreateKey().then(({ rec, persistent }) => {
        keyRecord = rec;
        persistentKey = persistent;
        const now = { publicKey: h(rec.publicKey), principal: h(principalOf(rec.publicKey)) };
        const changed = !cached || cached.principal !== now.principal;
        cached = now;
        if (persistent) {
          try { localStorage.setItem(CACHE_KEY, JSON.stringify(now)); } catch (_) { /* no storage */ }
        }
        if (changed && typeof dispatchEvent === "function" && typeof CustomEvent === "function") {
          dispatchEvent(new CustomEvent("thebes:identity", { detail: now }));
        }
        return now.principal;
      });
      readyPromise.catch(() => { readyPromise = null; });
    }
    return readyPromise;
  }
  function notReady() {
    return typedError("ThebesIdentityNotReady",
      "This browser's Thebes key is not loaded yet: await EgyptBoundary.ready() before reading identity().");
  }
  function ID() {
    if (cached) return cached.principal;
    throw notReady();
  }
  function publicKeyHex() {
    if (cached) return cached.publicKey;
    throw notReady();
  }
  async function signPayload(payload) {
    if (!keyRecord) await ready();
    if (keyRecord.kind === "webcrypto") {
      return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keyRecord.privateKey, payload));
    }
    let ed;
    try {
      ed = await loadNoble();
    } catch (err) {
      throw unsupported(err && err.message ? err.message : String(err));
    }
    return await ed.signAsync(payload, keyRecord.secretKey);
  }
  // The chain keeps the highest executed nonce per sender and refuses any
  // nonce at or below it, so nonces only grow: microseconds since the epoch
  // plus a random tail, never below the last one this browser used.
  let lastNonce = 0;
  function nextNonce() {
    let floor = 0;
    try { floor = Number(localStorage.getItem(NONCE_KEY)) || 0; } catch (_) { /* no storage */ }
    const nonce = Math.max(Date.now() * 1000 + Math.floor(Math.random() * 1000), lastNonce + 1, floor + 1);
    lastNonce = nonce;
    try { localStorage.setItem(NONCE_KEY, String(nonce)); } catch (_) { /* no storage */ }
    return nonce;
  }
  // A nonce refused as already used never executed, so the call is re-signed
  // with a new nonce (two tabs of one browser can race on the same key).
  const NONCE_REPLAY = /^replay: nonce \d+ already used/;
  const MAX_NONCE_RETRIES = 2;
  window.EgyptBoundary={BOUNDARY:e,T:t,identity:ID,uleb:n,sleb:r,readUleb:o,readSleb:s,fieldHash:a,encodeArg:function(e){const t=[],r={n:0},o=f(e=i(e),t,r,new Map),s=[68,73,68,76];return s.push(...n(r.n)),s.push(...t),s.push(...n(1)),l(s,o),p(s,e),new Uint8Array(s)},encodeArgs:function(e){const t=e.map(i),r=[],o={n:0},s=new Map,c=t.map(e=>f(e,r,o,s)),u=[68,73,68,76];u.push(...n(o.n)),u.push(...r),u.push(...n(t.length));for(const e of c)l(u,e);for(const e of t)p(u,e);return new Uint8Array(u)},decodeNatReply:function(e){const t="string"==typeof e?d(e):e;let n=4;const[r,c]=o(t,n);n=c;for(let e=0;e<Number(r);e++){const[e,r]=s(t,n);n=r}const[u,a]=o(t,n);n=a;const[i,l]=s(t,n);n=l;const[f,p]=o(t,n);return f},decodeBoolReply:function(e){const t="string"==typeof e?d(e):e;let n=4;const[r,c]=o(t,n);n=c;for(let e=0;e<Number(r);e++){const[e,r]=s(t,n);n=r}const[u,a]=o(t,n);n=a;const[i,l]=s(t,n);return n=l,0!==t[n]},decodeVecRecord:function(e,n){const r="string"==typeof e?d(e):e;let c=4;const[i,l]=o(r,c);c=l;for(let e=0;e<Number(i);e++){const[e,n]=s(r,c);if(c=n,e===BigInt(t.RECORD)){const[e,t]=o(r,c);c=t;for(let t=0;t<Number(e);t++){const[e,t]=o(r,c);c=t;const[n,u]=s(r,c);c=u}}else if(e===BigInt(t.VEC)||e===BigInt(t.OPT)){const[e,t]=s(r,c);c=t}}const[f,p]=o(r,c);c=p;const[h,y]=s(r,c);c=y;const[m,g]=o(r,c);c=g;const w=[],N=n.slice().sort((e,t)=>a(e.name)-a(t.name));for(let e=0;e<Number(m);e++){const e={};for(const t of N)if("nat"===t.type){const[n,s]=o(r,c);c=s,e[t.name]=n}else if("int"===t.type){const[n,o]=s(r,c);c=o,e[t.name]=n}else if("bool"===t.type)e[t.name]=0!==r[c++];else if("principal"===t.type){c++;const[pn,ps]=o(r,c);c=ps;e[t.name]=Array.from(r.subarray(c,c+Number(pn)),x=>x.toString(16).padStart(2,"0")).join("");c+=Number(pn)}else{if("text"!==t.type)throw new Error("unsupported decode field type: "+t.type);{const[n,s]=o(r,c);c=s,e[t.name]=u.decode(r.subarray(c,c+Number(n))),c+=Number(n)}}w.push(e)}return w},bytesToHex:h,hexToBytes:d,randomBytes:y,EMPTY_ARGS_HEX:m,
    ready,
    publicKey: publicKeyHex,
    principalOf: (publicKeyHexOrBytes) => h(principalOf(typeof publicKeyHexOrBytes === "string" ? d(publicKeyHexOrBytes) : publicKeyHexOrBytes)),
    isPersistentIdentity: () => persistentKey,
    callSigningPayload,
    // For a client with its own transport: the signed fields of one /api/call
    // body ({ sender, nonce, signature }), by this browser's key, with the next
    // nonce. The client submits it and handles a replayed nonce itself.
    signCall: async function (canisterId, method, argHex) {
      await ready();
      const arg = null == argHex ? m : argHex;
      const nonce = nextNonce();
      const signature = await signPayload(callSigningPayload(Number(canisterId), method, d(arg), keyRecord.publicKey, nonce));
      return { sender: cached.publicKey, nonce, signature: h(signature) };
    },
    callUpdate: async function (canisterId, method, argHex, opts) {
      opts = opts || {};
      await ready();
      if (opts.sender != null && opts.sender !== cached.publicKey) {
        throw typedError("ThebesUnsignedSender",
          "boundary.js signs every update with this browser's key and cannot send as another sender (" + opts.sender + ").");
      }
      const arg = null == argHex ? m : argHex;
      const argBytes = d(arg);
      for (let attempt = 0; ; attempt++) {
        const nonce = attempt === 0 && opts.nonce != null ? opts.nonce : nextNonce();
        const signature = await signPayload(callSigningPayload(Number(canisterId), method, argBytes, keyRecord.publicKey, nonce));
        const submitted = await fetch(e + "/api/call", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ canister_id: Number(canisterId), method, arg, sender: cached.publicKey, nonce, signature: h(signature) }),
        }).then((res) => res.json()).catch(() => ({}));
        if (submitted.error) throw new Error("call rejected: " + submitted.error);
        if (!submitted.message_hash) throw new Error("call: no message_hash");
        const hash = submitted.message_hash, deadline = Date.now() + (opts.timeoutMs || 1e4);
        let receipt = null;
        while (Date.now() < deadline) {
          await new Promise((res) => setTimeout(res, 150));
          const got = await fetch(e + "/api/receipt?hash=" + hash).then((res) => res.json()).catch(() => ({}));
          if ("success" === got.status || "error" === got.status) { receipt = got; break; }
        }
        if (!receipt) throw new Error("receipt poll timed out");
        if (receipt.status === "error" && NONCE_REPLAY.test(String(receipt.error || "")) && attempt < MAX_NONCE_RETRIES) continue;
        return receipt;
      }
    },
    // Queries are not signed (the chain does not check a query's caller, V151):
    // they name this browser's key so a canister's caller-scoped reads match
    // its updates.
    callQuery: async function (canisterId, method, argHex, opts) {
      opts = opts || {};
      let sender = opts.sender;
      if (sender == null) { await ready(); sender = cached.publicKey; }
      return await fetch(e + "/api/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ canister_id: Number(canisterId), method, arg: null == argHex ? m : argHex, sender }),
      }).then((res) => res.json()).catch(() => ({}));
    },
  };
  // Load (or make) the key as soon as the page runs, so the first call finds it ready.
  ready().catch(() => {});
}();
