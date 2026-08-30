/*
 * Memphis passkey sign-in client (browser, no framework).
 *
 * Talks to:
 *   POST /api/call                    (boundary passthrough → validator /api/call)
 *   GET  /api/receipt?hash=<hex>      (boundary passthrough → validator /api/receipt)
 *   POST /api/v1/canister/921/query   (boundary query passthrough)
 *
 * Surface exposed at window.MemphisPasskey:
 *   register(name)               -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag }
 *   signIn(name)                 -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag }
 *   signInOrRegister(name)       -> auto-decide via anchor_for_name lookup
 *   whoami(session_token_hex)    -> { anchor_id_hex, expires_at_ns, display_tag }
 *   lookupName(name)             -> principal hex or null
 *   loadSession()                -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag } | null
 *   saveSession(session)
 *   clearSession()               -> localStorage-only (legacy; does not revoke server-side)
 *   signOut()                    -> async; calls end_session on canister, then clearSession()
 *
 * The Memphis canister is at cid 921; RP_ID matches the page's origin
 * (memphis.mercaturaforum.com).
 *
 * REGISTRATION TAKES THREE FACTORS (MIN_FACTORS_AT_SIGNUP = 3 since
 * 2026-08-29): a device passkey, a second passkey, and a recovery phrase.
 * `register(name)` below sends ONE and is kept only for a canister that still
 * accepts that; against cid 921 it is refused with InsufficientFactors. Drive
 * a signup through beginRegistrationChallenge + buildDeviceFactor x2 +
 * buildRecoveryFactor + registerWithFactors, which is what the connect broker
 * and every current example do. `recovery.js` must be loaded alongside this
 * file for the phrase factor.
 */
(function (global) {
    "use strict";

    const MEMPHIS_CID = 921;
    const BOUNDARY = location.origin.includes("memphis.mercaturaforum.com")
        ? ""
        : "https://memphis.mercaturaforum.com";
    const RP_ID = "memphis.mercaturaforum.com";

    // ─── tiny utilities ────────────────────────────────────────────────────
    function bytesToHex(u8) {
        let s = "";
        for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
        return s;
    }
    function hexToBytes(hex) {
        if (hex.length & 1) throw new Error("odd-length hex");
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }
    function concat(...arrs) {
        let total = 0;
        for (const a of arrs) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arrs) { out.set(a, off); off += a.length; }
        return out;
    }
    function randomBytes(n) {
        const u = new Uint8Array(n);
        crypto.getRandomValues(u);
        return u;
    }
    const utf8 = new TextEncoder();
    const utf8d = new TextDecoder();

    // ─── LEB128 ────────────────────────────────────────────────────────────
    function uleb(n) {
        if (typeof n === "number") n = BigInt(n);
        const out = [];
        while (true) {
            let b = Number(n & 0x7fn);
            n >>= 7n;
            if (n === 0n) { out.push(b); return out; }
            out.push(b | 0x80);
        }
    }
    function sleb(n) {
        if (typeof n === "number") n = BigInt(n);
        const out = [];
        while (true) {
            let b = Number(n & 0x7fn);
            const sign = (b & 0x40) !== 0;
            n >>= 7n;
            if ((n === 0n && !sign) || (n === -1n && sign)) { out.push(b); return out; }
            out.push(b | 0x80);
        }
    }
    function readUleb(u8, off) {
        let r = 0n, shift = 0n, b;
        do {
            b = u8[off++];
            r |= BigInt(b & 0x7f) << shift;
            shift += 7n;
        } while (b & 0x80);
        return [r, off];
    }
    function readSleb(u8, off) {
        let r = 0n, shift = 0n, b;
        while (true) {
            b = u8[off++];
            r |= BigInt(b & 0x7f) << shift;
            shift += 7n;
            if ((b & 0x80) === 0) {
                if (shift < 64n && (b & 0x40)) r |= -(1n << shift);
                return [r, off];
            }
        }
    }

    // ─── Candid: a hand-written builder targeting only the shapes we need ──
    //
    // We emit a self-contained type table per call. For multi-arg methods we
    // build several arg type entries. This is the Candid 0.x wire format.
    //
    //   T_text       = sleb(-15)
    //   T_blob       = sleb(-19) sleb(-5)         ; vec nat8
    //   T_nat64      = sleb(-8)
    //   T_record(fs) = sleb(-20) uleb(count) (uleb(hash) sleb(type)){count}
    //   T_vec(t)     = sleb(-19) sleb(t)
    //
    // For arg encoding:
    //   text   : uleb(len) bytes
    //   blob   : uleb(len) bytes
    //   nat64  : 8 little-endian bytes
    //   record : each field in hash-sorted order
    //   vec    : uleb(len) then each element
    function candidFieldHash(name) {
        let h = 0n;
        for (const c of utf8.encode(name)) h = (h * 223n + BigInt(c)) & 0xffffffffn;
        return Number(h);
    }
    const TY = { TEXT: -15, BLOB_BYTES: -5, OPT: -18, VEC: -19, RECORD: -20, NAT64: -8 };

    // A FactorRegistration / FactorAssertion record shares the same field set
    // (with one extra field on registration).
    const FACTOR_REG_FIELDS = [
        // name -> primitive type code for the field's value
        ["credential_id", "blob"],
        ["cose_pub_key_bytes", "blob"],
        ["authenticator_data", "blob"],
        ["client_data_json", "blob"],
        ["signature", "blob"],
    ];
    const FACTOR_ASSERT_FIELDS = [
        ["credential_id", "blob"],
        ["authenticator_data", "blob"],
        ["client_data_json", "blob"],
        ["signature", "blob"],
    ];

    // Encode `(vec FactorRegistration)`. Three type-table entries: T0 is
    // `vec nat8` (blob), T1 is the record whose fields ALL reference T0,
    // T2 is `vec T1`. Field type-refs in T1 are POSITIVE-SLEB type-table
    // indices, not inline `vec nat8` opcodes — Candid forbids compound
    // types (vec, opt, record, variant) appearing inline at a field's
    // type-ref position; they MUST appear in the type table and the
    // field references the index.
    function encVecFactorRegistration(factors) {
        // Blob fields plus the optional `kind : opt FactorKindArg` (P2.4 —
        // marks a signup factor as the recovery phrase; absent ⇒ WebAuthn).
        // A canister that predates the field skips it per Candid width
        // subtyping, so this encoding is safe against cid 921 as deployed.
        const KIND_ORDER = ["WebAuthn", "RecoveryPhrase"]
            .map(n => ({ name: n, hash: candidFieldHash(n) }))
            .sort((a, b) => a.hash - b.hash);
        const sorted = FACTOR_REG_FIELDS
            .map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
            .concat([{ name: "kind", hash: candidFieldHash("kind"), t: "optkind" }])
            .sort((a, b) => a.hash - b.hash);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(5));
        // T0 = vec nat8 (blob)
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // T1 = variant { kinds → null }
        out.push(...sleb(-21));
        out.push(...uleb(KIND_ORDER.length));
        for (const k of KIND_ORDER) {
            out.push(...uleb(k.hash));
            out.push(...sleb(-1)); // null payload
        }
        // T2 = opt T1
        out.push(...sleb(TY.OPT));
        out.push(...sleb(1));
        // T3 = record { blob fields → T0, kind → T2 }
        out.push(...sleb(TY.RECORD));
        out.push(...uleb(sorted.length));
        for (const f of sorted) {
            out.push(...uleb(f.hash));
            out.push(...sleb(f.t === "optkind" ? 2 : 0));
        }
        // T4 = vec T3
        out.push(...sleb(TY.VEC));
        out.push(...sleb(3));
        // 1 arg of type T4
        out.push(...uleb(1));
        out.push(...sleb(4));
        // value
        out.push(...uleb(factors.length));
        for (const f of factors) {
            for (const fd of sorted) {
                if (fd.t === "optkind") {
                    const k = f.kind;
                    if (k == null) { out.push(0x00); continue; }
                    const idx = KIND_ORDER.findIndex(e => e.name === k);
                    if (idx < 0) throw new Error("unknown factor kind " + k);
                    out.push(0x01);
                    out.push(...uleb(idx));
                    continue;
                }
                const v = f[fd.name];
                if (!(v instanceof Uint8Array)) throw new Error("factor field " + fd.name + " must be Uint8Array");
                out.push(...uleb(v.length));
                for (const b of v) out.push(b);
            }
        }
        return new Uint8Array(out);
    }

    // Encode `(FactorAssertion)`. Two type-table entries: T0 is
    // `vec nat8` (blob), T1 is the record whose fields ALL reference T0.
    // Same rule as encVecFactorRegistration: compound types live in the
    // type table; field type-refs are positive-sleb indices.
    function encFactorAssertion(assertion) {
        const sorted = FACTOR_ASSERT_FIELDS
            .map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
            .sort((a, b) => a.hash - b.hash);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(2));
        // T0 = vec nat8 (blob)
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // T1 = record { fields → T0 }
        out.push(...sleb(TY.RECORD));
        out.push(...uleb(sorted.length));
        for (const f of sorted) {
            out.push(...uleb(f.hash));
            out.push(...sleb(0)); // type ref → T0
        }
        // 1 arg of type T1
        out.push(...uleb(1));
        out.push(...sleb(1));
        for (const fd of sorted) {
            const v = assertion[fd.name];
            if (!(v instanceof Uint8Array)) throw new Error("assertion field " + fd.name + " must be Uint8Array");
            out.push(...uleb(v.length));
            for (const b of v) out.push(b);
        }
        return new Uint8Array(out);
    }

    // Encode `(blob)` single arg.
    function encBlob(bytes) {
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        out.push(...uleb(1));
        out.push(...sleb(0));
        out.push(...uleb(bytes.length));
        for (const b of bytes) out.push(b);
        return new Uint8Array(out);
    }

    // Encode `(text)` single arg.
    function encText(s) {
        const bytes = utf8.encode(s);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(0));
        out.push(...uleb(1));
        out.push(...sleb(TY.TEXT));
        out.push(...uleb(bytes.length));
        for (const b of bytes) out.push(b);
        return new Uint8Array(out);
    }


    // Encode `(blob, text, nat64)` for issue_scoped_session.
    function encScopedSessionArgs(token, origin, ttlNs) {
        const tokenBytes = token instanceof Uint8Array ? token : hexToBytes(token);
        const originBytes = utf8.encode(origin);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        out.push(...uleb(3));
        out.push(...sleb(0));
        out.push(...sleb(TY.TEXT));
        out.push(...sleb(TY.NAT64));
        out.push(...uleb(tokenBytes.length));
        for (const b of tokenBytes) out.push(b);
        out.push(...uleb(originBytes.length));
        for (const b of originBytes) out.push(b);
        const v = BigInt(ttlNs);
        for (let i = 0n; i < 8n; i++) out.push(Number((v >> (i * 8n)) & 0xffn));
        return new Uint8Array(out);
    }

    // Encode `(blob, text)` for issue_refresh / exchange_refresh. Same shape as
    // encScopedSessionArgs without the ttl: the canister owns the lifetimes, so
    // there is nothing for a client to ask for and nothing it could inflate.
    function encBlobTextArgs(token, text) {
        const tokenBytes = token instanceof Uint8Array ? token : hexToBytes(token);
        const textBytes = utf8.encode(text);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        out.push(...uleb(2));
        out.push(...sleb(0));
        out.push(...sleb(TY.TEXT));
        out.push(...uleb(tokenBytes.length));
        for (const b of tokenBytes) out.push(b);
        out.push(...uleb(textBytes.length));
        for (const b of textBytes) out.push(b);
        return new Uint8Array(out);
    }

    // Encode `(blob, text, text, nat64)` for claim_name.
    function encClaimNameArgs(token, name, origin, version) {
        const tokenBytes = token instanceof Uint8Array ? token : hexToBytes(token);
        const nameBytes = utf8.encode(name);
        const originBytes = utf8.encode(origin);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        // T0 = blob (vec nat8)
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // 4 args: T0, text, text, nat64
        out.push(...uleb(4));
        out.push(...sleb(0));
        out.push(...sleb(TY.TEXT));
        out.push(...sleb(TY.TEXT));
        out.push(...sleb(TY.NAT64));
        // value: blob
        out.push(...uleb(tokenBytes.length));
        for (const b of tokenBytes) out.push(b);
        // value: text name
        out.push(...uleb(nameBytes.length));
        for (const b of nameBytes) out.push(b);
        // value: text origin
        out.push(...uleb(originBytes.length));
        for (const b of originBytes) out.push(b);
        // value: nat64 (LE)
        const v = BigInt(version);
        for (let i = 0n; i < 8n; i++) out.push(Number((v >> (i * 8n)) & 0xffn));
        return new Uint8Array(out);
    }

    // ─── Candid: small reply decoder that walks the wire format ────────────
    //
    // We don't build a general decoder; instead, each reply shape has a
    // dedicated routine that knows what to expect. This keeps the parser
    // small and easy to audit.

    function skipTypeTable(u8, off) {
        // We don't *use* the type table for the value walker — the canister
        // emits a well-known shape per method — but we have to advance past
        // it. Each type def is a sleb followed by a variable structure.
        const [tts, a1] = readUleb(u8, off); off = a1;
        for (let i = 0n; i < tts; i++) {
            const [code, a2] = readSleb(u8, off); off = a2;
            if (code === -20n || code === -21n) {
                // record / variant: uleb count, then (hash sleb, type-ref sleb) pairs
                const [cnt, a3] = readUleb(u8, off); off = a3;
                for (let j = 0n; j < cnt; j++) {
                    const [_h, a4] = readUleb(u8, off); off = a4;
                    const [_t, a5] = readSleb(u8, off); off = a5;
                }
            } else if (code === -18n || code === -19n) {
                // opt / vec: one inner type-ref
                const [_t, a3] = readSleb(u8, off); off = a3;
            } else if (code === -22n) {
                // func: arg-vec, ret-vec, ann-vec — we don't expect these
                throw new Error("func type unexpected");
            } else if (code === -23n) {
                throw new Error("service type unexpected");
            }
            // primitive (-1..-15) and references take no further bytes
        }
        // arg count + arg type refs
        const [args, a6] = readUleb(u8, off); off = a6;
        for (let i = 0n; i < args; i++) {
            const [_t, a7] = readSleb(u8, off); off = a7;
        }
        return off;
    }

    function expectDidlMagic(u8) {
        if (u8.length < 4 || u8[0] !== 0x44 || u8[1] !== 0x49 || u8[2] !== 0x44 || u8[3] !== 0x4c) {
            throw new Error("reply missing DIDL magic");
        }
        return 4;
    }

    // Decode a `variant { Ok : blob; Err : MemphisError }` reply where Ok is blob.
    function decodeResultBlob(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const [len, a2] = readUleb(replyBytes, off); off = a2;
            return { ok: replyBytes.slice(off, off + Number(len)) };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode a `variant { Ok; Err : MemphisError }` reply where Ok carries no
    // payload (used by end_session). Returns { ok: true } or { err: {...} }.
    function decodeResultEmpty(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) return { ok: true };
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode a `variant { Ok : record { anchor_id : blob; session_token : blob; expires_at_ns : nat64 }; Err : MemphisError }`.
    // We rely on the canister always emitting fields in hash-sorted order
    // (Candid mandates this); the actual hashes are:
    //   anchor_id      = candidFieldHash("anchor_id")      = 0x00B2D8B8 = 11721912
    //   session_token  = candidFieldHash("session_token")  = ...
    //   expires_at_ns  = candidFieldHash("expires_at_ns")  = ...
    // We compute the three hashes, sort them, and decode in that order.
    function decodeResultRecordReg(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const order = sortedFieldOrder([
                ["anchor_id", "blob"],
                ["session_token", "blob"],
                ["expires_at_ns", "nat64"],
                ["display_tag", "text"],
            ]);
            const rec = {};
            for (const fd of order) {
                if (fd.t === "blob") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = replyBytes.slice(off, off + Number(len));
                    off += Number(len);
                } else if (fd.t === "nat64") {
                    let v = 0n;
                    for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                    rec[fd.name] = v;
                    off += 8;
                } else if (fd.t === "text") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = utf8d.decode(replyBytes.slice(off, off + Number(len)));
                    off += Number(len);
                }
            }
            return { ok: rec };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    function decodeResultRecordAuth(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const order = sortedFieldOrder([
                ["session_token", "blob"],
                ["expires_at_ns", "nat64"],
            ]);
            const rec = {};
            for (const fd of order) {
                if (fd.t === "blob") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = replyBytes.slice(off, off + Number(len));
                    off += Number(len);
                } else if (fd.t === "nat64") {
                    let v = 0n;
                    for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                    rec[fd.name] = v;
                    off += 8;
                }
            }
            return { ok: rec };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode `variant { Ok : record {...}; Err : MemphisError }` for any field
    // list. The two decoders above are this function with their field lists
    // inlined; new records use this rather than growing a third copy.
    // Candid mandates hash-sorted field order on the wire, which is what
    // sortedFieldOrder reproduces — the declaration order here is irrelevant.
    function decodeResultRecordFields(replyBytes, fields) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag !== 0n) return { err: extractErrorTag(replyBytes, off, tag) };
        const rec = {};
        for (const fd of sortedFieldOrder(fields)) {
            if (fd.t === "blob") {
                const [len, ax] = readUleb(replyBytes, off); off = ax;
                rec[fd.name] = replyBytes.slice(off, off + Number(len));
                off += Number(len);
            } else if (fd.t === "nat64") {
                let v = 0n;
                for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                rec[fd.name] = v;
                off += 8;
            } else if (fd.t === "text") {
                const [len, ax] = readUleb(replyBytes, off); off = ax;
                rec[fd.name] = utf8d.decode(replyBytes.slice(off, off + Number(len)));
                off += Number(len);
            }
        }
        return { ok: rec };
    }

    // Decode `(opt blob)` reply for anchor_for_name / lookup_name.
    function decodeOptBlob(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const present = replyBytes[off++];
        if (present === 0) return null;
        const [len, a1] = readUleb(replyBytes, off); off = a1;
        return replyBytes.slice(off, off + Number(len));
    }

    // Decode `(variant { Ok : text; Err : MemphisError })` for claim_name.
    function decodeResultText(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const [len, a2] = readUleb(replyBytes, off); off = a2;
            return { ok: utf8d.decode(replyBytes.slice(off, off + Number(len))) };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    function sortedFieldOrder(fields) {
        return fields.map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
                     .sort((a, b) => a.hash - b.hash);
    }

    // Decode the MemphisError variant payload that follows the outer Err tag.
    // Candid orders variant fields by FIELD HASH, not declaration order — the
    // previous version of this function mapped the OUTER tag through a
    // positional table and rendered every error as "NotAuthenticated". This
    // one reads the INNER variant tag and resolves it through the hash-sorted
    // name list, and decodes the payload of the carriers so the UI can show
    // the canister's actual sentence.
    const MEMPHIS_ERROR_VARIANTS = [
        "NotAuthenticated", "Unauthorized", "SessionExpired", "ChallengeExpired",
        "AnchorNotFound", "FactorNotFound", "InsufficientFactors", "DuplicateCredential",
        "InvalidArgument", "InvariantViolation", "RemovalDelayNotElapsed",
    ];
    function extractErrorTag(u8, off, tag) {
        if (Number(tag) !== 1) return { tag: Number(tag), name: "variant#" + tag };
        const order = MEMPHIS_ERROR_VARIANTS
            .map(n => ({ name: n, hash: candidFieldHash(n) }))
            .sort((a, b) => a.hash - b.hash);
        const [itag, a1] = readUleb(u8, off); off = a1;
        const entry = order[Number(itag)];
        const name = entry ? entry.name : ("error#" + itag);
        const out = { tag: 1, name };
        try {
            if (name === "InvalidArgument") {
                const [len, a2] = readUleb(u8, off); off = a2;
                out.message = utf8d.decode(u8.slice(off, off + Number(len)));
            } else if (name === "InvariantViolation") {
                // record { id : text; details : text } in hash order.
                const rec = {};
                for (const fd of sortedFieldOrder([["id", "text"], ["details", "text"]])) {
                    const [len, a2] = readUleb(u8, off); off = a2;
                    rec[fd.name] = utf8d.decode(u8.slice(off, off + Number(len)));
                    off += Number(len);
                }
                out.id = rec.id;
                out.message = rec.details;
            } else if (name === "RemovalDelayNotElapsed") {
                let v = 0n;
                for (let i = 0n; i < 8n; i++) v |= BigInt(u8[off + Number(i)]) << (i * 8n);
                out.effective_at_ns = v;
            }
        } catch (_) { /* payload decode is best-effort; the name is what matters */ }
        return out;
    }

    // ─── boundary transport ────────────────────────────────────────────────
    async function memphisCallAwait(method, argBytes) {
        const argHex = bytesToHex(argBytes);
        // Anonymous calls need a fresh sender per submission, otherwise the
        // validator's per-(sender, nonce) replay set rejects the second call
        // from "sender=""" with "nonce 0 already used". We don't sign these
        // envelopes (the canister auths via WebAuthn factor proofs, not
        // msg_caller), so a random 32-byte sender is fine for transport.
        const sender = bytesToHex(randomBytes(32));
        const callRes = await fetch(BOUNDARY + "/api/call", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                canister_id: MEMPHIS_CID,
                method,
                arg: argHex,
                sender,
            }),
        }).then(r => r.json());
        if (callRes.error) throw new Error("call: " + callRes.error);
        if (!callRes.message_hash) throw new Error("call: missing message_hash in response");
        const hash = callRes.message_hash;
        // Poll up to ~8 s — single-canister cluster finalises in ~200 ms,
        // so this is generous but bounded.
        const deadline = Date.now() + 8000;
        let lastLifecycle = "submitted";
        while (Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 150));
            const recRes = await fetch(BOUNDARY + "/api/receipt?hash=" + hash);
            const rec = await recRes.json().catch(() => ({}));
            lastLifecycle = rec.lifecycle || lastLifecycle;
            if (rec.status === "success" && rec.reply) {
                return hexToBytes(rec.reply);
            }
            if (rec.status === "error") {
                throw new Error("canister error: " + (rec.error || "unknown"));
            }
        }
        throw new Error("receipt poll timeout (last lifecycle=" + lastLifecycle + ")");
    }

    function bytesToBase64(u8) {
        let s = "";
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return btoa(s);
    }
    function base64ToBytes(b64) {
        const bin = atob(b64);
        const u = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
        return u;
    }
    async function memphisQuery(method, argBytes) {
        const argB64 = bytesToBase64(argBytes);
        const res = await fetch(BOUNDARY + "/api/v1/canister/" + MEMPHIS_CID + "/query", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ method, arg: argB64, sender: "" }),
        }).then(r => r.json());
        if (res.status !== "success") throw new Error("query: " + (res.error || res.status));
        if (!res.reply) throw new Error("query: empty reply");
        // /api/v1/canister/{cid}/query returns reply as base64; /api/receipt
        // (used by memphisCallAwait below) returns it as hex.
        return base64ToBytes(res.reply);
    }

    // ─── CBOR (the minimum needed to extract authData) ─────────────────────
    function cborRead(buf, off) {
        const initial = buf[off++];
        const major = initial >> 5;
        const ai = initial & 0x1f;
        let val;
        if (ai < 24) val = ai;
        else if (ai === 24) { val = buf[off++]; }
        else if (ai === 25) { val = (buf[off++] << 8) | buf[off++]; }
        else if (ai === 26) {
            val = ((buf[off++] << 24) >>> 0) + (buf[off++] << 16) + (buf[off++] << 8) + buf[off++];
            val = val >>> 0;
        } else if (ai === 27) {
            // 8-byte length — rarely used at WebAuthn scale; reject for safety.
            throw new Error("CBOR 64-bit length unsupported");
        } else {
            throw new Error("CBOR indef/reserved unsupported ai=" + ai);
        }
        if (major === 0) return [val, off];
        if (major === 1) return [-1 - val, off];
        if (major === 2) return [buf.slice(off, off + val), off + val];
        if (major === 3) return [utf8d.decode(buf.slice(off, off + val)), off + val];
        if (major === 4) {
            const arr = [];
            for (let i = 0; i < val; i++) { const [v, o] = cborRead(buf, off); arr.push(v); off = o; }
            return [arr, off];
        }
        if (major === 5) {
            const map = new Map();
            for (let i = 0; i < val; i++) {
                const [k, o1] = cborRead(buf, off); off = o1;
                const [v, o2] = cborRead(buf, off); off = o2;
                map.set(typeof k === "string" ? k : k, v);
            }
            return [map, off];
        }
        if (major === 6) {
            // tagged value — read the inner item; we ignore tags.
            return cborRead(buf, off);
        }
        throw new Error("unsupported CBOR major: " + major);
    }

    // Given the raw CBOR-encoded attestation object, extract authData bytes.
    function extractAuthData(attestationObject) {
        const [obj] = cborRead(attestationObject, 0);
        if (!(obj instanceof Map)) throw new Error("attestation object is not a CBOR map");
        const authData = obj.get("authData");
        if (!(authData instanceof Uint8Array)) throw new Error("attestation missing authData bytes");
        return authData;
    }

    // Parse the authData layout and return { credentialId, credentialPublicKeyBytes }.
    // Layout:
    //   rpIdHash (32) | flags (1) | signCount (4) | aaguid (16) |
    //   credentialIdLength (2 BE) | credentialId (var) |
    //   credentialPublicKey (CBOR-encoded COSE_Key, var)
    function parseAttestedCredentialData(authData) {
        if (authData.length < 37 + 18) throw new Error("authData too short for attested credential data");
        const flags = authData[32];
        if ((flags & 0x40) === 0) throw new Error("authData flag AT (attested credential data) not set");
        let off = 37; // skip rpIdHash + flags + signCount
        off += 16;   // skip aaguid
        const credIdLen = (authData[off] << 8) | authData[off + 1];
        off += 2;
        const credentialId = authData.slice(off, off + credIdLen);
        off += credIdLen;
        // The COSE key is a single CBOR object starting at off; we need its
        // exact byte span so the canister can re-parse it.
        const start = off;
        const [_obj, end] = cborRead(authData, off);
        const credentialPublicKeyBytes = authData.slice(start, end);
        return { credentialId, credentialPublicKeyBytes };
    }

    // ─── WebAuthn ceremonies ───────────────────────────────────────────────
    //
    // Registration is a create()+get() PAIR over the same canister-issued
    // challenge, with attestation:"none":
    //   1. create() mints the credential; we extract only the COSE public key
    //      from authData (we do NOT use the attestation statement — "none"
    //      works on iOS/macOS Safari and Android, which don't emit "packed").
    //   2. get() immediately produces a real "webauthn.get" assertion over the
    //      same challenge — a standard ECDSA-P256 sig over
    //      authData ‖ SHA-256(clientDataJSON). The canister's INV-MEM-7
    //      verifier REQUIRES clientDataJSON.type == "webauthn.get" (see
    //      crates/memphis-webauthn verify_assertion), so the create-only
    //      ("webauthn.create") path is rejected.
    // Two user-presence prompts (one per ceremony); works on every device.
    async function webauthnCreate(challengeBytes, displayName) {
        // create()+get() PAIR over the same challenge. create() with
        // attestation:"none" mints the credential (we only need the COSE public
        // key from authData — no attStmt, so it works on iOS/macOS Safari and
        // Android which return "none"). An immediate get() yields a real
        // "webauthn.get" assertion, which the canister's INV-MEM-7 REQUIRES
        // (clientDataJSON.type must be "webauthn.get" — see crates/memphis-webauthn
        // verify_assertion). Two user-presence prompts; works on every device.
        const created = await navigator.credentials.create({
            publicKey: {
                challenge: challengeBytes,
                rp: { id: RP_ID, name: "Memphis" },
                user: {
                    id: randomBytes(32),
                    name: displayName,
                    displayName: displayName,
                },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                // residentKey — without it the minted credential is non-
                // discoverable and signIn's get({allowCredentials: []}) cannot
                // find it (2026-08-29 register-vs-signIn defect). "required" +
                // the WebAuthn-L1 spelling matches the thebes-sdk runtime.
                authenticatorSelection: {
                    residentKey: "required",
                    requireResidentKey: true,
                    userVerification: "preferred",
                },
                timeout: 60000,
                attestation: "none",
            },
        });
        if (!created) throw new Error("navigator.credentials.create returned null");
        const credentialId = new Uint8Array(created.rawId);
        const attestationObject = new Uint8Array(created.response.attestationObject);

        // Parse the CBOR attestationObject only to pull authData → COSE pubkey.
        const [obj] = cborRead(attestationObject, 0);
        if (!(obj instanceof Map)) throw new Error("attestationObject is not a CBOR map");
        const authData = obj.get("authData");
        if (!(authData instanceof Uint8Array)) {
            throw new Error("attestationObject missing authData");
        }
        const { credentialPublicKeyBytes } = parseAttestedCredentialData(authData);

        // Immediate get() over the SAME challenge → "webauthn.get" assertion.
        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challengeBytes,
                rpId: RP_ID,
                allowCredentials: [
                    { type: "public-key", id: credentialId, transports: ["internal", "hybrid", "usb", "nfc", "ble"] },
                ],
                userVerification: "preferred",
                timeout: 60000,
            },
        });
        if (!assertion) throw new Error("navigator.credentials.get returned null (registration probe)");
        return {
            credentialId,
            cose_pub_key_bytes: credentialPublicKeyBytes,
            authenticator_data: new Uint8Array(assertion.response.authenticatorData),
            client_data_json: new Uint8Array(assertion.response.clientDataJSON),
            signature: new Uint8Array(assertion.response.signature),
        };
    }

    async function webauthnGet(challengeBytes, allowCredentialIds) {
        const cred = await navigator.credentials.get({
            publicKey: {
                challenge: challengeBytes,
                rpId: RP_ID,
                allowCredentials: (allowCredentialIds || []).map(id => ({
                    type: "public-key",
                    id,
                    transports: ["internal", "hybrid", "usb", "nfc", "ble"],
                })),
                userVerification: "preferred",
                timeout: 60000,
            },
        });
        if (!cred) throw new Error("navigator.credentials.get returned null");
        return {
            credentialId: new Uint8Array(cred.rawId),
            authenticatorData: new Uint8Array(cred.response.authenticatorData),
            clientDataJSON: new Uint8Array(cred.response.clientDataJSON),
            signature: new Uint8Array(cred.response.signature),
        };
    }

    // ─── High-level flows ──────────────────────────────────────────────────
    function validateName(name) {
        const n = name.trim().toLowerCase();
        if (!n.endsWith(".thebes")) throw new Error("name must end with .thebes");
        const stem = n.slice(0, -".thebes".length);
        if (stem.length < 3 || stem.length > 32) throw new Error("name stem must be 3-32 chars");
        if (!/^[a-z0-9-]+$/.test(stem)) throw new Error("name stem may only contain a-z 0-9 -");
        if (stem.startsWith("-") || stem.endsWith("-")) throw new Error("stem may not start/end with -");
        return n;
    }

    async function lookupAnchor(name) {
        const reply = await memphisQuery("anchor_for_name", encText(name));
        return decodeOptBlob(reply);
    }

    async function lookupNameToPrincipal(name) {
        const reply = await memphisQuery("lookup_name", encText(name));
        return decodeOptBlob(reply);
    }

    async function nameForPrincipal(principalBytes) {
        const reply = await memphisQuery("name_for", encBlob(principalBytes));
        // (opt text) reply
        let off = expectDidlMagic(reply);
        off = skipTypeTable(reply, off);
        const present = reply[off++];
        if (present === 0) return null;
        const [len, a1] = readUleb(reply, off); off = a1;
        return utf8d.decode(reply.slice(off, off + Number(len)));
    }

    async function register(name) {
        const validated = validateName(name);
        // 1. begin_registration -> 32-byte challenge
        const challengeReply = await memphisCallAwait("begin_registration", new Uint8Array([0x44, 0x49, 0x44, 0x4c, 0x00, 0x00]));
        const dec = decodeResultBlob(challengeReply);
        if (dec.err) throw new Error("begin_registration: " + dec.err.name);
        const challenge = dec.ok;

        // 2. Pair of WebAuthn ceremonies (create + immediate get over same challenge)
        const factor = await webauthnCreate(challenge, validated);

        // 3. register([factor])
        const regReply = await memphisCallAwait(
            "register",
            encVecFactorRegistration([
                {
                    credential_id: factor.credentialId,
                    cose_pub_key_bytes: factor.cose_pub_key_bytes,
                    authenticator_data: factor.authenticator_data,
                    client_data_json: factor.client_data_json,
                    signature: factor.signature,
                },
            ])
        );
        const regDec = decodeResultRecordReg(regReply);
        if (regDec.err) {
            // Carry the typed variant + the canister's sentence so callers can
            // react (e.g. INV-MEM-1 → run the multi-factor signup ceremony).
            const e = new Error("register: " + (regDec.err.message || regDec.err.name));
            e.code = regDec.err.name;
            e.errId = regDec.err.id;
            throw e;
        }
        const anchorIdHex = bytesToHex(regDec.ok.anchor_id);
        const sessionTokenHex = bytesToHex(regDec.ok.session_token);

        // 4. claim_name (binds the handle to the per-app principal for THIS origin).
        const claimReply = await memphisCallAwait(
            "claim_name",
            encClaimNameArgs(regDec.ok.session_token, validated, location.origin, 0)
        );
        const claimDec = decodeResultText(claimReply);
        if (claimDec.err) throw new Error("claim_name: " + claimDec.err.name);

        const session = {
            name: validated,
            anchor_id_hex: anchorIdHex,
            session_token_hex: sessionTokenHex,
            expires_at_ns: regDec.ok.expires_at_ns.toString(),
            // Display tag = last 4 hex chars of anchor_id_hex. The canister
            // returns the canonical value in `regDec.ok.display_tag`; if that
            // field is missing (older canister), fall back to deriving it
            // client-side from anchor_id_hex (same formula, same result).
            display_tag: regDec.ok.display_tag || anchorIdHex.slice(-4),
        };
        saveSession(session);
        return session;
    }

    async function signIn(name) {
        const validated = validateName(name);
        const anchorBytes = await lookupAnchor(validated);
        if (!anchorBytes) throw new Error("no Memphis identity for " + validated + " — register first");
        // 1. begin_authentication(anchor_id)
        const challengeReply = await memphisCallAwait("begin_authentication", encBlob(anchorBytes));
        const dec = decodeResultBlob(challengeReply);
        if (dec.err) throw new Error("begin_authentication: " + dec.err.name);
        const challenge = dec.ok;
        // 2. navigator.credentials.get with allowCredentials = [] so the
        //    authenticator surfaces all stored credentials matching the rp.
        //    (We don't track credential ids client-side; the canister will
        //    refuse if the asserted credential_id isn't bound to the anchor.)
        const assertion = await webauthnGet(challenge, []);
        // 3. authenticate
        const authReply = await memphisCallAwait("authenticate", encFactorAssertion({
            credential_id: assertion.credentialId,
            authenticator_data: assertion.authenticatorData,
            client_data_json: assertion.clientDataJSON,
            signature: assertion.signature,
        }));
        const authDec = decodeResultRecordAuth(authReply);
        if (authDec.err) throw new Error("authenticate: " + authDec.err.name);
        const session = {
            name: validated,
            anchor_id_hex: bytesToHex(anchorBytes),
            session_token_hex: bytesToHex(authDec.ok.session_token),
            expires_at_ns: authDec.ok.expires_at_ns.toString(),
            // AuthResult doesn't carry display_tag (the reply is just token +
            // expiry); derive it client-side from anchor_id. The canister
            // uses the same formula in lib.rs:display_tag().
            display_tag: bytesToHex(anchorBytes).slice(-4),
        };
        saveSession(session);
        return session;
    }

    // P1.4 — never silently mint a NEW anchor under a name the user expected to
    // sign INTO. If the name resolves, sign in. If it does not, the caller must
    // explicitly opt into creation (`{ confirmCreate: true }`) after asking the
    // user; otherwise we throw a typed `NameNotRegistered` so the UI can confirm.
    // (Before this fix, a lookup miss silently re-registered — the "silent
    // re-registration" bug. P0.1 stable storage removed the main trigger, but
    // this closes the unsafe path itself.)
    async function signInOrRegister(name, opts) {
        const validated = validateName(name);
        const anchorBytes = await lookupAnchor(validated);
        if (anchorBytes) return signIn(validated);
        if (opts && opts.confirmCreate === true) return register(validated);
        const err = new Error("No Memphis identity exists for \"" + validated + "\".");
        err.code = "NameNotRegistered";
        err.nameRequested = validated;
        throw err;
    }

    // ─── P2 — factor lifecycle: add device / recovery phrase / remove ──────
    //
    // Canister surface (canisters/memphis/src/lib.rs):
    //   begin_add_factor(session_token)                       -> challenge
    //   add_factor(session_token, FactorRegistration, kind)   -> AddFactorResult
    //   remove_factor(session_token, factor_id)               -> RemoveFactorStatus
    //   cancel_factor_removal(session_token, factor_id)       -> ()
    //   list_factors(session_token)                           -> vec FactorInfo
    // A RecoveryPhrase factor is a client-side BIP39-derived P-256 key
    // (recovery.js / global.MemphisRecovery); its assertions are synthetic but
    // byte-shape-identical to a platform authenticator's, so the canister's
    // INV-MEM-7 path verifies both the same way.

    const TY_NULL = -1;
    const TY_VARIANT = -21;
    const FACTOR_KIND_VARIANTS = ["WebAuthn", "RecoveryPhrase"];

    function factorKindWireIndex(kindName) {
        const order = FACTOR_KIND_VARIANTS
            .map(n => ({ name: n, hash: candidFieldHash(n) }))
            .sort((a, b) => a.hash - b.hash);
        const idx = order.findIndex(e => e.name === kindName);
        if (idx < 0) throw new Error("unknown factor kind " + kindName);
        return { idx, order };
    }

    // Encode `(blob, FactorRegistration, FactorKindArg)` for add_factor.
    function encAddFactorArgs(tokenBytes, factor, kindName) {
        const sorted = FACTOR_REG_FIELDS
            .map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
            .sort((a, b) => a.hash - b.hash);
        const kind = factorKindWireIndex(kindName);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(3));
        // T0 = vec nat8 (blob)
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // T1 = record { fields -> T0 }
        out.push(...sleb(TY.RECORD));
        out.push(...uleb(sorted.length));
        for (const f of sorted) {
            out.push(...uleb(f.hash));
            out.push(...sleb(0));
        }
        // T2 = variant { kinds -> null }, fields in hash order
        out.push(...sleb(TY_VARIANT));
        out.push(...uleb(kind.order.length));
        for (const e of kind.order) {
            out.push(...uleb(e.hash));
            out.push(...sleb(TY_NULL));
        }
        // 3 args: T0, T1, T2
        out.push(...uleb(3));
        out.push(...sleb(0));
        out.push(...sleb(1));
        out.push(...sleb(2));
        // value: blob token
        out.push(...uleb(tokenBytes.length));
        for (const b of tokenBytes) out.push(b);
        // value: record
        for (const fd of sorted) {
            const v = factor[fd.name];
            if (!(v instanceof Uint8Array)) throw new Error("factor field " + fd.name + " must be Uint8Array");
            out.push(...uleb(v.length));
            for (const b of v) out.push(b);
        }
        // value: variant index (null payload -> nothing)
        out.push(...uleb(kind.idx));
        return new Uint8Array(out);
    }

    // Encode `(blob, blob)` for remove_factor / cancel_factor_removal.
    function encTwoBlobs(aBytes, bBytes) {
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        out.push(...uleb(2));
        out.push(...sleb(0));
        out.push(...sleb(0));
        for (const bytes of [aBytes, bBytes]) {
            out.push(...uleb(bytes.length));
            for (const b of bytes) out.push(b);
        }
        return new Uint8Array(out);
    }

    // Decode `variant { Ok : AddFactorResult; Err }`.
    function decodeResultAddFactor(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag !== 0n) return { err: extractErrorTag(replyBytes, off, tag) };
        const rec = {};
        for (const fd of sortedFieldOrder([["factor_id", "blob"], ["factor_count", "nat64"]])) {
            if (fd.t === "blob") {
                const [len, ax] = readUleb(replyBytes, off); off = ax;
                rec[fd.name] = replyBytes.slice(off, off + Number(len));
                off += Number(len);
            } else {
                let v = 0n;
                for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                rec[fd.name] = v;
                off += 8;
            }
        }
        return { ok: rec };
    }

    // Decode `variant { Ok : RemoveFactorStatus; Err }` where
    // RemoveFactorStatus = variant { PendingUntil : record { effective_at_ns };
    // Removed } (fields hash-sorted on the wire).
    function decodeResultRemoveFactor(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag !== 0n) return { err: extractErrorTag(replyBytes, off, tag) };
        const order = ["PendingUntil", "Removed"]
            .map(n => ({ name: n, hash: candidFieldHash(n) }))
            .sort((a, b) => a.hash - b.hash);
        const [itag, a2] = readUleb(replyBytes, off); off = a2;
        const which = order[Number(itag)] ? order[Number(itag)].name : null;
        if (which === "Removed") return { ok: { status: "Removed" } };
        if (which === "PendingUntil") {
            let v = 0n;
            for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
            return { ok: { status: "PendingUntil", effective_at_ns: v } };
        }
        return { err: { tag: Number(itag), name: "unknown-remove-status" } };
    }

    // Decode `variant { Ok : vec FactorInfo; Err }` where FactorInfo =
    // record { factor_id : blob; kind : FactorKindArg; removal_effective_at_ns : opt nat64 }.
    function decodeResultFactorInfos(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag !== 0n) return { err: extractErrorTag(replyBytes, off, tag) };
        const kindOrder = FACTOR_KIND_VARIANTS
            .map(n => ({ name: n, hash: candidFieldHash(n) }))
            .sort((a, b) => a.hash - b.hash);
        const fieldOrder = sortedFieldOrder([
            ["factor_id", "blob"],
            ["kind", "kind"],
            ["removal_effective_at_ns", "optnat64"],
        ]);
        const [count, a2] = readUleb(replyBytes, off); off = a2;
        const rows = [];
        for (let i = 0n; i < count; i++) {
            const row = {};
            for (const fd of fieldOrder) {
                if (fd.t === "blob") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    row[fd.name] = replyBytes.slice(off, off + Number(len));
                    off += Number(len);
                } else if (fd.t === "kind") {
                    const [ktag, ax] = readUleb(replyBytes, off); off = ax;
                    row[fd.name] = kindOrder[Number(ktag)] ? kindOrder[Number(ktag)].name : ("kind#" + ktag);
                } else { // opt nat64
                    const present = replyBytes[off++];
                    if (present === 0) { row[fd.name] = null; continue; }
                    let v = 0n;
                    for (let j = 0n; j < 8n; j++) v |= BigInt(replyBytes[off + Number(j)]) << (j * 8n);
                    row[fd.name] = v;
                    off += 8;
                }
            }
            rows.push(row);
        }
        return { ok: rows };
    }

    // ── synthetic (recovery-phrase) assertion envelope ─────────────────────
    async function sha256b(bytes) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    }
    function bytesToBase64Url(u8) {
        let bin = "";
        for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // Build the WebAuthn-shaped blobs a platform authenticator would produce,
    // signed by the phrase-derived key instead: authenticatorData =
    // rpIdHash ‖ flags(UP|UV) ‖ signCount(0); clientDataJSON carries the
    // challenge (base64url) and THIS page's origin; the ECDSA message is
    // authData ‖ SHA-256(clientDataJSON) — exactly what INV-MEM-7 verifies.
    async function buildRecoveryAssertion(identity, challengeBytes) {
        const rpIdHash = await sha256b(utf8.encode(RP_ID));
        const authData = concat(rpIdHash, new Uint8Array([0x05]), new Uint8Array(4));
        const cdj = utf8.encode(JSON.stringify({
            type: "webauthn.get",
            challenge: bytesToBase64Url(challengeBytes),
            origin: location.origin,
        }));
        const cdjHash = await sha256b(cdj);
        const signature = await identity.sign(concat(authData, cdjHash));
        return { authenticator_data: authData, client_data_json: cdj, signature };
    }

    function requireRecoveryModule() {
        if (!global.MemphisRecovery) {
            throw new Error("recovery.js not loaded (window.MemphisRecovery missing)");
        }
        return global.MemphisRecovery;
    }

    // ── high-level factor flows ────────────────────────────────────────────

    async function beginAddFactor(sessionTokenHex) {
        const reply = await memphisCallAwait("begin_add_factor", encBlob(hexToBytes(sessionTokenHex)));
        const dec = decodeResultBlob(reply);
        if (dec.err) throw new Error("begin_add_factor: " + (dec.err.message || dec.err.name));
        return dec.ok;
    }

    async function submitAddFactor(sessionTokenHex, factorReg, kindName) {
        const reply = await memphisCallAwait(
            "add_factor",
            encAddFactorArgs(hexToBytes(sessionTokenHex), factorReg, kindName)
        );
        const dec = decodeResultAddFactor(reply);
        if (dec.err) throw new Error("add_factor: " + (dec.err.message || dec.err.name));
        return {
            factor_id_hex: bytesToHex(dec.ok.factor_id),
            factor_count: Number(dec.ok.factor_count),
        };
    }

    /// Attach a NEW device passkey to the signed-in identity. Two prompts
    /// (create + assertion probe), same shape as registration.
    async function addDevice(sessionTokenHex, label) {
        const challenge = await beginAddFactor(sessionTokenHex);
        const f = await webauthnCreate(challenge, label || "memphis device");
        return submitAddFactor(sessionTokenHex, {
            credential_id: f.credentialId,
            cose_pub_key_bytes: f.cose_pub_key_bytes,
            authenticator_data: f.authenticator_data,
            client_data_json: f.client_data_json,
            signature: f.signature,
        }, "WebAuthn");
    }

    /// Generate a recovery phrase, register its derived key as a
    /// RecoveryPhrase factor, and hand the phrase back for one-time display.
    /// The phrase itself never leaves the browser.
    async function setupRecoveryPhrase(sessionTokenHex) {
        const R = requireRecoveryModule();
        const phrase = await R.generatePhrase();
        const identity = await R.deriveIdentity(phrase);
        const challenge = await beginAddFactor(sessionTokenHex);
        const blobs = await buildRecoveryAssertion(identity, challenge);
        const added = await submitAddFactor(sessionTokenHex, {
            credential_id: identity.credentialId,
            cose_pub_key_bytes: identity.cosePubKey,
            authenticator_data: blobs.authenticator_data,
            client_data_json: blobs.client_data_json,
            signature: blobs.signature,
        }, "RecoveryPhrase");
        return { phrase, factor_id_hex: added.factor_id_hex, factor_count: added.factor_count };
    }

    /// Zero-device sign-in: name + recovery phrase, no authenticator involved.
    async function signInWithRecoveryPhrase(name, phrase) {
        const R = requireRecoveryModule();
        const validated = validateName(name);
        if (!(await R.validatePhrase(phrase))) {
            throw new Error("that is not a valid recovery phrase — check the words and their order");
        }
        const anchorBytes = await lookupAnchor(validated);
        if (!anchorBytes) throw new Error("no Memphis identity for " + validated);
        const identity = await R.deriveIdentity(phrase);
        const challengeReply = await memphisCallAwait("begin_authentication", encBlob(anchorBytes));
        const dec = decodeResultBlob(challengeReply);
        if (dec.err) throw new Error("begin_authentication: " + (dec.err.message || dec.err.name));
        const blobs = await buildRecoveryAssertion(identity, dec.ok);
        const authReply = await memphisCallAwait("authenticate", encFactorAssertion({
            credential_id: identity.credentialId,
            authenticator_data: blobs.authenticator_data,
            client_data_json: blobs.client_data_json,
            signature: blobs.signature,
        }));
        const authDec = decodeResultRecordAuth(authReply);
        if (authDec.err) {
            const n = authDec.err.name;
            throw new Error(n === "FactorNotFound"
                ? "this phrase is not registered as a recovery factor for " + validated
                : "authenticate: " + (authDec.err.message || n));
        }
        const session = {
            name: validated,
            anchor_id_hex: bytesToHex(anchorBytes),
            session_token_hex: bytesToHex(authDec.ok.session_token),
            expires_at_ns: authDec.ok.expires_at_ns.toString(),
            display_tag: bytesToHex(anchorBytes).slice(-4),
        };
        saveSession(session);
        return session;
    }

    async function listFactors(sessionTokenHex) {
        const reply = await memphisQuery("list_factors", encBlob(hexToBytes(sessionTokenHex)));
        const dec = decodeResultFactorInfos(reply);
        if (dec.err) throw new Error("list_factors: " + (dec.err.message || dec.err.name));
        return dec.ok.map(r => ({
            factor_id_hex: bytesToHex(r.factor_id),
            kind: r.kind,
            removal_effective_at_ns: r.removal_effective_at_ns === null
                ? null : r.removal_effective_at_ns.toString(),
        }));
    }

    /// First call marks the removal pending (24h veto window); a call after
    /// the window completes it. Returns { status, effective_at_ns? }, or
    /// throws with the canister's RemovalDelayNotElapsed sentence.
    async function removeFactor(sessionTokenHex, factorIdHex) {
        const reply = await memphisCallAwait(
            "remove_factor",
            encTwoBlobs(hexToBytes(sessionTokenHex), hexToBytes(factorIdHex))
        );
        const dec = decodeResultRemoveFactor(reply);
        if (dec.err) {
            if (dec.err.name === "RemovalDelayNotElapsed") {
                const e = new Error("removal is still inside its 24-hour window");
                e.code = "RemovalDelayNotElapsed";
                e.effective_at_ns = dec.err.effective_at_ns ? dec.err.effective_at_ns.toString() : null;
                throw e;
            }
            throw new Error("remove_factor: " + (dec.err.message || dec.err.name));
        }
        return {
            status: dec.ok.status,
            effective_at_ns: dec.ok.effective_at_ns ? dec.ok.effective_at_ns.toString() : null,
        };
    }

    async function cancelFactorRemoval(sessionTokenHex, factorIdHex) {
        const reply = await memphisCallAwait(
            "cancel_factor_removal",
            encTwoBlobs(hexToBytes(sessionTokenHex), hexToBytes(factorIdHex))
        );
        const dec = decodeResultEmpty(reply);
        if (dec.err) throw new Error("cancel_factor_removal: " + (dec.err.message || dec.err.name));
        return true;
    }

    // ── multi-factor registration (P2.4: MIN_FACTORS_AT_SIGNUP = 3) ────────
    //
    // The granular pieces let the UI orchestrate a 3-factor signup ceremony
    // (device passkey + second passkey + recovery phrase) over ONE
    // registration challenge. register(name) above stays the 1-factor path
    // for canisters that still accept it; a caller that receives INV-MEM-1
    // retries through these.

    async function beginRegistrationChallenge() {
        const reply = await memphisCallAwait("begin_registration",
            new Uint8Array([0x44, 0x49, 0x44, 0x4c, 0x00, 0x00]));
        const dec = decodeResultBlob(reply);
        if (dec.err) throw new Error("begin_registration: " + (dec.err.message || dec.err.name));
        return dec.ok;
    }

    async function buildDeviceFactor(challenge, label) {
        const f = await webauthnCreate(challenge, label);
        return {
            credential_id: f.credentialId,
            cose_pub_key_bytes: f.cose_pub_key_bytes,
            authenticator_data: f.authenticator_data,
            client_data_json: f.client_data_json,
            signature: f.signature,
            kind: "WebAuthn",
        };
    }

    async function buildRecoveryFactor(challenge, phrase) {
        const R = requireRecoveryModule();
        const identity = await R.deriveIdentity(phrase);
        const blobs = await buildRecoveryAssertion(identity, challenge);
        return {
            credential_id: identity.credentialId,
            cose_pub_key_bytes: identity.cosePubKey,
            authenticator_data: blobs.authenticator_data,
            client_data_json: blobs.client_data_json,
            signature: blobs.signature,
            kind: "RecoveryPhrase",
        };
    }

    async function registerWithFactors(name, factors) {
        const validated = validateName(name);
        const regReply = await memphisCallAwait("register", encVecFactorRegistration(factors));
        const regDec = decodeResultRecordReg(regReply);
        if (regDec.err) {
            const e = new Error("register: " + (regDec.err.message || regDec.err.name));
            e.code = regDec.err.name;
            e.detail = regDec.err.message;
            throw e;
        }
        const anchorIdHex = bytesToHex(regDec.ok.anchor_id);
        const sessionTokenHex = bytesToHex(regDec.ok.session_token);
        const claimReply = await memphisCallAwait(
            "claim_name",
            encClaimNameArgs(regDec.ok.session_token, validated, location.origin, 0)
        );
        const claimDec = decodeResultText(claimReply);
        if (claimDec.err) throw new Error("claim_name: " + (claimDec.err.message || claimDec.err.name));
        const session = {
            name: validated,
            anchor_id_hex: anchorIdHex,
            session_token_hex: sessionTokenHex,
            expires_at_ns: regDec.ok.expires_at_ns.toString(),
            display_tag: regDec.ok.display_tag || anchorIdHex.slice(-4),
        };
        saveSession(session);
        return session;
    }

    // ─── session storage ───────────────────────────────────────────────────
    const STORAGE_KEY = "memphisSessionV1";

    function loadSession() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            const s = JSON.parse(raw);
            if (!s.session_token_hex || !s.anchor_id_hex || !s.name) return null;
            // Back-fill display_tag for sessions stored before P1.2 landed.
            // Same formula as canisters/memphis/src/lib.rs:display_tag().
            if (!s.display_tag) s.display_tag = s.anchor_id_hex.slice(-4);
            return s;
        } catch (_) { return null; }
    }
    function saveSession(s) {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch (_) {}
    }
    function clearSession() {
        try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
    }

    // ─── P1.1.6: durable revoke-retry queue (Service Worker) ────────────────
    //
    // Shared IndexedDB contract (MUST match sw.js):
    //   db    = "memphis-revoke-db" v1
    //   store = "pending", keyPath "token_hex"
    //   rec   = { token_hex, arg_hex, queued_at_ns, expires_at_ns, attempts }
    //
    // The page writes the entry BEFORE the canister call so a page-close
    // mid-revoke doesn't lose it; the Service Worker drains it with retry.
    const REVOKE_DB = "memphis-revoke-db";
    const REVOKE_DB_VERSION = 1;
    const REVOKE_STORE = "pending";
    const REVOKE_SYNC_TAG = "memphis-revoke-retry";

    function openRevokeDb() {
        return new Promise(function (resolve, reject) {
            if (!global.indexedDB) { reject(new Error("no indexedDB")); return; }
            const req = indexedDB.open(REVOKE_DB, REVOKE_DB_VERSION);
            req.onupgradeneeded = function () {
                const db = req.result;
                if (!db.objectStoreNames.contains(REVOKE_STORE)) {
                    db.createObjectStore(REVOKE_STORE, { keyPath: "token_hex" });
                }
            };
            req.onsuccess = function () { resolve(req.result); };
            req.onerror = function () { reject(req.error); };
        });
    }

    // keyPath = token_hex → put() overwrites, so the same token never
    // double-queues (acceptance #5 dedup). Fail-soft on any IDB error.
    async function queueRevoke(tokenHex, argHex, expiresAtNs) {
        try {
            const db = await openRevokeDb();
            await new Promise(function (resolve, reject) {
                const tx = db.transaction(REVOKE_STORE, "readwrite");
                tx.objectStore(REVOKE_STORE).put({
                    token_hex: tokenHex,
                    arg_hex: argHex,
                    queued_at_ns: String(BigInt(Date.now()) * 1000000n),
                    expires_at_ns: String(expiresAtNs || "0"),
                    attempts: 0,
                });
                tx.oncomplete = resolve;
                tx.onerror = function () { reject(tx.error); };
            });
        } catch (_) { /* fail-soft: no IDB → revoke is one-shot best-effort */ }
    }

    async function dequeueRevoke(tokenHex) {
        try {
            const db = await openRevokeDb();
            await new Promise(function (resolve, reject) {
                const tx = db.transaction(REVOKE_STORE, "readwrite");
                tx.objectStore(REVOKE_STORE).delete(tokenHex);
                tx.oncomplete = resolve;
                tx.onerror = function () { reject(tx.error); };
            });
        } catch (_) { /* fail-soft */ }
    }

    // Register the Service Worker + wire the page-driven retry triggers
    // (initial drain + window 'online'). Background Sync (Chrome/Edge) handles
    // page-close durability; the message path covers Safari/Firefox while a
    // page is open. Idempotent — safe to call from every page's init.
    function registerRevokeWorker() {
        if (!("serviceWorker" in navigator)) return;
        navigator.serviceWorker.register("sw.js").then(function () {
            // Drain any backlog left from a previous session right away.
            kickRevokeRetry();
            global.addEventListener("online", kickRevokeRetry);
        }).catch(function () { /* SW unavailable (file:// , no-HTTPS) → fail-soft */ });
    }

    function kickRevokeRetry() {
        if (!("serviceWorker" in navigator)) return;
        navigator.serviceWorker.ready.then(function (reg) {
            // Prefer Background Sync — durable across page close.
            if (reg.sync && typeof reg.sync.register === "function") {
                reg.sync.register(REVOKE_SYNC_TAG).catch(function () {});
            }
            // Always also poke the active worker for an immediate drain.
            if (reg.active) reg.active.postMessage({ type: "retry-revokes" });
        }).catch(function () {});
    }

    // Server-side revoke + localStorage clear. Idempotent: if no live session
    // is stored, just clears localStorage and returns. If the canister call
    // fails (network, expired session, bad token), the local copy is still
    // cleared — leaving the UI signed out — and the revoke is durably queued
    // (P1.1.6) so the Service Worker retries it until the canister confirms or
    // the token naturally expires.
    //
    // Mirrors canisters/memphis/src/lib.rs:end_session, which is itself
    // idempotent against unknown tokens (so re-issuing signOut is safe).
    async function signOut() {
        const s = loadSession();
        clearSession();
        if (!s || !s.session_token_hex) return { ok: true, revoked: false };
        const tokenBytes = hexToBytes(s.session_token_hex);
        const argHex = bytesToHex(encBlob(tokenBytes));
        // Queue BEFORE the network call — survives a page-close mid-revoke.
        await queueRevoke(s.session_token_hex, argHex, s.expires_at_ns);
        try {
            const reply = await memphisCallAwait("end_session", encBlob(tokenBytes));
            const dec = decodeResultEmpty(reply);
            if (dec.err) { kickRevokeRetry(); return { ok: false, revoked: false, err: dec.err }; }
            await dequeueRevoke(s.session_token_hex); // confirmed → drop from queue
            return { ok: true, revoked: true };
        } catch (e) {
            kickRevokeRetry(); // leave queued; the Service Worker retries
            return { ok: false, revoked: false, err: { name: "NetworkError", message: String(e && e.message || e) } };
        }
    }


    // Mint an ORIGIN-SCOPED credential from a master session.
    //
    // This is what an app is given. The master session token stays on the
    // Memphis origin and is never handed out: a token bound to one origin is
    // inert everywhere else, so an app cannot use it to authenticate as its own
    // users at some other app.
    //
    // `ttlNs` defaults to the u64 maximum, which does NOT mean "forever" — the
    // canister clamps to min(requested, its own ceiling, the parent's remaining
    // life). Asking for the maximum is how to say "for as long as the session I
    // came from lives" without this client knowing the canister's clock scaling.
    async function issueScopedSession(sessionToken, origin, ttlNs) {
        if (!origin) throw new Error("issueScopedSession: an origin is required");
        const ttl = (ttlNs === undefined || ttlNs === null) ? 0xffffffffffffffffn : ttlNs;
        const reply = await memphisCallAwait(
            "issue_scoped_session", encScopedSessionArgs(sessionToken, origin, ttl));
        const dec = decodeResultBlob(reply);
        if (dec.err) {
            const e = new Error("issue_scoped_session: " + (dec.err.message || dec.err.name));
            e.code = dec.err.name;
            throw e;
        }
        return { scoped_token: dec.ok, scoped_token_hex: bytesToHex(dec.ok) };
    }

    // ─── P4: staying signed in ─────────────────────────────────────────────
    // A scoped session lasts 30 real minutes. A refresh credential lets the app
    // mint a fresh one for weeks without another passkey ceremony, and is
    // deliberately weak: pinned to this one origin, able to mint only short
    // access tokens for it, and never a master session.
    async function issueRefresh(sessionToken, origin) {
        if (!origin) throw new Error("issueRefresh: an origin is required");
        const reply = await memphisCallAwait(
            "issue_refresh", encBlobTextArgs(sessionToken, origin));
        const dec = decodeResultRecordFields(reply, [
            ["refresh_token", "blob"],
            ["expires_at_ns", "nat64"],
            ["absolute_expires_at_ns", "nat64"],
        ]);
        if (dec.err) {
            const e = new Error("issue_refresh: " + (dec.err.message || dec.err.name));
            e.code = dec.err.name;
            throw e;
        }
        return {
            refresh_token_hex: bytesToHex(dec.ok.refresh_token),
            expires_at_ns: dec.ok.expires_at_ns.toString(),
            absolute_expires_at_ns: dec.ok.absolute_expires_at_ns.toString(),
        };
    }

    // Rotate the chain one step. BOTH halves are new and the presented refresh
    // token is dead the moment this returns, so a caller that stores only the
    // access token has silently ended its own chain — store both or neither.
    // Presenting a spent token again revokes the whole chain, by design: the
    // only safe reading of a replay is that it was stolen.
    async function exchangeRefresh(refreshToken, origin) {
        if (!origin) throw new Error("exchangeRefresh: an origin is required");
        const reply = await memphisCallAwait(
            "exchange_refresh", encBlobTextArgs(refreshToken, origin));
        const dec = decodeResultRecordFields(reply, [
            ["session_token", "blob"],
            ["expires_at_ns", "nat64"],
            ["refresh_token", "blob"],
            ["refresh_expires_at_ns", "nat64"],
        ]);
        if (dec.err) {
            const e = new Error("exchange_refresh: " + (dec.err.message || dec.err.name));
            e.code = dec.err.name;
            throw e;
        }
        return {
            scoped_token_hex: bytesToHex(dec.ok.session_token),
            expires_at_ns: dec.ok.expires_at_ns.toString(),
            refresh_token_hex: bytesToHex(dec.ok.refresh_token),
            refresh_expires_at_ns: dec.ok.refresh_expires_at_ns.toString(),
        };
    }

    global.MemphisPasskey = {
        issueRefresh,
        exchangeRefresh,
        issueScopedSession,
        register,
        signIn,
        signInOrRegister,
        lookupAnchor,
        lookupName: lookupNameToPrincipal,
        nameForPrincipal,
        loadSession,
        saveSession,
        clearSession,
        signOut,
        registerRevokeWorker,
        validateName,
        // P2 — factor lifecycle (identity durability).
        addDevice,
        setupRecoveryPhrase,
        signInWithRecoveryPhrase,
        listFactors,
        removeFactor,
        cancelFactorRemoval,
        // P2.4 — granular multi-factor signup ceremony pieces.
        beginRegistrationChallenge,
        buildDeviceFactor,
        buildRecoveryFactor,
        registerWithFactors,
        // Lower-level helpers, exposed for diagnostics.
        _memphisCallAwait: memphisCallAwait,
        _memphisQuery: memphisQuery,
        _bytesToHex: bytesToHex,
    };
})(window);
