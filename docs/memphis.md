# Memphis — the integration guide

Memphis (contract **921**) is the Thebes identity contract. It gives every person
a passkey-backed *anchor*, and gives every application a **stable, per-app,
pseudonymous principal** derived from that anchor. The same human is the same
principal in your app forever, and an unlinkable different principal in every
other app.

This is the canonical guide for both halves of the integration — the browser
ceremony (`runtime/passkey.js`, `useMemphis`, `<MemphisGate>`) and the backend
gate (`MemphisAuth` in [thebes-lib](https://github.com/Mercatura-Forum/thebes-lib)).
Everything below is the *current* contract. Where a rule looks arbitrary, it is
written down because getting it wrong cost us a day.

---

## 1. The three identifiers, and why confusing them breaks things

Every Memphis bug we have shipped came from treating two of these as one.

| | What it is | Set where | If you change it |
| --- | --- | --- | --- |
| **`msg.caller`** | The *transport sender* — whatever key signed the request envelope. Authenticated by the boundary, but **not a person**. | The client's agent key | n/a — never key user data on this |
| **`origin`** | Your **pseudonym namespace**. An arbitrary stable label; `"my-app"` is as valid as a URL. Feeds principal derivation. | `MemphisAuth.initFromCid(921, origin, version)` | **Every user's principal changes and their data is orphaned.** Never touch it on a live app. |
| **`audience`** | The **web origin your app is served from** — `"https://my-app.com"`. Memphis compares it byte-exactly against the origin it minted the token for. | Per call: `verifyWithAudience(gate, token, audience)` | Harmless. It only says where tokens are accepted from. |

`origin` and `audience` are frequently **not equal** — Thebes Hosting's namespace
is the literal string `"thebes-hosting"` while its audience is
`"https://thebesprotocol.com"`. Present the namespace as the audience and every
verification returns `#Unauthorized`; "fix" that by changing the namespace to the
URL and you orphan every existing account.

> **Byte-exact** means byte-exact. A trailing slash, a differing port, or a case
> difference is a mismatch.

`verify(gate, token)` is shorthand for `verifyWithAudience(gate, token, gate.origin)`.
It is correct **only** when your namespace already *is* the URL.

---

## 2. The flow, end to end

```
 your page              connect window            Memphis (921)        your contract
 (my-app.com)          (Memphis origin)           ─────────────        ─────────────
 memphis.connect()
   ├─ opens ──────────────►
                    begin_authentication ───────────►
                    ◄─────────────────────── challenge
                    navigator.credentials.get   ← the RP-ID wall is why
                    authenticate ───────────────────►  this runs HERE
                    ◄──── master session token   (never leaves this origin)
                    issue_scoped_session(tok,
                      "https://my-app.com") ────────►
                    ◄──── SCOPED token
   ◄─ postMessage ──────┤
   │   (or #fragment)
   │
   └─ call(yourContract, method, { session: scopedToken, … }) ────────────►
                                                                    verifyWithAudience
                                    ◄──── whoami_scoped_u(token, audience) ──┤
                                    ├───► anchor_id, expiry
                                    ◄──── derive_principal_for_u(anchor,
                                    │        origin, version) ───────────────┤
                                    ├───► 29-byte principal
                                                                    key state on it
```

**Why the master token never leaves the browser.** A master session token is
anchor-scoped: whoever holds it *is* that user everywhere. Hand one to an app and
that app can authenticate as its own users at every other Thebes app — the
confused deputy (Hardy, 1988). So the client sends a credential minted for one
origin and refused at every other, the same shape as OAuth's `aud` claim
(RFC 9068) and Internet Identity's per-frontend delegation. The scoped token is
strictly weaker than the session it came from: it cannot outlive it, it dies when
that session is revoked, and it dies on sign-out-everywhere.

---

## 3. The backend half

```motoko
import MemphisAuth "mo:thebes-lib/MemphisAuth";

persistent actor MyApp {
  // Pseudonym namespace — NEVER change this on a live app.
  var gate = MemphisAuth.initFromCid(921, "my-app", 1);

  // The web origin this app is served from. A compile-time constant, not state.
  let AUDIENCE = "https://my-app.com";

  public shared func myProfile(session : Blob) : async Result.Result<Profile, Text> {
    switch (await* MemphisAuth.verifyWithAudience(gate, session, AUDIENCE)) {
      case (#err(#Memphis(#Unauthorized))) { #err("Token was minted for another origin") };
      case (#err(#Expired))                { #err("Session expired — sign in again") };
      case (#err(e))                       { #err("Auth failed") };
      case (#ok(id))                       { #ok(loadProfile(id.principal)) };
    };
  };
}
```

### Rule 1 — `await*`, never `await`

`verify` and `verifyWithAudience` are **`async*`**. A module-level `async` helper
that awaits another contract loses the caller's continuation: the engine replies
with the *inner* awaited value instead of your handler's own return, and any state
mutation after the await is dropped.

The symptom does not look like an auth bug. It looks like a client-side Candid
decode error naming a field your method never declared — because the client is
decoding `Result<Identity, AuthError>` instead of your return type.

> **The diagnostic that isolates it in one step:** call an update that makes *no*
> inter-contract call, and one that does. If the first returns its declared type
> and the second returns the callee's, this is your bug. Anything else is a red
> herring.

### Rule 2 — bind the `_u` methods, never the `query` ones

Memphis exports each resolution method twice, with identical bodies:

| For the browser (cheap, non-replicated) | For a contract |
| --- | --- |
| `whoami`, `whoami_scoped` — `query` | `whoami_u`, **`whoami_scoped_u`** — update |
| `derive_principal_for` — `query` | **`derive_principal_for_u`** — update |

A contract-to-contract `await` on a **query** export gets no reply on this
substrate; the call fails as `method 'canister_update <name>' not found`.

> ⚠️ Probing the query form over the boundary's `POST /api/query` **succeeds**,
> which is exactly what makes a wrong binding look correct. That path exercises
> the callee's query entry point — not the path a contract takes.

### Rule 3 — the audience is an argument, not state

There is deliberately no `initWithAudience`. Adding a field to a stable record
hits **M0170** (incompatible stable variable — `?Text` does not help, Motoko
rejects an added record field either way), and marking the holder `transient` to
dodge that hits **M0169** (a stable variable cannot be implicitly discarded).
Both walls exist for a value that never needed to persist.

Copy the pattern: compile-time config belongs in an argument. Reserve `State` for
what genuinely must survive an upgrade.

### Caching

`verifyWithAudience` caches `token → Identity` until the session expiry passes,
so a cache miss costs two inter-contract calls and a hit costs none. Call
`MemphisAuth.forget(gate, token)` on sign-out and `evictExpired` from a timer if
you want the hygiene.

---

## 4. The browser half

### Which sign-in your app needs

A WebAuthn credential is bound to a **Relying Party ID**, and a page may only
claim an RP ID that is a registrable-domain suffix of its own origin. Memphis
anchors live under one RP ID. So a page served from `my-app.com` **physically
cannot** run the Memphis passkey ceremony — the browser refuses before any of our
code runs.

| Your app is served from | Use | Runtime |
| --- | --- | --- |
| the Memphis origin | `useMemphis` | `passkey.js` |
| **its own domain** | `useMemphisConnect(app)` | `memphis-connect.js` |

Almost every real app is the second row.

### Connect: sign-in from your own domain

```html
<script src="./memphis-connect.js"></script>
```

```tsx
const auth = useMemphisConnect('My App')

<button onClick={() => auth.signIn({ mode: 'auto' })}>Sign in</button>

// auth.token is the origin-scoped session token. Pass it to your contract.
await update(CID, 'myProfile', encodeArgs([{ type: 'blob', value: auth.token }]))
```

The ceremony happens in a window at the Memphis origin. That window holds the
master session, exchanges it for a token minted **for your origin**, and hands
back only that. Your app never sees a master token, and nothing needs
allowlisting — which is why it works for any domain, including ones we have never
heard of. It is the same shape as Internet Identity's per-frontend delegation.

**`mode`**: `"popup"` (default), `"redirect"`, or `"auto"` — a popup that falls
back to a full-page redirect when the browser blocks it. Use `"auto"` in
production: an in-app WebView (Instagram, LinkedIn) and iOS Safari outside a
gesture will block a popup, and without the fallback those users simply cannot
sign in. In redirect mode `useMemphisConnect` collects the answer on the next
page load; if you drive `window.memphis` directly, call `memphis.resume()`
yourself on load.

**Call `signIn` from a user gesture.** A popup opened outside one is blocked, and
a redirect outside one is a navigation the person did not ask for. Do not `await`
anything before it — an await ends the gesture, and this is the single most common
way a working implementation stops working on iPhone.

### The security property, and how to not break it

A page may **lie** about its origin in the request. It gains nothing, because the
answer is delivered only to the origin it claimed:

- **popup** — `postMessage(payload, RETURN_TO)`, never `"*"`. The browser refuses
  delivery when the opener's real origin is not `RETURN_TO`. The liar gets silence.
- **redirect** — the return URL must be same-origin with the claimed origin, so
  the credential lands on the victim's own page where the liar cannot read it.

Both are the browser's to enforce, which is what makes them worth relying on.
Widening the target origin to `"*"`, or accepting a return URL on a different
origin than the claimed one, removes the only thing protecting every app on the
chain. This is tested rather than believed — `e2e_origin_lie.py`, with an
anti-vacuity control proving the ceremony actually ran before the attacker got
nothing.

> The redirect token arrives in the URL **fragment**, never the query string, so
> it is not sent to your server and does not appear in a `Referer` header or an
> access log. If your app has an open redirect it can bounce that fragment to an
> attacker — the same failure OAuth deployments have had for fifteen years.
> Validate your own return paths.

### If you are on the Memphis origin

```tsx
import { MemphisGate, useAuth } from '@thebes/sdk'

<MemphisGate>
  <App />          {/* useAuth() gives you { session, principal, signOut } */}
</MemphisGate>
```

Three things in `runtime/passkey.js` are load-bearing.

**Discoverable credentials are required.** `signIn` calls
`navigator.credentials.get` with `allowCredentials: []` so the authenticator
surfaces every credential it holds for the relying party. An authenticator only
surfaces credentials it can *discover*, and WebAuthn's default when `residentKey`
is unspecified is a **non-discoverable** credential — so registration would mint
exactly the kind of credential sign-in cannot find. Registration must pass:

```js
authenticatorSelection: {
  residentKey: "required",
  requireResidentKey: true,   // WebAuthn L1 spelling, for older clients
  userVerification: "preferred",
}
```

This works today on Touch ID, Windows Hello, iCloud Keychain and Google Password
Manager *even without it*, because those create discoverable credentials for
platform attachment regardless of the request. On a roaming security key, or a
browser that follows the spec literally, the person registers successfully and
can then never sign in again — and the only symptom is a sentence about the
device not confirming the passkey, which points at their hardware rather than at
you.

**A lookup miss is a question, not a licence to mint.** `signInOrRegister` raises
`NameNotRegistered` rather than silently creating an identity; creation happens
only on an explicit `{ confirmCreate: true }`. A typo'd handle must not quietly
become a second, empty account — the person's real account still exists and they
cannot find it. `useMemphis` prompts and retries; if you drive `passkey.js`
directly, you own that prompt.

**Query Memphis on `/api/v1/canister/<cid>/query`.** The boundary route was
renamed from `/contract/`; the old path answers 404 with a **zero-length body**,
so an unguarded `.json()` throws `Unexpected end of JSON input` and names no URL.
Read the response as text first and report the status.

> `/api/v1/canister/...` does not send permissive CORS headers the way
> `/api/query` does, so it only works same-origin. That is not a limitation in
> practice: the passkey RP-ID wall already forces your page onto one origin.

---

## 5. Account durability

Since 2026-08-29 an anchor is a **set of factors**, not a single passkey.

- **Registration requires ≥ 3 factors** (`MIN_FACTORS_AT_SIGNUP`). One device is
  one bad phone away from a lost account. The signup ceremony collects a passkey
  plus additional factors before the anchor is admitted.
- **`begin_add_factor` / `add_factor`** append a factor to a live anchor. A
  credential id must be globally fresh.
- **`remove_factor`** schedules removal after a **24-hour delay**, surfaced as
  `removal_effective_at_ns`; **`cancel_factor_removal`** is the owner's veto. The
  last remaining factor is irremovable. The delay is what turns a stolen device
  into a recoverable incident rather than an eviction.
- **Recovery phrase** — a BIP-39 phrase is a first-class factor
  (`FactorKind = RecoveryPhrase`), so an account survives losing every device.
- **`list_factors`** enumerates the calling session's factors; build your
  "Security & recovery" screen on it.

> The 3-factor floor binds **at registration only**. Anchors created before it
> keep authenticating with what they have — a floor asserted at upgrade time
> would trap the shared contract for everyone.

---

## 6. Sessions and the clock

Memphis TTLs are written against the substrate clock, which runs at
`CANISTER_SECONDS_PER_REAL_SECOND = 13`. The constants therefore read as
`30 * 60 * 13 * 1_000_000_000` — that is **30 real minutes**, not 6.5 hours. Do
not "simplify" that factor out, and do not compute your own expiry against
`Time.now()` without it.

`EXPIRY_TOO_FAR_FUTURE` is a *separate* wall-clock skew check at the HTTP
boundary. It is not the same clock and the two must not be merged.

---

## 7. What to pin

| | Pin | Note |
| --- | --- | --- |
| `thebes-lib` | `#v1.0.0` | First tag with origin-scoping, `_u` bindings and `async*`. **`v0.4.0` and earlier call `whoami`, which resolves a token at any origin.** |
| `@thebes/sdk` | current tag | Needs the `/api/v1/canister/` route, `residentKey: "required"`, and confirm-before-mint. |

Example repositories vendor a snapshot of both under `motoko/thebes-lib` and
`frontend/vendor/@thebes/sdk`. A snapshot is frozen at the moment it was taken —
when a shared library misbehaves, **diff it against the copy a working production
app uses**, not against the newest tag. Both times this bit us, the published
copy was the stale one and a product tree held the fix.

---

## 8. Pre-flight checklist

- [ ] `origin` is a stable label you will never change; `AUDIENCE` is the URL.
- [ ] Every gated method uses `await*`.
- [ ] The actor type binds `whoami_scoped_u` and `derive_principal_for_u`.
- [ ] Registration passes `residentKey: "required"`.
- [ ] A lookup miss asks before it creates.
- [ ] The passkey client calls `/api/v1/canister/<cid>/query`.
- [ ] `#Unauthorized` is surfaced to the user as *"signed in for another site"*,
      not as a generic failure — it is the single most common misconfiguration.
- [ ] A "Security & recovery" screen exists: list factors, add, remove (with the
      24 h notice), and set a recovery phrase.
