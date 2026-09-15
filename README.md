# Thebes SDK: the client toolkit for applications on the Thebes substrate

**The Thebes SDK is the browser and React toolkit every application on the
Thebes substrate is built with.** A boundary client that encodes Candid, keeps
a browser identity and polls receipts; a typed query and update layer; React
hooks; and the Memphis passkey identity: sign-in with a passkey on the Memphis
origin, or from an application's own domain through the connect broker. It is
the upstream every example vendors and the toolkit the public systems below
are written against. TypeScript and plain JavaScript. Apache 2.0.

- **One boundary client.** `runtime/boundary.js` encodes and decodes Candid by
  hand, keeps a persisted browser identity, submits calls and polls receipts
  against the cluster API. No generated bindings, no bundler required.
- **Passkey identity on any domain.** `passkey.js` runs the WebAuthn ceremony on
  the Memphis origin; `memphis-connect.js` opens that ceremony from an app on
  its own domain and hands back a token minted for that origin only. The list
  of credential algorithms offered is read from the identity contract itself.
- **Three factors at signup.** A device passkey, a second passkey and a
  recovery phrase, driven over one registration challenge; a lost device is not
  a lost identity.
- **Sessions that renew.** A refresh credential renews an access token
  silently, and a session survives a page reload; the same session module is
  used with React, without React, or from a script tag.
- **A catalogue of complete applications.** Twelve example repositories, each a
  Motoko backend and a frontend served as certified assets, and three
  production systems published as open source on the same substrate.

| | |
|---|---|
| Runtime | `boundary.js`, `passkey.js`, `memphis-connect.js`, `recovery.js` as plain script tags |
| React | `useQuery`, `useUpdate`, `useMediaUpload`, `useMemphis`, `useMemphisConnect`, `<MemphisGate>`, `<MemphisConnectGate>` |
| Framework-free | `session.ts`: `ensureSession`, `getSession`, `signIn`, `signOut`, `resumeFromRedirect`, `onSessionChange` |
| Identity | Memphis, the passkey identity contract of the Thebes substrate; WebAuthn with ES256, EdDSA and RS256 |
| Verification | the encoding oracle (`npm test`) compares the Candid wire bytes of two independent builds |

## Systems built on Thebes

Three production systems are published as open source, each written in Motoko
for the Thebes substrate, on the same boundary, identity and certified-asset
model this SDK targets.

| System | What it is | Repository |
| --- | --- | --- |
| **Manticore** | Core banking and payments: a provable double-entry journal, maker-checker on every money-moving act, ISO 20022 and Mojaloop payments, certified reports | [Manticore](https://github.com/Mercatura-Forum/Manticore) |
| **Solari** | An audit system for audit firms: a hash-chained engagement trail, journal-entry testing, passkey sign-offs, certified figures a third party can verify | [Solari](https://github.com/Mercatura-Forum/Solari) |
| **Tachyon** | Delivery-versus-payment settlement: two-phase escrow, both-or-neither settlement, batch matching, certified receipts over ICRC-1, ICRC-2 and ICRC-7 | [Tachyon](https://github.com/Mercatura-Forum/Tachyon) |

## Example applications

Each example is a complete repository: a Motoko backend that owns the on-chain
state and a React frontend served as certified assets. Each isolates a pattern
that recurs in a real product.

| Application | What it demonstrates | Repository |
| --- | --- | --- |
| **Store** | Catalogue, carts, orders, an admin surface, on-chain media | [thebes-example-store](https://github.com/Mercatura-Forum/thebes-example-store) |
| **Chat** | Real-time rooms, members, passkey-gated profiles | [thebes-example-chat](https://github.com/Mercatura-Forum/thebes-example-chat) |
| **CRM** | Contacts, a sales pipeline, contact media | [thebes-example-crm](https://github.com/Mercatura-Forum/thebes-example-crm) |
| **Restaurant** | Menu, customer orders, a forward-only kitchen lifecycle | [thebes-example-restaurant](https://github.com/Mercatura-Forum/thebes-example-restaurant) |
| **Finance** | Accounts, budgets, a dashboard, balance guards | [thebes-example-finance](https://github.com/Mercatura-Forum/thebes-example-finance) |
| **Booking** | Listings, reservations, a double-booking guard | [thebes-example-booking](https://github.com/Mercatura-Forum/thebes-example-booking) |
| **Loyalty** | Points, cards, transaction history | [thebes-example-loyalty](https://github.com/Mercatura-Forum/thebes-example-loyalty) |
| **University** | Course catalogue, enrolment, a registrar role | [thebes-example-university](https://github.com/Mercatura-Forum/thebes-example-university) |
| **Cards** | Majlis, an on-chain card game (Estimation and Tarneeb) | [thebes-example-cards](https://github.com/Mercatura-Forum/thebes-example-cards) |
| **Invoicing** | Invoices with an on-chain recomputed total and a guarded lifecycle (also embedded in Store and Restaurant) | [thebes-example-invoicing](https://github.com/Mercatura-Forum/thebes-example-invoicing) |
| **Medical imaging** | Lumen: X-ray studies with images in the media contract, clinical role-based access, an immutable access log | [thebes-example-xray](https://github.com/Mercatura-Forum/thebes-example-xray) |
| **Open banking (ISO 20022)** | Message validation and an audit hub for the ISO 20022 payment standard; a backend contract with no web frontend | [thebes-example-open-banking-iso20022](https://github.com/Mercatura-Forum/thebes-example-open-banking-iso20022) |

Every example builds on this SDK and on the
[thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) Motoko library. Each
example repository vendors a snapshot of both (under `frontend/vendor/@thebes/sdk`
and `motoko/thebes-lib`) so that it builds self-contained; this repository and
`thebes-lib` are the upstream from which those snapshots are refreshed.

## What is here

| Path | What it is |
| --- | --- |
| `runtime/boundary.js` | The browser boundary client (`window.EgyptBoundary`): Candid encode and decode, a persisted browser identity, call submission and receipt polling. |
| `runtime/passkey.js` | The Memphis passkey client (`window.MemphisPasskey`): the WebAuthn ceremony, the three-factor signup, sessions. Runs on the Memphis origin only (see Identity). |
| `runtime/recovery.js` | The recovery-phrase factor: a BIP39 phrase whose derived key registers as a factor and signs in like a passkey. Loaded alongside `passkey.js`. |
| `runtime/memphis-connect.js` | `window.memphis.connect()`: sign-in for an application served from its own domain, as a popup or a full-page redirect. |
| `src/thebes.ts` | The typed wrapper over the boundary client: `query`, `update`, media upload, decoders. Framework-agnostic. |
| `src/useThebes.ts` | React hooks: `useQuery`, `useUpdate`, `useMediaUpload`. |
| `src/useMemphis.ts` | React hook `useMemphis`: the passkey session, Memphis origin only. |
| `src/session.ts` | The framework-free session API: `ensureSession`, `getSession`, `signIn`, `signOut`, `resumeFromRedirect`, `onSessionChange`. |
| `src/useMemphisConnect.ts` | React hook `useMemphisConnect(app)`, a thin face over `session.ts`. |
| `src/MemphisGate.tsx` | `<MemphisGate>`, `useAuth()` and `<SignOutChip>` for an application on the Memphis origin. |
| `src/MemphisConnectGate.tsx` | `<MemphisConnectGate app>`, `useConnectAuth()` and `<ConnectChip>` for an application on its own domain. |
| `oracle/` | The encoding oracle behind `npm test`. |
| `docs/memphis.md` | The identity guide: the ceremony, the backend gate, the rules that are not style preferences. |

## Identity

Read [`docs/memphis.md`](./docs/memphis.md) before wiring authentication. It
covers both halves of the Memphis integration, the browser passkey ceremony
and the backend `MemphisAuth` gate, and the rules that are not style
preferences: `await*` rather than `await`, the `_u` bindings rather than the
`query` ones, the `origin` and `audience` split, discoverable credentials, and
confirm-before-mint.

**Which sign-in does an application need?** A WebAuthn credential is bound to a
Relying Party ID, and a page may claim only an RP ID that is a registrable-domain
suffix of its own origin, so the passkey ceremony cannot run on another domain.

| The application is served from | Use | Runtime to load |
| --- | --- | --- |
| the Memphis origin | `useMemphis` | `passkey.js` and `recovery.js` |
| its own domain | `<MemphisConnectGate app>` or `useMemphisConnect(app)` | `memphis-connect.js` |

Without React, `session.ts` is the same thing and is what the hook is built on:

```ts
import { ensureSession, signIn, resumeFromRedirect } from '@thebes/sdk/session'

const held = resumeFromRedirect() ?? await ensureSession('My App')  // renews if lapsed
button.onclick = () => signIn('My App')   // from a gesture, never after an await
```

`useMemphisConnect` opens the ceremony in a window at the Memphis origin, which
attenuates the master session into a token minted for the application's origin
and hands back only that. The application never sees a master token, and no
allowlisting is needed: it works for any domain.

The credential algorithms offered at registration are read from the identity
contract's `algorithms()` query (ES256, EdDSA and RS256), with ES256 as the
fallback against an older build, so an authenticator that cannot produce a
P-256 key still registers.

## Use it (React and Vite)

Add the SDK as a pinned dependency; no registry account is required:

```jsonc
// package.json
{ "dependencies": { "@thebes/sdk": "github:Mercatura-Forum/thebes-sdk#v0.4.0" } }
```

```ts
import { MemphisGate, useAuth, useQuery, useUpdate, encodeArgs, decodeVecRecord } from '@thebes/sdk'
```

The browser runtimes load as plain `<script>` tags. Sync the ones in use into
the application's `public/` at build time (swap `memphis-connect.js` for
`passkey.js` and `recovery.js` only when the application is served from the
Memphis origin):

```jsonc
// package.json scripts
{
  "sync-sdk": "mkdir -p public && cp node_modules/@thebes/sdk/runtime/boundary.js node_modules/@thebes/sdk/runtime/memphis-connect.js public/",
  "dev": "npm run sync-sdk && vite",
  "build": "npm run sync-sdk && tsc -b && vite build"
}
```

```html
<!-- index.html -->
<script src="./boundary.js"></script>
<script src="./memphis-connect.js"></script>
```

## The backend library

The Motoko backend library (`Admin`, `MemphisAuth`, `Users`, `Pagination`)
lives in [thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) and installs
through [mops](https://mops.one) as a git dependency:

```toml
# mops.toml
[dependencies]
thebes-lib = "https://github.com/Mercatura-Forum/thebes-lib#v1.0.0"
```

```motoko
import Admin "mo:thebes-lib/Admin";
```

Pin `v1.0.0` or later: from that release `MemphisAuth.verify` resolves a token
at the application's own origin only. See [`docs/memphis.md`](./docs/memphis.md).

## Building and testing

```
npm install
npm run build      # tsc, emits lib/
npm test           # the encoding oracle (Candid wire bytes of two builds agree) and the
                   # transport oracle (the passkey runtime against a scripted network)
npm run audit:copies:live   # every deployed copy of the passkey runtime against this tree
python3 tools/e2e-new-user.py   # browser battery: sign up, sign in, sign out, sign in again,
                                # per algorithm, same device and cross device (needs Playwright)
```

## Contributing

Work on this repository continues in the open. Open an issue for a defect or a
question, with the file and line; open a pull request against `main` with
`npm run build` and `npm test` green. Each example repository carries its own
contributing guide. Contributions are attributed to the team.

## Licence

Apache License 2.0. See [`NOTICE`](./NOTICE).

Attribution: Thebes Core Team.
