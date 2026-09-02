# Thebes Protocol SDK

The developer SDK and starting point for building on
[Thebes Protocol](https://thebesprotocol.com) — a
high-throughput Layer 1 with on-chain threshold signing, passkey identity, and
certified asset hosting.

This repository is two things:

1. **The client SDK** every Thebes application uses — a browser boundary client,
   a typed query/update layer, React hooks, and the Memphis passkey gate.
2. **The front door to the example library** — a growing, open catalog of
   production-grade reference applications and the educational material that
   explains how they work.

## Example applications

Each app is a complete, self-contained repository: a Motoko backend that owns the
on-chain state and a React frontend served as certified assets. Together they
form a teaching library — every app isolates a different pattern you will reuse
in your own product.

| Application | What it demonstrates | Repository |
| --- | --- | --- |
| **Store** | Catalog, carts, orders, admin surface, on-chain media | [thebes-example-store](https://github.com/Mercatura-Forum/thebes-example-store) |
| **Chat** | Real-time rooms, members, passkey-gated profiles | [thebes-example-chat](https://github.com/Mercatura-Forum/thebes-example-chat) |
| **CRM** | Contacts, a sales pipeline, contact media | [thebes-example-crm](https://github.com/Mercatura-Forum/thebes-example-crm) |
| **Restaurant** | Menu, customer orders, a forward-only kitchen lifecycle | [thebes-example-restaurant](https://github.com/Mercatura-Forum/thebes-example-restaurant) |
| **Finance** | Accounts, budgets, a dashboard, balance guards | [thebes-example-finance](https://github.com/Mercatura-Forum/thebes-example-finance) |
| **Booking** | Listings, reservations, a double-booking guard | [thebes-example-booking](https://github.com/Mercatura-Forum/thebes-example-booking) |
| **Loyalty** | Points, cards, transaction history | [thebes-example-loyalty](https://github.com/Mercatura-Forum/thebes-example-loyalty) |
| **University** | Course catalog, enrollment, a registrar role | [thebes-example-university](https://github.com/Mercatura-Forum/thebes-example-university) |
| **Cards** | Majlis — an on-chain card game (Estimation & Tarneeb) | [thebes-example-cards](https://github.com/Mercatura-Forum/thebes-example-cards) |
| **Invoicing** | Invoices with an on-chain-recomputed total and a guarded lifecycle (also embedded in Store & Restaurant) | [thebes-example-invoicing](https://github.com/Mercatura-Forum/thebes-example-invoicing) |
| **Medical imaging** | Lumen — X-ray studies with images in the media contract, clinical RBAC, and an immutable access log | [thebes-example-xray](https://github.com/Mercatura-Forum/thebes-example-xray) |
| **Open banking (ISO 20022)** | Message validation + audit hub for the ISO 20022 payment standard — backend contract, no web frontend | [thebes-example-open-banking-iso20022](https://github.com/Mercatura-Forum/thebes-example-open-banking-iso20022) |

Every example builds on this SDK and on the
[thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) Motoko library. Each
example repository vendors a snapshot of both (under `frontend/vendor/@thebes/sdk`
and `motoko/thebes-lib`) so it builds self-contained; this repository and
`thebes-lib` remain the single upstream source of truth from which those
snapshots are refreshed.

## What's in this SDK

| Path | What it is |
| --- | --- |
| `runtime/boundary.js` | Browser boundary client (`window.EgyptBoundary`): Candid encode/decode, persisted browser identity, call + receipt polling. |
| `runtime/passkey.js` | Memphis passkey client (`window.MemphisPasskey`): WebAuthn sign-in → session. **Only works on the Memphis origin** — see below. |
| `runtime/memphis-connect.js` | `window.memphis.connect()` — sign-in for an app served from **its own domain**. Popup or full-page redirect. |
| `src/thebes.ts` | Typed wrapper over the boundary client — `query` / `update`, media upload, decoders. Framework-agnostic. |
| `src/useThebes.ts` | React hooks — `useQuery`, `useUpdate`, `useMediaUpload`. |
| `src/useMemphis.ts` | React hook — `useMemphis` (passkey session, Memphis origin only). |
| `src/session.ts` | **Framework-free** session API — `ensureSession` / `getSession` / `signIn` / `signOut` / `resumeFromRedirect` / `onSessionChange`. Use it from a static page, Vue, Svelte, or a script tag. |
| `src/useMemphisConnect.ts` | React hook — `useMemphisConnect(app)`, a thin face over `session.ts`. |
| `src/MemphisGate.tsx` | `<MemphisGate>` auth gate + `useAuth()` + `<SignOutChip>` (Memphis origin only). |
| `src/MemphisConnectGate.tsx` | `<MemphisConnectGate app>` + `useConnectAuth()` + `<ConnectChip>` for an app on its own domain. |

## Identity

Read **[`docs/memphis.md`](./docs/memphis.md)** before wiring authentication. It
is the canonical guide to both halves of the Memphis integration — the browser
passkey ceremony and the backend `MemphisAuth` gate — and it carries the rules
that are not style preferences: `await*` rather than `await`, the `_u` bindings
rather than the `query` ones, the `origin`/`audience` split, discoverable
credentials, and confirm-before-mint. Each one is written down because getting it
wrong produced a bug that did not look like an auth bug.

**Which sign-in do you need?** A WebAuthn credential is bound to a Relying
Party ID, and a page may only claim an RP ID that is a registrable-domain
suffix of its own origin. So the passkey ceremony physically cannot run on your
domain.

| Your app is served from | Use | Runtime to load |
| --- | --- | --- |
| the Memphis origin | `useMemphis` | `passkey.js` |
| **its own domain** | `<MemphisConnectGate app>` / `useMemphisConnect(app)` | `memphis-connect.js` |

Not on React? **`session.ts`** is the same thing without it, and it is what the
hook is built on, so both get identical behaviour:

```ts
import { ensureSession, signIn, resumeFromRedirect } from '@thebes/sdk/session'

const held = resumeFromRedirect() ?? await ensureSession('My App')  // renews silently
button.onclick = () => signIn('My App')   // from a gesture, never after an await
```

`useMemphisConnect` opens the ceremony in a window at the Memphis origin, which
attenuates the master session into a token minted for *your* origin and hands
back only that. Your app never sees a master token, and no allowlisting is
needed — it works for any domain, including ones we have never heard of.

## Use it (React + Vite)

Add the SDK as a pinned dependency — no registry account required:

```jsonc
// package.json
{ "dependencies": { "@thebes/sdk": "github:Mercatura-Forum/thebes-sdk#v0.4.0" } }
```

```ts
import { MemphisGate, useAuth, useQuery, useUpdate, encodeArgs, decodeVecRecord } from '@thebes/sdk'
```

The browser runtimes load as plain `<script>` tags. Sync the ones you use into
your app's `public/` at build time (swap `memphis-connect.js` for `passkey.js`
only if your app is served from the Memphis origin):

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

## Failure handling

The boundary reports exactly three failure shapes, and they split on the one
question that decides whether a retry is safe: **was a message hash issued?**

| What happened | `ThebesCallError.kind` | Retried by the SDK? |
| --- | --- | --- |
| The submit was refused (cluster degraded, rate-limited, network drop) — no message hash was issued, so nothing was accepted | `refused` | Yes — same nonce, exponential backoff |
| The boundary or the contract said no — the answer is deterministic | `rejected` | Never |
| The message was accepted but did not finalize inside the polling window — it may still land | `receipt-timeout` | Never — re-read state, or pass a longer `timeoutMs` |
| A query's transport failed — reads are idempotent | `network` | Yes — backoff |

`update` fixes one nonce per logical call and reuses it across submit retries, so
the chain sees a single message however many times the gateway refused the door.
A receipt timeout is the one case an app must not blindly retry — the update may
have landed; re-read your state first. Queries that fail no longer come back as
an empty reply for your decoder to chew on: they throw, so the failure is
visible.

```ts
import { update, ThebesCallError } from '@thebes/sdk'

try {
  await update(cid, 'place_order', argHex, { timeoutMs: 30_000 })
} catch (e) {
  if (e instanceof ThebesCallError && e.kind === 'receipt-timeout') {
    await refetchOrders() // it may have landed — read before retrying
  }
}
```

Defaults: 2 retries, 400 ms backoff base for updates (250 ms for queries), and
the runtime's own 10 s receipt window — all tunable per call via the options
argument. The failure semantics are pinned by `oracle/faults.mjs`, which drives
the typed layer against every shape the boundary client actually throws.

## The backend library

The Motoko backend library — `Admin`, `MemphisAuth`, `Users`, `Pagination` —
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

> Pin `v1.0.0` or later. `v0.4.0` and earlier predate origin-scoped sessions:
> `MemphisAuth.verify` resolved a token at *any* origin, so a token your app was
> handed authenticated as that user at every other Thebes app. See
> [`docs/memphis.md`](./docs/memphis.md).

## Roadmap

This library grows. On the path ahead:

- **More reference applications** spanning additional domains and patterns.
- **A multi-page commerce build** to join the catalog.
- **Educational material** — guides and walkthroughs that explain each app end to
  end, from passkey identity to threshold-signed state.
- **Registry publishing** — `@thebes/sdk` on npm and `thebes-lib` on mops, so the
  pinned git dependency becomes a versioned registry dependency with no code
  change.

Contributions are welcome — each example repository carries its own
`CONTRIBUTING` guide.

## Acknowledgements

Thebes stands on the shoulders of the [Internet Computer](https://internetcomputer.org)
and the [DFINITY Foundation](https://dfinity.org). Their **canister model** — smart
contracts as orthogonally-persistent actors, with the Motoko language built around
it — is genuinely excellent work, and it directly inspired the design of this
stack. We are grateful to the DFINITY team and the wider IC community for showing
what a smart-contract platform can be.

## License

Apache-2.0. See [`NOTICE`](./NOTICE). Authored by the Thebes Protocol contributors.
