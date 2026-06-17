# Thebes Protocol SDK

The developer SDK and starting point for building on
[Thebes Protocol](https://github.com/Mercatura-Forum/Thebes-Protocol-) — a
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

Every example depends on this SDK and on the
[thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) Motoko library — it
never copies them in. There is exactly one source of truth for the toolkit, and
every app inherits improvements to it.

## What's in this SDK

| Path | What it is |
| --- | --- |
| `runtime/boundary.js` | Browser boundary client (`window.EgyptBoundary`): Candid encode/decode, persisted browser identity, call + receipt polling. |
| `runtime/passkey.js` | Memphis passkey client (`window.MemphisPasskey`): WebAuthn sign-in → session. |
| `src/thebes.ts` | Typed wrapper over the boundary client — `query` / `update`, media upload, decoders. Framework-agnostic. |
| `src/useThebes.ts` | React hooks — `useQuery`, `useUpdate`, `useMediaUpload`. |
| `src/useMemphis.ts` | React hook — `useMemphis` (passkey session). |
| `src/MemphisGate.tsx` | `<MemphisGate>` auth gate + `useAuth()` + `<SignOutChip>`. |

## Use it (React + Vite)

Add the SDK as a pinned dependency — no registry account required:

```jsonc
// package.json
{ "dependencies": { "@thebes/sdk": "github:Mercatura-Forum/thebes-sdk#v0.1.1" } }
```

```ts
import { MemphisGate, useAuth, useQuery, useUpdate, encodeArgs, decodeVecRecord } from '@thebes/sdk'
```

The two browser runtimes load as plain `<script>` tags. Sync them into your app's
`public/` at build time:

```jsonc
// package.json scripts
{
  "sync-sdk": "mkdir -p public && cp node_modules/@thebes/sdk/runtime/boundary.js node_modules/@thebes/sdk/runtime/passkey.js public/",
  "dev": "npm run sync-sdk && vite",
  "build": "npm run sync-sdk && tsc -b && vite build"
}
```

```html
<!-- index.html -->
<script src="./boundary.js"></script>
<script src="./passkey.js"></script>
```

## The backend library

The Motoko backend library — `Admin`, `MemphisAuth`, `Users`, `Pagination` —
lives in [thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) and installs
through [mops](https://mops.one) as a git dependency:

```toml
# mops.toml
[dependencies]
thebes-lib = "https://github.com/Mercatura-Forum/thebes-lib#v0.1.0"
```

```motoko
import Admin "mo:thebes-lib/Admin";
```

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
