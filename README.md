# @thebes/sdk

The shared developer SDK for [Thebes Protocol](https://github.com/Mercatura-Forum/Thebes-Protocol-)
example dapps. One source of truth for the client toolkit and the Motoko backend
library that every example used to copy into itself.

Before this package, `boundary.js` was duplicated across **10** examples (and one
copy had already drifted to a different build), the typed `thebes.ts` layer across
**9**, and `Admin.mo` across **9**. This repo holds each of those **once**;
examples depend on it instead of carrying their own copy.

## What's inside

| Path | What it is |
| --- | --- |
| `runtime/boundary.js` | Browser boundary client (`window.EgyptBoundary`): Candid encode/decode, persisted browser identity, call + receipt polling. |
| `runtime/passkey.js` | Memphis passkey client (`window.MemphisPasskey`): WebAuthn sign-in → session. |
| `src/thebes.ts` | Typed wrapper over `window.EgyptBoundary` — `query` / `update`, media upload, decoders. Framework-agnostic. |
| `src/useThebes.ts` | React hooks — `useQuery`, `useUpdate`, `useMediaUpload`. |
| `src/useMemphis.ts` | React hook — `useMemphis` (passkey session). |
| `src/MemphisGate.tsx` | `<MemphisGate>` auth gate + `useAuth()` + `<SignOutChip>`. |
| `motoko/src/*.mo` | Motoko backend lib — `Admin`, `MemphisAuth`, `Users`, `Pagination`. |

## Install (git dependency — no registry credentials needed)

Pin a tag so builds are reproducible:

```jsonc
// package.json
{
  "dependencies": {
    "@thebes/sdk": "github:Mercatura-Forum/thebes-sdk#v0.1.0"
  }
}
```

`npm install` runs the package's `prepare` step, which compiles `src/` to `dist/`.

### Frontend (React + Vite)

```ts
import { MemphisGate, useAuth, useQuery, useUpdate, encodeArgs, decodeVecRecord } from '@thebes/sdk'
```

The two browser runtimes load as plain `<script>` tags, so copy them into your
app's `public/` (Vite serves `public/` at the web root). Add this to your build:

```jsonc
// package.json scripts
{
  "scripts": {
    "presync": "true",
    "sync-sdk": "cp node_modules/@thebes/sdk/runtime/boundary.js node_modules/@thebes/sdk/runtime/passkey.js public/",
    "build": "npm run sync-sdk && tsc -b && vite build",
    "dev": "npm run sync-sdk && vite"
  }
}
```

```html
<!-- index.html -->
<script src="./boundary.js"></script>
<script src="./passkey.js"></script>
```

> Later upgrade path: when an npm `@thebes` token is provisioned, this same
> package is published to the registry and the dependency becomes
> `"@thebes/sdk": "^0.1.0"` — a one-line change per example, no code change.

### Backend (Motoko)

The Motoko lib lives under `motoko/` as the `thebes-lib` package. Until it is
published to [mops](https://mops.one), consume it as a git dependency or vendor
`motoko/src/*.mo` into your contract's `lib/` from this single source:

```motoko
import Admin "lib/Admin";
import Users "lib/Users";
```

## Verify — wire-output oracle

Extracting one shared `boundary.js` is only safe if **no example's on-the-wire
bytes change** when it switches from its vendored copy to the SDK. The oracle
proves it: it loads the canonical build and e-commerce's drifted copy side by
side and asserts every Candid-encoded argument and decoded reply is
byte-identical across both.

```
npm run oracle
```

It confirms the **only** difference between the two builds is the transport
envelope field name (`contract_id` vs `canister_id`) — a request-shape field,
not part of the Candid payload — so adopting the SDK changes zero wire bytes and
normalizes e-commerce onto the current field. Any encoding divergence exits
non-zero (a real regression).

## Develop

```
npm install      # installs typescript + @types/react, runs prepare (build)
npm run build    # tsc → dist/
npm run oracle   # wire-equivalence proof
```

## License

Apache-2.0. See [`NOTICE`](./NOTICE). Authored by the Thebes Protocol contributors.
