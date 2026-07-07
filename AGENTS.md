# AGENTS.md — working on the Thebes SDK

Orientation for an automated agent landing in `thebes-sdk`, the shared frontend
toolkit for Thebes applications. Human-readable detail in [README.md](README.md).

## Layout

```
runtime/boundary.js    browser boundary client (window.EgyptBoundary)
runtime/passkey.js     Memphis passkey client (window.MemphisPasskey)
src/thebes.ts          typed query/update + media upload + Candid decoders
src/useThebes.ts       React hooks: useQuery / useUpdate / useMediaUpload
src/useMemphis.ts      React hook: useMemphis (passkey session)
src/MemphisGate.tsx    <MemphisGate> auth gate + useAuth() + <SignOutChip>
oracle/                the SDK's own verification harness
dist/                  build output (tsc)
```

## How it is consumed

Two ways: as a **pinned npm git dependency**
(`"@thebes/sdk": "github:Mercatura-Forum/thebes-sdk#v0.1.1"`) or — in every
`thebes-example-*` repository — as a **vendored snapshot** under
`frontend/vendor/@thebes/sdk`. This repo is the upstream source of truth;
never patch a vendored copy in an example.

## Conventions that bite (respect these when editing)

- The boundary decodes `vec record` of scalars — single records travel as
  0-or-1-element arrays, never bare options; scalars as `[{ field = text }]`.
- Principals are 56-char hex everywhere (`identity()`, `decodeVecRecord`,
  `encodeArg({type:'principal'})`).
- Frontends call backend `*OrTrap` twins so rejected guards throw a reason
  instead of arriving as a status-success `#err` the SPA would swallow.
- A release = tag `vX.Y.Z` here → examples refresh their vendored snapshot.

## Related repositories

Hub: [Thebes-Protocol-](https://github.com/Mercatura-Forum/Thebes-Protocol-)
(spec, docs, catalog, `thebes-deploy` releases) ·
Backend lib: [thebes-lib](https://github.com/Mercatura-Forum/thebes-lib) ·
Examples: `thebes-example-<name>` (each carries its own AGENTS.md).
