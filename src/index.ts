/**
 * @thebes/sdk — the shared frontend SDK for Thebes Protocol example dapps.
 *
 * One source of truth for the toolkit every example used to copy:
 *   • thebes      — typed query/update calls + media upload over window.EgyptBoundary
 *   • useThebes   — React hooks (useQuery / useUpdate / useMediaUpload)
 *   • useMemphis  — Memphis passkey sign-in session hook (Memphis origin ONLY)
 *   • MemphisGate — passkey auth gate + useAuth() + SignOutChip (same)
 *   • session     — the Memphis session for ANY site, framework-free TS
 *   • useMemphisConnect / MemphisConnectGate
 *                 — Memphis sign-in for an app served from its OWN domain. The
 *                   ceremony cannot run on your origin (the WebAuthn RP-ID
 *                   wall), so it happens at the Memphis origin and returns a
 *                   token minted for yours. Almost every real app wants this.
 *
 * The three browser runtimes (boundary.js, passkey.js, memphis-connect.js) ship
 * alongside this package under `@thebes/sdk/<name>.js`; an app copies them
 * into its `public/` and loads them with <script> tags (see the README). This
 * barrel only re-exports the TypeScript layer.
 */
export * from './thebes.js'
export * from './useThebes.js'
export * from './useMemphis.js'
export * from './session.js'
export * from './useMemphisConnect.js'
export * from './MemphisGate.js'
export * from './MemphisConnectGate.js'
