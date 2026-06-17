/**
 * @thebes/sdk — the shared frontend SDK for Thebes Protocol example dapps.
 *
 * One source of truth for the toolkit every example used to copy:
 *   • thebes      — typed query/update calls + media upload over window.EgyptBoundary
 *   • useThebes   — React hooks (useQuery / useUpdate / useMediaUpload)
 *   • useMemphis  — Memphis passkey sign-in session hook
 *   • MemphisGate — passkey auth gate + useAuth() + SignOutChip
 *
 * The two browser runtimes (boundary.js, passkey.js) ship alongside this package
 * under `@thebes/sdk/boundary.js` and `@thebes/sdk/passkey.js`; an app copies them
 * into its `public/` and loads them with <script> tags (see the README). This
 * barrel only re-exports the TypeScript layer.
 */
export * from './thebes.js'
export * from './useThebes.js'
export * from './useMemphis.js'
export * from './MemphisGate.js'
