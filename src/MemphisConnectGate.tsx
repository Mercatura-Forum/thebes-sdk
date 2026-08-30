/**
 * MemphisConnectGate — the drop-in sign-in for an app served from ITS OWN domain.
 *
 * The twin of <MemphisGate>. Same shape, same open-demo behaviour: it always
 * renders the app and exposes the session through useConnectAuth(), so visitors
 * roam freely and sign in on demand from the header chip.
 *
 * Use this one whenever your app is not served from the Memphis origin — which
 * is every app with a domain of its own. <MemphisGate> runs the passkey ceremony
 * in the page, and a page may only claim an RP ID that is a registrable-domain
 * suffix of its own origin, so on your domain the browser refuses it outright.
 * This gate opens the ceremony at the Memphis origin instead and receives back a
 * token minted for YOUR origin.
 *
 *     <MemphisConnectGate app="My App">
 *       <App />
 *     </MemphisConnectGate>
 *
 * Then pass `useConnectAuth().token` to your contract, which verifies it with
 * `await* MemphisAuth.verifyWithAudience(gate, session, AUDIENCE)`.
 *
 * Requires `memphis-connect.js` loaded as a <script> tag. Copy it as-is; only
 * the per-app `--color-accent` token tunes the chip to its host app.
 */
import { createContext, useContext, type ReactNode } from 'react'
import { useMemphisConnect, type MemphisConnectAuth } from './useMemphisConnect.js'
import type { ConnectOptions } from './session.js'

const ConnectCtx = createContext<MemphisConnectAuth | null>(null)

/** The Memphis session + sign-in/out. Throws if used outside the gate. */
export function useConnectAuth(): MemphisConnectAuth {
  const v = useContext(ConnectCtx)
  if (!v) throw new Error('useConnectAuth must be used inside <MemphisConnectGate>')
  return v
}

/**
 * Open-demo gate: never blocks the app.
 *
 * @param app  The name shown to the person in the connect window, and the key
 *             this app's session is stored under. Keep it stable across releases
 *             or people are silently signed out.
 */
export function MemphisConnectGate({ app, children }: { app: string; children: ReactNode }) {
  const auth = useMemphisConnect(app)
  return <ConnectCtx.Provider value={auth}>{children}</ConnectCtx.Provider>
}

/**
 * Header chip. Signed in → "Signed in as <name>" + Sign out. Guest → a single
 * "Sign in" button.
 *
 * There is deliberately no handle input here. The connect window owns that
 * field, and it must: a person types their handle on the Memphis origin, where
 * the address bar shows them who is asking. Collecting it on the app's own page
 * teaches exactly the habit a phishing page needs.
 *
 * `mode` defaults to "auto" — a popup, falling back to a full-page redirect when
 * the browser blocks it. An in-app WebView (Instagram, LinkedIn) and iOS Safari
 * outside a gesture both block popups, and without the fallback those visitors
 * simply cannot sign in.
 */
export function ConnectChip({ className = '', mode = 'auto' }: { className?: string; mode?: ConnectOptions['mode'] }) {
  const auth = useConnectAuth()

  if (auth.signedIn) {
    return (
      <span className={`inline-flex items-center gap-2 text-xs ${className}`}>
        <span className="opacity-60">Signed in as {auth.displayName}</span>
        <button className="rounded-md px-2 py-1 font-medium opacity-80 hover:opacity-100"
                style={{ color: 'var(--color-accent)' }} onClick={auth.signOut}>Sign out</button>
      </span>
    )
  }

  // onClick, not an async handler awaiting anything first: the popup must open
  // inside the user gesture or iOS Safari blocks it.
  const submit = () => { auth.signIn({ mode }).catch(() => { /* surfaced by auth.error */ }) }

  return (
    <span className={`inline-flex flex-col items-stretch gap-1 text-xs ${className}`}>
      <button className="rounded-md px-2 py-1 font-medium text-white disabled:opacity-50"
              style={{ background: 'var(--color-accent)' }} onClick={submit} disabled={auth.busy}>
        {auth.busy ? 'Signing in…' : 'Sign in'}
      </button>
      {auth.error && <span className="max-w-[12rem] truncate text-red-600" title={auth.error}>{auth.error}</span>}
    </span>
  )
}
