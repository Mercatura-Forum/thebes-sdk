/**
 * useMemphisConnect — Memphis sign-in for an app served from ITS OWN domain.
 *
 * `useMemphis` runs the passkey ceremony in the page. That only works on the
 * Memphis origin itself: a WebAuthn credential is bound to a Relying Party ID,
 * and a page may only claim an RP ID that is a registrable-domain suffix of its
 * own origin. An app on `my-app.com` is refused by the browser before any of our
 * code runs.
 *
 * This hook is the way across that wall. The ceremony happens in a window at the
 * Memphis origin, which attenuates the master session into a token minted for
 * YOUR origin and hands back only that. Use it whenever your app is not served
 * from the Memphis origin — which is every app with a domain of its own.
 *
 * It is a thin React face over `session.ts`. All the bookkeeping — one session
 * per origin, expiry handling, redirect collection, legacy adoption — lives
 * there so a non-React site gets exactly the same behaviour.
 *
 * The returned `token` is an ORIGIN-SCOPED session token. Pass it to your
 * contract as a call argument; your contract passes its own audience alongside
 * it, and Memphis checks the two agree:
 *
 *     switch (await* MemphisAuth.verifyWithAudience(gate, session, AUDIENCE)) { … }
 *
 * Requires `memphis-connect.js` loaded as a <script> tag (see the README).
 */
import { useCallback, useEffect, useState } from 'react'
import {
  signIn as doSignIn, signOut as doSignOut,
  resumeFromRedirect, onSessionChange, ensureSession,
  type ConnectSession, type ConnectOptions, type LegacySessionKey,
} from './session.js'

export interface MemphisConnectAuth {
  session: ConnectSession | null
  signedIn: boolean
  displayName: string
  /** The scoped token to pass to your contract, or undefined when signed out. */
  token: string | undefined
  /** MUST be called from a user gesture — a popup or redirect outside one is blocked. */
  signIn: (opts?: ConnectOptions) => Promise<void>
  signOut: () => void
  busy: boolean
  error: string | undefined
}

/**
 * @param app     The name shown to the person in the connect window, and the key
 *                this app's session is stored under. Keep it stable across
 *                releases or people are silently signed out.
 * @param legacy  Storage keys this site used before adopting the SDK. Read once
 *                and adopted, so shipping this does not log out everyone who was
 *                already signed in.
 */
export function useMemphisConnect(app: string, legacy: LegacySessionKey[] = []): MemphisConnectAuth {
  const [session, setSession] = useState<ConnectSession | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  const cleanup = useState<{ fn?: () => void }>(() => ({}))[0]

  useEffect(() => {
    // Order matters. A redirect-mode return arrives in the URL fragment and must
    // be consumed on this load — resumeFromRedirect also strips the fragment, so
    // a token is never left in the address bar. Only if there is nothing to
    // collect do we fall back to a session held from an earlier visit.
    const returned = (() => { try { return resumeFromRedirect() } catch { return null } })()
    if (returned) setSession(returned)
    else {
      // Renew silently if the access token has lapsed. This is what makes a
      // week-old tab work without a passkey prompt; `getSession` alone would
      // show the sign-in button to someone who never actually signed out.
      let cancelled = false
      ensureSession(app, legacy).then((s) => { if (!cancelled) setSession(s) })
      // eslint-disable-next-line @typescript-eslint/no-extra-semi
      ;(cleanup as { fn?: () => void }).fn = () => { cancelled = true }
    }

    // Another tab signing out should not leave this one holding a token it has
    // forgotten, and another tab signing in should fill this one in.
    const unsubscribe = onSessionChange(app, setSession)
    return () => { cleanup.fn?.(); unsubscribe() }
    // `legacy` is a config array, not state; re-running on a new array identity
    // would re-adopt on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app])

  const signIn = useCallback(async (opts?: ConnectOptions) => {
    setBusy(true); setError(undefined)
    try {
      setSession(await doSignIn(app, opts))
    } catch (e) {
      const code = (e as { code?: string } | null)?.code
      // A cancellation is a decision, not a fault. Reporting it as an error
      // makes an app look broken when the person simply changed their mind.
      if (code === 'CANCELLED') { setError(undefined); return }
      setError(e instanceof Error ? e.message : String(e))
      throw e
    } finally { setBusy(false) }
  }, [app])

  const signOut = useCallback(() => {
    doSignOut(app, legacy)
    setSession(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app])

  return {
    session,
    signedIn: !!session,
    displayName: session?.name || '',
    token: session?.token,
    signIn,
    signOut,
    busy,
    error,
  }
}
