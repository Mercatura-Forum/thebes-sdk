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
 * YOUR origin and hands back only that. Use this hook whenever your app is not
 * served from the Memphis origin — which is every app with a domain of its own.
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

export interface ConnectSession {
  /** The app name this credential was minted for. */
  app: string
  /** The person's Memphis handle. */
  name: string
  /** 32-byte anchor_id_hash, hex. Never the raw anchor. */
  anchorId: string
  /** The origin-scoped session token, hex. This is what your contract verifies. */
  token: string
  /** The web origin this token is valid at, and only at. */
  origin: string
  /** Local upper bound on validity. The contract remains the authority. */
  expiresAtMs: number
}

export interface ConnectOptions {
  /** "popup" (default), "redirect", or "auto" to fall back when blocked. */
  mode?: 'popup' | 'redirect' | 'auto'
  /** Prefill for the handle field. Authorises nothing. */
  handle?: string
  /** Redirect mode only. Must be on this app's own origin. */
  returnTo?: string
  /** Override the Memphis connect page (tests, staging). */
  connectUrl?: string
  /** Popup mode only. Default 120000. */
  timeoutMs?: number
  /** Pass false to force a fresh ceremony even if a live token is held. */
  reuse?: boolean
}

type Connect = {
  connect: (opts: ConnectOptions & { app: string }) => Promise<ConnectSession>
  resume: () => ConnectSession | null
  loadSession: (app: string) => ConnectSession | null
  signOut: (app: string) => void
}

function mc(): Connect {
  const m = (window as unknown as { memphis?: Connect }).memphis
  if (!m || typeof m.connect !== 'function') {
    throw new Error('memphis-connect.js not loaded (window.memphis missing)')
  }
  return m
}

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
 * @param app  The name shown to the person in the connect window, and the key
 *             this app's session is stored under. Keep it stable.
 */
export function useMemphisConnect(app: string): MemphisConnectAuth {
  const [session, setSession] = useState<ConnectSession | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  useEffect(() => {
    try {
      // Order matters. A redirect-mode return arrives in the URL fragment and
      // must be consumed on this load — `resume` also strips the fragment, so a
      // token is never left in the address bar. Only if there is nothing to
      // collect do we fall back to a session held from an earlier visit.
      setSession(mc().resume() ?? mc().loadSession(app))
    } catch { /* memphis-connect.js not present yet */ }
  }, [app])

  const signIn = useCallback(async (opts?: ConnectOptions) => {
    setBusy(true); setError(undefined)
    try {
      setSession(await mc().connect({ ...(opts || {}), app }))
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
    // Local only: this app forgets the person. It does not end their Memphis
    // session, which this app cannot do and should not be able to — end_session
    // is caller-scoped on Memphis.
    try { mc().signOut(app) } catch { /* nothing held */ }
    setSession(null)
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
