/**
 * useMemphis — Memphis passkey sign-in as the app's web auth, over the proven
 * `window.MemphisPasskey` client (vendored passkey.js). This is the reusable
 * pattern for every Thebes example: sign in with a passkey → a session with a
 * stable Memphis identity (anchor + display name) → use the display name (and,
 * where a backend needs the cross-device principal, the session token) in calls.
 *
 * The Memphis contract is cid 921; the session is persisted in localStorage by
 * the client, so a refresh keeps you signed in.
 */
import { useCallback, useEffect, useState } from 'react'

export interface MemphisSession {
  name: string
  anchor_id_hex: string
  session_token_hex: string
  expires_at_ns: number
  display_tag: string
}

type Passkey = {
  signInOrRegister: (name: string) => Promise<MemphisSession>
  loadSession: () => MemphisSession | null
  signOut: () => Promise<void>
}
function pk(): Passkey {
  const p = (window as unknown as { MemphisPasskey?: Passkey }).MemphisPasskey
  if (!p) throw new Error('passkey.js not loaded (window.MemphisPasskey missing)')
  return p
}

export interface MemphisAuth {
  session: MemphisSession | null
  signedIn: boolean
  displayName: string
  signIn: (name: string) => Promise<void>
  signOut: () => Promise<void>
  busy: boolean
  error: string | undefined
}

export function useMemphis(): MemphisAuth {
  const [session, setSession] = useState<MemphisSession | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  useEffect(() => {
    try { setSession(pk().loadSession()) } catch { /* passkey.js not present yet */ }
  }, [])

  const signIn = useCallback(async (name: string) => {
    setBusy(true); setError(undefined)
    try { setSession(await pk().signInOrRegister(name)) }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); throw e }
    finally { setBusy(false) }
  }, [])

  const signOut = useCallback(async () => {
    setBusy(true)
    try { await pk().signOut() } catch { /* best-effort */ } finally { setSession(null); setBusy(false) }
  }, [])

  return {
    session,
    signedIn: !!session,
    displayName: session?.display_tag || session?.name || '',
    signIn,
    signOut,
    busy,
    error,
  }
}
