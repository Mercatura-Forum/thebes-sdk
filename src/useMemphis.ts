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
import { useCallback, useEffect, useRef, useState } from 'react'

export interface MemphisSession {
  name: string
  anchor_id_hex: string
  session_token_hex: string
  expires_at_ns: number
  display_tag: string
}

/** One registration proof, as `register` takes them. */
type FactorRegistration = Record<string, unknown>

type Passkey = {
  signInOrRegister: (name: string, opts?: { confirmCreate?: boolean }) => Promise<MemphisSession>
  signIn: (name: string) => Promise<MemphisSession>
  lookupAnchor: (name: string) => Promise<Uint8Array | null>
  loadSession: () => MemphisSession | null
  signOut: () => Promise<void>
  // The granular pieces a three-factor signup is built from.
  beginRegistrationChallenge: () => Promise<Uint8Array>
  buildDeviceFactor: (challenge: Uint8Array, label: string) => Promise<FactorRegistration>
  buildRecoveryFactor: (challenge: Uint8Array, phrase: string) => Promise<FactorRegistration>
  registerWithFactors: (name: string, factors: FactorRegistration[]) => Promise<MemphisSession>
}
type Recovery = { generatePhrase: () => Promise<string> }

function pk(): Passkey {
  const p = (window as unknown as { MemphisPasskey?: Passkey }).MemphisPasskey
  if (!p) throw new Error('passkey.js not loaded (window.MemphisPasskey missing)')
  return p
}
function recovery(): Recovery {
  const r = (window as unknown as { MemphisRecovery?: Recovery }).MemphisRecovery
  if (!r) throw new Error('recovery.js not loaded, so a new identity cannot be created safely (window.MemphisRecovery missing)')
  return r
}

export interface MemphisAuth {
  session: MemphisSession | null
  signedIn: boolean
  displayName: string
  signIn: (name: string) => Promise<void>
  signOut: () => Promise<void>
  busy: boolean
  error: string | undefined
  /** The twelve recovery words, while a signup is waiting for the person to
   *  confirm they have written them down. Null at every other moment. */
  phrase: string | null
  /** They wrote it down — continue the ceremony. */
  confirmPhrase: () => void
  /** Abort. Nothing has been created, so nothing needs undoing. */
  cancelPhrase: () => void
  /** Which factor the ceremony is on, for a UI that wants to say so. */
  progress: string | undefined
}

export function useMemphis(): MemphisAuth {
  const [session, setSession] = useState<MemphisSession | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [phrase, setPhrase] = useState<string | null>(null)
  const [progress, setProgress] = useState<string>()
  // Resolves when the person answers the recovery-phrase step.
  const phraseAnswer = useRef<((wrote: boolean) => void) | null>(null)

  useEffect(() => {
    try { setSession(pk().loadSession()) } catch { /* passkey.js not present yet */ }
  }, [])

  const confirmPhrase = useCallback(() => { phraseAnswer.current?.(true) }, [])
  const cancelPhrase = useCallback(() => { phraseAnswer.current?.(false) }, [])

  // A new identity needs THREE factors (Memphis INV-MEM-1, MIN_FACTORS_AT_SIGNUP
  // = 3 since 2026-08-29): this device's passkey, a second passkey, and a
  // recovery-phrase key. All three sign the SAME registration challenge, so
  // they land as one atomic `register`.
  //
  // The phrase comes first on purpose. It is the only factor a person has to
  // copy out by hand, and generating it before any passkey prompt means a
  // ceremony abandoned at this step leaves no identity behind.
  const runCeremony = useCallback(async (p: Passkey, name: string): Promise<MemphisSession> => {
    const rec = recovery()
    setProgress('A new identity needs three factors — passkey, second passkey, recovery phrase.')
    const words = await rec.generatePhrase()

    const wrote = await new Promise<boolean>((resolve) => {
      phraseAnswer.current = resolve
      setPhrase(words)
    })
    phraseAnswer.current = null
    setPhrase(null)
    if (!wrote) {
      const e = new Error('Registration cancelled — nothing was created.') as Error & { code?: string }
      e.code = 'CANCELLED'
      throw e
    }

    const challenge = await p.beginRegistrationChallenge()
    setProgress('Factor 1 of 3 — this device’s passkey…')
    const f1 = await p.buildDeviceFactor(challenge, name)
    setProgress('Factor 2 of 3 — a second passkey…')
    const f2 = await p.buildDeviceFactor(challenge, `${name} (backup)`)
    setProgress('Factor 3 of 3 — your recovery phrase…')
    const f3 = await p.buildRecoveryFactor(challenge, words)
    setProgress('Creating your identity on-chain…')
    return await p.registerWithFactors(name, [f1, f2, f3])
  }, [])

  const signIn = useCallback(async (name: string) => {
    setBusy(true); setError(undefined); setProgress(undefined)
    try {
      const p = pk()
      // Branch on the anchor lookup, which the canister answers directly.
      // Identity-durability P0: a lookup miss is a QUESTION for the human, not
      // a license to mint — and a sign-in must never fall through into creating
      // a second identity for a name that already exists.
      const existing = await p.lookupAnchor(name)
      if (existing) { setSession(await p.signIn(name)); return }

      const ok = typeof window !== 'undefined' && typeof window.confirm === 'function' &&
        window.confirm(`No Memphis identity exists for "${name}".\n\n` +
          'Create a NEW identity with this name? It takes three factors: a passkey on ' +
          'this device, a second passkey, and a recovery phrase you write down.\n\n' +
          '(Cancel if you meant to sign into an existing one.)')
      if (!ok) { setError('Sign-in cancelled — no identity created.'); return }

      setSession(await runCeremony(p, name))
    } catch (e) {
      const code = (e as { code?: string } | null)?.code
      if (code === 'CANCELLED') { setError('Registration cancelled — nothing was created.'); return }
      // Say what the canister said. The earlier client passed the OUTER Result
      // tag to its error decoder, so every failure read "NotAuthenticated" and
      // sent people looking at their passkey instead of at the rule they hit.
      const msg = e instanceof Error ? e.message : String(e)
      const detail = (e as { detail?: string } | null)?.detail
      setError(detail && detail !== msg ? `${msg} — ${detail}` : msg)
      throw e
    } finally {
      // A ceremony that threw mid-flight must not leave the phrase panel up.
      phraseAnswer.current = null
      setPhrase(null)
      setProgress(undefined)
      setBusy(false)
    }
  }, [runCeremony])

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
    phrase,
    confirmPhrase,
    cancelPhrase,
    progress,
  }
}
