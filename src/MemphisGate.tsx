/**
 * MemphisGate — Memphis passkey sign-in as the app's web auth, open-demo style.
 *
 * Wrap the app's routes in <MemphisGate>. The gate ALWAYS renders the app and
 * exposes the session via useAuth(), so visitors roam freely and sign in on
 * demand from the header chip. Memphis (cid 921) provides the human identity +
 * display name; the on-chain caller stays the boundary's persisted browser key,
 * so reads — and demo writes — work whether or not you have signed in.
 *
 * IMPORT this from '@thebes/sdk'; do NOT copy it into an app. Five examples
 * (chat, booking, restaurant, crm, cards) kept a local fork of this file, and
 * when the signup ceremony grew its recovery-phrase step those forks silently
 * lost it: they still called the updated useMemphis(), which suspends until
 * confirmPhrase(), but rendered no overlay, so signup hung at "Signing in…"
 * forever. An app that genuinely needs its own gate must render the exported
 * <RecoveryPhrasePanel auth={auth} /> alongside its children.
 *
 * Only the per-app `--color-accent` token (in index.css) tunes the chip to its
 * host app.
 */
import { createContext, useContext, useState, type ReactNode } from 'react'
import { useMemphis, type MemphisAuth } from './useMemphis.js'

const AuthCtx = createContext<MemphisAuth | null>(null)

/** The Memphis session + sign-in/out. Throws if used outside the gate. */
export function useAuth(): MemphisAuth {
  const v = useContext(AuthCtx)
  if (!v) throw new Error('useAuth must be used inside <MemphisGate>')
  return v
}

/** Open-demo gate: never blocks the app. `appName`/`tagline` are accepted for
 *  API compatibility with hosted apps but are unused in the open-demo flow. */
export function MemphisGate({ children }: { appName?: string; tagline?: string; children: ReactNode }) {
  const auth = useMemphis()
  return (
    <AuthCtx.Provider value={auth}>
      {children}
      <RecoveryPhrasePanel />
    </AuthCtx.Provider>
  )
}

/** The recovery-phrase step of a new-identity ceremony.
 *
 *  Memphis needs three factors to create an identity (INV-MEM-1): a device
 *  passkey, a second passkey, and this phrase. It is shown BEFORE any passkey
 *  prompt, because it is the one factor a person has to transcribe — and it is
 *  rendered by the gate rather than the chip so that it is a full overlay, not
 *  a dropdown that a short viewport can push Continue out of.
 *
 *  Nothing is created until Continue is pressed: cancelling here leaves no
 *  half-made identity behind.
 *
 *  EXPORTED, and takes `auth` explicitly, because several examples wrap the app
 *  in their OWN gate with their OWN context rather than this one. Such a gate
 *  gets the fixed `useMemphis()` — which suspends the ceremony until
 *  `confirmPhrase()` — but renders no overlay, so signup hangs on a
 *  confirmation the UI never shows. Those gates render this panel directly and
 *  pass their own `auth`; the context fallback keeps <MemphisGate> unchanged. */
export function RecoveryPhrasePanel({ auth: authProp }: { auth?: MemphisAuth } = {}) {
  const ctx = useContext(AuthCtx)
  const auth = authProp ?? ctx
  const [wrote, setWrote] = useState(false)
  if (!auth) throw new Error('RecoveryPhrasePanel needs an `auth` prop or a <MemphisGate> ancestor')
  if (!auth.phrase) return null
  const words = auth.phrase.split(/\s+/)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
         role="dialog" aria-modal="true" aria-label="Your recovery phrase">
      <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
        <h2 className="text-base font-semibold">First: your recovery phrase</h2>
        <p className="mt-1 text-xs leading-relaxed opacity-70">
          These twelve words are one of your three factors. They are shown once, they are
          never sent anywhere, and they are the only way back in if you lose every device.
          Write them down now.
        </p>
        <ol className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 rounded-lg bg-black/[0.04] p-3 font-mono text-[13px]">
          {words.map((w, i) => (
            <li key={`${i}-${w}`}><span className="mr-2 opacity-40">{String(i + 1).padStart(2, '0')}</span>{w}</li>
          ))}
        </ol>
        <label className="mt-4 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={wrote} onChange={(e) => setWrote(e.target.checked)} />
          I have written the phrase down
        </label>
        <div className="mt-4 flex gap-2">
          <button
            className="flex-1 rounded-md px-3 py-2 text-xs font-medium text-white disabled:opacity-50"
            style={{ background: 'var(--color-accent, #111)' }}
            disabled={!wrote}
            onClick={() => { setWrote(false); auth.confirmPhrase() }}
          >Continue</button>
          <button
            className="rounded-md border border-black/10 px-3 py-2 text-xs opacity-70 hover:opacity-100"
            onClick={() => { setWrote(false); auth.cancelPhrase() }}
          >Cancel</button>
        </div>
      </div>
    </div>
  )
}

/** Header chip. Signed in → "Signed in as <name>" + Sign out. Guest → a "Sign in"
 *  affordance that expands into a name input + passkey button. Native-looking;
 *  the accent comes from --color-accent. */
export function SignOutChip({ className = '' }: { className?: string }) {
  const auth = useAuth()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')

  if (auth.signedIn) {
    return (
      <span className={`inline-flex items-center gap-2 text-xs ${className}`}>
        <span className="opacity-60">Signed in as {auth.displayName}</span>
        <button className="rounded-md px-2 py-1 font-medium opacity-80 hover:opacity-100"
                style={{ color: 'var(--color-accent)' }} onClick={auth.signOut}>Sign out</button>
      </span>
    )
  }

  // Memphis handles look like  <stem>.thebes  — we append ".thebes" so a visitor
  // only types the stem (3–32 chars, a–z 0–9 -). No bare fallback: an invalid
  // stem keeps the button disabled instead of failing with a cryptic error.
  const stem = name.trim().toLowerCase().replace(/\.thebes$/, '')
  const stemOk = stem.length >= 3 && stem.length <= 32 && /^[a-z0-9-]+$/.test(stem) && !stem.startsWith('-') && !stem.endsWith('-')
  const handle = `${stem}.thebes`
  const submit = () => { if (stemOk && !auth.busy) auth.signIn(handle).catch(() => { /* surfaced by auth.error */ }) }

  if (!open) {
    return (
      <span className={`inline-flex items-center text-xs ${className}`}>
        <button className="rounded-md px-2 py-1 font-medium opacity-80 hover:opacity-100"
                style={{ color: 'var(--color-accent)' }} onClick={() => setOpen(true)}>Sign in</button>
      </span>
    )
  }

  return (
    <span className={`inline-flex flex-col items-stretch gap-1 text-xs ${className}`}>
      <span className="inline-flex items-center gap-2">
        <input
          className="w-28 rounded-md border border-black/10 bg-black/[0.03] px-2 py-1 outline-none focus:border-black/30"
          placeholder="yourname" value={name} autoFocus aria-label="Thebes handle"
          onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()}
        />
        <button className="rounded-md px-2 py-1 font-medium text-white disabled:opacity-50"
                style={{ background: 'var(--color-accent)' }} onClick={submit} disabled={auth.busy || !stemOk}>
          {auth.busy ? 'Signing in…' : 'Sign in with passkey'}
        </button>
      </span>
      <span style={{ fontSize: '11px', opacity: 0.7 }}>
        {auth.progress
          ? auth.progress
          : <>{stem ? <>→ becomes <b>{handle}</b></> : 'pick a handle — we add .thebes'} · 3–32 · a–z 0–9 -</>}
      </span>
      {auth.error && <span className="max-w-[10rem] truncate text-red-600" title={auth.error}>{auth.error}</span>}
    </span>
  )
}
