/**
 * MemphisGate — Memphis passkey sign-in as the app's web auth, open-demo style.
 *
 * Wrap the app's routes in <MemphisGate>. The gate ALWAYS renders the app and
 * exposes the session via useAuth(), so visitors roam freely and sign in on
 * demand from the header chip. Memphis (cid 921) provides the human identity +
 * display name; the on-chain caller stays the boundary's persisted browser key,
 * so reads — and demo writes — work whether or not you have signed in.
 *
 * This file is identical across every Thebes example — copy it as-is. Only the
 * per-app `--color-accent` token (in index.css) tunes the chip to its host app.
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
  return <AuthCtx.Provider value={auth}>{children}</AuthCtx.Provider>
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
        {stem ? <>→ becomes <b>{handle}</b></> : 'pick a handle — we add .thebes'} · 3–32 · a–z 0–9 -
      </span>
      {auth.error && <span className="max-w-[10rem] truncate text-red-600" title={auth.error}>{auth.error}</span>}
    </span>
  )
}
