/**
 * MemphisGate — Memphis passkey sign-in as the app's web auth.
 *
 * Wrap the app's routes in <MemphisGate appName="…">. Until the visitor signs
 * in with a passkey, the gate shows a sign-in card; once signed in, it renders
 * the app and exposes the session via useAuth() so the header can greet the
 * user and offer sign-out. Memphis (cid 921) provides the human identity +
 * display name; the on-chain caller stays the boundary's persisted browser key.
 *
 * This file is identical across every Thebes example — copy it as-is. Only the
 * per-app `--color-accent` token (in index.css) and the appName/tagline props
 * differ, so the gate always looks native to its host app.
 */
import { createContext, useContext, useState, type ReactNode } from 'react'
import { useMemphis, type MemphisAuth } from './useMemphis.js'

const AuthCtx = createContext<MemphisAuth | null>(null)

/** The signed-in Memphis session + sign-out. Throws if used outside the gate. */
export function useAuth(): MemphisAuth {
  const v = useContext(AuthCtx)
  if (!v) throw new Error('useAuth must be used inside <MemphisGate>')
  return v
}

export function MemphisGate({ appName, tagline, children }: { appName: string; tagline?: string; children: ReactNode }) {
  const auth = useMemphis()
  const [name, setName] = useState('')

  if (auth.signedIn) return <AuthCtx.Provider value={auth}>{children}</AuthCtx.Provider>

  const submit = () => { auth.signIn(name.trim() || 'Guest').catch(() => { /* surfaced by auth.error */ }) }
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm rounded-2xl border border-black/10 bg-white p-7 text-center shadow-xl"
           style={{ color: 'var(--color-ink)' }}>
        <div className="font-display text-3xl font-extrabold" style={{ color: 'var(--color-accent)' }}>{appName}</div>
        <p className="mt-2 text-sm opacity-70">{tagline ?? 'Sign in to continue.'}</p>
        <input
          className="mt-5 w-full rounded-xl border border-black/10 bg-black/[0.03] px-3 py-2.5 text-center outline-none focus:border-black/30"
          placeholder="Your name" value={name} autoFocus
          onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()}
        />
        <button
          className="mt-3 w-full rounded-xl px-4 py-2.5 text-sm font-semibold text-white transition hover:brightness-110 disabled:opacity-50"
          style={{ background: 'var(--color-accent)' }} onClick={submit} disabled={auth.busy}>
          {auth.busy ? 'Signing in…' : 'Sign in with passkey'}
        </button>
        {auth.error && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{auth.error}</p>}
        <p className="mt-4 text-xs opacity-50">A passkey is your identity — no password. Powered by Memphis.</p>
      </div>
    </div>
  )
}

/** Compact "signed in as … · Sign out" chip for app headers. Native-looking;
 *  the accent comes from --color-accent. */
export function SignOutChip({ className = '' }: { className?: string }) {
  const auth = useAuth()
  return (
    <span className={`inline-flex items-center gap-2 text-xs ${className}`}>
      <span className="opacity-60">{auth.displayName}</span>
      <button className="rounded-md px-2 py-1 font-medium opacity-80 hover:opacity-100"
              style={{ color: 'var(--color-accent)' }} onClick={auth.signOut}>Sign out</button>
    </span>
  )
}
