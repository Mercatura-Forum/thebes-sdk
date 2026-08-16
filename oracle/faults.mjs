/**
 * oracle/faults.mjs — failure-semantics oracle for the typed call layer.
 *
 * boundary.js reports exactly three failure shapes, and they split on the one
 * question that decides whether a retry is safe: was a message hash issued?
 *
 *   • `call: no message_hash`   — the submit was refused; nothing was accepted;
 *                                 retrying the SAME nonce is safe.
 *   • `call rejected: <detail>` — a deterministic no; retrying re-asks it.
 *   • `receipt poll timed out`  — accepted, not yet finalized; a resubmit here
 *                                 is how an app double-writes.
 *
 * This oracle drives the typed layer (dist/thebes.js) against a scripted fake
 * `window.EgyptBoundary` that throws those exact shapes, and asserts the layer
 * holds the discipline: refused submits retry with ONE nonce, rejections and
 * receipt timeouts never resubmit, queries retry transport failures instead of
 * handing the app an empty reply to decode, and every legacy call shape still
 * works untouched.
 *
 * Exit non-zero on any violation. Run: node oracle/faults.mjs
 * (fast: test backoffs are 1 ms)
 */

const EMPTY = '4449444c0000'

/** A scripted boundary: `plan` is consumed one entry per callUpdate/callQuery. */
function fake(plan) {
  const seen = { updates: [], queries: [] }
  const next = (kind) => {
    const step = plan.shift()
    if (!step) throw new Error(`oracle: fake boundary ran out of plan on a ${kind}`)
    if (step.throw) throw new Error(step.throw)
    return step.reply
  }
  globalThis.window = {
    EgyptBoundary: {
      EMPTY_ARGS_HEX: EMPTY,
      identity: () => 'oracle-sender',
      callUpdate: async (cid, method, argHex, opts) => {
        seen.updates.push({ cid, method, argHex, opts: { ...(opts || {}) } })
        return next('callUpdate')
      },
      callQuery: async (cid, method, argHex, opts) => {
        seen.queries.push({ cid, method, argHex, opts: { ...(opts || {}) } })
        return next('callQuery')
      },
    },
  }
  return seen
}

let failures = 0
const check = (name, cond, detail = '') => {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.error(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

const { query, update, ThebesCallError } = await import('../dist/thebes.js')
const FAST = { retries: 2, backoffMs: 1 }

// ── 1. a refused submit retries, and the chain sees ONE nonce ───────────────
{
  const seen = fake([
    { throw: 'call: no message_hash' },
    { throw: 'call: no message_hash' },
    { reply: { status: 'success', reply_hex: 'aa' } },
  ])
  const r = await update(7, 'add_item', EMPTY, FAST)
  check('refused submit retries to success', r.reply_hex === 'aa')
  check('three submits were made', seen.updates.length === 3, `saw ${seen.updates.length}`)
  const nonces = new Set(seen.updates.map((u) => u.opts.nonce))
  check('one nonce across every attempt', nonces.size === 1 && !nonces.has(undefined),
    `nonces=${[...nonces].join(',')}`)
}

// ── 2. a refusal that persists surfaces as a typed, retryable error ─────────
{
  const seen = fake([
    { throw: 'call: no message_hash' },
    { throw: 'call: no message_hash' },
    { throw: 'call: no message_hash' },
  ])
  const e = await update(7, 'add_item', EMPTY, FAST).then(() => null, (x) => x)
  check('persistent refusal throws ThebesCallError', e instanceof ThebesCallError)
  check("…kind 'refused', retryable", e?.kind === 'refused' && e?.retryable === true)
  check('…attempts counted', e?.attempts === 3, `attempts=${e?.attempts}`)
  check('…exactly retries+1 submits', seen.updates.length === 3)
}

// ── 3. a rejection is deterministic: one submit, no retry ───────────────────
{
  const seen = fake([{ throw: 'call rejected: quota exceeded' }])
  const e = await update(7, 'add_item', EMPTY, FAST).then(() => null, (x) => x)
  check("rejection throws kind 'rejected', not retryable",
    e instanceof ThebesCallError && e.kind === 'rejected' && e.retryable === false)
  check('…detail preserved', e?.detail === 'quota exceeded', `detail=${e?.detail}`)
  check('…exactly one submit', seen.updates.length === 1, `saw ${seen.updates.length}`)
}

// ── 4. a receipt timeout NEVER resubmits — the call may still land ──────────
{
  const seen = fake([{ throw: 'receipt poll timed out' }])
  const e = await update(7, 'add_item', EMPTY, FAST).then(() => null, (x) => x)
  check("receipt timeout throws kind 'receipt-timeout', not retryable",
    e instanceof ThebesCallError && e.kind === 'receipt-timeout' && e.retryable === false)
  check('…exactly one submit (a resubmit here double-writes)', seen.updates.length === 1,
    `saw ${seen.updates.length}`)
}

// ── 5. a contract-level error envelope is a rejection, once ─────────────────
{
  const seen = fake([{ reply: { status: 'error', error: 'trap: assertion failed' } }])
  const e = await update(7, 'add_item', EMPTY, FAST).then(() => null, (x) => x)
  check("receipt status 'error' throws kind 'rejected'",
    e instanceof ThebesCallError && e.kind === 'rejected')
  check('…one submit, no retry of a deterministic no', seen.updates.length === 1)
}

// ── 6. the runtime options actually reach boundary.js ───────────────────────
{
  const seen = fake([{ reply: { status: 'success', reply_hex: 'bb' } }])
  await update(7, 'add_item', EMPTY, { ...FAST, timeoutMs: 60_000, nonce: 42, sender: 'abc' })
  const o = seen.updates[0].opts
  check('timeoutMs / nonce / sender forwarded',
    o.timeoutMs === 60_000 && o.nonce === 42 && o.sender === 'abc',
    JSON.stringify(o))
}

// ── 7. the legacy call shape is untouched ────────────────────────────────────
{
  const seen = fake([{ reply: { status: 'success', reply_hex: 'cc' } }])
  const r = await update(7, 'add_item')
  check('update(cid, method) still works', r.reply_hex === 'cc')
  check('…defaults empty args', seen.updates[0].argHex === EMPTY)
  check('…generates a nonce when none is given',
    typeof seen.updates[0].opts.nonce === 'number')
}

// ── 8. a query transport failure retries, then errors — never `{}` ──────────
{
  const seen = fake([{ reply: {} }, { reply: {} }, { reply: { reply_hex: 'dd' } }])
  const r = await query(7, 'list_items', EMPTY, FAST)
  check('query retries the empty-reply shape to success', r.reply_hex === 'dd')
  check('…three reads were made', seen.queries.length === 3, `saw ${seen.queries.length}`)
}
{
  fake([{ reply: {} }, { reply: {} }, { reply: {} }])
  const e = await query(7, 'list_items', EMPTY, FAST).then(() => null, (x) => x)
  check("a read that failed is an ERROR the app can see, kind 'network'",
    e instanceof ThebesCallError && e.kind === 'network' && e.retryable === true)
}

// ── 9. a query the boundary rejected does not retry ──────────────────────────
{
  const seen = fake([{ reply: { error: 'no such method' } }])
  const e = await query(7, 'list_items', EMPTY, FAST).then(() => null, (x) => x)
  check("query error field throws kind 'rejected'",
    e instanceof ThebesCallError && e.kind === 'rejected' && e.detail === 'no such method')
  check('…one read', seen.queries.length === 1)
}

console.log(failures === 0
  ? '\nfaults oracle: every failure shape handled correctly'
  : `\nfaults oracle: ${failures} violation(s)`)
process.exit(failures === 0 ? 0 : 1)
