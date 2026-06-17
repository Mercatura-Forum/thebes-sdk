/**
 * oracle/encode-diff.mjs — wire-output equivalence oracle for the boundary client.
 *
 * The whole point of extracting one shared boundary.js is that no example's
 * on-the-wire bytes may change when it switches from its vendored copy to the
 * SDK. This oracle loads TWO boundary.js builds side by side:
 *
 *   • runtime/boundary.js          — the canonical SDK copy (what 9 examples use)
 *   • oracle/boundary.ecommerce.js — e-commerce's drifted copy (different hash)
 *
 * and runs the SAME battery of inputs through each, asserting that every
 * Candid-encoded argument and every decoded reply is BYTE-IDENTICAL across the
 * two. It then independently confirms the ONLY source-level difference is the
 * transport envelope field name (contract_id vs canister_id) — a request-shape
 * field, NOT part of the Candid wire payload — so adopting the SDK changes zero
 * encoding behaviour and merely normalizes e-commerce onto the current field.
 *
 * Exit non-zero on ANY encoding/decoding divergence (a real regression) or if
 * the drift is anything other than the known transport field.
 *
 * Run: node oracle/encode-diff.mjs   (also `npm run oracle`)
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import vm from 'node:vm'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')

/** Load a boundary.js IIFE in an isolated DOM-ish sandbox; return EgyptBoundary. */
function loadBoundary(relPath) {
  const code = readFileSync(join(ROOT, relPath), 'utf8')
  const store = new Map()
  const sandbox = {
    window: {},
    location: { origin: 'http://localhost' },
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    performance: { now: () => 0 },
    Date: { now: () => 0 },
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
    },
    console,
  }
  vm.createContext(sandbox)
  vm.runInContext(code, sandbox, { filename: relPath })
  const B = sandbox.window.EgyptBoundary
  if (!B) throw new Error(`${relPath}: window.EgyptBoundary not defined after load`)
  return B
}

const hex = (u8) => Buffer.from(u8).toString('hex')

/**
 * Deterministic battery. Each case returns a hex string from the given boundary
 * so the two builds can be compared exactly. NO Date/random in any path.
 */
function battery(B) {
  const principalHex = '00'.repeat(28) // 28-byte sender, all zeros
  const cases = {
    'encodeArgs/empty': () => hex(B.encodeArgs([])),
    'encodeArgs/nat0': () => hex(B.encodeArgs([0])),
    'encodeArgs/nat42': () => hex(B.encodeArgs([42])),
    'encodeArgs/nat-big': () => hex(B.encodeArgs([{ type: 'nat', value: 1000000000000n }])),
    'encodeArgs/int-neg': () => hex(B.encodeArgs([{ type: 'int', value: -12345 }])),
    'encodeArgs/text-unicode': () => hex(B.encodeArgs(['hello world ☕ منيس'])),
    'encodeArgs/bools': () => hex(B.encodeArgs([true, false])),
    'encodeArgs/vec-nat': () =>
      hex(B.encodeArgs([{ type: 'vec', inner: { type: 'nat' }, value: [0n, 1n, 2n, 3n] }])),
    // placeOrder(ids, qtys) — the exact shape the storefront sends
    'encodeArgs/placeOrder': () =>
      hex(
        B.encodeArgs([
          { type: 'vec', inner: { type: 'nat' }, value: [0n, 2n] },
          { type: 'vec', inner: { type: 'nat' }, value: [1n, 1n] },
        ]),
      ),
    'encodeArgs/record': () =>
      hex(B.encodeArgs([{ type: 'record', fields: { id: 0, name: 'Linen Notebook', price: 1800 } }])),
    'encodeArg/text': () => hex(B.encodeArg('abc')),
    'encodeArg/principal': () => hex(B.encodeArg({ type: 'principal', value: principalHex })),
    'EMPTY_ARGS_HEX': () => B.EMPTY_ARGS_HEX,
    'fieldHash/name': () => String(B.fieldHash('name')),
    'fieldHash/price': () => String(B.fieldHash('price')),
    // Decoders: round-trip a known reply hex (DIDL + nat 42, + bool true)
    'decodeNatReply/42': () => String(B.decodeNatReply(hex(B.encodeArg(42)))),
    'decodeBoolReply/true': () => String(B.decodeBoolReply(hex(B.encodeArg(true)))),
  }
  const out = {}
  for (const [k, fn] of Object.entries(cases)) out[k] = fn()
  return out
}

function main() {
  const canon = loadBoundary('runtime/boundary.js')
  const ecom = loadBoundary('oracle/boundary.ecommerce.js')

  const a = battery(canon)
  const b = battery(ecom)

  let fails = 0
  const keys = Object.keys(a)
  console.log(`\n  Thebes SDK boundary oracle — ${keys.length} cases × 2 builds\n`)
  for (const k of keys) {
    const ok = a[k] === b[k]
    if (!ok) fails++
    const tag = ok ? '  ok ' : 'FAIL'
    const shown = a[k].length > 40 ? a[k].slice(0, 40) + '…' : a[k]
    console.log(`  [${tag}] ${k.padEnd(26)} ${shown}${ok ? '' : `  !=  ${b[k]}`}`)
  }

  // Independently confirm the ONLY source drift is the transport envelope field.
  const canonSrc = readFileSync(join(ROOT, 'runtime/boundary.js'), 'utf8')
  const ecomSrc = readFileSync(join(ROOT, 'oracle/boundary.ecommerce.js'), 'utf8')
  const canonField = canonSrc.includes('contract_id:Number(t)')
  const ecomField = ecomSrc.includes('canister_id:Number(t)')
  // Strip the field-name difference; the rest of the source must be identical.
  const norm = (s) => s.replace(/canister_id:Number\(t\)/g, 'contract_id:Number(t)')
  const restIdentical = norm(canonSrc).trim() === norm(ecomSrc).trim()

  console.log('\n  Transport-envelope drift check:')
  console.log(`  [${canonField ? '  ok ' : 'FAIL'}] canonical uses transport field  contract_id`)
  console.log(`  [${ecomField ? '  ok ' : 'FAIL'}] e-commerce uses transport field canister_id`)
  console.log(`  [${restIdentical ? '  ok ' : 'FAIL'}] sources identical apart from that field name`)

  const driftOk = canonField && ecomField && restIdentical
  if (!driftOk) fails++

  console.log('')
  if (fails === 0) {
    console.log('  ✓ PASS — Candid wire encoding/decoding is BYTE-IDENTICAL across both')
    console.log('    builds. The sole difference is the transport envelope field name,')
    console.log('    which is not part of the Candid payload. Adopting the SDK changes no')
    console.log('    wire bytes and normalizes e-commerce onto the canonical field.\n')
    process.exit(0)
  }
  console.log(`  ✗ FAIL — ${fails} divergence(s). This is a wire regression; do NOT ship.\n`)
  process.exit(1)
}

main()
