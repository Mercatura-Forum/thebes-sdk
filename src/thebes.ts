/**
 * thebes.ts — a small TYPED wrapper over the proven `window.EgyptBoundary` SDK
 * (vendored as /boundary.js). It exposes exactly what an app needs:
 *   • query / update calls to a Motoko backend (Candid-encoded args)
 *   • raw-JSON calls to the Rust media contract (its methods take serde_json)
 *   • a chunked media upload that drives start → store_chunk → finish
 *   • the persisted browser identity (a stable per-browser sender principal)
 *
 * Why wrap rather than reimplement: boundary.js is the deployed, battle-tested
 * client (Candid LEB128 + receipt polling + identity). We add types + the media
 * flow on top, so examples stay correct and teachable.
 */

// ── The boundary global (shape of the bits we use) ──
type Boundary = {
  BOUNDARY: string
  identity: () => string
  encodeArg: (v: unknown) => Uint8Array
  encodeArgs: (vs: unknown[]) => Uint8Array
  bytesToHex: (b: Uint8Array) => string
  hexToBytes: (h: string) => Uint8Array
  EMPTY_ARGS_HEX: string
  decodeNatReply: (hexOrBytes: string | Uint8Array) => bigint
  decodeBoolReply: (hexOrBytes: string | Uint8Array) => boolean
  decodeVecRecord: (
    hexOrBytes: string | Uint8Array,
    fields: { name: string; type: 'nat' | 'int' | 'bool' | 'text' | 'principal' }[],
  ) => Record<string, unknown>[]
  callUpdate: (
    cid: number | string,
    method: string,
    argHex: string,
    opts?: { sender?: string; nonce?: number; timeoutMs?: number },
  ) => Promise<{ status: string; reply_hex?: string; reply?: string; error?: string }>
  callQuery: (
    cid: number | string,
    method: string,
    argHex: string,
    opts?: { sender?: string },
  ) => Promise<{ status?: string; reply_hex?: string; reply?: string; error?: string }>
}

function boundary(): Boundary {
  const b = (window as unknown as { EgyptBoundary?: Boundary }).EgyptBoundary
  if (!b) throw new Error('boundary.js not loaded (window.EgyptBoundary missing)')
  return b
}

// ── Failure-aware calls ──
//
// boundary.js reports exactly three failure shapes, and they differ in the one
// way that matters: whether the chain may have ACCEPTED the message.
//
//   • `call: no message_hash`   — the submit itself failed (the gateway refused
//     — e.g. an HTTP 503 while the cluster is degraded, a 429, or the network
//     dropped). No message hash was ever issued, so nothing was accepted and
//     resubmitting is safe.
//   • `call rejected: <detail>` — the boundary or the contract said no. The
//     answer is deterministic; retrying re-asks the same question.
//   • `receipt poll timed out`  — the message WAS accepted (a hash was issued)
//     and finalization simply outran the polling window. The update may still
//     land. Resubmitting here is how an app double-writes, so we never do it —
//     re-read state (or extend `timeoutMs`) instead.
//
// The rules below encode that split so every app gets it for free: refused
// submits retry with the SAME nonce and exponential backoff; rejections and
// receipt timeouts surface as typed errors an app can branch on.

export type CallFailureKind =
  | 'refused' // submit yielded no message hash — never accepted, safe to retry
  | 'rejected' // the boundary or contract said no — deterministic, do not retry
  | 'receipt-timeout' // accepted but not yet finalized — re-read state, never resubmit
  | 'network' // a query's transport failed — idempotent, safe to retry

export class ThebesCallError extends Error {
  readonly kind: CallFailureKind
  /** Whether an automatic retry of the SAME call is safe. */
  readonly retryable: boolean
  /** How many attempts were made before giving up. */
  readonly attempts: number
  /** The boundary's own detail string, when it gave one. */
  readonly detail?: string

  constructor(kind: CallFailureKind, message: string, attempts: number, detail?: string) {
    super(message)
    this.name = 'ThebesCallError'
    this.kind = kind
    this.retryable = kind === 'refused' || kind === 'network'
    this.attempts = attempts
    this.detail = detail
  }
}

/** Classify one boundary.js failure by the shape it actually throws. */
function classifyUpdateFailure(e: unknown): { kind: CallFailureKind; detail?: string } {
  const msg = e instanceof Error ? e.message : String(e)
  if (msg === 'call: no message_hash') return { kind: 'refused' }
  if (msg === 'receipt poll timed out') return { kind: 'receipt-timeout' }
  if (msg.startsWith('call rejected: ')) {
    return { kind: 'rejected', detail: msg.slice('call rejected: '.length) }
  }
  return { kind: 'rejected', detail: msg }
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms))
}

/** Exponential backoff with jitter, so retries under degradation spread out
 *  instead of arriving as a thundering herd the moment quorum returns. */
function backoffDelay(baseMs: number, attempt: number): number {
  return baseMs * 2 ** attempt + Math.random() * baseMs
}

export interface UpdateOpts {
  /** Override the persisted browser identity for this call. */
  sender?: string
  /** Fix the message nonce. Defaults once per LOGICAL call and is reused across
   *  submit retries, so the chain sees one message however many times the
   *  gateway refused the door. */
  nonce?: number
  /** Receipt-polling window, forwarded to boundary.js (its default is 10s).
   *  Size it to the work: a call that legitimately finalizes slowly deserves a
   *  longer window, not a resubmit. */
  timeoutMs?: number
  /** Extra attempts after a REFUSED submit (default 2). Refusals are the only
   *  update failure that retries — see the failure-shape notes above. */
  retries?: number
  /** Backoff base in ms (default 400). */
  backoffMs?: number
}

export interface QueryOpts {
  sender?: string
  /** Extra attempts after a transport failure (default 2). Queries are
   *  idempotent by construction, so this is unconditionally safe. */
  retries?: number
  /** Backoff base in ms (default 250). */
  backoffMs?: number
}

/** Stable per-browser identity (28-byte sender persisted in localStorage). */
export function identity(): string {
  return boundary().identity()
}

export const EMPTY_ARGS_HEX = (): string => boundary().EMPTY_ARGS_HEX

// ── Candid-encoded calls to a Motoko backend ──

/** Encode one Candid value to an arg hex string. */
export function encodeArg(value: unknown): string {
  const b = boundary()
  return b.bytesToHex(b.encodeArg(value))
}

/** Encode an ordered list of Candid values to an arg hex string. */
export function encodeArgs(values: unknown[]): string {
  const b = boundary()
  return b.bytesToHex(b.encodeArgs(values))
}

/**
 * Read a contract query. Idempotent, so transport failures retry with backoff.
 *
 * boundary.js swallows a failed fetch into an EMPTY reply object — without this
 * layer, a degraded cluster hands the app `{}`, the hook reads `reply_hex ?? ''`
 * and the decoder runs on an empty string. A read that failed must be an ERROR
 * the app can see, never garbage it can render.
 */
export async function query(cid: number, method: string, argHex?: string, opts?: QueryOpts) {
  const retries = opts?.retries ?? 2
  const backoffMs = opts?.backoffMs ?? 250
  let attempts = 0
  for (;;) {
    attempts++
    const r = await boundary().callQuery(cid, method, argHex ?? boundary().EMPTY_ARGS_HEX, {
      sender: opts?.sender,
    })
    if (r.error) throw new ThebesCallError('rejected', `query rejected: ${r.error}`, attempts, r.error)
    if (r.reply_hex !== undefined || r.reply !== undefined) return r
    // No reply and no error — boundary.js's shape for "the fetch itself failed".
    if (attempts > retries) {
      throw new ThebesCallError(
        'network',
        `query ${method} got no reply from the boundary after ${attempts} attempt(s)`,
        attempts,
      )
    }
    await sleep(backoffDelay(backoffMs, attempts - 1))
  }
}

/**
 * Run an update call. Retries ONLY the refused-submit case (no message hash was
 * issued, so nothing was accepted), reusing the same nonce across attempts; a
 * rejection is deterministic and a receipt timeout may already have landed, so
 * neither ever auto-retries. Both surface as `ThebesCallError` with a `kind`
 * the app can branch on.
 */
export async function update(cid: number, method: string, argHex?: string, opts?: UpdateOpts) {
  const retries = opts?.retries ?? 2
  const backoffMs = opts?.backoffMs ?? 400
  // One nonce per LOGICAL call, fixed before the first attempt: however many
  // times the gateway refuses the door, the chain sees a single message.
  const nonce = opts?.nonce ?? Date.now() * 1000 + Math.floor(Math.random() * 1024)
  let attempts = 0
  for (;;) {
    attempts++
    try {
      const r = await boundary().callUpdate(cid, method, argHex ?? boundary().EMPTY_ARGS_HEX, {
        sender: opts?.sender,
        nonce,
        timeoutMs: opts?.timeoutMs,
      })
      if (r.status === 'error') {
        throw new ThebesCallError(
          'rejected',
          `update ${method} rejected: ${r.error || 'call rejected'}`,
          attempts,
          r.error,
        )
      }
      return r
    } catch (e: unknown) {
      if (e instanceof ThebesCallError) throw e
      const { kind, detail } = classifyUpdateFailure(e)
      if (kind === 'refused' && attempts <= retries) {
        await sleep(backoffDelay(backoffMs, attempts - 1))
        continue
      }
      const why =
        kind === 'refused'
          ? `submit refused after ${attempts} attempt(s) — the gateway accepted nothing`
          : kind === 'receipt-timeout'
            ? 'accepted but not finalized within the polling window — re-read state before retrying, or pass a longer timeoutMs'
            : `rejected: ${detail}`
      throw new ThebesCallError(kind, `update ${method} ${why}`, attempts, detail)
    }
  }
}

// Re-export the decoders so app code can shape replies.
export const decodeNat = (r: string | Uint8Array) => boundary().decodeNatReply(r)
export const decodeBool = (r: string | Uint8Array) => boundary().decodeBoolReply(r)
export const decodeVecRecord = (
  r: string | Uint8Array,
  fields: { name: string; type: 'nat' | 'int' | 'bool' | 'text' | 'principal' }[],
) => boundary().decodeVecRecord(r, fields)

// ── Media contract (raw-JSON args) ──

const enc = new TextEncoder()

/** The media contract methods take raw JSON, NOT Candid — encode JSON → hex. */
function jsonArgHex(obj: unknown): string {
  return boundary().bytesToHex(enc.encode(JSON.stringify(obj)))
}

export type MediaClass = 'avatar' | 'photo' | 'document' | 'video'

export interface FinishReply {
  path: string
  sha256_hex: string
  size: number
  content_type: string
}

/** Public boundary URL to GET a stored media path from a contract. */
export function mediaUrl(mediaCid: number, path: string): string {
  const base = boundary().BOUNDARY || ''
  return `${base}/_/raw/${mediaCid}/${path.replace(/^\//, '')}`
}

const CHUNK_BYTES = 32 * 1024

function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

/**
 * Upload bytes to the media contract via the chunked flow, returning the stored
 * path + metadata. The server transcodes images (pass-3) so the client only
 * needs to keep the upload under the class input cap — the caller can downscale
 * first via `downscaleImage`. `onProgress` reports 0..1 across stored chunks.
 */
export async function uploadMedia(
  mediaCid: number,
  cls: MediaClass,
  contentType: string,
  bytes: Uint8Array,
  onProgress?: (fraction: number) => void,
): Promise<FinishReply> {
  const uploadId = `${identity()}-${cls}-${bytes.length}-${Math.floor(performance.now())}`
  const total = Math.max(1, Math.ceil(bytes.length / CHUNK_BYTES))

  await update(mediaCid, 'start_media_upload', jsonArgHex({
    upload_id: uploadId,
    media_class: cls,
    content_type: contentType,
    total_chunks: total,
  }))

  for (let i = 0; i < total; i++) {
    const slice = bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES)
    await update(mediaCid, 'store_chunk', jsonArgHex({
      upload_id: uploadId,
      chunk_index: i,
      body: toBase64(slice),
    }))
    onProgress?.((i + 1) / total)
  }

  const fin = await update(mediaCid, 'finish_media_upload', jsonArgHex({ upload_id: uploadId }))
  const hex = fin.reply_hex ?? fin.reply ?? ''
  const json = new TextDecoder().decode(boundary().hexToBytes(hex))
  return JSON.parse(json) as FinishReply
}

/**
 * Client-side downscale + JPEG encode via <canvas> so the upload stays under the
 * class input cap (the contract also transcodes server-side — this just bounds
 * the bytes we send). Returns JPEG bytes + content type.
 */
export async function downscaleImage(file: File, maxDim: number, quality = 0.85): Promise<{ bytes: Uint8Array; contentType: string }> {
  const bitmap = await createImageBitmap(file)
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height))
  const w = Math.max(1, Math.round(bitmap.width * scale))
  const h = Math.max(1, Math.round(bitmap.height * scale))
  const canvas = document.createElement('canvas')
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')!
  ctx.drawImage(bitmap, 0, 0, w, h)
  const blob: Blob = await new Promise((res, rej) =>
    canvas.toBlob((b) => (b ? res(b) : rej(new Error('toBlob failed'))), 'image/jpeg', quality),
  )
  return { bytes: new Uint8Array(await blob.arrayBuffer()), contentType: 'image/jpeg' }
}
