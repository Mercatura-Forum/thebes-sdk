/**
 * useThebes — React hooks over the typed `thebes` SDK. These are the idiomatic
 * data-access primitives every Thebes example reuses:
 *   • useQuery  — read a contract query, with loading/error/refetch
 *   • useUpdate — run an update call, tracking pending/error
 *   • useMediaUpload — downscale + chunked-upload an image, with progress
 *
 * They follow React best practices: stable callbacks (useCallback), abortable
 * effects, no state updates after unmount, and explicit dependency arrays.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  query,
  update,
  uploadMedia,
  downscaleImage,
  type MediaClass,
  type FinishReply,
} from './thebes.js'

export interface QueryState<T> {
  data: T | undefined
  loading: boolean
  error: string | undefined
  refetch: () => void
}

/**
 * Read a contract query and map its raw reply with `decode`. Re-runs when any
 * value in `deps` changes; `decode` should be stable (define outside render or
 * memoize). Stale replies from a superseded run are ignored.
 */
export function useQuery<T>(
  cid: number,
  method: string,
  argHex: string | undefined,
  decode: (replyHex: string) => T,
  deps: readonly unknown[] = [],
): QueryState<T> {
  const [data, setData] = useState<T>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const runId = useRef(0)

  const run = useCallback(() => {
    const id = ++runId.current
    setLoading(true)
    setError(undefined)
    query(cid, method, argHex)
      .then((r) => {
        if (id !== runId.current) return // superseded
        const hex = r.reply_hex ?? r.reply ?? ''
        setData(decode(hex))
      })
      .catch((e: unknown) => {
        if (id !== runId.current) return
        setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (id === runId.current) setLoading(false)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cid, method, argHex, ...deps])

  useEffect(() => {
    run()
    return () => {
      runId.current++ // invalidate in-flight on unmount/dep-change
    }
  }, [run])

  return { data, loading, error, refetch: run }
}

export interface UpdateState {
  call: (cid: number, method: string, argHex?: string) => Promise<{ reply_hex?: string; reply?: string }>
  pending: boolean
  error: string | undefined
}

/** Run update calls, tracking a single in-flight pending flag + last error. */
export function useUpdate(): UpdateState {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string>()
  const call = useCallback(async (cid: number, method: string, argHex?: string) => {
    setPending(true)
    setError(undefined)
    try {
      return await update(cid, method, argHex)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
      throw e
    } finally {
      setPending(false)
    }
  }, [])
  return { call, pending, error }
}

export interface MediaUploadState {
  upload: (file: File, cls: MediaClass) => Promise<FinishReply>
  progress: number // 0..1
  busy: boolean
  error: string | undefined
}

/**
 * Downscale (client-side, to stay under the class input cap) then chunked-upload
 * an image to the media contract. The contract re-encodes server-side (pass-3),
 * so this is just a courtesy bound on upload size. Returns the stored path.
 */
export function useMediaUpload(mediaCid: number): MediaUploadState {
  const [progress, setProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  const upload = useCallback(
    async (file: File, cls: MediaClass): Promise<FinishReply> => {
      setBusy(true)
      setError(undefined)
      setProgress(0)
      try {
        // Avatars downscale to 256, photos to 1600 (server then bounds to 1280).
        const maxDim = cls === 'avatar' ? 256 : 1600
        const { bytes, contentType } = await downscaleImage(file, maxDim)
        return await uploadMedia(mediaCid, cls, contentType, bytes, setProgress)
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        setError(msg)
        throw e
      } finally {
        setBusy(false)
      }
    },
    [mediaCid],
  )

  return { upload, progress, busy, error }
}
