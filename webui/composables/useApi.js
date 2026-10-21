// Shared client helpers for the PVM control-plane API.
// Every page calls useApi() to get typed wrappers with the bearer secret.
const API_SECRET = typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_SECRET

// The api secret is read at runtime from the page if served with a meta
// tag, or from sessionStorage after the operator entered it once (the
// 401 prompt). There is NO fallback default: the server refuses weak
// default secrets, and a hardcoded one here would silently authenticate
// as master against any deployment that regressed to it.
const SESSION_KEY = 'pvm.api-key'
let prompted = false

/**
 * Return a configured build-time key; otherwise use the page's api-secret
 * meta value if the tag exists, or the session key. Return '' if none is
 * available.
 * Browser storage access errors propagate to the caller.
 */
export function apiKey() {
  if (API_SECRET) return API_SECRET
  if (typeof document !== 'undefined') {
    const m = document.querySelector('meta[name="api-secret"]')
    if (m) return m.content
  }
  if (typeof sessionStorage !== 'undefined') {
    return sessionStorage.getItem(SESSION_KEY) || ''
  }
  return ''
}

// setApiKey stores the operator-entered key for this browser session only
// (sessionStorage: cleared when the tab closes — a deliberate choice over
// localStorage so a forgotten console does not keep master credentials).
export function setApiKey(k) {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem(SESSION_KEY, k)
  }
}

/**
 * Return a configured key or prompt at most once per module instance for one.
 * A nonblank entry is trimmed and saved to sessionStorage. Return '' if the
 * prompt is unavailable, already used, dismissed, or blank. Storage errors
 * reject the promise. apiFetch calls this after a 401 response.
 */
export async function ensureApiKey() {
  const k = apiKey()
  if (k) return k
  if (prompted || typeof window === 'undefined') return ''
  prompted = true
  const entered = window.prompt('PVM API key required (this server has no embedded secret)')
  if (entered && entered.trim()) {
    setApiKey(entered.trim())
    return entered.trim()
  }
  return ''
}

/**
 * Fetch an API response with a bearer key and return its JSON or text body.
 * Object bodies are JSON-encoded, replacing opts.body. Without a build-time
 * key, a 401 can retry once with the key returned by ensureApiKey.
 * A 202 response (such as approval_required) is returned normally. Other
 * non-OK responses, including 409 conflicts (duplicate or already-decided
 * tickets, or invalid state), reject with the server's error message and a
 * status property. Network, storage, serialization, and
 * successful-response decoding errors also propagate.
 */
export async function apiFetch(path, opts = {}) {
  let headers = { Authorization: `Bearer ${apiKey()}`, ...(opts.headers || {}) }
  if (opts.body && typeof opts.body === 'object') {
    headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(opts.body)
  }
  let res = await fetch(path, { ...opts, headers })
  if (res.status === 401 && !API_SECRET) {
    // No usable key: offer the operator a one-time prompt and retry once
    // with what they entered (or the meta tag value if the server set one
    // but the operator's session lacked it).
    const k = await ensureApiKey()
    if (k) {
      headers = { ...headers, Authorization: `Bearer ${k}` }
      res = await fetch(path, { ...opts, headers })
    }
  }
  if (!res.ok && res.status !== 202) {
    let msg = res.statusText
    try { const j = await res.json(); msg = j.error || msg } catch (e) {}
    const err = new Error(msg)
    err.status = res.status
    throw err
  }
  const ct = res.headers.get('content-type') || ''
  if (ct.includes('application/json')) return res.json()
  return res.text()
}

// Polling helper: returns a reactive ref + starts/stops a timer.
// Three guards keep a slow or unreachable API from wasting requests:
//   - in-flight dedup: ticks are skipped while a fetch is pending, so an
//     endpoint slower than the interval never piles up concurrent requests.
//   - hidden-tab pause: ticks are skipped while the tab is backgrounded.
//   - error backoff: each consecutive failure doubles the effective interval
//     (capped at 8x) until a fetch succeeds again.
// refresh() shares the in-flight guard: a refresh issued while a poll fetch
// is still pending is dropped and the data converges on the next tick.
import { ref, onMounted, onUnmounted } from 'vue'
export function usePoll(fn, ms = 2000) {
  const data = ref(null)
  const error = ref(null)
  let timer
  let inflight = false
  let fails = 0
  let retryAt = 0
  const run = async () => {
    if (inflight) return
    inflight = true
    try {
      data.value = await fn()
      error.value = null
      fails = 0
      retryAt = 0
    } catch (e) {
      error.value = e.message
      fails = Math.min(fails + 1, 3)
      retryAt = Date.now() + ms * Math.min(2 ** fails, 8)
    } finally {
      inflight = false
    }
  }
  onMounted(() => {
    run()
    timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return
      if (Date.now() < retryAt) return
      run()
    }, ms)
  })
  onUnmounted(() => clearInterval(timer))
  return { data, error, refresh: run }
}
