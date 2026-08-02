// Shared client helpers for the PVM control-plane API.
// Every page calls useApi() to get typed wrappers with the bearer secret.
const API_SECRET = typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_SECRET

// The api secret is read at runtime from the page if served with a meta tag,
// otherwise defaults to 'secret' (matches the server default).
export function apiKey() {
  if (API_SECRET) return API_SECRET
  if (typeof document !== 'undefined') {
    const m = document.querySelector('meta[name="api-secret"]')
    if (m) return m.content
  }
  return 'secret'
}

// apiFetch normalizes the response. 202 (Accepted) is a business-level
// "request received" (e.g. /api/exec returning approval_required) and is
// returned as JSON. 409 (Conflict) is a hard failure (duplicate ticket,
// already-decided, invalid state) and is thrown with the server's reason so
// the caller can surface it instead of silently treating it as success.
export async function apiFetch(path, opts = {}) {
  const headers = { Authorization: `Bearer ${apiKey()}`, ...(opts.headers || {}) }
  if (opts.body && typeof opts.body === 'object') {
    headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(opts.body)
  }
  const res = await fetch(path, { ...opts, headers })
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
import { ref, onMounted, onUnmounted } from 'vue'
export function usePoll(fn, ms = 2000) {
  const data = ref(null)
  const error = ref(null)
  let timer
  const run = async () => {
    try { data.value = await fn(); error.value = null }
    catch (e) { error.value = e.message }
  }
  onMounted(() => { run(); timer = setInterval(run, ms) })
  onUnmounted(() => clearInterval(timer))
  return { data, error, refresh: run }
}
