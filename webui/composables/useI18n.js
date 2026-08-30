// Zero-dependency i18n composable. A single module-level reactive locale is
// shared by every caller (app.vue toggle + all pages); the choice persists
// in localStorage and falls back to English for any missing key.
//
// Dictionaries live in ~/locales/{en,zh}.js as nested objects addressed by
// dotted paths ("pages.index.title"). webui/test/i18n_parity.mjs enforces
// that both dictionaries expose the exact same key tree.
import { ref } from 'vue'
import en from '~/locales/en'
import zh from '~/locales/zh'

const dicts = { en, zh }
const STORAGE_KEY = 'pvm.locale'

const locale = ref('en')
try {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved && dicts[saved]) locale.value = saved
} catch {
  // Restricted storage policy or opaque origin (SecurityError): keep the
  // in-memory default instead of breaking module init.
}

// Dot-path lookup; returns undefined unless the leaf is a string.
const lookup = (dict, path) => {
  let node = dict
  for (const part of path.split('.')) {
    if (node === null || typeof node !== 'object') return undefined
    node = node[part]
  }
  return typeof node === 'string' ? node : undefined
}

// "{name}" placeholder interpolation; unknown placeholders stay verbatim.
const interpolate = (str, params) => {
  if (!params) return str
  return str.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined ? String(params[k]) : m))
}

export function useI18n() {
  const t = (key, params) => {
    const raw = lookup(dicts[locale.value], key)
    if (raw !== undefined) return interpolate(raw, params)
    // Fallback: English, then the key itself so a missing entry is visible
    // (and greppable) instead of rendering as blank.
    const fb = lookup(dicts.en, key)
    if (fb !== undefined) return interpolate(fb, params)
    return key
  }

  const setLocale = (l) => {
    if (!dicts[l]) return
    locale.value = l
    try { localStorage.setItem(STORAGE_KEY, l) } catch { /* storage unavailable */ }
  }

  const toggleLocale = () => setLocale(locale.value === 'en' ? 'zh' : 'en')

  return { locale, t, setLocale, toggleLocale }
}
