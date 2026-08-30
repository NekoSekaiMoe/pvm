#!/usr/bin/env node
// Offline i18n parity check: locales/en.js and locales/zh.js must expose the
// exact same nested key tree (missing or extra keys on either side fail).
// No dependencies, no network — pure static parse + recursive compare.
//
//   node webui/test/i18n_parity.mjs   → exit 0 (green) or exit 1 with a diff
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const localesDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'locales')

// Statically parse `export default { ... }` into a live object. The
// dictionaries are plain object literals, so evaluating the literal body is
// safe and avoids any module-resolution/network dependency.
function loadDict(name) {
  const src = readFileSync(join(localesDir, `${name}.js`), 'utf8')
  const m = /export\s+default\s*/.exec(src)
  if (!m) {
    throw new Error(`${name}.js: expected exactly one "export default" object`)
  }
  const body = src.slice(m.index + m[0].length).replace(/;\s*$/, '')
  const obj = new Function(`"use strict"; return (${body});`)()
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(`${name}.js: export default must be a plain object`)
  }
  return obj
}

// Flatten the nested tree into a set of dotted leaf paths.
function flatten(obj, prefix = '', out = new Set()) {
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v, path, out)
    } else {
      out.add(path)
    }
  }
  return out
}

const en = flatten(loadDict('en'))
const zh = flatten(loadDict('zh'))

const missingInZh = [...en].filter(k => !zh.has(k)).sort()
const missingInEn = [...zh].filter(k => !en.has(k)).sort()

if (missingInZh.length || missingInEn.length) {
  if (missingInZh.length) {
    console.error(`missing in zh.js (${missingInZh.length}):`)
    for (const k of missingInZh) console.error(`  - ${k}`)
  }
  if (missingInEn.length) {
    console.error(`missing in en.js (${missingInEn.length}):`)
    for (const k of missingInEn) console.error(`  - ${k}`)
  }
  process.exit(1)
}

console.log(`i18n parity OK: ${en.size} keys present in both en.js and zh.js`)
