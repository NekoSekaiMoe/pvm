<template>
  <div>
    <h1>{{ t('pages.audit.title') }}</h1>
    <p class="muted">Tamper-evident ledger (plan.md §14). Records live outside the sandbox; the agent cannot rewrite its own history.</p>

    <div class="glass-card">
      <div class="input-group">
        <input v-model="taskId" :placeholder="t('pages.audit.taskIdPh')" @keyup.enter="load" />
        <button class="btn btn-primary" @click="load">{{ t('pages.audit.btnLoadLedger') }}</button>
        <button class="btn btn-primary" @click="verify" :disabled="!records">{{ t('pages.audit.btnVerify') }}</button>
      </div>
      <div v-if="verifyResult" class="callout" :class="verifyResult.valid ? 'ok' : 'err'">
        <strong>{{ verifyResult.valid ? 'Chain intact.' : 'TAMPER DETECTED.' }}</strong>
        {{ verifyResult.records }} record(s) verified.
        <span v-if="verifyResult.error">First broken link: {{ verifyResult.error }}</span>
      </div>
    </div>

    <div v-if="records && records.length > 0" class="glass-card">
      <h3>Evidence Timeline — <span class="mono">{{ taskId }}</span></h3>
      <div class="timeline">
        <div v-for="(r, i) in records" :key="i" class="timeline-item">
          <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
            <span class="pill" :class="r.decision">{{ r.decision }}</span>
            <strong>{{ r.action }}</strong>
            <span class="muted">·</span>
            <span class="mono">{{ r.subject }}</span>
            <span class="pill allow" style="background:rgba(148,163,184,0.2);color:#94a3b8;">{{ r.phase }}</span>
            <span v-if="r.redacted" class="pill redacted" title="Secret material in this record was masked by the audit redactor">🔒 redacted</span>
          </div>
          <div class="timeline-meta">{{ fmt(r.at) }} · seq {{ r.seq }}<span v-if="r.reason"> — {{ r.reason }}</span></div>
          <div v-if="r.params" class="timeline-meta mono" style="opacity:0.85;"><span v-for="(p, j) in splitMasked(r.params)" :key="j" :class="{ 'redacted-val': p.masked }">{{ p.text }}</span></div>
          <div class="timeline-hash">prev: {{ r.prev_hash?.slice(0,16) || '∅' }} → this: {{ r.this_hash?.slice(0,16) }}</div>
        </div>
      </div>
    </div>
    <div v-else-if="loaded && records && records.length === 0" class="callout warn">
      {{ t('pages.audit.emptyLedger', { id: taskId }) }}
    </div>
    <div v-if="error" class="callout err">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { apiFetch } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()
const route = useRoute()
const taskId = ref(route.params.id || '')
const records = ref(null)
const verifyResult = ref(null)
const loaded = ref(false)
const error = ref('')

const load = async () => {
  error.value = ''; verifyResult.value = null; loaded.value = true
  if (!taskId.value) { error.value = t('pages.audit.errTaskId'); return }
  try { records.value = await apiFetch(`/api/audit/${encodeURIComponent(taskId.value)}`) }
  catch (e) { error.value = e.message; records.value = null }
}
const verify = async () => {
  error.value = ''
  try { verifyResult.value = await apiFetch(`/api/audit/${encodeURIComponent(taskId.value)}/verify`) }
  catch (e) { error.value = e.message }
}
const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '—'

// Render params with masked secret material ([REDACTED]) visually distinct.
const MASK = '[REDACTED]'
const splitMasked = (val) => {
  const s = typeof val === 'string' ? val : JSON.stringify(val)
  if (!s || !s.includes(MASK)) return [{ text: s, masked: false }]
  return s.split(MASK).flatMap((part, i, arr) => {
    const out = []
    if (part) out.push({ text: part, masked: false })
    if (i < arr.length - 1) out.push({ text: MASK, masked: true })
    return out
  })
}
onMounted(() => { if (taskId.value) load() })
</script>
