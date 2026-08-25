<template>
  <div>
    <h1>Audit</h1>
    <p class="muted">Tamper-evident ledger (plan.md §14). Records live outside the sandbox; the agent cannot rewrite its own history.</p>
    <div class="glass-card">
      <h3>Redaction Policy</h3>
      <p class="muted" style="font-size:0.8rem;margin-bottom:1rem;">
        Secret material (tokens, API keys, bearer strings) is masked as <span class="redacted-val">[REDACTED]</span>
        at ledger write time, and again at read time for legacy rows.
      </p>
      <div v-if="policy" style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;">
        <label class="switch" title="Toggle write-time redaction (operator escape hatch). Existing rows are unchanged and are still redacted at read time once re-enabled.">
          <input type="checkbox" :checked="policy.enabled" :disabled="policyBusy" @change="togglePolicy" />
          <span class="slider"></span>
        </label>
        <span class="pill" :class="policy.enabled ? 'allow' : 'constrain'">{{ policy.enabled ? 'enabled' : 'disabled' }}</span>
        <span class="muted" style="font-size:0.85rem;">{{ policy.patterns_count }} secret pattern(s) active</span>
      </div>
      <div v-if="policy && policy.key_denylist && policy.key_denylist.length" style="margin-top:0.75rem;">
        <span class="muted" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;">Param key denylist</span>
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.4rem;">
          <span v-for="k in policy.key_denylist" :key="k" class="mono" style="background:rgba(0,0,0,0.3);border:1px solid var(--glass-border);border-radius:0.4rem;padding:0.15rem 0.5rem;font-size:0.75rem;">{{ k }}</span>
        </div>
      </div>
      <div v-if="policyError" class="callout err" style="margin-top:1rem;">{{ policyError }}</div>
    </div>

    <div class="glass-card">
      <div class="input-group">
        <input v-model="taskId" placeholder="Task ID (e.g. agent-task)" @keyup.enter="go" />
        <button class="btn btn-primary" @click="go">Open Ledger</button>
      </div>
      <p class="muted" style="font-size:0.8rem;">Tip: from a task row, click the <em>Audit</em> button to jump straight in.</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { apiFetch } from '~/composables/useApi'
const router = useRouter()
const taskId = ref('')
const go = () => {
  const id = taskId.value.trim()
  if (!id) return
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) { alert('Invalid task id'); return }
  router.push(`/audit/${id}`)
}

// Redaction policy card (GET/PUT /api/audit/redaction-policy)
const policy = ref(null)
const policyBusy = ref(false)
const policyError = ref('')
const loadPolicy = async () => {
  try { policy.value = await apiFetch('/api/audit/redaction-policy') }
  catch (e) { policyError.value = e.message }
}
const togglePolicy = async (ev) => {
  const next = ev.target.checked
  policyBusy.value = true; policyError.value = ''
  try {
    policy.value = await apiFetch('/api/audit/redaction-policy', { method: 'PUT', body: { enabled: next } })
  } catch (e) {
    policyError.value = e.message
    // Roll back from the server-known state (policy is a ref — read
    // .value), not from the uncommitted checkbox: showing "redaction
    // off" while the server still scrubs would misrepresent the
    // security posture.
    ev.target.checked = policy.value ? policy.value.enabled : !next
  } finally { policyBusy.value = false }
}
onMounted(loadPolicy)
</script>
