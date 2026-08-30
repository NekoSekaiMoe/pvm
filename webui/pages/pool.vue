<template>
  <div>
    <h1>{{ t('pages.pool.title') }}</h1>
    <p class="muted">Warm pool + per-tenant quota (plan.md §12). Shared read-only images, never shared task identity or writable state.</p>

    <div class="stat-grid">
      <div class="stat-tile"><div class="stat-value">{{ stats.ready ?? '—' }}</div><div class="stat-label">Ready</div></div>
      <div class="stat-tile"><div class="stat-value">{{ stats.claimed ?? '—' }}</div><div class="stat-label">Claimed</div></div>
      <div class="stat-tile"><div class="stat-value">{{ stats.total ?? '—' }}</div><div class="stat-label">Total</div></div>
    </div>

    <div class="glass-card">
      <h3>Warm Pool</h3>
      <p class="muted" style="font-size:0.8rem;margin-bottom:0.75rem;">Pre-create sandboxes so task claims don't pay cold-start.</p>
      <div class="form-row">
        <input v-model="tmpl.name" placeholder="template name" />
        <input v-model="tmpl.base_image" placeholder="base image path" />
      </div>
      <div class="form-row">
        <input v-model="tmpl.memory" placeholder="memory e.g. 512M" />
        <input v-model="tmpl.cpu" type="number" placeholder="cpu (millicpu)" />
      </div>
      <div class="input-group">
        <input v-model.number="warmN" type="number" min="1" max="100" placeholder="count" style="flex:0.3" />
        <button class="btn btn-primary" @click="doWarm">{{ t('pages.pool.btnWarm', { n: warmN }) }}</button>
      </div>
      <div v-if="warmMsg" class="callout ok">{{ warmMsg }}</div>
      <div v-if="warmErr" class="callout err">{{ warmErr }}</div>
    </div>

    <div class="glass-card">
      <h3>Set Tenant Quota</h3>
      <div class="form-row">
        <input v-model="quota.tenant" placeholder="tenant id" />
        <input v-model.number="quota.MaxConcurrent" type="number" placeholder="max concurrent" />
      </div>
      <div class="form-row">
        <input v-model.number="quota.MaxCPU" type="number" placeholder="max cpu sum" />
        <input v-model.number="quota.MaxMemoryMB" type="number" placeholder="max memory MB" />
      </div>
      <div class="input-group">
        <input v-model.number="quota.MaxTasksPerHour" type="number" placeholder="max tasks / hour" />
        <button class="btn btn-primary" @click="setQuota">{{ t('pages.pool.btnApplyQuota') }}</button>
      </div>
      <div v-if="quotaMsg" class="callout ok">{{ quotaMsg }}</div>
      <div v-if="quotaErr" class="callout err">{{ quotaErr }}</div>
    </div>

    <div v-if="error" class="callout err">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

const stats = ref({})
const error = ref(null)
usePoll(async () => {
  stats.value = await apiFetch('/api/pool/stats')
  return stats.value
}, 2500)

const tmpl = ref({ name: 'alpine', base_image: 'rootfs.img', memory: '512M', cpu: 1 })
const warmN = ref(2)
const warmMsg = ref(''); const warmErr = ref('')
const doWarm = async () => {
  warmMsg.value = ''; warmErr.value = ''
  try {
    const r = await apiFetch('/api/pool/warm', { method: 'POST', body: { template: { ...tmpl.value, cpu: Number(tmpl.value.cpu) }, n: Number(warmN.value) } })
    warmMsg.value = `Created ${r.created} sandbox(es).`
  } catch (e) { warmErr.value = e.message }
}

const quota = ref({ tenant: 'eng', MaxConcurrent: 4, MaxCPU: 4, MaxMemoryMB: 4096, MaxTasksPerHour: 20 })
const quotaMsg = ref(''); const quotaErr = ref('')
const setQuota = async () => {
  quotaMsg.value = ''; quotaErr.value = ''
  try {
    await apiFetch('/api/pool/quota', { method: 'POST', body: { tenant: quota.value.tenant, quota: {
      MaxConcurrent: Number(quota.value.MaxConcurrent),
      MaxCPU: Number(quota.value.MaxCPU),
      MaxMemoryMB: Number(quota.value.MaxMemoryMB),
      MaxTasksPerHour: Number(quota.value.MaxTasksPerHour),
    } } })
    quotaMsg.value = `Quota set for tenant "${quota.value.tenant}".`
  } catch (e) { quotaErr.value = e.message }
}
</script>
