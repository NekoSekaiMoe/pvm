<template>
  <div>
    <h1>{{ t('pages.policy.title') }}</h1>
    <p class="muted">Tool/Policy Gateway rules (plan.md §6). First match wins; a default-deny catch-all is auto-appended.</p>

    <div class="glass-card">
      <div class="input-group">
        <input v-model="task" placeholder="Task ID" @keyup.enter="load" />
        <button class="btn btn-primary" @click="load">{{ t('pages.policy.btnView') }}</button>
      </div>
      <div v-if="error" class="callout err">{{ error }}</div>
    </div>

    <div v-if="rules && rules.length" class="glass-card">
      <h3>Tool Rules — <span class="mono">{{ task }}</span></h3>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>#</th><th>Tool</th><th>Action</th><th>Effect</th><th>Reason</th></tr>
          </thead>
          <tbody>
            <tr v-for="(r, i) in rules" :key="i">
              <td class="muted">{{ i + 1 }}</td>
              <td><code>{{ r.Name }}</code></td>
              <td><span class="pill" :class="r.Action">{{ r.Action }}</span></td>
              <td>{{ r.Effect || '—' }}</td>
              <td class="muted">{{ r.Reason || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="muted" style="font-size:0.8rem;margin-top:0.75rem;">
        Decision matrix (plan.md §6.2): <span class="pill allow">allow</span> read-only ·
        <span class="pill constrain">constrain</span> write (task branch) ·
        <span class="pill approve">approve</span> send/delete (human ticket) ·
        <span class="pill deny">deny</span> pay/prod.
      </p>
    </div>

    <div v-if="rules && rules.length" class="glass-card">
      <h3>Try a tool call (dry-run)</h3>
      <div class="form-row">
        <input v-model="probe.name" placeholder="tool name" />
        <input v-model="probe.args" placeholder='args JSON: {"path":"/etc/hosts"}' />
      </div>
      <button class="btn btn-primary" @click="probeCall">{{ t('pages.policy.btnRun') }}</button>
      <div v-if="probeResult !== null" class="callout" :class="probeOk ? 'ok' : 'err'" style="margin-top:0.75rem;">
        <pre class="mono" style="white-space:pre-wrap;margin:0;">{{ JSON.stringify(probeResult, null, 2) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

const task = ref('')
const rules = ref(null)
const error = ref('')

const load = async () => {
  error.value = ''; rules.value = null
  if (!task.value) { error.value = 'enter a task id'; return }
  try {
    rules.value = await apiFetch(`/api/policy/${encodeURIComponent(task.value)}`)
  } catch (e) { error.value = e.message }
}

const probe = ref({ name: 'read_file', args: '{}' })
const probeResult = ref(null)
const probeOk = ref(true)

const probeCall = async () => {
  probeResult.value = null
  let args = {}
  try { args = JSON.parse(probe.value.args || '{}') } catch (e) {
    probeOk.value = false; probeResult.value = { error: 'args must be JSON' }; return
  }
  // Convert to the flat "name k=v k2=v2" command form the /exec endpoint expects.
  const parts = [probe.value.name]
  for (const [k, v] of Object.entries(args)) parts.push(`${k}=${v}`)
  try {
    const r = await apiFetch(`/api/exec?task=${encodeURIComponent(task.value)}`, {
      method: 'POST', body: { cmd: parts.join(' ') }
    })
    probeOk.value = true; probeResult.value = r
  } catch (e) {
    probeOk.value = false; probeResult.value = { error: e.message }
  }
}
</script>
