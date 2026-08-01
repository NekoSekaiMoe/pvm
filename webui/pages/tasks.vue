<template>
  <div>
    <h1>Tasks</h1>
    <p class="muted">Lifecycle FSM (plan.md §8). Each task moves through Pending → Provisioning → Ready → Running → Review → Completed.</p>

    <!-- Launch from TaskSpec -->
    <div class="glass-card">
      <h3>Launch from TaskSpec (TOML)</h3>
      <div class="form-row full">
        <textarea v-model="toml" placeholder="version = 1&#10;caller = 'alice'&#10;[runtime]&#10;name = 't1'&#10;memory = '512M'&#10;..."></textarea>
      </div>
      <div class="input-group">
        <input v-model="specPath" placeholder="Optional: path to ./uml/agentpvm.toml on server" />
        <button class="btn btn-primary" @click="validateSpec">Validate / Fingerprint</button>
        <button class="btn btn-primary" @click="launchSpec" :disabled="!fingerprint">Launch</button>
      </div>
      <div v-if="fingerprint" class="callout ok">
        <strong>Valid.</strong> Fingerprint: <span class="mono">{{ fingerprint }}</span>
      </div>
      <div v-if="specError" class="callout err"><strong>Invalid:</strong> {{ specError }}</div>
    </div>

    <!-- Task table -->
    <div class="glass-card">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Task</th>
              <th>Tenant</th>
              <th>Status</th>
              <th>PID</th>
              <th>Started</th>
              <th>Spec FP</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tasks" :key="t.id">
              <td class="mono">{{ t.id }}</td>
              <td>{{ t.tenant || '—' }}</td>
              <td><span class="badge" :class="t.status">{{ t.status }}</span></td>
              <td>{{ t.pid || '—' }}</td>
              <td class="timeline-meta">{{ fmt(t.started_at) }}</td>
              <td class="mono" :title="t.spec_fingerprint">{{ short(t.spec_fingerprint) }}</td>
              <td>
                <NuxtLink :to="`/audit/${t.id}`" class="btn btn-primary" style="font-size:0.8rem;text-decoration:none;margin-right:0.4rem;">Audit</NuxtLink>
                <button class="btn btn-primary" @click="showTransitions(t)" style="font-size:0.8rem;">FSM</button>
              </td>
            </tr>
            <tr v-if="!tasks || tasks.length === 0">
              <td colspan="7" class="muted" style="text-align:center;padding:2rem;">No tasks yet.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Transition modal -->
    <div v-if="selected" class="glass-card">
      <h3>FSM Transitions — {{ selected.id }}</h3>
      <div class="timeline">
        <div v-for="(tr, i) in selected.transitions || []" :key="i" class="timeline-item">
          <span class="badge" :class="tr.to">{{ tr.to }}</span>
          <span class="muted"> from </span>
          <span class="badge" :class="tr.from">{{ tr.from }}</span>
          <span class="pill allow"> {{ tr.actor }}</span>
          <div class="timeline-meta">{{ fmt(tr.at) }} — {{ tr.reason }}</div>
        </div>
        <div v-if="!selected.transitions || selected.transitions.length === 0" class="muted">No transitions recorded.</div>
      </div>
      <div class="input-group" style="margin-top:1rem;">
        <select v-model="newTo" style="flex:0.5">
          <option v-for="s in states" :key="s" :value="s">{{ s }}</option>
        </select>
        <input v-model="newReason" placeholder="reason" />
        <button class="btn btn-primary" @click="transition(selected.id)">Transition</button>
        <button class="btn btn-danger" @click="selected = null">Close</button>
      </div>
      <div v-if="transError" class="callout err">{{ transError }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const tasks = ref([])
const { refresh } = usePoll(async () => {
  const list = await apiFetch('/api/tasks')
  tasks.value = list || []
  return list
}, 2500)

const toml = ref(`version = 1
caller = "alice"
tenant = "eng"

[runtime]
name = "agent-task"
cpu = 1000
memory = "512M"

[workspace]
base_image = "rootfs.img"
init = "/sbin/init"

[kernel]
path = "./bin/linux"

[network]
enabled = false

[lifecycle]
on_anomaly = "pause"
ttl = "1h"
`)
const specPath = ref('')
const fingerprint = ref('')
const specError = ref('')

const validateSpec = async () => {
  fingerprint.value = ''; specError.value = ''
  try {
    const body = specPath.value ? { path: specPath.value } : { content: toml.value }
    const r = await apiFetch('/api/tasks/load-spec', { method: 'POST', body })
    fingerprint.value = r.fingerprint
  } catch (e) { specError.value = e.message }
}

const launchSpec = () => {
  // Launch is done by the controller (agentpvm run); from the UI we surface a
  // hint: copy the validated toml into a local file and run agentpvm. A future
  // /api/tasks/start endpoint would do this in-process.
  alert(`TaskSpec validated (fp ${fingerprint.value.slice(0,12)}).\n\nTo launch, run:\n  agentpvm run -config <(echo "$TOML")\n\n(or save to uml/agentpvm.toml and run agentpvm run)`)
}

// FSM inspection
const selected = ref(null)
const states = ['pending','provisioning','ready','running','suspended','resuming','review','completed','failed','quarantined','destroy']
const newTo = ref('provisioning')
const newReason = ref('')
const transError = ref('')

const showTransitions = async (t) => {
  selected.value = await apiFetch(`/api/tasks/${t.id}`)
  transError.value = ''
}
const transition = async (id) => {
  transError.value = ''
  try {
    await apiFetch(`/api/tasks/${id}/transition`, {
      method: 'POST',
      body: { to: newTo.value, actor: 'human', reason: newReason.value || 'manual ui transition' }
    })
    selected.value = await apiFetch(`/api/tasks/${id}`)
    refresh()
  } catch (e) { transError.value = e.message }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '—'
const short = (h) => h ? h.slice(0, 12) : '—'
</script>
