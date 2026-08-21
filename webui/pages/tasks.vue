<template>
  <div>
    <h1>Task Sandboxes</h1>
    <p class="muted">Lifecycle FSM (plan.md §8). Tasks move through Pending → Provisioning → Ready → Running ↔ Suspended → Review → Completed.</p>

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
      <!-- Status Tabs -->
      <div class="tabs">
        <button 
          v-for="s in ['all', 'running', 'suspended', 'provisioning', 'ready', 'review', 'completed', 'failed', 'quarantined']" 
          :key="s" 
          class="tab" 
          :class="{ active: currentFilter === s }"
          @click="currentFilter = s"
        >
          {{ s.toUpperCase() }}
        </button>
      </div>

      <div class="toolbar">
        <input v-model="searchQuery" placeholder="Search tasks by ID, tenant, or fingerprint..." class="search-input" />
        <span class="muted" style="font-size:0.875rem;">Total: {{ filteredTasks.length }} task(s)</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Task ID</th>
              <th>Tenant</th>
              <th>Status</th>
              <th>PID</th>
              <th>Started</th>
              <th>Spec FP</th>
              <th>Lifecycle Controls</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in filteredTasks" :key="t.id">
              <td class="mono"><strong>{{ t.id }}</strong></td>
              <td>{{ t.tenant || '—' }}</td>
              <td><span class="badge" :class="t.status">{{ t.status }}</span></td>
              <td>{{ t.pid || '—' }}</td>
              <td class="timeline-meta">{{ fmt(t.started_at) }}</td>
              <td class="mono" :title="t.spec_fingerprint">{{ short(t.spec_fingerprint) }}</td>
              <td>
                <!-- Pause Button for Running -->
                <button 
                  v-if="t.status === 'running'" 
                  class="btn btn-danger" 
                  style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;"
                  @click="pauseTask(t.id)"
                >
                  ⏸ Pause
                </button>
                <!-- Resume Button for Suspended -->
                <button 
                  v-if="t.status === 'suspended'" 
                  class="btn btn-primary" 
                  style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;background:var(--success);"
                  @click="resumeTask(t.id)"
                >
                  ▶ Resume
                </button>
                <button class="btn btn-primary" @click="showTransitions(t)" style="font-size:0.75rem;padding:0.3rem 0.6rem;">
                  FSM
                </button>
              </td>
              <td>
                <NuxtLink :to="`/audit/${t.id}`" class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;text-decoration:none;margin-right:0.3rem;">Audit</NuxtLink>
                <NuxtLink :to="`/logs/${t.id}`" class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;text-decoration:none;">Logs</NuxtLink>
              </td>
            </tr>
            <tr v-if="filteredTasks.length === 0">
              <td colspan="8" class="muted" style="text-align:center;padding:2rem;">No tasks match filter.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Transition modal -->
    <div v-if="selected" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="fsm-modal-title" @keydown.esc="selected = null">
      <div class="modal-box">
        <h3 id="fsm-modal-title">FSM Transitions — {{ selected.id }}</h3>
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
        <div class="input-group" style="margin-top:1.5rem;">
          <select v-model="newTo" aria-label="Target State" style="background:rgba(0,0,0,0.3);color:white;border:1px solid var(--glass-border);padding:0.75rem;border-radius:0.5rem;flex:0.6;">
            <option v-for="s in states" :key="s" :value="s">{{ s }}</option>
          </select>
          <input v-model="newReason" placeholder="transition reason" aria-label="Transition Reason" />
          <button class="btn btn-primary" @click="transition(selected.id)">Apply</button>
          <button class="btn btn-danger" @click="selected = null">Close</button>
        </div>
        <div v-if="transError" class="callout err" style="margin-top:1rem;">{{ transError }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const tasks = ref([])
const currentFilter = ref('all')
const searchQuery = ref('')

const { refresh } = usePoll(async () => {
  const list = await apiFetch('/api/tasks')
  tasks.value = list || []
  return list
}, 2500)

const filteredTasks = computed(() => {
  let list = tasks.value
  if (currentFilter.value !== 'all') {
    list = list.filter(t => t.status === currentFilter.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter(t => 
      (t.id && t.id.toLowerCase().includes(q)) ||
      (t.tenant && t.tenant.toLowerCase().includes(q)) ||
      (t.spec_fingerprint && t.spec_fingerprint.toLowerCase().includes(q))
    )
  }
  return list
})

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
  alert(`TaskSpec validated (fp ${fingerprint.value.slice(0,12)}).\n\nTo launch, run:\n  agentpvm run -config <(echo "$TOML")\n\n(or save to uml/agentpvm.toml and run agentpvm run)`)
}

const pauseTask = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/pause`, { method: 'POST' })
    refresh()
  } catch (e) {
    alert(`Pause error: ${e.message}`)
  }
}

const resumeTask = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/resume`, { method: 'POST' })
    refresh()
  } catch (e) {
    alert(`Resume error: ${e.message}`)
  }
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
