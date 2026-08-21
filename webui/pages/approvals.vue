<template>
  <div>
    <div class="toolbar">
      <div>
        <h1>Human Approvals Inbox</h1>
        <p class="muted">Human-in-the-loop governance (plan.md §10). Side-effectful actions (e.g. <code>pay</code>, <code>deploy</code>, <code>send</code>) pause until approved.</p>
      </div>
    </div>

    <div v-if="error" class="callout err">{{ error }}</div>

    <div class="glass-card">
      <div class="toolbar">
        <input v-model="filterTask" placeholder="Filter by Task ID..." class="search-input" />
        <span class="muted" style="font-size:0.875rem;">Pending Tickets: {{ filteredTickets.length }}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Ticket ID</th>
              <th>Task</th>
              <th>Tool</th>
              <th>Target</th>
              <th>Bound Parameters</th>
              <th>Why / Reason</th>
              <th>Deadline</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in filteredTickets" :key="t.id">
              <td class="mono" :title="t.id"><strong>{{ t.id.slice(0, 16) }}…</strong></td>
              <td class="mono">{{ t.task_id }}</td>
              <td><code>{{ t.tool }}</code></td>
              <td><span class="pill allow">{{ t.target || '—' }}</span></td>
              <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;" :title="JSON.stringify(t.params)">
                {{ JSON.stringify(t.params) }}
              </td>
              <td>{{ t.why || '—' }}</td>
              <td class="timeline-meta">{{ fmt(t.deadline) }}</td>
              <td>
                <button class="btn btn-primary" @click="decide(t.id, true)" style="background:var(--success);font-size:0.8rem;margin-right:0.3rem;">Approve</button>
                <button class="btn btn-danger" @click="decide(t.id, false)" style="font-size:0.8rem;">Reject</button>
              </td>
            </tr>
            <tr v-if="filteredTickets.length === 0">
              <td colspan="8" class="muted" style="text-align:center;padding:2rem;">No pending approval tickets.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Test Ticket Form -->
    <div class="glass-card">
      <h3>Create Test Ticket</h3>
      <p class="muted" style="font-size:0.8rem;margin-bottom:1rem;">Manually inject an approval ticket to test operator decision workflows.</p>
      <div class="form-row">
        <div>
          <label class="section-title" for="approval-task-id">Task ID</label>
          <input id="approval-task-id" v-model="form.task_id" placeholder="e.g. agent-task-01" />
        </div>
        <div>
          <label class="section-title" for="approval-tool">Tool Name</label>
          <input id="approval-tool" v-model="form.tool" placeholder="e.g. send_email, deploy_app" />
        </div>
      </div>
      <div class="form-row">
        <div>
          <label class="section-title" for="approval-target">Target</label>
          <input id="approval-target" v-model="form.target" placeholder="e.g. production-smtp" />
        </div>
        <div>
          <label class="section-title" for="approval-why">Justification (Why)</label>
          <input id="approval-why" v-model="form.why" placeholder="e.g. user requested quarterly report" />
        </div>
      </div>
      <div class="form-row full">
        <label class="section-title" for="approval-params">Parameters (JSON)</label>
        <input id="approval-params" v-model="form.params" placeholder='{"recipient": "alex@company.com", "subject": "Report"}' />
      </div>
      
      <div style="margin-top:1rem;">
        <button class="btn btn-primary" @click="create">Create Ticket</button>
      </div>

      <div v-if="createMsg" class="callout ok" style="margin-top:1rem;">{{ createMsg }}</div>
      <div v-if="createErr" class="callout err" style="margin-top:1rem;">{{ createErr }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const tickets = ref([])
const filterTask = ref('')
const error = ref(null)

const { refresh } = usePoll(async () => {
  tickets.value = await apiFetch('/api/approvals')
  return tickets.value
}, 2500)

const filteredTickets = computed(() => {
  if (!filterTask.value) return tickets.value || []
  const q = filterTask.value.toLowerCase()
  return (tickets.value || []).filter(t => t.task_id && t.task_id.toLowerCase().includes(q))
})

const form = ref({ task_id: 'demo-task', tool: 'send_email', target: 'prod-smtp', why: 'sending notification', params: '{"to":"admin@example.com"}' })
const createMsg = ref('')
const createErr = ref('')

const create = async () => {
  createMsg.value = ''; createErr.value = ''
  let params = {}
  try { params = JSON.parse(form.value.params || '{}') } catch (e) {
    createErr.value = 'params must be valid JSON'; return
  }
  try {
    const r = await apiFetch('/api/approvals', {
      method: 'POST',
      body: { ...form.value, params }
    })
    createMsg.value = `Created ticket ${r.id}`
    refresh()
  } catch (e) { createErr.value = e.message }
}

const decide = async (id, approved) => {
  if (!confirm(`${approved ? 'Approve' : 'Reject'} ticket ${id.slice(0,16)}…?`)) return
  try {
    await apiFetch(`/api/approvals/${id}/decide`, { method: 'POST', body: { approved } })
    refresh()
  } catch (e) { error.value = e.message }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleTimeString() : '—'
</script>
