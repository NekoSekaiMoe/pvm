<template>
  <div>
    <h1>Approvals</h1>
    <p class="muted">Human-in-the-loop gate (plan.md §10). Side-effectful actions pause here until a bound ticket is decided.</p>

    <div v-if="error" class="callout err">{{ error }}</div>

    <div class="glass-card">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Ticket</th>
              <th>Task</th>
              <th>Tool</th>
              <th>Target</th>
              <th>Params</th>
              <th>Why</th>
              <th>Deadline</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tickets" :key="t.id">
              <td class="mono" :title="t.id">{{ t.id.slice(0, 16) }}…</td>
              <td class="mono">{{ t.task_id }}</td>
              <td><code>{{ t.tool }}</code></td>
              <td>{{ t.target || '—' }}</td>
              <td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;">
                {{ JSON.stringify(t.params) }}
              </td>
              <td>{{ t.why || '—' }}</td>
              <td class="timeline-meta">{{ fmt(t.deadline) }}</td>
              <td>
                <button class="btn btn-primary" @click="decide(t.id, true)" style="background:var(--success);">Approve</button>
                <button class="btn btn-danger" @click="decide(t.id, false)" style="margin-left:0.4rem;">Reject</button>
              </td>
            </tr>
            <tr v-if="!tickets || tickets.length === 0">
              <td colspan="8" class="muted" style="text-align:center;padding:2rem;">No pending tickets.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="glass-card">
      <h3>Create test ticket</h3>
      <p class="muted" style="font-size:0.8rem;margin-bottom:0.75rem;">For exercising the flow without a real agent attached.</p>
      <div class="form-row">
        <input v-model="form.task_id" placeholder="task id" />
        <input v-model="form.tool" placeholder="tool name" />
      </div>
      <div class="form-row">
        <input v-model="form.target" placeholder="target (e.g. prod-mailer)" />
        <input v-model="form.why" placeholder="why" />
      </div>
      <div class="form-row full">
        <input v-model="form.params" placeholder='params as JSON: {"to":"x@y.com"}' />
      </div>
      <button class="btn btn-primary" @click="create">Create Ticket</button>
      <div v-if="createMsg" class="callout ok" style="margin-top:0.75rem;">{{ createMsg }}</div>
      <div v-if="createErr" class="callout err" style="margin-top:0.75rem;">{{ createErr }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const tickets = ref([])
const error = ref(null)
const { refresh } = usePoll(async () => {
  tickets.value = await apiFetch('/api/approvals')
  return tickets.value
}, 2500)

const form = ref({ task_id: 'demo', tool: 'send_email', target: 'prod', why: '', params: '{}' })
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
    await apiFetch(`/api/approvals/${id}/decide`, { method: 'POST', body: { approved, by: 'ui-operator' } })
    refresh()
  } catch (e) { error.value = e.message }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleTimeString() : '—'
</script>
