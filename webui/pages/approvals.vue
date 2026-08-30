<template>
  <div>
    <div class="toolbar">
      <div>
        <h1>{{ t('pages.approvals.title') }}</h1>
        <p class="muted">{{ t('pages.approvals.subtitle') }}</p>
      </div>
    </div>

    <div v-if="error" class="callout err">{{ error }}</div>

    <div class="glass-card">
      <div class="toolbar">
        <input v-model="filterTask" :placeholder="t('pages.approvals.searchPh')" class="search-input" />
        <span class="muted" style="font-size:0.875rem;">{{ t('pages.approvals.pending', { n: filteredTickets.length }) }}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>{{ t('pages.approvals.colTicket') }}</th>
              <th>{{ t('pages.approvals.colTask') }}</th>
              <th>{{ t('pages.approvals.colTool') }}</th>
              <th>{{ t('pages.approvals.colTarget') }}</th>
              <th>{{ t('pages.approvals.colParams') }}</th>
              <th>{{ t('pages.approvals.colWhy') }}</th>
              <th>{{ t('pages.approvals.colDeadline') }}</th>
              <th>{{ t('pages.approvals.colActions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tk in filteredTickets" :key="tk.id">
              <td class="mono" :title="tk.id"><strong>{{ tk.id.slice(0, 16) }}…</strong></td>
              <td class="mono">{{ tk.task_id }}</td>
              <td><code>{{ tk.tool }}</code></td>
              <td><span class="pill allow">{{ tk.target || '—' }}</span></td>
              <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;" :title="JSON.stringify(tk.params)">
                {{ JSON.stringify(tk.params) }}
              </td>
              <td>{{ tk.why || '—' }}</td>
              <td class="timeline-meta">{{ fmt(tk.deadline) }}</td>
              <td>
                <button class="btn btn-primary" @click="decide(tk.id, true)" style="background:var(--success);font-size:0.8rem;margin-right:0.3rem;">{{ t('pages.approvals.approve') }}</button>
                <button class="btn btn-danger" @click="decide(tk.id, false)" style="font-size:0.8rem;">{{ t('pages.approvals.reject') }}</button>
              </td>
            </tr>
            <tr v-if="filteredTickets.length === 0">
              <td colspan="8" class="muted" style="text-align:center;padding:2rem;">{{ t('pages.approvals.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Test Ticket Form -->
    <div class="glass-card">
      <h3>{{ t('pages.approvals.createTitle') }}</h3>
      <p class="muted" style="font-size:0.8rem;margin-bottom:1rem;">{{ t('pages.approvals.createSub') }}</p>
      <div class="form-row">
        <div>
          <label class="section-title" for="approval-task-id">{{ t('pages.approvals.labelTaskId') }}</label>
          <input id="approval-task-id" v-model="form.task_id" :placeholder="t('pages.approvals.phTaskId')" />
        </div>
        <div>
          <label class="section-title" for="approval-tool">{{ t('pages.approvals.labelTool') }}</label>
          <input id="approval-tool" v-model="form.tool" :placeholder="t('pages.approvals.phTool')" />
        </div>
      </div>
      <div class="form-row">
        <div>
          <label class="section-title" for="approval-target">{{ t('pages.approvals.labelTarget') }}</label>
          <input id="approval-target" v-model="form.target" :placeholder="t('pages.approvals.phTarget')" />
        </div>
        <div>
          <label class="section-title" for="approval-why">{{ t('pages.approvals.labelWhy') }}</label>
          <input id="approval-why" v-model="form.why" :placeholder="t('pages.approvals.phWhy')" />
        </div>
      </div>
      <div class="form-row full">
        <label class="section-title" for="approval-params">{{ t('pages.approvals.labelParams') }}</label>
        <input id="approval-params" v-model="form.params" placeholder='{"recipient": "alex@company.com", "subject": "Report"}' />
      </div>

      <div style="margin-top:1rem;">
        <button class="btn btn-primary" @click="create">{{ t('pages.approvals.btnCreate') }}</button>
      </div>

      <div v-if="createMsg" class="callout ok" style="margin-top:1rem;">{{ createMsg }}</div>
      <div v-if="createErr" class="callout err" style="margin-top:1rem;">{{ createErr }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

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
  return (tickets.value || []).filter(tk => tk.task_id && tk.task_id.toLowerCase().includes(q))
})

const form = ref({ task_id: 'demo-task', tool: 'send_email', target: 'prod-smtp', why: 'sending notification', params: '{"to":"admin@example.com"}' })
const createMsg = ref('')
const createErr = ref('')

const create = async () => {
  createMsg.value = ''; createErr.value = ''
  let params = {}
  try { params = JSON.parse(form.value.params || '{}') } catch (e) {
    createErr.value = t('pages.approvals.paramsInvalid'); return
  }
  try {
    const r = await apiFetch('/api/approvals', {
      method: 'POST',
      body: { ...form.value, params }
    })
    createMsg.value = t('pages.approvals.created', { id: r.id })
    refresh()
  } catch (e) { createErr.value = e.message }
}

const decide = async (id, approved) => {
  if (!confirm(t('pages.approvals.confirmDecide', { action: approved ? t('pages.approvals.approve') : t('pages.approvals.reject'), id: id.slice(0, 16) + '…' }))) return
  try {
    await apiFetch(`/api/approvals/${id}/decide`, { method: 'POST', body: { approved } })
    refresh()
  } catch (e) { error.value = e.message }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleTimeString() : '—'
</script>
