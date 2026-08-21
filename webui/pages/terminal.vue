<template>
  <div>
    <h1>Tool Terminal &amp; Policy Gateway</h1>
    <p class="muted">Interactive tool invocation console routed through the per-task Policy Gateway (plan.md §6).</p>

    <div class="glass-card">
      <div class="form-row">
        <div>
          <label class="section-title">Target Task ID</label>
          <input v-model="taskId" placeholder="e.g. agent-task" />
        </div>
        <div>
          <label class="section-title">Common Tool Shortcuts</label>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;padding-top:0.25rem;">
            <button class="btn btn-primary" style="font-size:0.8rem;" @click="setCommand('read_file path=/etc/resolv.conf')">read_file</button>
            <button class="btn btn-primary" style="font-size:0.8rem;" @click="setCommand('run_tests suite=unit')">run_tests</button>
            <button class="btn btn-primary" style="font-size:0.8rem;" @click="setCommand('send_email to=user@corp.com')">send_email (approve)</button>
            <button class="btn btn-danger" style="font-size:0.8rem;" @click="setCommand('rm_rf path=/')">rm_rf (deny)</button>
          </div>
        </div>
      </div>

      <div class="form-row full">
        <label class="section-title">Tool Execution Command (e.g. <code>tool_name key=val arg1</code>)</label>
        <div class="input-group">
          <input v-model="cmd" placeholder="read_file path=/etc/hosts" @keyup.enter="execTool" />
          <button class="btn btn-primary" @click="execTool" :disabled="loading">
            {{ loading ? 'Executing...' : 'Execute' }}
          </button>
        </div>
      </div>

      <!-- Execution Status / Output -->
      <div v-if="result" style="margin-top:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
          <h4>Gateway Response:</h4>
          <span v-if="result.status === 'approval_required'" class="pill approve">202 APPROVAL REQUIRED</span>
          <span v-else-if="result.exitCode === 0" class="pill allow">200 ALLOWED</span>
          <span v-else-if="result.error" class="pill deny">403 BLOCKED</span>
        </div>

        <div v-if="result.status === 'approval_required'" class="callout warn">
          <strong>Approval Ticket Created!</strong> Side-effectful action was intercepted. Go to
          <NuxtLink to="/approvals" style="color:var(--primary);font-weight:600;">Approvals Inbox</NuxtLink> to decide this ticket.
        </div>

        <pre class="code-block" style="min-height:120px;">{{ JSON.stringify(result, null, 2) }}</pre>
      </div>

      <div v-if="error" class="callout err" style="margin-top:1rem;">{{ error }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch } from '~/composables/useApi'

const taskId = ref('agent-task')
const cmd = ref('read_file path=/etc/resolv.conf')
const loading = ref(false)
const result = ref(null)
const error = ref('')

const setCommand = (c) => {
  cmd.value = c
}

const execTool = async () => {
  if (!taskId.value || !cmd.value) return
  loading.value = true
  result.value = null
  error.value = ''

  try {
    const res = await apiFetch(`/api/exec?task=${encodeURIComponent(taskId.value)}`, {
      method: 'POST',
      body: { cmd: cmd.value }
    })
    result.value = res
  } catch (e) {
    if (e.status === 403) {
      result.value = { error: e.message || 'Forbidden by Policy Gateway' }
    } else {
      error.value = e.message
    }
  } finally {
    loading.value = false
  }
}
</script>
