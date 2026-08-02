<template>
  <div>
    <h1>Audit</h1>
    <p class="muted">Tamper-evident ledger (plan.md §14). Records live outside the sandbox; the agent cannot rewrite its own history.</p>
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
import { ref } from 'vue'
import { useRouter } from 'vue-router'
const router = useRouter()
const taskId = ref('')
const go = () => {
  const id = taskId.value.trim()
  if (!id) return
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) { alert('Invalid task id'); return }
  router.push(`/audit/${id}`)
}
</script>
