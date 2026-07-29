<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
      <h1>Container Logs: {{ $route.params.id }}</h1>
      <NuxtLink to="/" class="btn btn-primary" style="text-decoration:none;">&larr; Back</NuxtLink>
    </div>
    
    <div class="glass-card">
      <pre class="log-viewer">{{ logs }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const logs = ref('Loading logs...')
let timer

const fetchLogs = async () => {
  try {
    const res = await fetch(`/api/containers/${route.params.id}/logs`)
    if (res.ok) {
      logs.value = await res.text()
    } else {
      logs.value = "No logs available or container is dead."
    }
  } catch(e) {
    logs.value = "Error fetching logs."
  }
}

onMounted(() => {
  fetchLogs()
  timer = setInterval(fetchLogs, 2000)
})

onUnmounted(() => {
  clearInterval(timer)
})
</script>

<style scoped>
.log-viewer {
  background: rgba(0,0,0,0.5);
  padding: 1rem;
  border-radius: 0.5rem;
  color: #a7f3d0;
  font-family: monospace;
  white-space: pre-wrap;
  min-height: 300px;
  max-height: 600px;
  overflow-y: auto;
}
</style>
