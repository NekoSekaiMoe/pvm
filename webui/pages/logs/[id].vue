<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:1rem;">
      <div>
        <h1>Console Logs: <span class="mono">{{ $route.params.id }}</span></h1>
        <p class="muted" style="font-size:0.875rem;">Lines: {{ lineCount }} | Size: {{ logSizeKB }} KB</p>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;">
        <button class="btn btn-primary" @click="copyLogs" style="font-size:0.85rem;">Copy Logs</button>
        <button class="btn btn-primary" @click="downloadLogs" style="font-size:0.85rem;background:var(--success);">Download</button>
        <NuxtLink to="/" class="btn btn-primary" style="text-decoration:none;font-size:0.85rem;">&larr; Back</NuxtLink>
      </div>
    </div>

    <!-- Filter & Options Bar -->
    <div class="glass-card" style="padding:1rem;">
      <div class="toolbar" style="margin-bottom:0;">
        <input v-model="filterKeyword" placeholder="Filter log lines..." class="search-input" />
        <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;color:var(--text-muted);font-size:0.875rem;">
          <input type="checkbox" v-model="autoScroll" style="width:auto;" />
          <span>Auto-Scroll to Bottom</span>
        </label>
      </div>
    </div>
    
    <div class="glass-card">
      <pre ref="logContainer" class="log-viewer">{{ displayedLogs }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const rawLogs = ref('Loading logs...')
const filterKeyword = ref('')
const autoScroll = ref(true)
const logContainer = ref(null)
let timer

const lineCount = computed(() => rawLogs.value ? rawLogs.value.split('\n').length : 0)
const logSizeKB = computed(() => rawLogs.value ? (rawLogs.value.length / 1024).toFixed(1) : 0)

const displayedLogs = computed(() => {
  if (!filterKeyword.value) return rawLogs.value
  const q = filterKeyword.value.toLowerCase()
  return rawLogs.value
    .split('\n')
    .filter(line => line.toLowerCase().includes(q))
    .join('\n')
})

const fetchLogs = async () => {
  try {
    const res = await fetch(`/api/containers/${route.params.id}/logs`)
    if (res.ok) {
      rawLogs.value = await res.text()
      if (autoScroll.value) {
        nextTick(() => {
          if (logContainer.value) {
            logContainer.value.scrollTop = logContainer.value.scrollHeight
          }
        })
      }
    } else {
      rawLogs.value = "No logs available or container is dead."
    }
  } catch (e) {
    rawLogs.value = "Error fetching logs."
  }
}

const copyLogs = async () => {
  try {
    await navigator.clipboard.writeText(rawLogs.value)
    alert("Logs copied to clipboard!")
  } catch (e) {
    alert("Failed to copy logs")
  }
}

const downloadLogs = () => {
  const blob = new Blob([rawLogs.value], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `console-${route.params.id}.log`
  a.click()
  URL.revokeObjectURL(url)
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
  background: rgba(0,0,0,0.6);
  padding: 1.25rem;
  border-radius: 0.5rem;
  color: #a7f3d0;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 0.85rem;
  line-height: 1.4;
  white-space: pre-wrap;
  min-height: 350px;
  max-height: 600px;
  overflow-y: auto;
  border: 1px solid var(--glass-border);
}
</style>
