<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:1rem;">
      <div>
        <h1>{{ t('pages.logs.title') }} <span class="mono">{{ $route.params.id }}</span></h1>
        <p class="muted" style="font-size:0.875rem;">{{ t('pages.logs.lines', { n: lineCount, kb: logSizeKB }) }}</p>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;">
        <button class="btn btn-primary" @click="fetchLogs" style="font-size:0.85rem;">{{ t('pages.logs.btnRefresh') }}</button>
        <button class="btn btn-primary" @click="copyLogs" style="font-size:0.85rem;">{{ t('pages.logs.btnCopy') }}</button>
        <button class="btn btn-primary" @click="downloadLogs" style="font-size:0.85rem;background:var(--success);">{{ t('pages.logs.btnDownload') }}</button>
        <NuxtLink to="/" class="btn btn-primary" style="text-decoration:none;font-size:0.85rem;">{{ t('common.back') }}</NuxtLink>
      </div>
    </div>

    <!-- Filter & Options Bar -->
    <div class="glass-card" style="padding:1rem;">
      <div class="toolbar" style="margin-bottom:0;">
        <input v-model="filterKeyword" :placeholder="t('pages.logs.filterPh')" class="search-input" />
        <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;color:var(--text-muted);font-size:0.875rem;">
          <input type="checkbox" v-model="autoScroll" style="width:auto;" />
          <span>{{ t('pages.logs.autoScroll') }}</span>
        </label>
      </div>
    </div>
    
    <div class="glass-card">
      <pre ref="logContainer" class="log-viewer">{{ displayedLogs }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()
const route = useRoute()
const rawLogs = ref('Loading logs...')
const filterKeyword = ref('')
const autoScroll = ref(true)
const logContainer = ref(null)

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

// Tail the logs through the shared usePoll helper (in-flight dedup,
// hidden-tab pause, error backoff). Fetch errors still surface in-page via
// rawLogs, but the callback MUST rethrow: usePoll only engages its shared
// failure backoff (fails/retryAt doubling) when fn rejects — swallowing the
// error would poll a dead container at full rate forever.
const { refresh: fetchLogs } = usePoll(async () => {
  let res
  try {
    res = await fetch(`/api/containers/${route.params.id}/logs`)
  } catch (e) {
    rawLogs.value = "Error fetching logs."
    throw e // let usePoll record the failure and back off
  }
  if (!res.ok) {
    rawLogs.value = "No logs available or container is dead."
    throw new Error(`log fetch failed: HTTP ${res.status}`) // same backoff path
  }
  rawLogs.value = await res.text()
  if (autoScroll.value) {
    nextTick(() => {
      if (logContainer.value) {
        logContainer.value.scrollTop = logContainer.value.scrollHeight
      }
    })
  }
}, 2000)

const copyLogs = async () => {
  try {
    await navigator.clipboard.writeText(rawLogs.value)
    alert(t('pages.logs.copied'))
  } catch (e) {
    alert(t('pages.logs.copyFail'))
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
