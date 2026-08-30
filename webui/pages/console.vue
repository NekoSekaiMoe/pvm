<template>
  <div>
    <h1>{{ t('pages.console.title') }}</h1>
    <p class="muted">{{ t('pages.console.subtitle') }}</p>

    <div class="console-layout">
      <!-- Left: task selector -->
      <aside class="console-tasks glass-card">
        <h3>{{ t('pages.console.taskList') }}</h3>
        <input v-model="taskFilter" :placeholder="t('pages.console.taskSearchPh')" class="search-input" style="width:100%;margin-bottom:0.75rem;" />
        <div class="task-list">
          <button
            v-for="task in filteredTasks"
            :key="task.id"
            class="task-item"
            :class="{ active: task.id === selectedId }"
            @click="selectTask(task.id)"
          >
            <span class="mono" style="font-size:0.8rem;">{{ task.id }}</span>
            <span class="badge" :class="task.status">{{ task.status }}</span>
          </button>
          <div v-if="filteredTasks.length === 0" class="muted" style="font-size:0.85rem;padding:0.5rem 0;">
            {{ t('pages.console.noTasks') }}
          </div>
        </div>
      </aside>

      <!-- Right: everything about the selected task -->
      <div class="console-main">
        <div v-if="!selected" class="glass-card muted" style="text-align:center;padding:3rem;">
          {{ t('pages.console.selectTask') }}
        </div>

        <template v-else>
          <!-- Task detail + metrics -->
          <div class="glass-card">
            <div class="toolbar">
              <h3>{{ t('pages.console.detailTitle') }} — <span class="mono">{{ selected.id }}</span></h3>
              <span class="badge" :class="selected.status">{{ selected.status }}</span>
            </div>
            <div class="stat-grid">
              <div class="stat-tile">
                <div class="stat-value">{{ metrics ? (metrics.net_tx_bytes ?? '—') : '—' }}</div>
                <div class="stat-label">{{ t('pages.console.metricNetTx') }}</div>
              </div>
              <div class="stat-tile">
                <div class="stat-value">{{ metrics ? (metrics.egress_denied_total ?? '—') : '—' }}</div>
                <div class="stat-label">{{ t('pages.console.metricDenied') }}</div>
              </div>
              <div class="stat-tile">
                <div class="stat-value" style="display:flex;gap:0.5rem;justify-content:center;">
                  <button
                    v-if="selected.status === 'running'"
                    class="btn btn-danger"
                    style="font-size:0.8rem;"
                    @click="lifecycle('pause')"
                  >
                    {{ t('pages.console.btnPause') }}
                  </button>
                  <button
                    v-if="selected.status === 'suspended'"
                    class="btn btn-primary"
                    style="font-size:0.8rem;background:var(--success);"
                    @click="lifecycle('resume')"
                  >
                    {{ t('pages.console.btnResume') }}
                  </button>
                </div>
                <div class="stat-label">{{ metricsErr ? t('pages.console.metricsUnavailable') : 'PID ' + (selected.pid || '—') }}</div>
              </div>
            </div>
          </div>

          <!-- Exec panel (Tool Gateway) -->
          <div class="glass-card">
            <h3>{{ t('pages.console.execTitle') }}</h3>
            <div class="input-group" style="margin-top:0.75rem;">
              <input
                v-model="execCmd"
                :placeholder="t('pages.console.execPh')"
                class="mono"
                @keyup.enter="runExec"
              />
              <button class="btn btn-primary" :disabled="execBusy || !execCmd.trim()" @click="runExec">
                {{ execBusy ? t('pages.console.running') : t('pages.console.btnRun') }}
              </button>
            </div>
            <div v-if="execApproval" class="callout warn" style="margin-top:0.75rem;">
              {{ t('pages.console.approvalRequired') }}
              <NuxtLink to="/approvals" style="margin-left:0.5rem;">{{ t('pages.console.goToApprovals') }} →</NuxtLink>
            </div>
            <div v-if="execResult !== null" style="margin-top:0.75rem;">
              <div class="section-title">{{ t('pages.console.result') }}</div>
              <pre class="mono console-pre">{{ typeof execResult === 'string' ? execResult : JSON.stringify(execResult, null, 2) }}</pre>
            </div>
          </div>

          <!-- Console tail -->
          <div class="glass-card">
            <h3>{{ t('pages.console.tailTitle') }}</h3>
            <pre class="mono console-pre" style="margin-top:0.75rem;">{{ consoleTail || (tailError ? t('pages.console.tailError', { msg: tailError }) : t('pages.console.tailEmpty')) }}</pre>
          </div>

          <!-- Snapshot timeline -->
          <div class="glass-card">
            <div class="toolbar">
              <h3>{{ t('pages.console.snapshotsTitle') }}</h3>
              <div class="input-group">
                <input v-model="snapEventId" :placeholder="t('pages.console.eventPh')" style="flex:1;" />
                <button class="btn btn-primary" style="background:var(--success);font-size:0.8rem;" @click="takeSnapshot">
                  {{ t('pages.console.btnTakeSnap') }}
                </button>
              </div>
            </div>
            <div class="timeline" style="margin-top:0.75rem;">
              <div v-for="s in snapshots" :key="s.id" class="timeline-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                  <span class="pill allow">{{ s.event_id || s.id }}</span>
                  <button
                    class="btn btn-primary"
                    style="font-size:0.7rem;padding:0.2rem 0.5rem;background:var(--accent);"
                    @click="rollbackSnapshot(s.id)"
                  >
                    ↩ {{ t('pages.console.rollback') }}
                  </button>
                  <button class="btn btn-primary" style="font-size:0.7rem;padding:0.2rem 0.5rem;" @click="cloneTask">
                    🐑 {{ t('pages.console.clone') }}
                  </button>
                </div>
                <div class="timeline-meta mono">{{ s.id }} · {{ fmt(s.created_at) }}</div>
              </div>
              <div v-if="snapshots.length === 0" class="muted">{{ t('pages.console.noSnapshots') }}</div>
            </div>
          </div>

          <!-- File browser -->
          <div class="glass-card">
            <h3>{{ t('pages.console.filesTitle') }}</h3>
            <div class="input-group" style="margin-top:0.75rem;">
              <input v-model="filePath" :placeholder="t('pages.console.filesPathPh')" class="mono" @keyup.enter="loadFiles" />
              <button class="btn btn-primary" @click="loadFiles">{{ t('pages.console.btnList') }}</button>
            </div>
            <div v-if="filesError" class="callout err" style="margin-top:0.75rem;">
              {{ t('pages.console.filesError', { msg: filesError }) }}
            </div>
            <div class="table-container" style="margin-top:0.75rem;max-height:240px;overflow-y:auto;">
              <table>
                <thead>
                  <tr>
                    <th>{{ t('pages.console.colName') }}</th>
                    <th>{{ t('pages.console.colSize') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-if="filePath && filePath !== '/'" class="file-row" @click="openParent">
                    <td colspan="2" class="mono">📁 .. <span class="muted" style="font-size:0.75rem;">({{ t('pages.console.parentDir') }})</span></td>
                  </tr>
                  <tr v-for="f in files" :key="f.name" class="file-row" @click="openEntry(f)">
                    <td class="mono">{{ f.is_dir ? '📁' : '📄' }} {{ f.name }}</td>
                    <td class="muted">{{ f.is_dir ? '—' : f.size }}</td>
                  </tr>
                  <tr v-if="files.length === 0 && !filesError">
                    <td colspan="2" class="muted" style="text-align:center;padding:1rem;">
                      {{ t('pages.console.filesEmpty') }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-if="filePreview !== null" style="margin-top:0.75rem;">
              <div class="section-title">{{ t('pages.console.preview') }} — <span class="mono">{{ filePreviewPath }}</span></div>
              <pre class="mono console-pre">{{ filePreview || '·' }}</pre>
            </div>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t, locale } = useI18n()

// --- Task list (left pane) ---
const tasks = ref([])
const taskFilter = ref('')
const selectedId = ref('')

const { refresh: refreshTasks } = usePoll(async () => {
  const list = await apiFetch('/api/tasks')
  tasks.value = Array.isArray(list) ? list : []
  return tasks.value
}, 3000)

const filteredTasks = computed(() => {
  if (!taskFilter.value) return tasks.value
  const q = taskFilter.value.toLowerCase()
  return tasks.value.filter(tk => tk.id && tk.id.toLowerCase().includes(q))
})

const selected = computed(() => tasks.value.find(tk => tk.id === selectedId.value) || null)

const selectTask = (id) => {
  selectedId.value = id
  // Per-task panels start from a clean slate; the polls below refill them.
  execResult.value = null
  execApproval.value = false
  filePreview.value = null
  filePreviewPath.value = ''
  filesError.value = ''
  files.value = []
  filePath.value = '/'
  loadFiles()
}

// --- Metrics (polled per selected task) ---
const metrics = ref(null)
const metricsErr = ref('')
usePoll(async () => {
  const id = selectedId.value
  if (!id) return null
  try {
    const r = await apiFetch(`/api/tasks/${encodeURIComponent(id)}/metrics`)
    // The await can span a task switch: a stale response must not land in
    // the panel of a different task.
    if (id !== selectedId.value) return null
    metrics.value = r
    metricsErr.value = ''
  } catch (e) {
    if (id !== selectedId.value) return null
    metricsErr.value = e.message
    metrics.value = null
  }
  return metrics.value
}, 3000)

// --- Lifecycle controls ---
const lifecycle = async (action) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/${action}`, { method: 'POST' })
    refreshTasks()
  } catch (e) {
    alert(t('pages.console.errLifecycle', { msg: e.message }))
  }
}

// --- Exec panel (POST /api/exec through the Tool Gateway) ---
const execCmd = ref('')
const execBusy = ref(false)
const execResult = ref(null)
const execApproval = ref(false)

const runExec = async () => {
  const cmd = execCmd.value.trim()
  if (!cmd || execBusy.value) return
  execBusy.value = true
  execResult.value = null
  execApproval.value = false
  try {
    const r = await apiFetch(`/api/exec?task=${encodeURIComponent(selectedId.value)}`, {
      method: 'POST',
      body: { cmd }
    })
    // 202 business-level response: the gateway paused the call for a human.
    if (r && r.status === 'approval_required') {
      execApproval.value = true
    } else {
      execResult.value = r
    }
  } catch (e) {
    execResult.value = { error: e.message }
  } finally {
    execBusy.value = false
  }
}

// --- Console tail (2s poll of the ring buffer) ---
const consoleTail = ref('')
const tailError = ref('')
usePoll(async () => {
  const id = selectedId.value
  if (!id) return null
  try {
    const r = await apiFetch(`/api/tasks/${encodeURIComponent(id)}/console`)
    if (id !== selectedId.value) return null
    consoleTail.value = (r && r.tail) || ''
    tailError.value = ''
  } catch (e) {
    if (id !== selectedId.value) return null
    tailError.value = e.message
  }
  return consoleTail.value
}, 2000)

// --- Snapshot timeline ---
const snapshots = ref([])
const snapEventId = ref('')

const loadSnapshots = async () => {
  const id = selectedId.value
  if (!id) return
  try {
    const r = (await apiFetch(`/api/tasks/${encodeURIComponent(id)}/snapshots`)) || []
    if (id === selectedId.value) snapshots.value = r
  } catch (e) {
    if (id === selectedId.value) snapshots.value = []
  }
}
usePoll(loadSnapshots, 5000)

const takeSnapshot = async () => {
  if (!selectedId.value) return
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/snapshots`, {
      method: 'POST',
      body: { event_id: snapEventId.value.trim() || 'manual' }
    })
    snapEventId.value = ''
    await loadSnapshots()
  } catch (e) {
    alert(e.message)
  }
}

const rollbackSnapshot = async (snapId) => {
  if (!confirm(t('pages.console.confirmRollback', { id: selectedId.value, snapId }))) return
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/rollback`, {
      method: 'POST',
      body: { snapshot_id: snapId }
    })
    await loadSnapshots()
  } catch (e) {
    alert(e.message)
  }
}

const cloneTask = async () => {
  const newID = prompt(t('pages.console.clonePrompt', { id: selectedId.value }), `${selectedId.value}-cloned`)
  if (!newID) return
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/clone`, {
      method: 'POST',
      body: { new_id: newID }
    })
    refreshTasks()
  } catch (e) {
    alert(e.message)
  }
}

// --- File browser (host-side workspace API) ---
const filePath = ref('/')
const files = ref([])
const filesError = ref('')
const filePreview = ref(null)
const filePreviewPath = ref('')

const normalize = (p) => {
  const abs = p.startsWith('/') ? p : `/${p}`
  const parts = []
  for (const seg of abs.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') { parts.pop(); continue }
    parts.push(seg)
  }
  return '/' + parts.join('/')
}

const loadFiles = async () => {
  if (!selectedId.value) return
  filesError.value = ''
  try {
    const r = await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/files/list?path=${encodeURIComponent(normalize(filePath.value))}`)
    // Entry shape is defensive: {entries:[...]} or a bare array; each entry
    // may be {name,is_dir,size} or a plain string.
    const raw = Array.isArray(r) ? r : (r && r.entries) || []
    files.value = raw.map(e => {
      if (typeof e === 'string') return { name: e, is_dir: false, size: '' }
      return {
        name: e.name || e.Name || '',
        is_dir: !!(e.is_dir ?? e.dir ?? (e.type === 'dir' || e.type === 'directory')),
        size: e.size !== undefined ? e.size : ''
      }
    }).filter(e => e.name).sort((a, b) => (b.is_dir - a.is_dir) || a.name.localeCompare(b.name))
  } catch (e) {
    filesError.value = e.message
    files.value = []
  }
}

const openEntry = async (f) => {
  const p = normalize(`${filePath.value}/${f.name}`)
  if (f.is_dir) {
    filePath.value = p
    filePreview.value = null
    filePreviewPath.value = ''
    await loadFiles()
    return
  }
  try {
    filePreview.value = await apiFetch(`/api/tasks/${encodeURIComponent(selectedId.value)}/files/read?path=${encodeURIComponent(p)}`)
    filePreviewPath.value = p
  } catch (e) {
    filePreview.value = e.message
    filePreviewPath.value = p
  }
}

const openParent = () => {
  const p = normalize(filePath.value)
  filePath.value = p.slice(0, p.lastIndexOf('/')) || '/'
  filePreview.value = null
  filePreviewPath.value = ''
  loadFiles()
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString(locale.value) : '—'
</script>

<style scoped>
.console-layout {
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 1rem;
  margin-top: 1rem;
}
@media (max-width: 900px) {
  .console-layout { grid-template-columns: 1fr; }
}
.console-tasks {
  align-self: start;
  padding: 1rem;
}
.task-list {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  max-height: 480px;
  overflow-y: auto;
}
.task-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.5rem 0.65rem;
  border-radius: 0.5rem;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-main);
  cursor: pointer;
  font: inherit;
}
.task-item:hover { background: rgba(255, 255, 255, 0.05); }
.task-item.active {
  background: rgba(59, 130, 246, 0.15);
  border-color: var(--glass-border);
}
.console-main {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  min-width: 0;
}
.console-pre {
  background: rgba(0, 0, 0, 0.5);
  border: 1px solid var(--glass-border);
  border-radius: 0.5rem;
  padding: 0.9rem;
  font-size: 0.8rem;
  line-height: 1.4;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 260px;
  overflow-y: auto;
  margin: 0;
}
.file-row { cursor: pointer; }
.file-row:hover td { background: rgba(255, 255, 255, 0.05); }
</style>
