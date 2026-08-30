<template>
  <div>
    <h1>{{ t('pages.tasks.title') }}</h1>
    <p class="muted">{{ t('pages.tasks.subtitle') }}</p>

    <!-- Launch from TaskSpec -->
    <div class="glass-card">
      <h3>{{ t('pages.tasks.specTitle') }}</h3>
      <div class="form-row full">
        <textarea v-model="toml" placeholder="version = 1&#10;caller = 'alice'&#10;[runtime]&#10;name = 't1'&#10;memory = '512M'&#10;..."></textarea>
      </div>
      <div class="input-group" style="align-items:center;">
        <label class="muted" style="font-size:0.85rem;white-space:nowrap;" title="UML kernel fast seccomp userspace mode (security.uml_seccomp)">uml_seccomp</label>
        <select v-model="seccompSelect" aria-label="UML seccomp mode" :disabled="!!specPath" :title="specPath ? t('pages.tasks.seccompFileModeTitle') : t('pages.tasks.seccompModeTitle')" style="background:rgba(0,0,0,0.3);color:white;border:1px solid var(--glass-border);padding:0.75rem;border-radius:0.5rem;flex:0.3;">
          <option value="off">off (default)</option>
          <option value="auto">auto</option>
          <option value="on">on</option>
        </select>
        <span class="muted" style="font-size:0.75rem;">
          {{ t('pages.tasks.seccompHint') }} <span class="mono">[security]</span> {{ t('pages.tasks.seccompHint2') }} <span class="mono">uml_seccomp</span> {{ t('pages.tasks.seccompHint3') }}
        </span>
      </div>
      <div class="input-group">
        <input v-model="specPath" :placeholder="t('pages.tasks.specPathPh')" />
        <button class="btn btn-primary" @click="validateSpec">{{ t('pages.tasks.btnValidate') }}</button>
        <button class="btn btn-primary" @click="launchSpec" :disabled="!fingerprint">{{ t('pages.tasks.btnLaunch') }}</button>
      </div>
      <div v-if="fingerprint" class="callout ok">
        <strong>{{ t('pages.tasks.valid') }}</strong> {{ t('pages.tasks.fingerprint') }} <span class="mono">{{ fingerprint }}</span>
      </div>
      <div v-if="specError" class="callout err"><strong>{{ t('pages.tasks.invalid') }}</strong> {{ specError }}</div>
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
        <input v-model="searchQuery" :placeholder="t('pages.tasks.searchPh')" class="search-input" />
        <span class="muted" style="font-size:0.875rem;">{{ t('pages.tasks.totalTasks', { n: filteredTasks.length }) }}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>{{ t('pages.tasks.colId') }}</th>
              <th>{{ t('pages.tasks.colTenant') }}</th>
              <th>{{ t('pages.tasks.colStatus') }}</th>
              <th>{{ t('pages.tasks.colPid') }}</th>
              <th>{{ t('pages.tasks.colStarted') }}</th>
              <th>{{ t('pages.tasks.colFp') }}</th>
              <th>{{ t('pages.tasks.colLifecycle') }}</th>
              <th>{{ t('pages.tasks.colInspect') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="task in filteredTasks" :key="task.id">
              <td class="mono"><strong>{{ task.id }}</strong></td>
              <td>{{ task.tenant || '—' }}</td>
              <td>
                <span class="badge" :class="task.status">{{ task.status }}</span>
                <span class="badge" :class="'seccomp-' + seccompMode(task)" :title="seccompTip(task)" style="margin-left:0.4rem;font-size:0.7rem;">seccomp:{{ seccompMode(task) }}</span>
              </td>
              <td>{{ task.pid || '—' }}</td>
              <td class="timeline-meta">{{ fmt(task.started_at) }}</td>
              <td class="mono" :title="task.spec_fingerprint">{{ short(task.spec_fingerprint) }}</td>
              <td>
                <!-- Pause Button for Running -->
                <button
                  v-if="task.status === 'running'"
                  class="btn btn-danger"
                  style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;"
                  @click="pauseTask(task.id)"
                >
                  {{ t('pages.tasks.btnPause') }}
                </button>
                <!-- Resume Button for Suspended -->
                <button
                  v-if="task.status === 'suspended'"
                  class="btn btn-primary"
                  style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;background:var(--success);"
                  @click="resumeTask(task.id)"
                >
                  {{ t('pages.tasks.btnResume') }}
                </button>
                <button class="btn btn-primary" @click="showTransitions(task)" style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;">
                  {{ t('pages.tasks.btnFsm') }}
                </button>
                <button class="btn btn-primary" @click="openSnapshotModal(task)" style="font-size:0.75rem;padding:0.3rem 0.6rem;margin-right:0.3rem;">
                  {{ t('pages.tasks.btnSnaps') }}
                </button>
                <button class="btn btn-primary" @click="cloneTaskPrompt(task.id)" style="font-size:0.75rem;padding:0.3rem 0.6rem;">
                  {{ t('pages.tasks.btnClone') }}
                </button>
              </td>
              <td>
                <NuxtLink :to="`/audit/${task.id}`" class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;text-decoration:none;margin-right:0.3rem;">{{ t('pages.tasks.btnAudit') }}</NuxtLink>
                <NuxtLink :to="`/logs/${task.id}`" class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;text-decoration:none;">{{ t('pages.tasks.btnLogs') }}</NuxtLink>
              </td>
            </tr>
            <tr v-if="filteredTasks.length === 0">
              <td colspan="8" class="muted" style="text-align:center;padding:2rem;">{{ t('pages.tasks.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Transition modal -->
    <div v-if="selected" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="fsm-modal-title" @keydown.esc="selected = null">
      <div class="modal-box">
        <h3 id="fsm-modal-title">{{ t('pages.tasks.fsmTitle', { id: selected.id }) }}</h3>
        <p class="muted" style="margin-bottom:1rem;font-size:0.85rem;">
          {{ t('pages.tasks.fsmSeccompPrefix') }} <span class="badge" :class="'seccomp-' + seccompMode(selected)" :title="seccompTip(selected)">{{ seccompMode(selected) }}</span>
          <span v-if="seccompMode(selected) !== 'off'">{{ t('pages.tasks.fsmSeccompWarn') }}</span>
        </p>
        <div class="timeline">
          <div v-for="(tr, i) in selected.transitions || []" :key="i" class="timeline-item">
            <span class="badge" :class="tr.to">{{ tr.to }}</span>
            <span class="muted"> {{ t('pages.tasks.fsmFrom') }} </span>
            <span class="badge" :class="tr.from">{{ tr.from }}</span>
            <span class="pill allow"> {{ tr.actor }}</span>
            <div class="timeline-meta">{{ fmt(tr.at) }} — {{ tr.reason }}</div>
          </div>
          <div v-if="!selected.transitions || selected.transitions.length === 0" class="muted">{{ t('pages.tasks.fsmNoTransitions') }}</div>
        </div>
        <div class="input-group" style="margin-top:1.5rem;">
          <select v-model="newTo" aria-label="Target State" style="background:rgba(0,0,0,0.3);color:white;border:1px solid var(--glass-border);padding:0.75rem;border-radius:0.5rem;flex:0.6;">
            <option v-for="s in states" :key="s" :value="s">{{ s }}</option>
          </select>
          <input v-model="newReason" :placeholder="t('pages.tasks.fsmReasonPh')" aria-label="Transition Reason" />
          <button class="btn btn-primary" @click="transition(selected.id)">{{ t('pages.tasks.btnApply') }}</button>
          <button class="btn btn-danger" @click="selected = null">{{ t('common.close') }}</button>
        </div>
        <div v-if="transError" class="callout err" style="margin-top:1rem;">{{ transError }}</div>
      </div>
    </div>

    <!-- Snapshot modal -->
    <div v-if="snapModalTask" ref="snapModalBackdrop" class="modal-backdrop" tabindex="-1" role="dialog" aria-modal="true" aria-labelledby="snap-modal-title" @keydown.esc="snapModalTask = null">
      <div class="modal-box">
        <h3 id="snap-modal-title">{{ t('pages.tasks.snapTitle', { id: snapModalTask.id }) }}</h3>

        <!-- Take Snapshot -->
        <div class="input-group" style="margin-top:1rem;margin-bottom:1.5rem;">
          <input v-model="snapEventId" :placeholder="t('pages.tasks.snapEventPh')" style="flex:0.6;" />
          <button class="btn btn-primary" @click="takeSnapshot(snapModalTask.id)">{{ t('pages.tasks.btnTakeSnap') }}</button>
        </div>

        <!-- Snapshots List -->
        <div class="table-container" style="max-height:250px;overflow-y:auto;">
          <table>
            <thead>
              <tr>
                <th>{{ t('pages.tasks.snapColId') }}</th>
                <th>{{ t('pages.tasks.snapColEvent') }}</th>
                <th>{{ t('pages.tasks.snapColCreated') }}</th>
                <th>{{ t('pages.tasks.snapColAction') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in taskSnapshots" :key="s.id">
                <td class="mono" style="font-size:0.8rem;">{{ s.id }}</td>
                <td>{{ s.event_id }}</td>
                <td class="timeline-meta">{{ fmt(s.created_at) }}</td>
                <td>
                  <button class="btn btn-primary" style="font-size:0.75rem;padding:0.2rem 0.5rem;background:var(--accent);" @click="rollbackToSnap(snapModalTask.id, s.id)">
                    {{ t('pages.tasks.btnRollback') }}
                  </button>
                </td>
              </tr>
              <tr v-if="taskSnapshots.length === 0">
                <td colspan="4" class="muted" style="text-align:center;padding:1rem;">{{ t('pages.tasks.snapEmpty') }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="snapError" class="callout err" style="margin-top:1rem;">{{ snapError }}</div>

        <div style="display:flex;justify-content:flex-end;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="snapModalTask = null">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, nextTick } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

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
    list = list.filter(tk => tk.status === currentFilter.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter(tk =>
      (tk.id && tk.id.toLowerCase().includes(q)) ||
      (tk.tenant && tk.tenant.toLowerCase().includes(q)) ||
      (tk.spec_fingerprint && tk.spec_fingerprint.toLowerCase().includes(q))
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

// UML seccomp mode (TaskSpec security.uml_seccomp). 'off' is the spec
// default, so only non-default selections are injected into the TOML.
const seccompSelect = ref('off')
const specWithSeccomp = (content) => {
  if (seccompSelect.value === 'off') return content
  const line = `uml_seccomp = "${seccompSelect.value}"`
  const secHeader = content.match(/^\s*\[security\]\s*$/m)
  if (secHeader) {
    const after = content.slice(secHeader.index + secHeader[0].length)
    const nextTable = after.match(/^\s*\[[^\]]*\]\s*$/m)
    const secBody = nextTable ? after.slice(0, nextTable.index) : after
    // Only a uml_seccomp INSIDE [security] is an explicit override; the
    // same key in any other table is unrelated and must not suppress
    // the injection.
    if (/^\s*uml_seccomp\s*=/m.test(secBody)) return content
    return content.replace(/^(\s*\[security\]\s*)$/m, `$1\n${line}`)
  }
  return content.trimEnd() + `\n\n[security]\n${line}\n`
}

const validateSpec = async () => {
  fingerprint.value = ''; specError.value = ''
  try {
    const body = specPath.value ? { path: specPath.value } : { content: specWithSeccomp(toml.value) } // specPath mode: server reads the file; the seccomp selector does not apply
    const r = await apiFetch('/api/tasks/load-spec', { method: 'POST', body })
    fingerprint.value = r.fingerprint
  } catch (e) { specError.value = e.message }
}

const launchSpec = () => {
  alert(t('pages.tasks.launchAlert', { fp: fingerprint.value.slice(0, 12) }))
}

const pauseTask = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/pause`, { method: 'POST' })
    refresh()
  } catch (e) {
    alert(t('pages.tasks.errPause', { msg: e.message }))
  }
}

const resumeTask = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/resume`, { method: 'POST' })
    refresh()
  } catch (e) {
    alert(t('pages.tasks.errResume', { msg: e.message }))
  }
}

// Clone
const cloneTaskPrompt = async (id) => {
  const newID = prompt(t('pages.tasks.clonePrompt', { id }), `${id}-cloned`)
  if (!newID) return
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/clone`, {
      method: 'POST',
      body: { new_id: newID }
    })
    refresh()
  } catch (e) {
    alert(t('pages.tasks.errClone', { msg: e.message }))
  }
}

// Snapshots & Rollback
const snapModalTask = ref(null)
const taskSnapshots = ref([])
const snapEventId = ref('')
const snapError = ref('')

const snapModalBackdrop = ref(null)

const openSnapshotModal = async (task) => {
  snapModalTask.value = task
  snapError.value = ''
  snapEventId.value = `step_${Date.now().toString().slice(-4)}`
  await nextTick()
  if (snapModalBackdrop.value) {
    snapModalBackdrop.value.focus()
  }
  await loadSnapshots(task.id)
}

const loadSnapshots = async (id) => {
  try {
    taskSnapshots.value = await apiFetch(`/api/tasks/${encodeURIComponent(id)}/snapshots`) || []
  } catch (e) {
    snapError.value = e.message
  }
}

const takeSnapshot = async (id) => {
  snapError.value = ''
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/snapshots`, {
      method: 'POST',
      body: { event_id: snapEventId.value || 'manual' }
    })
    await loadSnapshots(id)
  } catch (e) {
    snapError.value = e.message
  }
}

const rollbackToSnap = async (id, snapId) => {
  if (!confirm(t('pages.tasks.confirmRollback', { id, snapId }))) return
  snapError.value = ''
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/rollback`, {
      method: 'POST',
      body: { snapshot_id: snapId }
    })
    refresh()
    alert(t('pages.tasks.rollbackOk', { snapId }))
  } catch (e) {
    snapError.value = e.message
  }
}

// FSM inspection
const selected = ref(null)
const states = ['pending','provisioning','ready','running','suspended','resuming','review','completed','failed','quarantined','destroy']
const newTo = ref('provisioning')
const newReason = ref('')
const transError = ref('')

const showTransitions = async (task) => {
  selected.value = await apiFetch(`/api/tasks/${task.id}`)
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

// security.uml_seccomp badge (off=neutral, auto=info, on=warning). The task
// state/detail carries a security section; absent means the spec default.
const seccompMode = (task) => (task && task.security && task.security.uml_seccomp) || 'off'
const seccompTip = (task) => {
  const m = seccompMode(task)
  if (m === 'on') return t('pages.tasks.seccompTipOn')
  if (m === 'auto') return t('pages.tasks.seccompTipAuto')
  return t('pages.tasks.seccompTipOff')
}
</script>
