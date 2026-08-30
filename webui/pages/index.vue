<template>
  <div>
    <h1>{{ t('pages.index.title') }}</h1>
    <p class="muted">{{ t('pages.index.subtitle') }}</p>

    <!-- Quick Stats -->
    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-value">{{ runningCount }}</div>
        <div class="stat-label">{{ t('pages.index.statRunning') }}</div>
      </div>
      <div class="stat-tile">
        <div class="stat-value">{{ stoppedCount }}</div>
        <div class="stat-label">{{ t('pages.index.statStopped') }}</div>
      </div>
      <div class="stat-tile">
        <div class="stat-value">{{ containers.length }}</div>
        <div class="stat-label">{{ t('pages.index.statTotal') }}</div>
      </div>
    </div>

    <!-- Launch Form -->
    <div class="glass-card">
      <h3>{{ t('pages.index.launchTitle') }}</h3>
      <div class="form-row">
        <div>
          <label class="section-title">{{ t('pages.index.nameLabel') }}</label>
          <input v-model="newContainer.name" :placeholder="t('pages.index.namePh')" />
        </div>
        <div>
          <label class="section-title">{{ t('pages.index.rootfsLabel') }}</label>
          <input v-model="newContainer.rootfs" :placeholder="t('pages.index.rootfsPh')" />
        </div>
      </div>
      <div class="form-row">
        <div>
          <label class="section-title">{{ t('pages.index.memLabel') }}</label>
          <input v-model="newContainer.mem" :placeholder="t('pages.index.memPh')" />
        </div>
        <div>
          <label class="section-title">{{ t('pages.index.cpuLabel') }}</label>
          <input v-model.number="newContainer.cpu" type="number" :placeholder="t('pages.index.cpuPh')" />
        </div>
      </div>

      <div style="display:flex;gap:1rem;margin-top:1rem;">
        <button class="btn btn-primary" @click="startContainer">{{ t('pages.index.launchBtn') }}</button>
        <button class="btn btn-primary" @click="restoreContainer" style="background:var(--success);">{{ t('pages.index.restoreBtn') }}</button>
      </div>
    </div>

    <!-- Containers List -->
    <div class="glass-card">
      <div class="toolbar">
        <input v-model="searchQuery" :placeholder="t('pages.index.searchPh')" class="search-input" />
        <span class="muted" style="font-size:0.875rem;">{{ t('common.total', { n: filteredContainers.length }) }}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>{{ t('pages.index.colId') }}</th>
              <th>{{ t('pages.index.colStatus') }}</th>
              <th>{{ t('pages.index.colPid') }}</th>
              <th>{{ t('pages.index.colActions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in filteredContainers" :key="c.id">
              <td class="mono"><strong>{{ c.id }}</strong></td>
              <td>
                <span class="badge" :class="c.status.toLowerCase()">{{ c.status }}</span>
              </td>
              <td>{{ c.pid || '—' }}</td>
              <td>
                <NuxtLink :to="`/logs/${c.id}`" class="btn btn-primary" style="margin-right:0.4rem;text-decoration:none;font-size:0.8rem;">{{ t('pages.index.btnLogs') }}</NuxtLink>
                <button
                  v-if="c.status.toLowerCase() === 'running'"
                  class="btn btn-danger"
                  style="margin-right:0.4rem;font-size:0.8rem;"
                  @click="pauseContainer(c.id)"
                >
                  {{ t('pages.index.btnPause') }}
                </button>
                <button
                  v-if="c.status.toLowerCase() === 'suspended'"
                  class="btn btn-primary"
                  style="margin-right:0.4rem;font-size:0.8rem;background:var(--success);"
                  @click="resumeContainer(c.id)"
                >
                  {{ t('pages.index.btnResume') }}
                </button>
                <button
                  class="btn btn-primary"
                  @click="snapshotContainer(c.id)"
                  :disabled="snapshotInFlight(c.id)"
                  style="margin-right:0.4rem;background:var(--success);font-size:0.8rem;"
                >
                  {{ snapshotInFlight(c.id) ? t('pages.index.btnSaving') : t('pages.index.btnSnapshot') }}
                </button>
                <button class="btn btn-danger" style="font-size:0.8rem;" @click="deleteContainer(c.id)">{{ t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="filteredContainers.length === 0">
              <td colspan="4" class="muted" style="text-align:center;padding:2rem;">{{ t('pages.index.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

const containers = ref([])
const searchQuery = ref('')
const newContainer = ref({ name: '', rootfs: 'alpine', mem: '512M', cpu: 0 })
const snapshottingIds = ref(new Set())

const snapshotInFlight = (id) => snapshottingIds.value.has(id)

const runningCount = computed(() => containers.value.filter(c => c.status.toLowerCase() === 'running').length)
const stoppedCount = computed(() => containers.value.filter(c => c.status.toLowerCase() !== 'running').length)

const filteredContainers = computed(() => {
  if (!searchQuery.value) return containers.value
  const q = searchQuery.value.toLowerCase()
  return containers.value.filter(c => c.id && c.id.toLowerCase().includes(q))
})

// Poll the container list through the shared usePoll helper (in-flight
// dedup, hidden-tab pause, error backoff); refresh doubles as the
// imperative fetch used after mutations.
// API guarantees [] (never null) for empty lists — regression-locked by
// TestAPI_EmptyListsAreArraysNotNull; assign directly like approvals.vue.
const { refresh: fetchContainers } = usePoll(async () => {
  containers.value = await apiFetch('/api/containers')
}, 2000)

const startContainer = async () => {
  if (!newContainer.value.name) return
  try {
    await apiFetch('/api/containers/start', {
      method: 'POST',
      body: newContainer.value
    })
    newContainer.value.name = ''
    setTimeout(fetchContainers, 500)
  } catch (e) {
    alert(t('pages.index.errStart', { msg: e.message }))
  }
}

const pauseContainer = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/pause`, { method: 'POST' })
    fetchContainers()
  } catch (e) {
    alert(t('pages.index.errPause', { msg: e.message }))
  }
}

const resumeContainer = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/resume`, { method: 'POST' })
    fetchContainers()
  } catch (e) {
    alert(t('pages.index.errResume', { msg: e.message }))
  }
}

const restoreContainer = async () => {
  const name = (newContainer.value.name || '').trim()
  if (!name) {
    alert(t('pages.index.restorePrompt'))
    return
  }
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(name)}/restore`, { method: 'POST' })
    newContainer.value.name = ''
    alert(t('pages.index.restoreOk'))
    setTimeout(fetchContainers, 500)
  } catch (e) {
    alert(t('pages.index.errRestore', { msg: e.message }))
  }
}

const deleteContainer = async (id) => {
  if (!confirm(t('pages.index.confirmDelete', { id }))) return
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(id)}`, { method: 'DELETE' })
    fetchContainers()
  } catch (e) {
    alert(t('pages.index.errDelete', { msg: e.message }))
  }
}

const snapshotContainer = async (id) => {
  if (snapshotInFlight(id)) return
  if (!confirm(t('pages.index.confirmSnap', { id }))) return
  snapshottingIds.value.add(id)
  snapshottingIds.value = new Set(snapshottingIds.value)
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(id)}/snapshot`, { method: 'POST' })
    alert(t('pages.index.snapOk', { id }))
  } catch (e) {
    alert(t('pages.index.errSnap', { msg: e.message }))
  } finally {
    snapshottingIds.value.delete(id)
    snapshottingIds.value = new Set(snapshottingIds.value)
  }
}

</script>
