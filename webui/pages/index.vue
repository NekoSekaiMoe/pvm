<template>
  <div>
    <h1>Containers Dashboard</h1>
    <p class="muted">Manage standalone UML container instances and snapshots.</p>

    <!-- Quick Stats -->
    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-value">{{ runningCount }}</div>
        <div class="stat-label">Running Instances</div>
      </div>
      <div class="stat-tile">
        <div class="stat-value">{{ stoppedCount }}</div>
        <div class="stat-label">Stopped / Exited</div>
      </div>
      <div class="stat-tile">
        <div class="stat-value">{{ containers.length }}</div>
        <div class="stat-label">Total Registered</div>
      </div>
    </div>
    
    <!-- Launch Form -->
    <div class="glass-card">
      <h3>Launch New Container</h3>
      <div class="form-row">
        <div>
          <label class="section-title">Container Name</label>
          <input v-model="newContainer.name" placeholder="e.g. web-node-1" />
        </div>
        <div>
          <label class="section-title">Rootfs Image</label>
          <input v-model="newContainer.rootfs" placeholder="rootfs.img or alpine" />
        </div>
      </div>
      <div class="form-row">
        <div>
          <label class="section-title">Memory Allocation</label>
          <input v-model="newContainer.mem" placeholder="512M or 1G" />
        </div>
        <div>
          <label class="section-title">CPU Millicpu (0 = unlimited)</label>
          <input v-model.number="newContainer.cpu" type="number" placeholder="1000" />
        </div>
      </div>
      
      <div style="display:flex;gap:1rem;margin-top:1rem;">
        <button class="btn btn-primary" @click="startContainer">Launch Container</button>
        <button class="btn btn-primary" @click="restoreContainer" style="background:var(--success);">Restore from Snapshot</button>
      </div>
    </div>

    <!-- Containers List -->
    <div class="glass-card">
      <div class="toolbar">
        <input v-model="searchQuery" placeholder="Search containers..." class="search-input" />
        <span class="muted" style="font-size:0.875rem;">Total: {{ filteredContainers.length }}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID / Name</th>
              <th>Status</th>
              <th>PID</th>
              <th>Actions</th>
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
                <NuxtLink :to="`/logs/${c.id}`" class="btn btn-primary" style="margin-right:0.4rem;text-decoration:none;font-size:0.8rem;">Logs</NuxtLink>
                <button 
                  v-if="c.status.toLowerCase() === 'running'" 
                  class="btn btn-danger" 
                  style="margin-right:0.4rem;font-size:0.8rem;" 
                  @click="pauseContainer(c.id)"
                >
                  Pause
                </button>
                <button 
                  v-if="c.status.toLowerCase() === 'suspended'" 
                  class="btn btn-primary" 
                  style="margin-right:0.4rem;font-size:0.8rem;background:var(--success);" 
                  @click="resumeContainer(c.id)"
                >
                  Resume
                </button>
                <button 
                  class="btn btn-primary" 
                  @click="snapshotContainer(c.id)" 
                  :disabled="snapshotInFlight(c.id)" 
                  style="margin-right:0.4rem;background:var(--success);font-size:0.8rem;"
                >
                  {{ snapshotInFlight(c.id) ? 'Saving...' : 'Snapshot' }}
                </button>
                <button class="btn btn-danger" style="font-size:0.8rem;" @click="deleteContainer(c.id)">Delete</button>
              </td>
            </tr>
            <tr v-if="filteredContainers.length === 0">
              <td colspan="4" class="muted" style="text-align:center;padding:2rem;">No containers found.</td>
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
    alert(`Error starting container: ${e.message}`)
  }
}

const pauseContainer = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/pause`, { method: 'POST' })
    fetchContainers()
  } catch (e) {
    alert(`Pause error: ${e.message}`)
  }
}

const resumeContainer = async (id) => {
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(id)}/resume`, { method: 'POST' })
    fetchContainers()
  } catch (e) {
    alert(`Resume error: ${e.message}`)
  }
}

const restoreContainer = async () => {
  const name = (newContainer.value.name || '').trim()
  if (!name) {
    alert("Please enter the original container name to restore from")
    return
  }
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(name)}/restore`, { method: 'POST' })
    newContainer.value.name = ''
    alert("Container restored successfully!")
    setTimeout(fetchContainers, 500)
  } catch (e) {
    alert(`Error restoring container: ${e.message}`)
  }
}

const deleteContainer = async (id) => {
  if (!confirm(`Delete container ${id}?`)) return
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(id)}`, { method: 'DELETE' })
    fetchContainers()
  } catch (e) {
    alert(`Error deleting container: ${e.message}`)
  }
}

const snapshotContainer = async (id) => {
  if (snapshotInFlight(id)) return
  if (!confirm(`Snapshot container ${id}?`)) return
  snapshottingIds.value.add(id)
  snapshottingIds.value = new Set(snapshottingIds.value)
  try {
    await apiFetch(`/api/containers/${encodeURIComponent(id)}/snapshot`, { method: 'POST' })
    alert(`Snapshot for ${id} created successfully!`)
  } catch (e) {
    alert(`Error creating snapshot: ${e.message}`)
  } finally {
    snapshottingIds.value.delete(id)
    snapshottingIds.value = new Set(snapshottingIds.value)
  }
}

</script>
