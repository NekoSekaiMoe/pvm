<template>
  <div>
    <div class="toolbar">
      <div>
        <h1>Persistent Volumes</h1>
        <p class="muted">Storage volume registry (plan.md §11). Mountable into sandboxes via hostfs/virtio drivers.</p>
      </div>
      <button class="btn btn-primary" @click="showCreateModal = true">+ Create Volume</button>
    </div>

    <!-- Volumes Table -->
    <div class="glass-card">
      <div class="toolbar">
        <input v-model="searchQuery" placeholder="Search volumes..." class="search-input" />
        <span class="muted" style="font-size:0.875rem;">Total: {{ filteredVolumes.length }} volume(s)</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Volume ID</th>
              <th>Name</th>
              <th>Driver</th>
              <th>Ref Count</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in filteredVolumes" :key="v.volume_id">
              <td class="mono"><strong>{{ v.volume_id }}</strong></td>
              <td>{{ v.name }}</td>
              <td><span class="pill allow">{{ v.driver || 'builtin' }}</span></td>
              <td>
                <span class="badge" :class="v.refcount > 0 ? 'running' : 'pending'">
                  {{ v.refcount }} mount(s)
                </span>
              </td>
              <td class="timeline-meta">{{ fmt(v.created_at) }}</td>
              <td>
                <button class="btn btn-danger" style="font-size:0.8rem;" @click="deleteVolume(v.volume_id)" :disabled="v.refcount > 0" :title="v.refcount > 0 ? 'Cannot delete mounted volume' : 'Delete volume'">
                  Delete
                </button>
              </td>
            </tr>
            <tr v-if="filteredVolumes.length === 0">
              <td colspan="6" class="muted" style="text-align:center;padding:2rem;">No persistent volumes found.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreateModal" class="modal-backdrop">
      <div class="modal-box">
        <h3>Create Persistent Volume</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Register a storage volume backed by builtin hostfs or external driver plugin.</p>
        
        <div class="form-row full">
          <label class="section-title">Volume Name / ID</label>
          <input v-model="form.name" placeholder="e.g. workspace-data-1" />
        </div>
        <div class="form-row full">
          <label class="section-title">Driver Type</label>
          <select v-model="form.driver" style="background:rgba(0,0,0,0.3);color:white;border:1px solid var(--glass-border);padding:0.75rem;border-radius:0.5rem;width:100%;">
            <option value="builtin">builtin (hostfs directory)</option>
            <option value="nfs">nfs (external plugin)</option>
            <option value="s3">s3 (cloud bucket)</option>
          </select>
        </div>
        <div class="form-row full">
          <label class="section-title">Auth Token (Optional, masked in API)</label>
          <input v-model="form.token" type="password" placeholder="Access token for remote storage plugin" />
        </div>
        <div class="form-row full">
          <label class="section-title">Private Configuration Data (Optional)</label>
          <input v-model="form.private_data" placeholder="JSON or config string for plugin" />
        </div>

        <div v-if="errorMsg" class="callout err">{{ errorMsg }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="showCreateModal = false">Cancel</button>
          <button class="btn btn-primary" @click="createVolume">Create</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const volumes = ref([])
const searchQuery = ref('')
const showCreateModal = ref(false)
const errorMsg = ref('')

const form = ref({
  name: '',
  driver: 'builtin',
  token: '',
  private_data: ''
})

const { refresh } = usePoll(async () => {
  const res = await apiFetch('/api/volumes')
  volumes.value = res || []
  return volumes.value
}, 2500)

const filteredVolumes = computed(() => {
  if (!searchQuery.value) return volumes.value
  const q = searchQuery.value.toLowerCase()
  return volumes.value.filter(v => 
    (v.volume_id && v.volume_id.toLowerCase().includes(q)) ||
    (v.name && v.name.toLowerCase().includes(q)) ||
    (v.driver && v.driver.toLowerCase().includes(q))
  )
})

const createVolume = async () => {
  errorMsg.value = ''
  if (!form.value.name) {
    errorMsg.value = 'Volume name is required'
    return
  }
  try {
    await apiFetch('/api/volumes', {
      method: 'POST',
      body: form.value
    })
    showCreateModal.value = false
    form.value = { name: '', driver: 'builtin', token: '', private_data: '' }
    refresh()
  } catch (e) {
    errorMsg.value = e.message
  }
}

const deleteVolume = async (id) => {
  if (!confirm(`Delete persistent volume ${id}?`)) return
  try {
    await apiFetch(`/api/volumes/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    })
    refresh()
  } catch (e) {
    alert(`Error deleting volume: ${e.message}`)
  }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '—'
</script>
