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
                <button class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;margin-right:0.3rem;" @click="snapshotVolumePrompt(v.volume_id)">
                  📸 Snapshot
                </button>
                <button class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;margin-right:0.3rem;" @click="cloneVolumePrompt(v.volume_id)">
                  🐑 Clone
                </button>
                <button class="btn btn-primary" style="font-size:0.75rem;padding:0.3rem 0.5rem;margin-right:0.3rem;background:var(--accent);" @click="rollbackVolumePrompt(v.volume_id)">
                  ↩ Rollback
                </button>
                <button class="btn btn-danger" style="font-size:0.75rem;padding:0.3rem 0.5rem;" @click="deleteVolume(v.volume_id)" :disabled="v.refcount > 0" :title="v.refcount > 0 ? 'Cannot delete mounted volume' : 'Delete volume'">
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

    <!-- Snapshot Modal -->
    <div v-if="snapshotModalVolume" ref="snapshotModalEl" class="modal-backdrop" role="dialog" aria-modal="true" tabindex="-1" @keydown.esc="snapshotModalVolume = null">
      <div class="modal-box">
        <h3>Snapshot Volume — {{ snapshotModalVolume }}</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Branch an instant Copy-on-Write snapshot of this volume (stored as snap-&lt;name&gt;.qcow2 by the cow engine).</p>

        <div class="form-row full">
          <label class="section-title" for="snapshot-name">Snapshot Name</label>
          <input id="snapshot-name" v-model="snapshotName" placeholder="e.g. pre-migration (leave empty to auto-generate)" />
        </div>

        <div v-if="snapshotError" class="callout err">{{ snapshotError }}</div>
        <div v-if="snapshotSuccess" class="callout allow" style="color:var(--success, #4ade80);background:rgba(74,222,128,0.1);padding:0.75rem;border-radius:0.5rem;margin-top:1rem;">{{ snapshotSuccess }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="snapshotModalVolume = null">Close</button>
          <button class="btn btn-primary" @click="executeSnapshotVolume">Create Snapshot</button>
        </div>
      </div>
    </div>

    <!-- Clone Modal -->
    <div v-if="cloneModalVolume" ref="cloneModalEl" class="modal-backdrop" role="dialog" aria-modal="true" tabindex="-1" @keydown.esc="cloneModalVolume = null">
      <div class="modal-box">
        <h3>Clone Volume — {{ cloneModalVolume }}</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Create an instant Copy-on-Write branch of this persistent volume.</p>
        
        <div class="form-row full">
          <label class="section-title" for="clone-vol-id">New Volume ID</label>
          <input id="clone-vol-id" v-model="cloneTargetID" placeholder="e.g. workspace-data-clone" />
        </div>

        <div v-if="cloneError" class="callout err">{{ cloneError }}</div>
        <div v-if="cloneSuccess" class="callout allow" style="color:var(--success, #4ade80);background:rgba(74,222,128,0.1);padding:0.75rem;border-radius:0.5rem;margin-top:1rem;">{{ cloneSuccess }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="cloneModalVolume = null">Close</button>
          <button class="btn btn-primary" @click="executeCloneVolume">Clone</button>
        </div>
      </div>
    </div>

    <!-- Rollback Modal -->
    <div v-if="rollbackModalVolume" ref="rollbackModalEl" class="modal-backdrop" role="dialog" aria-modal="true" tabindex="-1" @keydown.esc="rollbackModalVolume = null">
      <div class="modal-box">
        <h3>Rollback Volume — {{ rollbackModalVolume }}</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Restore volume to a previously created snapshot point.</p>
        
        <div class="form-row full">
          <label class="section-title" for="rollback-snap-id">Snapshot Name</label>
          <input id="rollback-snap-id" v-model="rollbackSnapName" placeholder="snapshot name, e.g. pre-migration" />
        </div>
        <div v-if="rollbackSnapshots.length" class="form-row full">
          <span class="muted" style="font-size:0.8rem;">Available snapshots (click to select):</span>
          <div style="display:flex;flex-wrap:wrap;gap:0.4rem;margin-top:0.4rem;">
            <button v-for="s in rollbackSnapshots" :key="s.name" type="button" class="pill allow" style="cursor:pointer;font-size:0.75rem;" :style="rollbackSnapName === s.name ? 'outline:2px solid var(--accent);' : ''" @click="rollbackSnapName = s.name">
              {{ s.name }}
            </button>
          </div>
        </div>
        <p v-else-if="!rollbackSnapshotsLoading" class="muted" style="font-size:0.8rem;">No snapshots found for this volume — create one with the 📸 Snapshot action first.</p>

        <div v-if="rollbackError" class="callout err">{{ rollbackError }}</div>
        <div v-if="rollbackSuccess" class="callout allow" style="color:var(--success, #4ade80);background:rgba(74,222,128,0.1);padding:0.75rem;border-radius:0.5rem;margin-top:1rem;">{{ rollbackSuccess }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="rollbackModalVolume = null">Close</button>
          <button class="btn btn-primary" @click="executeRollbackVolume">Rollback</button>
        </div>
      </div>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreateModal" class="modal-backdrop">
      <div class="modal-box">
        <h3>Create Persistent Volume</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Register a storage volume backed by builtin hostfs or external driver plugin.</p>
        
        <div class="form-row full">
          <label class="section-title" for="vol-name">Volume Name / ID</label>
          <input id="vol-name" v-model="form.name" placeholder="e.g. workspace-data-1" />
        </div>
        <div class="form-row full">
          <label class="section-title" for="vol-driver">Driver Type</label>
          <select id="vol-driver" v-model="form.driver" style="background:rgba(0,0,0,0.3);color:white;border:1px solid var(--glass-border);padding:0.75rem;border-radius:0.5rem;width:100%;">
            <option value="builtin">builtin (hostfs directory)</option>
            <option value="nfs">nfs (external plugin)</option>
            <option value="s3">s3 (cloud bucket)</option>
          </select>
        </div>
        <div class="form-row full">
          <label class="section-title" for="vol-token">Auth Token (Optional, masked in API)</label>
          <input id="vol-token" v-model="form.token" type="password" placeholder="Access token for remote storage plugin" />
        </div>
        <div class="form-row full">
          <label class="section-title" for="vol-private-data">Private Configuration Data (Optional)</label>
          <input id="vol-private-data" v-model="form.private_data" placeholder="JSON or config string for plugin" />
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
import { ref, computed, nextTick } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const volumes = ref([])
const searchQuery = ref('')
const showCreateModal = ref(false)
const errorMsg = ref('')

const snapshotModalVolume = ref(null)
const snapshotModalEl = ref(null)
const snapshotName = ref('')
const snapshotError = ref('')
const snapshotSuccess = ref('')

const cloneModalVolume = ref(null)
const cloneModalEl = ref(null)
const cloneTargetID = ref('')
const cloneError = ref('')
const cloneSuccess = ref('')

const rollbackModalVolume = ref(null)
const rollbackModalEl = ref(null)
const rollbackSnapName = ref('')
const rollbackError = ref('')
const rollbackSuccess = ref('')
const rollbackSnapshots = ref([])
const rollbackSnapshotsLoading = ref(false)

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

const snapshotVolumePrompt = (id) => {
  snapshotModalVolume.value = id
  snapshotName.value = ''
  snapshotError.value = ''
  snapshotSuccess.value = ''
  // Focus the dialog container so keyboard events (Esc) reach it
  // immediately — without this, focus stays on the trigger button outside
  // the backdrop and @keydown.esc never fires.
  nextTick(() => snapshotModalEl.value?.focus())
}

const executeSnapshotVolume = async () => {
  snapshotError.value = ''
  snapshotSuccess.value = ''
  // An empty name is valid: the server auto-generates one
  // (POST /api/volumes/:id/snapshots). Only let the server reject
  // genuinely invalid input.
  try {
    const res = await apiFetch(`/api/volumes/${encodeURIComponent(snapshotModalVolume.value)}/snapshots`, {
      method: 'POST',
      body: { snapshot: snapshotName.value }
    })
    const name = (res && res.snapshot) || snapshotName.value || '(auto-generated)'
    snapshotSuccess.value = `Snapshot "${name}" created for ${snapshotModalVolume.value}`
    refresh()
  } catch (e) {
    snapshotError.value = e.message
  }
}

const cloneVolumePrompt = (id) => {
  cloneModalVolume.value = id
  cloneTargetID.value = `${id}-cloned`
  cloneError.value = ''
  cloneSuccess.value = ''
  nextTick(() => cloneModalEl.value?.focus())
}

const executeCloneVolume = async () => {
  cloneError.value = ''
  cloneSuccess.value = ''
  if (!cloneTargetID.value) {
    cloneError.value = 'Target volume ID is required'
    return
  }
  try {
    await apiFetch(`/api/volumes/${encodeURIComponent(cloneModalVolume.value)}/clone`, {
      method: 'POST',
      body: { new_id: cloneTargetID.value }
    })
    cloneSuccess.value = `Successfully cloned to ${cloneTargetID.value}`
    refresh()
  } catch (e) {
    cloneError.value = e.message
  }
}

const rollbackVolumePrompt = async (id) => {
  rollbackModalVolume.value = id
  // Snapshot names are engine-global, NOT prefixed with the volume id —
  // start empty and offer the volume's real snapshots for one-click pick.
  rollbackSnapName.value = ''
  rollbackError.value = ''
  rollbackSuccess.value = ''
  nextTick(() => rollbackModalEl.value?.focus())
  rollbackSnapshots.value = []
  rollbackSnapshotsLoading.value = true
  try {
    const snaps = await apiFetch(`/api/volumes/${encodeURIComponent(id)}/snapshots`)
    rollbackSnapshots.value = (snaps || []).filter(s => s.origin_volume === id)
  } catch {
    // Listing is a convenience hint; rollback still works with a typed name.
  } finally {
    rollbackSnapshotsLoading.value = false
  }
}

const executeRollbackVolume = async () => {
  rollbackError.value = ''
  rollbackSuccess.value = ''
  if (!rollbackSnapName.value) {
    rollbackError.value = 'Snapshot name is required'
    return
  }
  try {
    await apiFetch(`/api/volumes/${encodeURIComponent(rollbackModalVolume.value)}/rollback`, {
      method: 'POST',
      body: { snapshot: rollbackSnapName.value }
    })
    rollbackSuccess.value = `Successfully rolled back volume ${rollbackModalVolume.value} to ${rollbackSnapName.value}`
    refresh()
  } catch (e) {
    rollbackError.value = e.message
  }
}

const deleteVolume = async (id) => {
  if (!confirm(`Are you sure you want to delete volume ${id}?`)) return
  try {
    await apiFetch(`/api/volumes/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    })
    refresh()
  } catch (e) {
    alert(`Delete error: ${e.message}`)
  }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '—'
</script>
