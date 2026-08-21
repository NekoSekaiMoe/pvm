<template>
  <div>
    <div class="toolbar">
      <div>
        <h1>Template Center</h1>
        <p class="muted">Immutable rootfs templates and snapshot catalog. Aliases allow dynamic resolution (e.g. <code>latest</code>).</p>
      </div>
      <button class="btn btn-primary" @click="showCreateModal = true">+ Register Template</button>
    </div>

    <!-- Templates Table -->
    <div class="glass-card">
      <div class="toolbar">
        <input v-model="searchQuery" placeholder="Search templates by ID, alias, or image..." class="search-input" />
        <span class="muted" style="font-size:0.875rem;">Total: {{ filteredTemplates.length }} template(s)</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Template ID</th>
              <th>Alias</th>
              <th>Image Reference</th>
              <th>Status</th>
              <th>Kind</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in filteredTemplates" :key="t.template_id">
              <td class="mono"><strong>{{ t.template_id }}</strong></td>
              <td>
                <span v-if="t.alias" class="pill approve">{{ t.alias }}</span>
                <span v-else class="muted">—</span>
              </td>
              <td class="mono">{{ t.image_ref || t.image_path || '—' }}</td>
              <td>
                <span class="badge" :class="statusClass(t.status)">
                  {{ t.status }}
                </span>
              </td>
              <td><span class="pill allow">{{ t.kind || 'template' }}</span></td>
              <td class="timeline-meta">{{ fmt(t.created_at) }}</td>
              <td>
                <button class="btn btn-primary" style="font-size:0.8rem;margin-right:0.4rem;" @click="openAliasModal(t)">
                  Set Alias
                </button>
                <button class="btn btn-danger" style="font-size:0.8rem;" @click="deleteTemplate(t.template_id)">
                  Delete
                </button>
              </td>
            </tr>
            <tr v-if="filteredTemplates.length === 0">
              <td colspan="7" class="muted" style="text-align:center;padding:2rem;">No templates found.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreateModal" class="modal-backdrop">
      <div class="modal-box">
        <h3>Register Sandbox Template</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Register a base image reference to produce a reusable template.</p>
        
        <div class="form-row full">
          <label class="section-title">Image Reference (Docker Hub / rootfs)</label>
          <input v-model="createForm.image_ref" placeholder="e.g. alpine:3.19 or ubuntu:22.04" />
        </div>
        <div class="form-row full">
          <label class="section-title">Initial Alias (Optional)</label>
          <input v-model="createForm.alias" placeholder="e.g. python-default" />
        </div>

        <div v-if="createError" class="callout err">{{ createError }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="showCreateModal = false">Cancel</button>
          <button class="btn btn-primary" @click="createTemplate">Register</button>
        </div>
      </div>
    </div>

    <!-- Set Alias Modal -->
    <div v-if="selectedTemplate" class="modal-backdrop">
      <div class="modal-box">
        <h3>Set Template Alias</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">Template: <span class="mono">{{ selectedTemplate.template_id }}</span></p>
        
        <div class="form-row full">
          <label class="section-title">New Alias (e.g. <code>stable</code>, <code>v1</code>)</label>
          <input v-model="aliasInput" placeholder="Enter alphanumeric alias..." />
        </div>

        <div v-if="aliasError" class="callout err">{{ aliasError }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="selectedTemplate = null">Cancel</button>
          <button class="btn btn-primary" @click="saveAlias">Save Alias</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'

const templates = ref([])
const searchQuery = ref('')
const showCreateModal = ref(false)
const createError = ref('')
const createForm = ref({ image_ref: '', alias: '' })

const selectedTemplate = ref(null)
const aliasInput = ref('')
const aliasError = ref('')

const { refresh } = usePoll(async () => {
  const res = await apiFetch('/api/templates')
  templates.value = res || []
  return templates.value
}, 2500)

const filteredTemplates = computed(() => {
  if (!searchQuery.value) return templates.value
  const q = searchQuery.value.toLowerCase()
  return templates.value.filter(t => 
    (t.template_id && t.template_id.toLowerCase().includes(q)) ||
    (t.alias && t.alias.toLowerCase().includes(q)) ||
    (t.image_ref && t.image_ref.toLowerCase().includes(q))
  )
})

const statusClass = (st) => {
  if (st === 'READY') return 'running'
  if (st === 'PENDING') return 'provisioning'
  return 'failed'
}

const createTemplate = async () => {
  createError.value = ''
  if (!createForm.value.image_ref) {
    createError.value = 'Image reference is required'
    return
  }
  try {
    await apiFetch('/api/templates', {
      method: 'POST',
      body: createForm.value
    })
    showCreateModal.value = false
    createForm.value = { image_ref: '', alias: '' }
    refresh()
  } catch (e) {
    createError.value = e.message
  }
}

const openAliasModal = (t) => {
  selectedTemplate.value = t
  aliasInput.value = t.alias || ''
  aliasError.value = ''
}

const saveAlias = async () => {
  aliasError.value = ''
  if (!selectedTemplate.value) return
  try {
    await apiFetch(`/api/templates/${encodeURIComponent(selectedTemplate.value.template_id)}/alias`, {
      method: 'POST',
      body: { alias: aliasInput.value }
    })
    selectedTemplate.value = null
    refresh()
  } catch (e) {
    aliasError.value = e.message
  }
}

const deleteTemplate = async (id) => {
  if (!confirm(`Delete template ${id}?`)) return
  try {
    await apiFetch(`/api/templates/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    })
    refresh()
  } catch (e) {
    alert(`Error deleting template: ${e.message}`)
  }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '—'
</script>
