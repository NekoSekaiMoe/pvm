<template>
  <div>
    <div class="toolbar">
      <div>
        <h1>{{ t('pages.templates.title') }}</h1>
        <p class="muted">{{ t('pages.templates.subtitle') }}</p>
      </div>
      <button class="btn btn-primary" @click="showCreateModal = true">{{ t('pages.templates.btnRegister') }}</button>
    </div>

    <!-- Live build progress (polls GET /api/templates/:id/build) -->
    <div v-if="build" class="glass-card">
      <div class="toolbar">
        <h3>{{ t('pages.templates.build.title', { id: buildId }) }}</h3>
        <span class="pill" :class="buildPillClass">{{ build.phase }}</span>
      </div>
      <div style="margin-top:0.75rem;">
        <div style="display:flex;justify-content:space-between;font-size:0.85rem;margin-bottom:0.35rem;">
          <span class="muted">{{ t('pages.templates.build.phase') }}: <strong>{{ build.phase }}</strong></span>
          <span class="muted">{{ t('pages.templates.build.progress') }}: {{ build.pct ?? 0 }}%</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" :style="{ width: (build.pct ?? 0) + '%' }"></div>
        </div>
      </div>
      <div v-if="buildDone" class="callout ok" style="margin-top:0.75rem;">{{ t('pages.templates.build.ready') }}</div>
      <div v-else-if="buildFailed" class="callout err" style="margin-top:0.75rem;">{{ t('pages.templates.build.failed') }}</div>
      <div v-else-if="buildError" class="callout warn" style="margin-top:0.75rem;">
        {{ t('pages.templates.build.err', { msg: buildError }) }}
      </div>
      <div v-if="build.log_tail" style="margin-top:0.75rem;">
        <button class="btn btn-primary" style="font-size:0.75rem;" @click="showBuildLog = !showBuildLog">
          {{ showBuildLog ? t('pages.templates.build.hideLog') : t('pages.templates.build.showLog') }}
        </button>
        <pre v-if="showBuildLog" class="build-log mono">{{ build.log_tail }}</pre>
      </div>
    </div>

    <!-- Templates Table -->
    <div class="glass-card">
      <div class="toolbar">
        <input v-model="searchQuery" :placeholder="t('pages.templates.searchPh')" class="search-input" />
        <span class="muted" style="font-size:0.875rem;">
          {{ t('pages.templates.totalTemplates', { n: filteredTemplates.length }) }}
        </span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>{{ t('pages.templates.colId') }}</th>
              <th>{{ t('pages.templates.colAlias') }}</th>
              <th>{{ t('pages.templates.colImage') }}</th>
              <th>{{ t('pages.templates.colStatus') }}</th>
              <th>{{ t('pages.templates.colKind') }}</th>
              <th>{{ t('pages.templates.colCreated') }}</th>
              <th>{{ t('pages.templates.colActions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tpl in filteredTemplates" :key="tpl.template_id">
              <td class="mono"><strong>{{ tpl.template_id }}</strong></td>
              <td>
                <span v-if="tpl.alias" class="pill approve">{{ tpl.alias }}</span>
                <span v-else class="muted">—</span>
              </td>
              <td class="mono">{{ tpl.image_ref || tpl.image_path || '—' }}</td>
              <td>
                <span class="badge" :class="statusClass(tpl.status)">
                  {{ tpl.status }}
                </span>
              </td>
              <td><span class="pill allow">{{ tpl.kind || 'template' }}</span></td>
              <td class="timeline-meta">{{ fmt(tpl.created_at) }}</td>
              <td>
                <button class="btn btn-primary" style="font-size:0.8rem;margin-right:0.4rem;" @click="openAliasModal(tpl)">
                  {{ t('pages.templates.btnSetAlias') }}
                </button>
                <button
                  class="btn btn-primary"
                  style="font-size:0.8rem;margin-right:0.4rem;background:var(--accent);"
                  :title="tpl.status === 'FAILED' ? t('pages.templates.btnRebuild') : t('pages.templates.btnBuild')"
                  @click="startBuild(tpl)"
                >
                  {{ tpl.status === 'FAILED' ? t('pages.templates.btnRebuild') : t('pages.templates.btnBuild') }}
                </button>
                <button class="btn btn-danger" style="font-size:0.8rem;" @click="deleteTemplate(tpl.template_id)">
                  {{ t('common.delete') }}
                </button>
              </td>
            </tr>
            <tr v-if="filteredTemplates.length === 0">
              <td colspan="7" class="muted" style="text-align:center;padding:2rem;">{{ t('pages.templates.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreateModal" class="modal-backdrop">
      <div class="modal-box">
        <h3>{{ t('pages.templates.createTitle') }}</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">{{ t('pages.templates.createSub') }}</p>

        <div class="form-row full">
          <label class="section-title" for="template-image-ref">{{ t('pages.templates.createImageLabel') }}</label>
          <input id="template-image-ref" v-model="createForm.image_ref" :placeholder="t('pages.templates.createImagePh')" />
        </div>

        <div v-if="createError" class="callout err">{{ createError }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="showCreateModal = false">{{ t('common.cancel') }}</button>
          <button class="btn btn-primary" @click="createTemplate">{{ t('common.save') }}</button>
        </div>
      </div>
    </div>

    <!-- Set Alias Modal -->
    <div v-if="selectedTemplate" class="modal-backdrop">
      <div class="modal-box">
        <h3>{{ t('pages.templates.aliasTitle') }}</h3>
        <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">
          {{ t('pages.templates.aliasSub') }} <span class="mono">{{ selectedTemplate.template_id }}</span>
        </p>

        <div class="form-row full">
          <label class="section-title" for="template-new-alias">{{ t('pages.templates.aliasLabel') }}</label>
          <input id="template-new-alias" v-model="aliasInput" :placeholder="t('pages.templates.aliasPh')" />
        </div>

        <div v-if="aliasError" class="callout err">{{ aliasError }}</div>

        <div style="display:flex;justify-content:flex-end;gap:1rem;margin-top:1.5rem;">
          <button class="btn btn-danger" @click="selectedTemplate = null">{{ t('common.cancel') }}</button>
          <button class="btn btn-primary" @click="saveAlias">{{ t('pages.templates.btnSaveAlias') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onUnmounted } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t, locale } = useI18n()

const templates = ref([])
const searchQuery = ref('')
const showCreateModal = ref(false)
const createError = ref('')
const createForm = ref({ image_ref: '' })

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
  if (st === 'PENDING' || st === 'BUILDING') return 'provisioning'
  return 'failed'
}

// --- Build pipeline: after registering (or rebuilding) a template, poll
// GET /api/templates/:id/build until phase reaches done/failed, then
// refresh the list. A single timer is enough: only one build is tracked.
const buildId = ref('')
const build = ref(null)
const buildError = ref('')
const showBuildLog = ref(false)
let buildTimer = null
// Polling generation token: clearTimeout cannot cancel an in-flight
// apiFetch. Every stop/start invalidates older epochs so a late response
// from a previous build neither writes stale state nor re-arms the timer
// (it must not stop a NEWER build's polling either).
let buildPollEpoch = 0

const buildDone = computed(() => build.value && (build.value.phase === 'done' || build.value.phase === 'READY'))
const buildFailed = computed(() => build.value && (build.value.phase === 'failed' || build.value.phase === 'FAILED'))
const buildPillClass = computed(() => {
  if (buildFailed.value) return 'deny'
  if (buildDone.value) return 'allow'
  return 'approve'
})

const stopBuildPolling = () => {
  buildPollEpoch++
  if (buildTimer) { clearTimeout(buildTimer); buildTimer = null }
}

const startBuildPolling = (id) => {
  stopBuildPolling()
  const epoch = buildPollEpoch
  buildId.value = id
  build.value = { phase: 'queued', pct: 0, log_tail: '' }
  buildError.value = ''
  showBuildLog.value = false
  let fails = 0
  // Serial setTimeout chain (not setInterval): the next poll is scheduled
  // only after the previous request settles, so a slow API never piles up
  // concurrent requests; repeated failures end the poll instead of hitting
  // a stuck/removed template every 1.5s forever.
  const tick = async () => {
    if (epoch !== buildPollEpoch) return
    if (typeof document !== 'undefined' && document.hidden) {
      buildTimer = setTimeout(tick, 1500)
      return
    }
    try {
      const r = await apiFetch(`/api/templates/${encodeURIComponent(id)}/build`)
      if (epoch !== buildPollEpoch) return
      build.value = r || {}
      buildError.value = ''
      fails = 0
      if (buildDone.value || buildFailed.value) {
        stopBuildPolling()
        refresh()
        return
      }
    } catch (e) {
      if (epoch !== buildPollEpoch) return
      // Transient errors surface as a warning line but keep the poll alive;
      // a stuck/removed template ends the poll after repeated failures.
      buildError.value = e.message
      if (++fails >= 5) {
        stopBuildPolling()
        return
      }
    }
    if (epoch !== buildPollEpoch) return
    buildTimer = setTimeout(tick, 1500)
  }
  buildTimer = setTimeout(tick, 1500)
}

onUnmounted(stopBuildPolling)

const createTemplate = async () => {
  createError.value = ''
  if (!createForm.value.image_ref) {
    createError.value = t('pages.templates.createRequired')
    return
  }
  try {
    const r = await apiFetch('/api/templates', {
      method: 'POST',
      body: createForm.value
    })
    showCreateModal.value = false
    createForm.value = { image_ref: '' }
    // New templates transition PENDING → BUILDING → READY|FAILED server-side;
    // attach the live progress card to the created id.
    const id = r && (r.template_id || r.id)
    if (id) startBuildPolling(id)
    refresh()
  } catch (e) {
    createError.value = e.message
  }
}

const startBuild = async (tmpl) => {
  try {
    await apiFetch(`/api/templates/${encodeURIComponent(tmpl.template_id)}/rebuild`, { method: 'POST' })
    startBuildPolling(tmpl.template_id)
  } catch (e) {
    alert(t('common.error', { msg: e.message }))
  }
}

const openAliasModal = (tmpl) => {
  selectedTemplate.value = tmpl
  aliasInput.value = tmpl.alias || ''
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
  if (!confirm(t('pages.templates.confirmDelete', { id }))) return
  try {
    await apiFetch(`/api/templates/${encodeURIComponent(id)}`, { method: 'DELETE' })
    refresh()
  } catch (e) {
    alert(t('pages.templates.errDelete', { msg: e.message }))
  }
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString(locale.value) : '—'
</script>

<style scoped>
.progress-track {
  height: 10px;
  border-radius: 999px;
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--glass-border);
  overflow: hidden;
}
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--primary), var(--success));
  border-radius: 999px;
  transition: width 0.4s ease;
}
.build-log {
  margin: 0.75rem 0 0;
  background: rgba(0, 0, 0, 0.5);
  border: 1px solid var(--glass-border);
  border-radius: 0.5rem;
  padding: 0.75rem;
  font-size: 0.78rem;
  line-height: 1.4;
  white-space: pre-wrap;
  max-height: 200px;
  overflow-y: auto;
}
</style>
