<template>
  <div>
    <h1>Ephemeral Sandboxes</h1>
    <p class="muted">
      Non-persistent task sandboxes (<span class="mono">workspace.ephemeral</span>): the rootfs boots
      read-only (kernel <span class="mono">ro</span> + read-only block backend), no qcow2 overlay is
      ever created, and guest scratch lives on tmpfs — writes to the read-only rootfs or to tmpfs
      scratch never reach the host disk. Exception: declared writable persistent volumes are
      user-intent mounts whose writes DO reach host storage and are retained after the task exits.
    </p>

    <!-- Builder form -->
    <div class="glass-card">
      <h3>Build an Ephemeral TaskSpec</h3>

      <div class="form-row">
        <div class="input-group">
          <input v-model="form.caller" placeholder="caller (who authorizes, e.g. alice)" />
          <input v-model="form.tenant" placeholder="tenant (quota scope, optional)" />
        </div>
      </div>

      <div class="form-row">
        <div>
          <div class="input-group">
            <input v-model="form.name" placeholder="task name (runtime.name)" />
            <input v-model="form.memory" placeholder="memory, e.g. 512M" />
            <input v-model="form.cpu" placeholder="cpu millicores, e.g. 1000" />
          </div>
          <p v-if="cpuError" class="field-error">{{ cpuError }}</p>
        </div>
      </div>

      <div class="form-row">
        <div class="input-group">
          <input v-model="form.baseImage" placeholder="base image (workspace.base_image, e.g. rootfs.img)" />
          <input v-model="form.init" placeholder="guest init (workspace.init, e.g. /init.sh)" />
          <input v-model="form.kernel" placeholder="kernel path (kernel.path)" />
        </div>
      </div>

      <div class="form-row">
        <div class="input-group">
          <label class="check">
            <input type="checkbox" v-model="form.ephemeral" />
            <span>ephemeral — read-only rootfs, no overlay, tmpfs scratch</span>
          </label>
          <label class="check">
            <input type="checkbox" v-model="form.vhost" />
            <span>use_vhost_blk — vhost-user-blk backend (read-only serving)</span>
          </label>
        </div>
      </div>

      <!-- Persistent volumes: allowed in ephemeral mode, preserved after exit -->
      <div class="form-row">
        <div>
          <h4 class="muted" style="margin-bottom:0.5rem;">
            Persistent volumes <span class="pill allow">attached &amp; preserved in ephemeral mode</span>
          </h4>
          <div v-for="(v, i) in form.volumes" :key="i" class="input-group" style="margin-bottom:0.5rem;">
            <input v-model="v.name" placeholder="volume name" />
            <input v-model="v.path" placeholder="guest mount path, e.g. /workspace" />
            <label class="check"><input type="checkbox" v-model="v.readOnly" /> ro</label>
            <button class="btn btn-danger" style="font-size:0.75rem;padding:0.3rem 0.6rem;" @click="form.volumes.splice(i, 1)">✕</button>
          </div>
          <button class="btn btn-primary" style="font-size:0.8rem;" @click="form.volumes.push({ name: '', path: '', readOnly: false })">+ Volume</button>
        </div>
      </div>
    </div>

    <!-- Generated TOML -->
    <div class="glass-card">
      <div class="toolbar">
        <h3>Generated TaskSpec (TOML)</h3>
        <div class="input-group">
          <button class="btn btn-primary" @click="validate">Validate / Fingerprint</button>
          <button class="btn btn-primary" @click="copyToml">Copy TOML</button>
        </div>
      </div>
      <textarea class="mono" :value="toml" rows="22" readonly spellcheck="false"></textarea>
      <div v-if="fingerprint" class="callout ok">
        <strong>Valid.</strong> Fingerprint: <span class="mono">{{ fingerprint }}</span>
      </div>
      <div v-if="specError" class="callout err"><strong>Invalid:</strong> {{ specError }}</div>
    </div>

    <!-- Launch cheatsheet -->
    <div class="glass-card">
      <h3>Launch</h3>
      <p class="muted" style="margin-bottom:0.75rem;">
        The API validates specs but launches happen on the host. Equivalent commands:
      </p>
      <pre class="mono" style="white-space:pre-wrap;"># agentpvm (full control plane)
agentpvm run -config ephemeral-task.toml
agentpvm run -config ephemeral-task.toml -ephemeral=false   # one-off persistent run

# umlctl thin launcher (read-only rootfs + state discard)
umlctl start -name ephemeral-task -rootfs {{ form.baseImage || 'rootfs.img' }} -ephemeral -rm

# REST (legacy container path; field accepted by POST /api/containers/start)
curl -X POST "$PVM_API/api/containers/start" \
  -H "Authorization: Bearer $API_SECRET" -H "Content-Type: application/json" \
  -d '{"name":"ephemeral-web","rootfs":"/var/lib/uml-container/images/rootfs.img","ephemeral":true}'</pre>
      <p class="muted">
        Guest writable paths must be tmpfs — use the reference init
        <span class="mono">uml/init-ephemeral.sh</span> (mounts /tmp, /var/tmp, /run, /dev/shm).
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { apiFetch } from '~/composables/useApi'

const form = ref({
  caller: 'alice',
  tenant: '',
  name: 'ephemeral-task',
  memory: '512M',
  cpu: '1000',
  baseImage: 'rootfs.img',
  init: '/init.sh',
  kernel: './bin/linux',
  ephemeral: true,
  vhost: true,
  volumes: []
})

const fingerprint = ref('')
const specError = ref('')

// cpu keeps the user's RAW input (no number coercion): "1000m", "1.5" or
// "abc" stay visible and rejectable instead of being silently coerced by
// parseInt ("1.5" -> 1, "abc" -> 0 = unlimited). Only a complete decimal
// integer is valid; anything else shows a field error and is emitted
// verbatim into the TOML so /api/tasks/load-spec rejects the spec.
const cpuRaw = computed(() => (form.value.cpu || '').trim())
const cpuError = computed(() => {
  if (cpuRaw.value === '') return ''
  return /^\d+$/.test(cpuRaw.value)
    ? ''
    : `cpu must be a whole number of millicores (e.g. 1000), got "${cpuRaw.value}"`
})

const toml = computed(() => {
  const f = form.value
  const lines = []
  lines.push('version = 1')
  lines.push(`caller = ${JSON.stringify(f.caller || 'alice')}`)
  if (f.tenant) lines.push(`tenant = ${JSON.stringify(f.tenant)}`)
  lines.push('')
  lines.push('[runtime]')
  lines.push(`name = ${JSON.stringify(f.name || 'ephemeral-task')}`)
  // Raw emission (see cpuRaw): valid integers pass through unchanged;
  // invalid values produce an invalid TOML integer so the server rejects
  // the spec instead of the form silently rewriting it.
  if (cpuRaw.value) lines.push(`cpu = ${cpuRaw.value}`)
  if (f.memory) lines.push(`memory = ${JSON.stringify(f.memory)}`)
  lines.push('')
  lines.push('[workspace]')
  if (f.baseImage) lines.push(`base_image = ${JSON.stringify(f.baseImage)}`)
  if (f.init) lines.push(`init = ${JSON.stringify(f.init)}`)
  lines.push(`ephemeral = ${f.ephemeral}`)
  lines.push('')
  lines.push('[kernel]')
  if (f.kernel) lines.push(`path = ${JSON.stringify(f.kernel)}`)
  lines.push(`use_vhost_blk = ${f.vhost}`)
  lines.push('')
  lines.push('[network]')
  lines.push('enabled = false')
  for (const v of f.volumes) {
    if (!v.name || !v.path) continue
    lines.push('')
    lines.push('[[volumes]]')
    lines.push(`name = ${JSON.stringify(v.name)}`)
    lines.push(`path = ${JSON.stringify(v.path)}`)
    if (v.readOnly) lines.push('read_only = true')
  }
  return lines.join('\n') + '\n'
})

const validate = async () => {
  fingerprint.value = ''
  specError.value = ''
  try {
    const r = await apiFetch('/api/tasks/load-spec', { method: 'POST', body: { content: toml.value } })
    fingerprint.value = r.fingerprint
  } catch (e) {
    specError.value = e.message
  }
}

const copyToml = async () => {
  try {
    await navigator.clipboard.writeText(toml.value)
  } catch (e) {
    // Clipboard API unavailable (insecure context); the textarea remains
    // selectable for manual copy.
  }
}
</script>

<style scoped>
.field-error {
  margin: 0.35rem 0 0;
  font-size: 0.8rem;
  color: #ff8f8f;
}
.check {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.875rem;
  color: var(--text-secondary, rgba(255, 255, 255, 0.75));
  white-space: nowrap;
  cursor: pointer;
}
textarea {
  width: 100%;
  font-size: 0.85rem;
  background: rgba(0, 0, 0, 0.35);
  color: #d7e2ea;
  border: 1px solid var(--glass-border);
  border-radius: 0.5rem;
  padding: 0.9rem;
  resize: vertical;
}
</style>
