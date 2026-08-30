<template>
  <div>
    <h1>{{ t('pages.network.title') }}</h1>
    <p class="muted">L7 egress gateway, DNS-learned allowlists and eBPF TC data plane (bridge default, bridgeless `tc` opt-in).</p>

    <!-- Live: TC/eBPF dataplane posture -->
    <div class="glass-card">
      <h3>TC/eBPF Data Plane <span v-if="dpErr" class="pill deny">{{ t('pages.network.unreachable') }}</span></h3>
      <p class="muted" style="margin-bottom:1rem;">
        Bridgeless dataplane posture from <code>GET /api/network/dataplane</code>.
        Default mode: <code>{{ dp.mode_default ?? '—' }}</code>;
        gateway device: <code>{{ gwDevice }}</code>.
      </p>
      <div v-if="tasksWithDp.length === 0" class="muted" style="font-size:0.85rem;">
        {{ t('pages.network.emptyDp') }}
      </div>
      <div v-else class="table-container">
        <table>
          <thead>
            <tr><th>Task</th><th>TAP / Host NIC</th><th>Addresses</th><th>Sessions</th><th>Programs</th><th>Counters</th></tr>
          </thead>
          <tbody>
            <tr v-for="t in tasksWithDp" :key="t.task">
              <td class="mono"><strong>{{ t.task }}</strong></td>
              <td class="mono">{{ t.tap }} → {{ t.host_nic }}</td>
              <td class="mono" style="font-size:0.72rem;">
                guest {{ t.guest_ip }} / gw {{ t.gateway_ip }}<br />
                SNAT {{ t.host_ip }}:{{ t.port_base }}+{{ t.port_window }}
              </td>
              <td>{{ t.sessions < 0 ? '—' : t.sessions }}</td>
              <td class="mono" style="font-size:0.72rem;">{{ (t.programs || []).join(', ') }}</td>
              <td class="mono" style="font-size:0.72rem;">{{ counterSummary(t.stats) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Live: DNS-learned egress allowlist -->
    <div class="glass-card">
      <h3>DNS-Learned Egress Allowlist</h3>
      <p class="muted" style="margin-bottom:0.75rem;">
        Resolved IPs of allowlisted domains learned from DNS answers are admitted by the eBPF
        whitelist until <code>min(DNS TTL, learn_ttl)</code> expires. Pick a task with
        <code>dns_learn_enabled</code>.
      </p>
      <div class="form-row">
        <select v-model="dnsTask" class="mono" style="flex:1;">
          <option value="" disabled>— select task —</option>
          <option v-for="t in taskOptions" :key="t.id" :value="t.id">{{ t.id }}</option>
        </select>
        <button class="btn" @click="refreshLearned" :disabled="!dnsTask">{{ t('pages.network.btnRefresh') }}</button>
      </div>

      <div v-if="learnErr" class="callout err">{{ learnErr }}</div>

      <template v-if="dnsTask && !learnErr">
        <div class="table-container" v-if="learned.length">
          <table>
            <thead>
              <tr><th>Domain</th><th>Learned IP</th><th>Expires In</th><th></th></tr>
            </thead>
            <tbody>
              <tr v-for="(e, i) in learned" :key="e.domain + e.ip">
                <td class="mono">{{ e.domain }}</td>
                <td class="mono">{{ e.ip }}</td>
                <td>{{ e.remaining_sec }}s</td>
                <td>
                  <button class="btn" style="font-size:0.72rem;padding:0.25rem 0.5rem;" @click="dropLearned(e.domain)">{{ t('pages.network.btnDrop') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else-if="dnsTask && loaded" class="muted" style="font-size:0.85rem;">
          No learned entries yet (only allowlisted domains are learned; default-deny floor still applies).
        </div>

        <div class="form-row" style="margin-top:0.75rem;">
          <input v-model="promoteDomain" placeholder="promote domain e.g. api.github.com" class="mono" />
          <button class="btn btn-primary" @click="promote" :disabled="!dnsTask || !promoteDomain">{{ t('pages.network.btnPromote') }}</button>
        </div>
        <div v-if="promoteMsg" class="callout ok">{{ promoteMsg }}</div>
        <div v-if="promoteErr" class="callout err">{{ promoteErr }}</div>
      </template>
    </div>

    <!-- Static reference: SSRF floor -->
    <div class="glass-card">
      <h3>eBPF Kernel SSRF IP-Floor Defense</h3>
      <p class="muted" style="margin-bottom:1rem;">Outbound TCP to loopback, link-local or private RFC1918 ranges is dropped by eBPF TC filters regardless of any allowlist (per-task gateway/guest addresses are exempted so the sandbox can function).</p>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Protected Subnet</th><th>Classification</th><th>Action</th></tr>
          </thead>
          <tbody>
            <tr><td><code>127.0.0.0/8</code></td><td>Host Loopback</td><td><span class="pill deny">DROP</span></td></tr>
            <tr><td><code>169.254.0.0/16</code></td><td>Cloud Metadata / Link-Local</td><td><span class="pill deny">DROP</span></td></tr>
            <tr><td><code>10.0.0.0/8</code></td><td>Private RFC1918 (Class A)</td><td><span class="pill deny">DROP</span></td></tr>
            <tr><td><code>172.16.0.0/12</code></td><td>Private RFC1918 (Class B)</td><td><span class="pill deny">DROP</span></td></tr>
            <tr><td><code>192.168.0.0/16</code></td><td>Private RFC1918 (Class C)</td><td><span class="pill deny">DROP</span></td></tr>
          </tbody>
        </table>
      </div>
      <p class="muted" style="margin-top:0.75rem;">
        Bridgeless <code>tc</code> dataplane fixes guest <code>169.254.68.6</code> /
        gateway <code>169.254.68.5</code> inside every sandbox: identical addresses everywhere,
        demultiplexed on the host by per-task TC programs and pinned session maps
        (<code>/sys/fs/bpf/pvm/&lt;task&gt;/</code>).
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { apiFetch, usePoll } from '~/composables/useApi'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

// --- TC/eBPF dataplane posture (global view, polled) ---
const dp = ref({})
const dpErr = ref('')
const { refresh: refreshDp } = usePoll(async () => {
  try {
    dp.value = await apiFetch('/api/network/dataplane')
    dpErr.value = ''
  } catch (e) {
    dpErr.value = e.message
    throw e // rethrow so usePoll's error backoff kicks in
  }
}, 4000)
refreshDp()

const tasksWithDp = computed(() => dp.value.tasks || [])
const gwDevice = computed(() => {
  const g = dp.value.gw_device || {}
  if (g.exists === undefined) return '—'
  return g.exists ? `${g.name || 'pvm-gw'} up` : 'not created (no tc task)'
})

function counterSummary(stats) {
  if (!stats) return '—'
  const parts = []
  if (stats.snat) parts.push(`snat ${stats.snat}`)
  if (stats.rev_fwd) parts.push(`rev ${stats.rev_fwd}`)
  if (stats.policy_drop) parts.push(`drop ${stats.policy_drop}`)
  if (stats.floor_drop) parts.push(`floor ${stats.floor_drop}`)
  return parts.join(' · ') || 'idle'
}

// --- DNS-learned allowlist (per selected task) ---
const taskOptions = ref([])
const dnsTask = ref('')
const learned = ref([])
const loaded = ref(false)
const learnErr = ref('')
const promoteDomain = ref('')
const promoteMsg = ref('')
const promoteErr = ref('')

usePoll(async () => {
  const list = await apiFetch('/api/tasks')
  taskOptions.value = Array.isArray(list) ? list : []
}, 8000)

async function refreshLearned() {
  if (!dnsTask.value) return
  loaded.value = false; learnErr.value = ''
  try {
    const r = await apiFetch(`/api/egress/${dnsTask.value}/learned`)
    learned.value = r.entries || []
    loaded.value = true
  } catch (e) {
    learnErr.value = e.message
    learned.value = []
  }
}

async function dropLearned(domain) {
  promoteErr.value = ''
  try {
    await apiFetch(`/api/egress/${dnsTask.value}/learned/${domain}`, { method: 'DELETE' })
    await refreshLearned()
  } catch (e) { promoteErr.value = e.message }
}

async function promote() {
  promoteMsg.value = ''; promoteErr.value = ''
  try {
    const r = await apiFetch(`/api/egress/${dnsTask.value}/allow`, {
      method: 'POST', body: { domain: promoteDomain.value.trim() },
    })
    promoteMsg.value = r.added_to_allowlist
      ? `added to allowlist, ${r.learned || 0} IP(s) learned now`
      : `already on allowlist; learned ${r.learned || 0} IP(s)`
    promoteDomain.value = ''
    await refreshLearned()
  } catch (e) { promoteErr.value = e.message }
}

watch(dnsTask, () => { learned.value = []; loaded.value = false; refreshLearned() })
</script>
