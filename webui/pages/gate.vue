<template>
  <div>
    <h1>Artifact Gate Verification</h1>
    <p class="muted">Release verification gate (plan.md §7). Scans diffs, build logs, execution traces, and declared files for credentials before release.</p>

    <!-- Presets -->
    <div class="glass-card">
      <div class="toolbar">
        <h3>Sample Verification Scenarios</h3>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          <button class="btn btn-primary" @click="loadPreset('clean')">Clean Release (PASS)</button>
          <button class="btn btn-danger" @click="loadPreset('aws_leak')">Leaked AWS Key (FAIL)</button>
          <button class="btn btn-danger" @click="loadPreset('token_leak')">Leaked GitHub Token (FAIL)</button>
        </div>
      </div>
    </div>

    <!-- Bundle Form -->
    <div class="glass-card">
      <h3>Artifact Bundle Payload</h3>
      <div class="form-row">
        <div>
          <label class="section-title" for="gate-task-id">Task ID</label>
          <input id="gate-task-id" v-model="bundle.task_id" placeholder="e.g. task-release-01" />
        </div>
        <div style="display:flex;align-items:center;padding-top:1.5rem;">
          <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">
            <input type="checkbox" v-model="bundle.claimed_ok" style="width:auto;" />
            <span>Agent Claims Success (claimed_ok)</span>
          </label>
        </div>
      </div>

      <div class="form-row">
        <div>
          <label class="section-title" for="gate-diff">Git Diff</label>
          <textarea id="gate-diff" v-model="bundle.diff" placeholder="--- a/main.go&#10;+++ b/main.go&#10;..." style="min-height:140px;"></textarea>
        </div>
        <div>
          <label class="section-title" for="gate-build-log">Build &amp; Test Log</label>
          <textarea id="gate-build-log" v-model="bundle.build_log" placeholder="=== RUN TestAll&#10;--- PASS: TestAll (0.02s)&#10;PASS" style="min-height:140px;"></textarea>
        </div>
      </div>

      <div class="form-row">
        <div>
          <label class="section-title" for="gate-trace">Execution Trace (comma separated)</label>
          <input id="gate-trace" v-model="traceInput" placeholder="go build ./..., go test ./..." />
        </div>
        <div>
          <label class="section-title" for="gate-files">Declared Files (JSON key: base64)</label>
          <input id="gate-files" v-model="filesJson" placeholder='{"out.txt": "aGVsbG8="}' />
        </div>
      </div>

      <div style="margin-top:1rem;">
        <button class="btn btn-primary" @click="runVerify" :disabled="verifying">
          {{ verifying ? 'Verifying...' : 'Run Gate Verification' }}
        </button>
      </div>

      <div v-if="verifyError" class="callout err" style="margin-top:1rem;">{{ verifyError }}</div>
    </div>

    <!-- Results Display -->
    <div v-if="verdict" class="glass-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
        <h3>Verification Verdict</h3>
        <span class="pill" :class="verdict.passed ? 'allow' : 'deny'" style="font-size:1rem;padding:0.4rem 1rem;">
          {{ verdict.passed ? 'PASS - RELEASE PERMITTED' : 'FAIL - RELEASE BLOCKED' }}
        </span>
      </div>

      <div v-if="verdict.hash" class="callout ok">
        <strong>Canonical Artifact Hash:</strong> <span class="mono">{{ verdict.hash }}</span>
      </div>

      <h4 style="margin:1rem 0 0.5rem;">Pipeline Steps:</h4>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Verification Step</th><th>Status / Reason</th></tr>
          </thead>
          <tbody>
            <tr v-for="(status, step) in verdict.step || {}" :key="step">
              <td><strong>{{ step }}</strong></td>
              <td>
                <span class="pill" :class="status === 'pass' || status === 'ok' ? 'allow' : 'deny'">
                  {{ status }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { apiFetch } from '~/composables/useApi'

const bundle = ref({
  task_id: 'task-clean',
  diff: '--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-fmt.Println("hello")\n+fmt.Println("hello world")\n',
  build_log: '=== RUN TestServer\n--- PASS: TestServer (0.01s)\nPASS',
  claimed_ok: true
})
const traceInput = ref('go build ./..., go test ./...')
const filesJson = ref('{}')

const verifying = ref(false)
const verdict = ref(null)
const verifyError = ref('')

const loadPreset = (type) => {
  verdict.value = null
  verifyError.value = ''
  if (type === 'clean') {
    bundle.value = {
      task_id: 'task-clean',
      diff: '--- a/app.go\n+++ b/app.go\n@@ -1 +1 @@\n-const v = 1\n+const v = 2\n',
      build_log: 'Build success. All 12 tests passed.',
      claimed_ok: true
    }
    traceInput.value = 'go build ./..., go test ./...'
    filesJson.value = '{"dist/bundle.js": "Y29uc29sZS5sb2coJ2hpJyk="}'
  } else if (type === 'aws_leak') {
    bundle.value = {
      task_id: 'task-aws-leak',
      diff: '--- a/config.env\n+++ b/config.env\n@@ -0,0 +1 @@\n+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n',
      build_log: 'Compiled.',
      claimed_ok: true
    }
    traceInput.value = 'cat config.env'
    filesJson.value = '{}'
  } else if (type === 'token_leak') {
    bundle.value = {
      task_id: 'task-gh-leak',
      diff: '',
      build_log: 'Testing...',
      claimed_ok: true
    }
    traceInput.value = 'make release'
    filesJson.value = '{"secrets.txt": "Z2hwX2FhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="}'
  }
}

const runVerify = async () => {
  verifying.value = true
  verdict.value = null
  verifyError.value = ''

  let files = {}
  try {
    files = JSON.parse(filesJson.value || '{}')
  } catch (e) {
    verifyError.value = 'Files map must be valid JSON: ' + e.message
    verifying.value = false
    return
  }

  const trace = traceInput.value.split(',').map(s => s.trim()).filter(Boolean)

  const payload = {
    ...bundle.value,
    trace,
    files
  }

  try {
    const res = await apiFetch('/api/gate/verify', {
      method: 'POST',
      body: payload
    })
    verdict.value = res
  } catch (e) {
    verifyError.value = e.message
  } finally {
    verifying.value = false
  }
}
</script>
