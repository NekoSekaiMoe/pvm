<template>
  <div>
    <h1>Identity &amp; Credential Broker</h1>
    <p class="muted">Credential Broker (plan.md §4). Mints short-lived, scope-bounded HMAC tokens so long-lived credentials never enter the guest.</p>

    <div class="glass-card">
      <h3>Broker Architecture</h3>
      <p class="muted" style="margin-bottom:1rem;">The guest sandbox only holds ephemeral tokens (<code>&lt;payload-b64&gt;.&lt;hmac-sha256&gt;</code>). When an agent invokes tools, the host-side broker validates capabilities and attaches credentials in-flight.</p>
      
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Capability Scope</th><th>Granted Privileges</th><th>Isolation Level</th></tr>
          </thead>
          <tbody>
            <tr><td><code>repo:read</code></td><td>Clone and read git repositories</td><td>Host-Side Token Injection</td></tr>
            <tr><td><code>repo:write</code></td><td>Push commits to task-scoped branch</td><td>Branch Constrained</td></tr>
            <tr><td><code>s3:read</code></td><td>Download read-only dependencies</td><td>Scoped IAM Session</td></tr>
            <tr><td><code>tool:exec</code></td><td>Invoke approved sandbox CLI tools</td><td>Policy Gateway Gated</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="glass-card">
      <h3>Security Guarantees</h3>
      <div class="stat-grid">
        <div class="stat-tile">
          <div class="stat-value">0</div>
          <div class="stat-label">Long-Lived Secrets in Guest</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">HMAC</div>
          <div class="stat-label">SHA-256 Signature Binding</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">1-Click</div>
          <div class="stat-label">Instant Task Revocation</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>
