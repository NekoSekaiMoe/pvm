<template>
  <div>
    <h1>Incidents &amp; Security Anomaly Center</h1>
    <p class="muted">Automated Incident Response Controller (plan.md §13). Escalates and isolates sandboxes upon detecting anomalies.</p>

    <!-- Decision Matrix -->
    <div class="glass-card">
      <h3>4-Tier Decision Matrix ("Kill is a Branch, Not a Fixed Step")</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Severity Tier</th><th>Trigger Examples</th><th>Action Taken</th><th>Preservation State</th></tr>
          </thead>
          <tbody>
            <tr>
              <td><span class="pill allow">Low</span></td>
              <td>Unrecognized tool arguments, minor rate burst</td>
              <td><span class="pill block">ActionBlock</span></td>
              <td>Sandbox continues running</td>
            </tr>
            <tr>
              <td><span class="pill constrain">Medium</span></td>
              <td>Budget wall-time exceeded, excessive CPU burst</td>
              <td><span class="pill approve">ActionPause</span></td>
              <td>cgroup frozen for human inspection</td>
            </tr>
            <tr>
              <td><span class="pill deny">High</span></td>
              <td>Blocked domain flood, secret leak attempt, repeated medium</td>
              <td><span class="pill revoke">ActionQuarantine</span></td>
              <td>Network cut, tokens revoked, frozen &amp; preserved</td>
            </tr>
            <tr>
              <td><span class="pill deny" style="background:rgba(220,38,38,0.4);">Critical</span></td>
              <td>Kernel exploit signature, out-of-bounds memory tamper</td>
              <td><span class="pill deny">ActionTerminate</span></td>
              <td>UML process immediately killed</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Escalation Rules -->
    <div class="glass-card">
      <h3>Incident Escalation &amp; Forensics</h3>
      <p class="muted" style="margin-bottom:1rem;">Tasks with multiple repeated low/medium anomalies escalate to full <strong>Quarantine</strong> to prevent credential harvesting.</p>
      
      <div class="stat-grid">
        <div class="stat-tile">
          <div class="stat-value">3</div>
          <div class="stat-label">Anomaly Escalation Threshold</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">RevokeAll</div>
          <div class="stat-label">Token Revocation on Quarantine</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">SHA-256</div>
          <div class="stat-label">Forensic Audit Trail</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>
