<template>
  <div>
    <h1>Network &amp; Egress Security</h1>
    <p class="muted">L7 HTTP proxy gateway and eBPF kernel-level SSRF IP-floor filtering (plan.md §5).</p>

    <!-- SSRF IP-Floor Card -->
    <div class="glass-card">
      <h3>eBPF Kernel SSRF IP-Floor Defense</h3>
      <p class="muted" style="margin-bottom:1rem;">All outbound TCP connections resolving to loopback, link-local, or private RFC1918 ranges are unconditionally dropped by eBPF TC filters.</p>
      
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Protected Subnet</th><th>Classification</th><th>Action</th><th>Enforcement</th></tr>
          </thead>
          <tbody>
            <tr><td><code>127.0.0.0/8</code></td><td>Host Loopback</td><td><span class="pill deny">DROP</span></td><td>eBPF TC Egress Filter</td></tr>
            <tr><td><code>169.254.0.0/16</code></td><td>Cloud Metadata / Link-Local</td><td><span class="pill deny">DROP</span></td><td>eBPF TC Egress Filter</td></tr>
            <tr><td><code>10.0.0.0/8</code></td><td>Private RFC1918 (Class A)</td><td><span class="pill deny">DROP</span></td><td>eBPF TC Egress Filter</td></tr>
            <tr><td><code>172.16.0.0/12</code></td><td>Private RFC1918 (Class B)</td><td><span class="pill deny">DROP</span></td><td>eBPF TC Egress Filter</td></tr>
            <tr><td><code>192.168.0.0/16</code></td><td>Private RFC1918 (Class C)</td><td><span class="pill deny">DROP</span></td><td>eBPF TC Egress Filter</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Egress Rules Card -->
    <div class="glass-card">
      <h3>L7 Egress Domain Rules</h3>
      <p class="muted" style="margin-bottom:1rem;">Tasks boot with default-deny network or strict domain allowlists with automatic credential injection over HTTPS.</p>

      <div class="table-container">
        <table>
          <thead>
            <tr><th>Task Type</th><th>Default Allow Domains</th><th>Scheme</th><th>Credential Injection</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>Coding Agent Sandbox</td>
              <td><code>api.github.com, registry.npmjs.org, proxy.golang.org</code></td>
              <td><code>HTTPS (Port 443)</code></td>
              <td><span class="pill allow">Enabled (Host-Side Only)</span></td>
            </tr>
            <tr>
              <td>Strict Default Sandbox</td>
              <td><span class="muted">None (Default Deny)</span></td>
              <td><code>—</code></td>
              <td><span class="pill deny">Disabled</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Interfaces & QoS -->
    <div class="glass-card">
      <h3>Bridge &amp; TAP Interfaces</h3>
      <div class="stat-grid">
        <div class="stat-tile">
          <div class="stat-value">10.0.0.1</div>
          <div class="stat-label">Gateway Bridge (uml-br0)</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">24</div>
          <div class="stat-label">Subnet Mask (/24)</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">tc tbf</div>
          <div class="stat-label">QoS Rate Limiter</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>
