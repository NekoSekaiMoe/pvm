# Web Dashboard (`webui/`)

This directory contains the source code for the PVM Web Dashboard, built with **Nuxt 3**, **Vue 3**, and vanilla CSS.

---

## Design System

The UI utilizes a **Glassmorphism** dark mode design system (`assets/css/main.css`) with blur filters, responsive CSS grid layouts, and color-coded status badges for lifecycle states and policy verdicts.

---

## Page Catalog

### Runtime Views
- **Containers (`/`)**: Live instance overview, resource limit configuration (CPU/mem), Pause/Resume controls, and snapshot management.
- **Images (`/images`)**: Base image registry, quick-pull presets (Alpine, Ubuntu, Debian, Python, Node), and ext4 layer synthesis.
- **Tasks (`/tasks`)**: TaskSpec-driven sandboxes, FSM transition modal, inline Pause/Resume, and status filtering.
- **Volumes (`/volumes`)**: Persistent storage registry, hostfs/plugin driver selection, and mount refcounting guards.
- **Templates (`/templates`)**: Immutable base image catalog, status indicators (PENDING/READY/FAILED), and dynamic alias resolution.
- **Pool & Quota (`/pool`)**: Warm sandbox capacity dashboard, template pre-warming, and tenant quota controls.
- **Tool Terminal (`/terminal`)**: Interactive tool execution console routed through the host-side Policy Gateway.
- **Console Logs (`/logs/:id`)**: Real-time console log viewer with text search, auto-scroll toggle, clipboard copy, and file download.

### Governance & Security Views
- **Approvals (`/approvals`)**: Human-in-the-loop pending approval ticket inbox with parameter inspection and decision buttons.
- **Policy (`/policy`)**: Policy Gateway rule matrix inspector and test command runner.
- **Artifact Gate (`/gate`)**: 4-step release verification tester (diff check, test logs, secret pattern scanning, canonical SHA-256 hash).
- **Audit Ledger (`/audit` & `/audit/:id`)**: Tamper-evident audit timeline with cryptographic hash chain integrity verification.
- **Network & Egress (`/network`)**: L7 domain rule inspector, QoS rate shaping, and eBPF SSRF IP-floor filtering status.
- **Incidents (`/incidents`)**: Anomaly event log, 4-tier decision matrix, and automated containment actions.
- **Identity & Tokens (`/identity`)**: Credential Broker capability scopes, ephemeral token architecture, and emergency revocation.

---

## Development & Build Workflow

Using **`pnpm`**:

```bash
# 1. Install dependencies
cd webui
pnpm install

# 2. Start development server (http://localhost:3000)
pnpm run dev

# 3. Build static assets for Go embedding
pnpm run generate

# 4. Rebuild the Go binary (which embeds .output/public)
cd ..
go build -o agentpvm ./cmd/agentpvm

# 5. Run the embedded dashboard
./agentpvm webui --port 3000
```
