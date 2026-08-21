# PVM (Pico VM)

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Nuxt 3](https://img.shields.io/badge/Nuxt-3-00DC82.svg)](https://nuxt.com)

**PVM** is a lightweight, User-Mode Linux (UML)-based container management system and hardened autonomous AI agent sandbox. It provides VM-level hardware-assisted isolation for untrusted processes and code execution using virtualized Linux kernels, paired with block-level Copy-on-Write (CoW) overlays, multi-tenant resource quotas, fine-grained L7/eBPF egress security, human-in-the-loop approval workflows, and an embedded glassmorphic Nuxt 3 WebUI.

---

## 🌟 Key Architecture & Capabilities

```
                                      HOST LAYER
+-----------------------------------------------------------------------------------------+
|                                    PVM Control Plane                                    |
|                                                                                         |
|  +-------------------+  +-------------------+  +-------------------+  +--------------+  |
|  |  Identity Broker  |  |  Tool / Policy GW |  |   Artifact Gate   |  |   Approval   |  |
|  |  (HMAC Scopes)    |  |  (Exec Sandbox)   |  |   (Secret Scan)   |  |   Tickets    |  |
|  +-------------------+  +-------------------+  +-------------------+  +--------------+  |
|  +-------------------+  +-------------------+  +-------------------+  +--------------+  |
|  |  Lifecycle / FSM  |  |  Incident Engine  |  |  Warm Pool/Quota  |  |  Audit Log   |  |
|  |  (AutoPause/Thaw) |  |  (Quarantine)     |  |  (Tenant Budgets) |  |  (SHA Chain) |  |
|  +-------------------+  +-------------------+  +-------------------+  +--------------+  |
|                                                                                         |
|  +---------------------------------------+   +---------------------------------------+  |
|  |  Storage: Pure-Go qcow2 CoW Engine    |   |  Network: L7 Egress Proxy + eBPF TC   |  |
|  |  (Overlay, In-Place Compact, Convert) |   |  (SSRF IP-Floor, Domain Allow/Deny)   |  |
|  +---------------------------------------+   +---------------------------------------+  |
|                     |                                            |                      |
|         vhost-user-blk (UNIX Socket)                  TAP Device (vec0 / L2 Bridge)     |
+---------------------|--------------------------------------------|----------------------+
                      |                                            |
                      v                                            v
+-----------------------------------------------------------------------------------------+
|                              GUEST SANDBOX (UML KERNEL)                                 |
|                                                                                         |
|   /dev/vda (ext4 rootfs)                            vec0 (10.0.0.x network)             |
|   In-Guest cgroup v2 (memory.max, pids.max)         Ephemeral scoped token in env       |
+-----------------------------------------------------------------------------------------+
```

### 1. Dual Execution Modes
- **`agentpvm run` (Hardened Agent Sandbox)**: Full TaskSpec-driven runtime with all 12 control planes active (Identity, L7 Egress, Tool Gateway, Artifact Gate, Approvals, Incident Controller, Warm Pool & Quotas, Volumes, Templates, AutoPause Lifecycle, CoW Overlays, and Tamper-Evident Audit Ledger).
- **`umlctl start` (Thin Container Launcher)**: Low-overhead UML instance launcher for simple container workflows and developer testing.

### 2. Storage & Block-Level Copy-on-Write
- **Pure-Go qcow2 Engine (`internal/cow`)**: Creates, mounts, inspects, and compacts qcow2 overlays in pure Go without requiring `qemu-img` at runtime.
- **In-Process vhost-user-blk Server (`internal/vhost/vu`)**: Serves qcow2 overlays directly over UNIX domain sockets into the UML guest's `virtio-blk` device.
- **Zero-Cluster Dropping & In-Place Compaction**: Transparently converts zeroed blocks to unallocated clusters upon sandbox termination (`CompactOnExit`).

### 3. Comprehensive Governance & Security Plane
- **Credential Broker (`internal/identity`)**: Mints short-lived, scope-bounded HMAC tokens; long-lived credentials never enter the guest sandbox.
- **Tool / Policy Gateway (`internal/policy`)**: Intercepts `/api/exec` calls, evaluates `allow`/`constrain`/`approve`/`deny` rule matrices, and scrubs sensitive API keys.
- **Artifact Gate (`internal/artifact`)**: 4-step verification pipeline (Reproducibility Replay, Test & Secret Scan, Sensitive-Diff Check, and SHA-256 Fingerprint Binding) before code or output release.
- **Human-in-the-Loop Approvals (`internal/approval`)**: Pauses side-effectful actions (`pay`, `deploy`, `send`) until an operator reviews parameter bindings.
- **Automated Incident Response (`internal/incident`)**: 4-tier response matrix (Block, Pause, Quarantine, Terminate) with automatic anomaly escalation.
- **Tamper-Evident Audit Ledger (`internal/audit`)**: Merkle-style SHA-256 hash-chained JSONL records stored outside the container, verifiable via `/api/audit/:id/verify`.
- **Egress & SSRF Protection (`internal/network/egress`, `bpf/egress.c`)**: L7 domain filtering with eBPF TC kernel enforcement blocking all private (RFC 1918), loopback (`127.0.0.0/8`), and cloud metadata (`169.254.169.254`) traffic.

### 4. Modern Glassmorphic Web Dashboard
Embedded Vue 3 & Nuxt 3 frontend bundled directly into the Go binary (`embed.go`), providing dedicated views for:
- Containers (`/`), Images (`/images`), Tasks (`/tasks`), Volumes (`/volumes`), Templates (`/templates`), Pool & Quota (`/pool`), Tool Terminal (`/terminal`), Approvals (`/approvals`), Policy (`/policy`), Artifact Gate (`/gate`), Audit (`/audit`), Network & Egress (`/network`), Incidents (`/incidents`), and Identity & Tokens (`/identity`).

---

## 🚀 Quick Start

### Build & Run

```bash
# 1. Build the frontend (using pnpm)
cd webui && pnpm install && pnpm run generate && cd ..

# 2. Build binaries
go build -o agentpvm ./cmd/agentpvm
go build -o bin/umlctl ./cmd/umlctl

# 3. Start the WebUI and REST API server (accessible at http://localhost:3000)
./agentpvm webui --port 3000

# 4. Launch an agent sandbox from TaskSpec TOML
./agentpvm run -config uml/agentpvm.toml

# 5. Or launch a standalone UML container with umlctl
./bin/umlctl start -name my-node -rootfs alpine.img -mem 512M
```

---

## 💻 CLI Subcommands Reference

### `agentpvm`
- `agentpvm run [-config <spec.toml>] [-name <id>] [-rootfs <base.img>] [-net]`: Launch hardened agent sandbox.
- `agentpvm api [-port 8080]`: Start E2B-compatible REST API server.
- `agentpvm webui [-port 3000]`: Start embedded Nuxt 3 dashboard + API server.
- `agentpvm cow -backing <base> -overlay <overlay.qcow2>`: Create qcow2 CoW overlay.
- `agentpvm cow -compact <overlay.qcow2>`: Rebuild and compact overlay in place.
- `agentpvm cow -to-raw <src> [-overlay <dst.img>]`: Convert qcow2 to raw image.
- `agentpvm cow -to-qcow2 <src> [-overlay <dst.qcow2>]`: Convert raw image to standalone qcow2.
- `agentpvm snapshot [export|import] <id> <file.tgz>`: Export or restore container archive.
- `agentpvm cgroup [freeze|thaw] <id>`: Freeze or thaw sandbox cgroup v2 hierarchy.
- `agentpvm gate -bundle <bundle.json>`: Offline Artifact Gate verification.
- `agentpvm approval [list]`: Query live pending approval tickets.
- `agentpvm pool [stats]`: Query warm pool readiness and tenant quota statistics.

### `umlctl`
- `umlctl start [-name <id>] [-rootfs <img.img>] [-mem <512M>] [-cpu <1000>] [-config <spec.toml>]`: Start UML container.
- `umlctl ps`: List running and stopped containers.
- `umlctl logs <container-id>`: Print console logs.
- `umlctl image pull <docker-image>`: Pull and export Docker image as ext4 rootfs.
- `umlctl network [create|rm] <bridge-name>`: Manage host bridge and NAT networking.

---

## 📡 REST API Summary (E2B SDK Compatible)

All API calls under `/api` require `Authorization: Bearer <API_SECRET>` (default: `secret`).

| Endpoint | Method | Description |
|:---|:---|:---|
| `/api/containers` | `GET` | List all containers and their status |
| `/api/containers/start` | `POST` | Launch a container (`name`, `rootfs`, `mem`, `cpu`) |
| `/api/containers/:id/logs` | `GET` | Retrieve console output |
| `/api/containers/:id` | `DELETE` | Terminate container and clean state |
| `/api/containers/:id/snapshot` | `POST` | Export container snapshot archive |
| `/api/containers/:id/restore` | `POST` | Restore container from snapshot |
| `/api/images/pull` | `POST` | Pull Docker image into ext4 rootfs |
| `/api/exec` | `POST` | Route tool execution through Policy Gateway |
| `/api/tasks` | `GET` | List all tasks and lifecycle FSM states |
| `/api/tasks/:id` | `GET` | Get task state, transitions, and fingerprint |
| `/api/tasks/:id/transition` | `POST` | Manually trigger FSM state transition |
| `/api/tasks/:id/pause` | `POST` | Pause / freeze sandbox cgroup runtime |
| `/api/tasks/:id/resume` | `POST` | Resume / thaw suspended sandbox |
| `/api/tasks/load-spec` | `POST` | Validate TaskSpec TOML & compute SHA fingerprint |
| `/api/volumes` | `GET`, `POST` | List and create persistent volumes |
| `/api/volumes/:id` | `GET`, `DELETE` | Retrieve details or delete volume (with refcount guard) |
| `/api/templates` | `GET`, `POST` | List and register base templates (PENDING status) |
| `/api/templates/:id` | `GET`, `DELETE` | Lookup by ID/Alias or delete template |
| `/api/templates/:id/alias` | `POST` | Assign alias to READY template |
| `/api/approvals` | `GET`, `POST` | List pending tickets or create test ticket |
| `/api/approvals/:id/decide` | `POST` | Approve or reject human approval ticket |
| `/api/gate/verify` | `POST` | Run 4-step Artifact Gate verification |
| `/api/policy/:task` | `GET` | Inspect compiled tool rules for task |
| `/api/pool/stats` | `GET` | Get warm pool ready, claimed, and total stats |
| `/api/pool/warm` | `POST` | Pre-warm N sandboxes from template |
| `/api/pool/quota` | `POST` | Configure tenant resource quotas |
| `/api/audit/:id` | `GET` | Retrieve complete audit ledger records |
| `/api/audit/:id/verify` | `GET` | Cryptographically verify audit hash chain integrity |

---

## 🧪 Testing

PVM includes 22 end-to-end integration shell suites in `tests/` alongside comprehensive Go unit and security test suites:

```bash
# Run all Go unit and integration tests
go test -v ./...

# Run all CI-safe end-to-end shell suites serially
for s in tests/*.sh; do ./"$s"; done
```

---

## 📁 Repository Structure

- [`cmd/`](./cmd/): Main executable entry points (`agentpvm`, `umlctl`).
- [`internal/`](./internal/): Core Go packages (25+ packages covering runtime, control planes, storage, and APIs).
- [`bpf/`](./bpf/): eBPF C program (`egress.c`) for SSRF IP-floor filtering.
- [`webui/`](./webui/): Nuxt 3 & Vue 3 frontend source code.
- [`tests/`](./tests/): Numbered end-to-end integration shell test suites (`01` through `22`).
- [`scripts/`](./scripts/): Kernel compilation and I/O performance benchmarking scripts.
- [`sdk/go/`](./sdk/go/): Typed Go client SDK for PVM REST APIs.
