# Internal Packages (`internal/`)

The `internal/` directory contains the core Go packages implementing PVM's kernel virtualization, storage virtualization, control plane subsystems, and REST APIs.

---

## Package Map

```
internal/
├── api/             # E2B-compatible REST API (Echo), WebUI handler, and /exec gateway
├── approval/        # Human-in-the-loop governance ticket manager (approve/reject)
├── artifact/        # Release verification gate (diff check, secret scan, SHA-256 hash)
├── audit/           # Tamper-evident ledger with SHA-256 Merkle hash chaining
├── cgroup/          # Linux cgroup v2 hierarchy management and freeze/thaw operations
├── config/          # Global configuration models and defaults
├── container/       # Container manager (legacy Start + TaskSpec StartTask)
├── cow/             # Pure-Go qcow2 engine (overlays, in-place compact, format convert)
├── ebpf/            # eBPF loader and whitelist map updater
├── filesystem/      # OverlayFS directory preparation and ext4 image creation
├── fsjson/          # Crash-safe atomic JSON file writing and directory fsync
├── identity/        # Credential Broker (ephemeral HMAC scoped token minting)
├── image/           # Image pull via crane and layer conversion to ext4
├── incident/        # Automated Incident Response (4-tier decision matrix & quarantine)
├── integrationtest/ # Cross-plane integration and full lifecycle test scenarios
├── lifecycle/       # Monotonic epoch-based AutoPause/Resume manager
├── log/             # Container console log streaming and isolation
├── network/         # Host bridge, TAP allocation, and QoS bandwidth shaping
│   └── egress/      # L7 HTTP/HTTPS proxy with domain allow/block rules & header injection
├── pkg/             # Package installer inside guests (e.g. apk, apt)
├── policy/          # Tool Gateway rule evaluator (allow, constrain, approve, deny)
├── pool/            # Warm sandbox pool and multi-tenant quota management
├── securitytest/    # Adversarial tests (token forging, ledger tamper, SSRF, secret leak)
├── snapshot/        # Container directory tarball archiving and safe extraction
├── spec/            # TaskSpec TOML schema parsing and validation
├── state/           # Finite State Machine (FSM) persistence and state transitions
├── template/        # Template Center storage with O(1) in-memory alias index
├── uml/             # User-Mode Linux kernel process launcher and parameter synthesizer
├── vhost/           # vhost-user backend (UNIX socket socket handling)
│   └── vu/          # In-process vhost-user-blk protocol implementation
└── volume/          # Persistent volume store and binary driver plugin manager
```

---

## Subsystem Highlights

### 1. Storage & Virtualization Plane
- **`cow/`**: Pure-Go qcow2 reader/writer. Handles cluster allocation, L1/L2 table indirection, backing file resolution, zero-cluster pruning, in-place compaction, and raw <-> qcow2 byte conversion.
- **`vhost/vu/`**: In-process vhost-user-blk server. Bridges the guest kernel's `virtio-blk` device directly to qcow2 overlays over a UNIX socket without needing an external storage daemon.
- **`uml/`**: Formulates UML kernel command lines (`ubd0`, `mem`, `eth0=tuntap`, `init`, `hostfs`), spawns the virtual machine process, and monitors child termination.

### 2. Governance & Control Plane
- **`identity/`**: Mints ephemeral HMAC-SHA256 tokens bounded by capability scopes and expiration TTLs. Verifies token integrity and supports atomic single/bulk revocation.
- **`policy/`**: Evaluates tool execution requests against declarative rules (`allow`, `constrain`, `approve`, `deny`). Scrubs matched secrets from tool arguments before execution.
- **`artifact/`**: Verifies agent release bundles across 4 steps: execution replay, test assertion, secret pattern scanning, and immutable canonical hashing.
- **`approval/`**: Manages human approval tickets for high-impact actions, complete with timeout deadlines and operator identity binding.
- **`incident/`**: Monitors anomaly counters and executes automated containment actions (Block, Pause, Quarantine, Terminate) following a 4-tier matrix.
- **`audit/`**: Enforces strict hash-chaining across all lifecycle, tool, approval, and incident events using locked JSONL append-only ledgers.

### 3. Lifecycle & Capacity
- **`lifecycle/`**: Tracks task idle timeouts with monotonic epoch generations, automatically freezing the cgroup v2 hierarchy to conserve compute when idle.
- **`pool/`**: Maintains a warm pool of pre-booted sandboxes for sub-second agent acquisition and enforces tenant CPU/memory/concurrency quotas.
- **`volume/` & `template/`**: Provide file-persisted volume and rootfs template stores with alias resolution and mount refcounting.
