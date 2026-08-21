# CLI Commands (`cmd/`)

This directory houses the main CLI binaries and entrypoints for PVM.

---

## 1. `agentpvm` (`cmd/agentpvm`)

The agent sandbox control plane binary. It owns TaskSpec-driven sandbox lifecycles, REST API services, WebUI hosting, and governance controls.

### Subcommands

#### `agentpvm run`
Launch an isolated AI agent sandbox driven by a TaskSpec TOML configuration.
```bash
agentpvm run -config ./uml/agentpvm.toml
agentpvm run -name my-task -rootfs alpine.img -kernel ./bin/linux -mem 512M -net
```

#### `agentpvm api`
Run the E2B-compatible REST API server.
```bash
agentpvm api -port 8080
```

#### `agentpvm webui`
Serve the embedded glassmorphic Nuxt 3 web dashboard alongside the REST API server.
```bash
agentpvm webui --port 3000
```

#### `agentpvm cow`
Manage pure-Go qcow2 Copy-on-Write overlays, in-place compaction, and format conversion without requiring `qemu-img`.
```bash
# Create CoW overlay
agentpvm cow -backing /path/base.img -overlay /path/out.qcow2

# Compact qcow2 overlay in place
agentpvm cow -compact /path/out.qcow2

# Convert formats
agentpvm cow -to-raw /path/disk.qcow2 -overlay /path/disk.raw
agentpvm cow -to-qcow2 /path/disk.raw -overlay /path/disk.qcow2
```

#### `agentpvm snapshot`
Export or import a container directory archive (`.tgz`).
```bash
agentpvm snapshot export <container-id> /path/archive.tgz
agentpvm snapshot import <container-id> /path/archive.tgz
```

#### `agentpvm cgroup`
Freeze or thaw a sandbox's cgroup v2 tree.
```bash
agentpvm cgroup freeze <container-id>
agentpvm cgroup thaw <container-id>
```

#### `agentpvm gate`
Perform offline verification of an Artifact Gate bundle.
```bash
agentpvm gate -bundle /path/bundle.json
```

#### `agentpvm approval`
Query live pending human approval tickets.
```bash
agentpvm approval list
```

#### `agentpvm pool`
Inspect warm pool readiness and tenant quota consumption.
```bash
agentpvm pool stats
```

---

## 2. `umlctl` (`cmd/umlctl`)

The thin UML container management CLI. Modeled after Docker CLI for rapid developer testing and lightweight container execution.

### Subcommands

- `umlctl start`: Start a UML container with virtualized resources.
  - `-name <id>`: Container identifier.
  - `-rootfs <path>`: Root filesystem image (ext4).
  - `-mem <size>`: Memory size (e.g. `512M`, `1G`).
  - `-cpu <millicpu>`: CPU limit (e.g. `1000` = 1 core).
  - `-init <path>`: Guest init path (default: `/sbin/init`).
  - `-volume <host:guest>`: Host directory bind mount via hostfs.
  - `-virtio`: Enable virtio-blk via vhost-user.
  - `-overlay`: Create and attach temporary CoW overlay.
  - `-rm`: Automatically remove container upon exit.
  - `-it`: Allocate interactive stdio console.
  - `-config <path>`: Load launch flags from a TaskSpec TOML file.
- `umlctl ps`: List active and stopped UML containers.
- `umlctl logs <container-id>`: Print console logs for a container.
- `umlctl image pull <image-name>`: Pull a container image and convert to ext4.
- `umlctl network [create|rm] <bridge-name>`: Manage host TAP and bridge network interfaces.
