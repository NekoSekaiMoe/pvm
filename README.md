# PVM

PVM is a lightweight, User-Mode Linux (UML)-based container management system. It provides strong isolation for processes by leveraging virtualized Linux kernels while maintaining a container-like CLI and experience.

## Features

- **UML Isolation**: Runs applications inside dedicated User-Mode Linux instances for VM-level security.
- **REST API**: Built-in HTTP server (`internal/api`) for remote orchestration, compatible with E2B SDK patterns.
- **Modern WebUI**: An embedded, glassmorphism-designed WebUI (built with Nuxt 3) for visually managing containers, images, and logs.
- **Networking**: Bridge and TAP interface management for UML networking.
- **Image Management**: Seamless pulling of Docker base images to be used as container rootfs via qcow2 CoW overlays served by qemu-storage-daemon over vhost-user-blk.

## Dependency
- x86/x64 device(no limits, arm64 uml is porting)
- qemu-storage-daemon(for virtio blk)

## Quick Start

```bash
# Build the project
go build ./cmd/umlctl

# Start the WebUI
./agentpvm webui --port 3000

# Start a container via CLI (umlctl legacy path: raw rootfs + ubd)
./umlctl start -name my-container -rootfs alpine.img

# Start an agent sandbox (agentpvm: qcow2 base + per-task CoW overlay + vhost)
qemu-img convert -O qcow2 alpine.img alpine.qcow2
./agentpvm run -name my-agent -rootfs alpine.qcow2 -vhost=true
```

## Storage & Overlay Architecture

PVM isolates each sandbox at the **block-device layer** using qcow2
Copy-on-Write overlays. There is no host-side directory rootfs — UML consumes
a block device, so CoW must happen at the storage layer, not the filesystem
layer.

### Three-layer chain

```text
                       host                                      guest
+----------------------------------------+   +------------------------+
|  base.qcow2  (shared, read-only)       |   |                        |
|     ^                                  |   |  /dev/vda (virtio-blk) |
|     | qcow2 backing reference          |   |     ^                  |
|  overlay.qcow2 (per-task, writable)    |<===+-----+  vhost-user-blk |
|     ^                                  |   |       over UNIX socket |
|     | --export vhost-user-blk          |   |                        |
|  qemu-storage-daemon                   |   |  ext4 root filesystem   |
+----------------------------------------+   +------------------------+
```

1. **Storage — qcow2 block-level CoW** (`internal/cow`)

   `agentpvm run` creates a per-task overlay on top of the shared base:

   ```bash
   qemu-img create -f qcow2 -b base.qcow2 -F qcow2 overlay.qcow2
   ```

   - **base.qcow2** is the immutable toolchain + repo snapshot, shared by N
     sandboxes. It is never written to.
   - **overlay.qcow2** is per-task and starts nearly empty (just qcow2
     metadata). All guest writes diverge into this file; unmodified blocks
     are satisfied by recursing into the backing base.
   - The base MUST be qcow2 — a raw backing image is rejected because the
     block backend only knows how to read qcow2.

2. **Device — qemu-storage-daemon → vhost-user-blk** (`internal/vhost`)

   `qemu-storage-daemon` opens the overlay and exports it as a vhost-user-blk
   device over a UNIX socket. **This is the only layer that understands qcow2** —
   it performs the backing recursion so the guest never has to:

   ```bash
   qemu-storage-daemon \
     --blockdev driver=file,node-name=disk0,filename=overlay.qcow2,aio=io_uring \
     --blockdev driver=qcow2,node-name=format0,file=disk0 \
     --export   type=vhost-user-blk,...,addr.path=vhost-blk.sock,writable=on
   ```

   This is why `agentpvm run` requires `-vhost=true` (and qemu-storage-daemon
   installed): UML's built-in `ubd0=` backend reads raw bytes and cannot parse
   qcow2, so feeding it a qcow2 file would panic the guest with
   `VFS: Unable to mount root fs`.

3. **Guest — virtio_uml mounts the block device** (`internal/container`)

   The UML kernel command line points virtio_uml at the daemon's socket:

   ```
   virtio_uml.device=<socket>:<id>  root=/dev/vda  rw
   ```

   The guest sees a plain read-write block device and mounts ext4 from it.
   qcow2 and the backing recursion are completely transparent to the guest.

### Data flow

- **Write** (`echo x > /etc/foo.conf`): guest ext4 writes a block → virtio-blk
  driver sends the request over the socket → daemon's qcow2 driver allocates a
  new cluster in overlay.qcow2 → base.qcow2 is untouched.
- **Read of an unmodified file** (`cat /etc/passwd`): guest reads a block →
  daemon's qcow2 driver finds no overlay cluster → recurses into base.qcow2 →
  returns the original bytes.

### Why this design

| Property | How it's achieved |
| --- | --- |
| **Per-task isolation** | Each task gets its own overlay; the shared base is immutable. |
| **Cheap cold start** | An overlay is created in milliseconds and starts ~96 KB; no full-base copy. |
| **Shared host cache** | N sandboxes share one base.qcow2, so the host page cache holds it once. |
| **Guest is unmodified** | qcow2 parsing lives in the host daemon; the guest mounts a normal block device with any filesystem. |
| **Auditable teardown** | Deleting the overlay returns a known-good empty state; `agentpvm cow` / `qemu-img convert` can merge an overlay into a standalone artifact. |

### Two launch paths

- **`umlctl start`** (legacy): mounts a raw image directly via UML's `ubd0=`.
  No CoW, no vhost. Used for simple single-container runs.
- **`agentpvm run`** (agent sandbox): qcow2 base + per-task CoW overlay served
  via vhost-user-blk. This is the path that gets CoW isolation, the control
  planes (identity / egress / policy / audit), and the warm pool.

## Repository Structure

- [`bpf/`](./bpf/): eBPF programs for advanced networking and security.
- [`cmd/`](./cmd/): Main executables (e.g., `umlctl`).
- [`internal/`](./internal/): Core Go packages and logic.
- [`scripts/`](./scripts/): Utility scripts for building and setup.
- [`tests/`](./tests/): Test suites.
- [`webui/`](./webui/): Frontend Nuxt 3 source code for the Web Dashboard.
