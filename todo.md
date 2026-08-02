# TODO

## Networking on the vhost (qcow2 CoW) path

**Status**: open. Workaround in place (use the ubd path).

The agent path has two block backends, selected by `Kernel.UseVhostBlk`:

| `use_vhost_blk` | Block device            | CoW isolation | Networking            |
| --------------- | ----------------------- | ------------- | --------------------- |
| `false` (default) | `ubd0=<raw base>`       | none          | **works** (eth0=tuntap) |
| `true`           | `virtio_uml.device` + qcow2 overlay via qemu-storage-daemon | yes           | **broken** (no NIC in guest) |

### Symptom

On the vhost path the guest boots, mounts root, but has no `eth0`:

```
### ip link show eth0
ip: can't find device 'eth0'
### ping 10.0.0.1
ping: sendto: Network unreachable
```

### Root cause (strong hypothesis, not yet confirmed at the source level)

The UML kernel command line on the vhost path carries both
`virtio_uml.device=<sock>:2` (block, VIRTIO_ID_BLOCK) **and** `eth0=tuntap,<tap>`
(net). These two transports do not coexist: the guest ends up with the virtio
block device but no `eth0`. On the ubd path the command line carries `ubd0=...`
+ `eth0=tuntap,...` — both legacy UML transports — and networking works.

The command line is the only variable that differs between the two paths
(the network parameter string is byte-identical: `eth0=tuntap,tap_pkg`), so
the virtio_uml block device is the prime suspect. Confirming this at the
source level needs the UML boot log (`Kernel command line:` + the
`Netdevice 0 ... TUN/TAP backend` / `Choosing a random ethernet address for
device eth0` dmesg lines, or their absence).

### Workaround

Callers that need networking in the guest use the ubd path
(`use_vhost_blk = false`, raw base image). This is the default in
`uml/agentpvm.toml` and `safeDefaultSpec`, and what
`scripts/test_pkg_install.sh` exercises. CoW isolation is lost on this path.

`scripts/test_io_perf.sh` and `tests/04_test_qcow2_mount.sh` use the vhost
path but do not need in-guest networking (they only download the alpine
rootfs on the host), so they are unaffected.

### Fix direction

Move networking onto `virtio_uml` as well, so block and net share the same
transport family. Concretely:

1. `internal/vhost/backend.go` currently exports only `vhost-user-blk`. Add a
   second `--export type=vhost-user-net,...` with its own UNIX socket, and
   attach the host TAP to it (the daemon has a `--export` for net that takes
   a tap fd via SCM_RIGHTS). `VirtioIDNet` (= 1) is already defined for this
   purpose and is currently unused (see its comment).
2. `internal/container/manager.go buildTaskArgs`: when `UseVhostBlk` is set,
   emit `virtio_uml.device=<net-sock>:<VIRTIO_ID_NET>` instead of
   `eth0=tuntap,<tap>`. The net socket path is published by the daemon just
   like the block socket.
3. Decide the lifecycle: one net export per task (per-task listener style,
   mirroring the block export) vs. a shared net export keyed by the X-Task-Id
   the guest would send. Per-task is the safer attribution model and matches
   the block path.
4. Update `uml/agentpvm.toml` default to `use_vhost_blk = true` once the
   vhost path has working networking, so CoW isolation becomes the default.

Reference: UML HowTo — `virtio_uml.device=<socket>:<virtio_id>` syntax, where
`virtio_id` for net is `1` (`VIRTIO_ID_NET`) and for block is `2`
(`VIRTIO_ID_BLOCK`); see `arch/um/drivers/virtio_uml.c`.
