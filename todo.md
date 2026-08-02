# TODO

## Networking: kernel defconfig missing CONFIG_UML_NET (root cause found)

**Status**: root cause identified; fix is in `scripts/build_kernel.sh` but
requires a kernel rebuild to take effect.

### Symptom

The guest boots, mounts root, but has no `eth0`:

```
### ip link show eth0
ip: can't find device 'eth0'
### ping 10.0.0.1
ping: sendto: Network unreachable
```

### Root cause (CONFIRMED, not a hypothesis)

The UML kernel build drops `eth0=tuntap,tap_pkg` on the floor:

```
Kernel command line: init=/init.sh ubd0=pkg_rootfs.img root=/dev/ubda rw eth0=tuntap,tap_pkg ...
Unknown kernel command line parameters "eth0=tuntap,tap_pkg ...", will be passed to user space.
```

`scripts/build_kernel.sh` enabled `CONFIG_VIRTIO_NET` (the generic virtio net
driver) and `CONFIG_NET_NS`, but never enabled the **UML network transport
layer**:

- `CONFIG_UML_NET` — the framework that parses `eth<n>=<transport>,...`
- `CONFIG_UML_NET_TUNTAP` — the tuntap transport PVM uses
- `CONFIG_UML_NET_VECTOR` — the newer/faster vec transport

Without `CONFIG_UML_NET` the kernel has no parser for the `eth<n>=` syntax, so
the parameter is reported as unknown and discarded, and no NIC is ever created.
`NET: Registered PF_INET / PF_PACKET` in the boot log is just the generic
Linux networking stack — it is NOT the UML virtual NIC driver. The dmesg shows
no `Netdevice 0` / `Choosing a random ethernet address` / `TUN/TAP backend`
lines precisely because the UML net driver was never compiled in.

This is independent of the block backend (ubd vs vhost) and independent of
the backing image format (raw vs qcow2). Earlier theories about
`virtio_uml.device` conflicting with `eth0=tuntap` were wrong.

### Fix

`scripts/build_kernel.sh` now enables:

```
CONFIG_UML_NET
CONFIG_UML_NET_TUNTAP
CONFIG_UML_NET_VECTOR
CONFIG_TUN
```

**Requires rebuilding the kernel** (`scripts/build_kernel.sh`) before the guest
gets a NIC. No PVM code change needed — `eth0=tuntap,<tap>` is the correct
parameter syntax and the code already emits it.

### Follow-ups (after the kernel rebuild confirms networking works)

- Revisit whether to switch networking to the vec transport for performance
  (UML docs say vec with tap does > 8 Gbit/s vs tuntap's much lower ceiling).
  That would change `buildTaskArgs` to emit `vec0:transport=tap,ifname=...`
  with the correct parameters (depth=128,gro=1; the old `vnet=1` was wrong).
- Once networking works on the ubd path, re-evaluate whether the qcow2+vhost
  path (CoW isolation) also works with networking, or still needs the network
  moved onto virtio_uml (vhost-user-net export from qemu-storage-daemon).
  The previous "virtio_uml block conflicts with eth0=tuntap" theory needs
  re-validation now that we know the kernel was missing UML_NET entirely.
