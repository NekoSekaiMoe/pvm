# TODO

## Networking: use the vec transport (legacy eth0=tuntap was removed in 6.16)

**Status**: fix in place (vec0 + CONFIG_UML_NET_VECTOR); needs a kernel
rebuild + re-run to confirm the guest actually gets a NIC.

### What was actually wrong

Every previous round of "networking is broken" was chasing the wrong thing.
The real root cause (confirmed in the kernel source and the commit log):

- **2019-12** commit `40814b98a570` "um: Mark non-vector net transports as
  obsolete": all non-vector UML net drivers (tuntap, slip, daemon, mcast,
  ethertap, pcap, vde) flagged obsolete.
- **2025-05** commit `e619e18ed462` "um: Remove legacy network transport
  infrastructure": those drivers were **deleted entirely**. Landed in 6.16.

`scripts/build_kernel.sh` builds `6.18.36`, so `CONFIG_UML_NET`,
`CONFIG_UML_NET_TUNTAP`, etc. **do not exist** in this kernel. The only UML
net transport left is `CONFIG_UML_NET_VECTOR`. That's why the boot log
showed:

```
Kernel command line: ... eth0=tuntap,tap_pkg ...
Unknown kernel command line parameters "eth0=tuntap,tap_pkg ...",
will be passed to user space.
```

No `eth0` driver exists to parse the parameter, so it was dropped and the
guest got no NIC. This was independent of ubd vs vhost block backend and
independent of raw vs qcow2 — those red herrings cost several rounds.

### Fix

1. `scripts/build_kernel.sh`: enable `CONFIG_UML_NET_VECTOR` + `CONFIG_TUN`
   (the host-side tun module). The `CONFIG_UML_NET` / `CONFIG_UML_NET_TUNTAP`
   lines an earlier attempt added are no-ops (symbols don't exist in 6.18)
   and have been removed.
2. `internal/container/manager.go` `buildTaskArgs` + `buildLegacyArgs`:
   emit `vec0:transport=tap,ifname=<tap>,depth=128,gro=1` instead of
   `eth0=tuntap,<tap>`. Parameters per
   `Documentation/virt/uml/user_mode_linux_howto_v2.rst`.
3. `scripts/test_pkg_install.sh` init.sh: configure `vec0` inside the guest
   (not `eth0`); the in-guest interface name matches the kernel parameter.

The vec tap transport requires the host tap to exist and be UP (the caller
already does `ip tuntap add` + `ip link set up`) and root or CAP_NET_ADMIN
(PVM runs the sandbox under sudo, so this is satisfied).

### Re-validate after the kernel rebuild

- Confirm the guest gets a `vec0` interface and can reach the gateway.
- Re-check whether the qcow2+vhost path (CoW isolation) also works with vec
  networking. The earlier "virtio_uml block conflicts with eth0=tuntap"
  theory was never the bug — it was CONFIG_UML_NET_VECTOR missing — so the
  vhost+vec combination may now Just Work. If so, flip
  `uml/agentpvm.toml` `use_vhost_blk` back to `true` for CoW by default.

### Reference

- Commit `e619e18ed462bded8e8f12672a37053d39451404` — "um: Remove legacy
  network transport infrastructure".
- `arch/um/drivers/Kconfig` (6.18): only `UML_NET_VECTOR` under
  "UML Network Devices".
- `Documentation/virt/uml/user_mode_linux_howto_v2.rst` — "tap transport":
  `vecX:transport=tap,ifname=tap0,depth=128,gro=1`, "tap0 must already
  exist and UP".
