# TODO

## Networking: vec transport (legacy eth0=tuntap was removed in 6.16)

**Status**: ✅ DONE — verified working in CI (run 83361317845, main @ 2026-08-02).

### Root cause (kept for posterity)

- **2019-12** commit `40814b98a570` "um: Mark non-vector net transports as
  obsolete": all non-vector UML net drivers (tuntap, slip, daemon, mcast,
  ethertap, pcap, vde) flagged obsolete.
- **2025-05** commit `e619e18ed462` "um: Remove legacy network transport
  infrastructure": those drivers were **deleted entirely**. Landed in 6.16.

`scripts/build_kernel.sh` builds `6.18.36`, so `CONFIG_UML_NET`,
`CONFIG_UML_NET_TUNTAP`, etc. **do not exist**. The only UML net transport
left is `CONFIG_UML_NET_VECTOR`, which parses `vecN:transport=...` params.
`eth0=tuntap,<tap>` was reported as an unknown kernel parameter and the guest
got no NIC.

### Fix (verified)

1. `scripts/build_kernel.sh`: `CONFIG_UML_NET_VECTOR` + `CONFIG_TUN` enabled.
2. `internal/container/manager.go` (`buildTaskArgs` + `buildLegacyArgs`):
   emits `vec0:transport=tap,ifname=<tap>,depth=128,gro=1`.
3. `scripts/test_pkg_install.sh` init.sh: configures `vec0` in the guest.

CI evidence (test_pkg_install.sh): guest got `vec0` from the uml-vector
driver, `inet 10.0.0.2/24`, default route via 10.0.0.1, ping gateway 0% loss,
apk installed fastfetch, `PKG_INSTALL_SUCCESS` observed.

### Note: ICMP vs TCP/UDP egress on CI

`ping 8.8.8.8` from the guest fails with 100% loss on GitHub-hosted runners —
the Azure fabric drops ICMP echo even though UDP (DNS to 8.8.8.8:53) and TCP
(HTTPS to the apk CDN) work fine. Not a PVM bug. The guest diag in
test_pkg_install.sh now uses a TCP 443 probe as the authoritative egress
check; the ping is kept as informational-only.

## vhost (qcow2 CoW) path: validate vhost+vec, then flip the default

**Status**: root cause of the CI "SIGABRT" identified; test rewritten to
validate the real boot. Awaiting a green CI run before flipping
`uml/agentpvm.toml` `use_vhost_blk` to `true`.

### What the "signal: aborted (core dumped)" in test 04 actually was

UML's kernel-panic path calls `os_dump_core()` → `uml_abort()` →
`kill(getpid(), SIGABRT)` (arch/um/os-Linux/util.c). Go's exec reports that
as `signal: aborted (core dumped)`. **So SIGABRT from a UML process means
"guest kernel panicked", not a host-side crash.**

Old `tests/04_test_qcow2_mount.sh` fed the guest a 10MB **empty ext4** image
(mkfs only, no `/sbin/init`). The kernel booted and then panicked with
"No working init found" — a content problem, not (necessarily) a vhost
transport problem. The test still passed because it only asserted that the
`vhost-blk.sock` *file* existed, and a stale socket file outlives the dead
qemu-storage-daemon (agentpvm's error path calls `os.Exit(1)`, skipping
defers, so nothing unlinked it).

### Fix

`tests/04_test_qcow2_mount.sh` rewritten to validate the full chain:
alpine rootfs + real init → qcow2 base → per-task CoW overlay →
qemu-storage-daemon (vhost-user-blk) → UML virtio_uml → virtio_blk (/dev/vda)
→ ext4 root mount → init → vec0 up → gateway ping. Passes only when
console.log contains `VHOST_COW_SUCCESS` and no `Kernel panic`; on failure it
dumps the kernel cmdline, virtio init lines, and panic markers.

### Remaining

- ⬜ Confirm the rewritten test 04 is green in CI (proves vhost+vec end-to-end).
- ⬜ If green: flip `uml/agentpvm.toml` `use_vhost_blk` to `true` so CoW is
  the default. Check tests/06 expectations when doing so (the smoke test
  asserts a specific FSM transition count on launch failure, which may shift
  when the failure point moves from "kernel exec" to "overlay creation").
- ⬜ Nice-to-have: `agentpvm run`'s error path uses `os.Exit(1)`, which skips
  defers and can leave the qemu-storage-daemon socket file behind. Consider
  unlinking `<statedir>/vhost-blk.sock` on teardown so stale files can't fool
  anyone again.

### Reference

- Commit `e619e18ed462bded8e8f12672a37053d39451404` — "um: Remove legacy
  network transport infrastructure".
- `arch/um/drivers/Kconfig` (6.18): only `UML_NET_VECTOR` under
  "UML Network Devices".
- `Documentation/virt/uml/user_mode_linux_howto_v2.rst` — "tap transport":
  `vecX:transport=tap,ifname=tap0,depth=128,gro=1`, "tap0 must already
  exist and UP".
- `arch/um/os-Linux/util.c` — `os_dump_core()` / `uml_abort()`: why a guest
  panic surfaces as SIGABRT on the host.
