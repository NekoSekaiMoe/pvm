# Utility Scripts (`scripts/`)

This directory contains shell scripts for kernel compilation, integration testing, and I/O performance benchmarking.

---

## Scripts Catalog

### `build_kernel.sh`
Downloads and compiles an optimized Linux 6.18.x User-Mode Linux (UML) kernel to `bin/linux`. Configures essential kernel options:
- `CONFIG_HOSTFS=y`: Host directory sharing.
- `CONFIG_VIRTIO_BLK=y` & `CONFIG_VIRTIO_UML=y`: vhost-user virtio disk devices.
- `CONFIG_MEMCG=y` & `CONFIG_CGROUP_PIDS=y`: In-guest cgroup resource isolation.
- `CONFIG_UML_NET_TUNTAP=y` & `CONFIG_UML_NET_VECTOR=y`: High-speed TAP networking.

```bash
./scripts/build_kernel.sh
```

### `test_integration.sh`
Spawns a real UML guest kernel with rootfs and asserts clean initialization, init output, and exit status.
```bash
./scripts/test_integration.sh
```

### `test_io_perf.sh`
Benchmarks disk throughput and I/O latency comparing hostfs, virtio-blk (vhost-user), and CoW qcow2 overlays using `fio` / `dd`.
```bash
./scripts/test_io_perf.sh
```

### `test_pkg_install.sh`
Validates guest-side package managers (`apk`, `apt`, `pip`) inside booted containers across various base distributions.
```bash
./scripts/test_pkg_install.sh
```
