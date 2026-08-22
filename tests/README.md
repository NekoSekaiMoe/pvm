# Integration & End-to-End Tests (`tests/`)

This directory contains shell-based integration and end-to-end (E2E) suites validating PVM's CLI commands, REST API endpoints, security defenses, and control plane integrations.

---

## Test Suites Matrix

| Suite | Requires Kernel / Root? | What It Validates |
|:---|:---:|:---|
| `01_test_e2b_api.sh` | No | E2B REST API: authentication, `/api/exec` gating, container start/logs/delete |
| `02_test_network_qos.sh` | Yes | TAP network interface and `tc tbf` bandwidth rate limiting |
| `03_test_cgroup_freeze.sh` | Yes | cgroup v2 freeze/thaw suspending and resuming guest processes |
| `04_test_qcow2_mount.sh` | Yes | qcow2 overlay creation and vhost-user-blk virtio mount |
| `05_test_controlplane_api.sh` | No | Full control plane: TaskSpec load, FSM transitions, audit verify, approvals, pool warm |
| `06_test_cli_smoke.sh` | No | CLI wiring: `agentpvm run -config`, default config fallback, FSM launch recording |
| `07_test_gate_snapshot_cli.sh`| No | `agentpvm gate` PASS/FAIL secret scan; `agentpvm snapshot` export/import |
| `08_test_approval_pool_cli.sh`| No | CLI subcommands for approvals and warm pool stats against live API |
| `09_test_cgroup_limits.sh` | Yes (+ Root) | Guest-side in-UML memory.max and pids.max OOM-kill limits |
| `10_test_volume_api_cli.sh` | No | Volume REST CRUD, token masking, ID regex validation, plugin CLI parsing |
| `11_test_template_api.sh` | No | Template Center REST API, PENDING->READY transitions, alias binding, conflict rejection |
| `12_test_lifecycle_autopause.sh` | No | Task Pause/Resume, cgroup.freeze synchronization, auto-resume on API activity |
| `13_test_e2b_api_security.sh` | No | Bearer token auth enforcement, custom API_SECRET, public WebUI route, input sanitization |
| `14_test_policy_gateway.sh` | No | Tool Gateway `/api/exec` syntax parsing, missing task gating, 403 unregistered policy |
| `15_test_audit_ledger.sh` | No | Cryptographic hash chain verification, tampering detection, truncation defense |
| `16_test_pool_quota.sh` | No | Warm pool pre-allocation (1..100 boundary checks), tenant quota management |
| `17_test_umlctl_cli.sh` | No | `umlctl start/logs/ps/network` CLI argument parsing and validation |
| `18_test_agentpvm_cli.sh` | No | `agentpvm` subcommands, usage banners, and missing flag handling |
| `19_test_cow_advanced.sh` | No | Pure-Go qcow2 path injection defense, in-place compaction, raw <-> qcow2 byte round-trip |
| `20_test_snapshot_security.sh`| No | Snapshot tarball directory structure integrity and destination overwrite protection |
| `21_test_state_fsm_durability.sh`| No | Complete lifecycle FSM path (pending->completed), illegal edge rejection, quarantine |
| `22_test_docker_image_pull.sh`| No | Docker image pull error handling and safeName sanitization |
| `23_test_container_api.sh` | No | Container REST: list shape, logs/delete/snapshot/restore id validation, `/containers/start` validation chain (name/CPU/rootfs injection/memory) |
| `24_test_tasks_audit_api.sh`| No | Task read API (`GET /tasks`, detail 400/404), unknown-task transition 404, `load-spec` path mode + `PVM_SPEC_ROOT` traversal defense, audit ledger read + chain verify |
| `25_test_e2b_api_full.sh` | No | Exhaustive sweep of ALL 34 API routes: success path where kernel-free, contract-correct error where kernel/root required |
| `26_test_full_feature_e2e.sh`| No | One task's full cross-plane lifecycle: load-spec → FSM → tool gateway (allow/deny/approve) → approval → pause/resume → gate release → completed → destroy → audit chain |
| `27_test_event_snapshot_clone_rollback.sh` | No | Event-level snapshots, instant task/container cloning (zero-copy CoW branching), historical rollback with audit verification |
| `28_test_webui_simulation.sh` | No | End-to-end verification of Nuxt 3 WebUI SPA routes, metrics, and page-dependent REST workflows |

---

## Running the Suites

```bash
# Run all unprivileged CI-safe suites (fails fast on first error)
set -e
for s in tests/{05,06,07,08,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28}_*.sh; do
    echo "Running $s..."
    ./"$s"
done
```
