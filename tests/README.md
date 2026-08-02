# Tests (`tests/`)

This directory contains integration and end-to-end (E2E) tests for the PVM system.

While unit tests in Go are typically placed alongside the code they test (e.g., `manager_test.go` in `internal/container/`), this directory is reserved for tests that require a full system setup, network configurations, or complex container lifecycles.

## Suites

| Script | Requires UML kernel? | What it covers |
|---|---|---|
| `01_test_e2b_api.sh` | no | E2B-compatible API: auth, `/api/exec` gating (400/403 instead of legacy 501), container CRUD |
| `02_test_network_qos.sh` | yes | TAP + tc tbf bandwidth shaping |
| `03_test_cgroup_freeze.sh` | yes | cgroup v2 freeze/thaw suspends CPU |
| `04_test_qcow2_mount.sh` | yes | qcow2 overlay + vhost-user-blk mount |
| `05_test_controlplane_api.sh` | **no** | Black-box REST test of the new control planes: TaskSpec load, FSM transitions, audit verify, approvals, pool warm/stats, artifact gate, `/exec` gating |
| `06_test_cli_smoke.sh` | **no** | CLI wiring: `agentpvm run -config`, default config path, FSM recording on launch failure, audit spec evidence, cow path-injection guard, pool subcommands, `umlctl -config` |
| `07_test_gate_snapshot_cli.sh` | **no** | `agentpvm gate`: PASS/FAIL verdicts + exit codes, secret scan in diff and in declared files, missing/malformed bundle, audit allow/deny rows; `agentpvm snapshot`: export/import round trip, invalid-id and existing-id rejection |
| `08_test_approval_pool_cli.sh` | **no** | `agentpvm approval`/`pool` subcommands against a live API: mandatory `API_SECRET`, empty/pending/decided ticket listing, pool stats reflecting REST-driven warm, documented `pool warm` CLI gap |

Suites `05`–`08` are **CI-safe** (no kernel, no root needed beyond `go build`). Run all of them serially:

```bash
for s in tests/*.sh; do ./"$s"; done
```

The Go test suite (adversarial + cross-plane included) is at:

- `internal/integrationtest/` — cross-plane flows (spec→task→audit, incident→revoke, pool→quota, policy→approval, artifact gate)
- `internal/securitytest/` — adversarial attacks (ledger tamper, token forge, SSRF, secret leak, quota bypass, param-binding bypass)
- `internal/spec/spec_matrix_test.go`, `internal/state/fsm_matrix_test.go`, `internal/audit/edge_test.go`, `internal/network/egress/edge_test.go`, `internal/policy/edge_test.go` — per-plane unit deepening
- `internal/config/parse_memory_test.go`, `internal/cgroup/manager_edge_test.go`, `internal/network/bridge_internal_test.go`, `cmd/agentpvm/main_test.go` — pure-helper units (memory parsing, cgroup input validation + env precedence, bridge error classification, CLI config resolution / safe defaults)
