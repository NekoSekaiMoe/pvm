# Repository Guidelines

Contributor guide for **PVM** (`uml-container`), a User-Mode Linux (UML) container manager written in Go with a Nuxt 3 WebUI and eBPF networking.

## Project Structure & Module Organization

- `cmd/` — entry points: `umlctl` (thin UML container launcher: start/image/logs/ps/network; supports `-config` for launch fields only), `agentpvm` (the real agent sandbox: run/api/webui/snapshot/cow/cgroup/network + new gate/approval/pool subcommands).
- `internal/` — core Go packages:
  - **Launch & runtime**: `uml/` (kernel launcher + console stdin/tee), `container/` (`Start` legacy + `StartTask` TaskSpec-driven), `vhost/`, `image/`, `filesystem/`, `cow/` (qcow2 block-level CoW), `console/` (guest console sessions: marker exec, PTY, ring buffer), `logx/` (rotating console logs).
  - **Control plane (plan.md §3-§11)**: `spec/` (TaskSpec + TOML), `state/` (lifecycle FSM), `audit/` (tamper-evident ledger + ed25519 signing + online verify), `identity/` (Credential Broker, persistent keys + refresh), `network/egress/` (L7 proxy + opt-in MITM credential injection) + `network/` (bridge/TAP/eBPF + persistent subnet registry), `policy/` (Tool Gateway + executors), `artifact/` (Artifact Gate: replay/tests/declare verifiers), `approval/` (human tickets, persistent + webhook), `incident/` (Incident Controller + REST sensors), `pool/` (Warm Pool + Quota, persistent factory).
  - **envd compat**: `api/envd.go` — :49982 version websocket + :49983 Connect-JSON (`process.Process`, `filesystem.Filesystem`, `/files`).
  - **Observability**: `metrics/` (Prometheus text registry: `/metrics`, `/healthz`, `/version`, opt-in pprof).
  - `api/` (E2B-compatible REST server, Echo; `/api/exec` is the Tool Gateway), `config/`, `log/`, `cgroup/`, `snapshot/` (+CRIU memory capture), `template/` (build pipeline PENDING→READY), `volume/`, `filesystem/`, `pkg/`.
- `bpf/` — eBPF C sources (`egress.c`: SSRF IP-floor); compiled into `internal/network/` via `bpf2go`.
- `uml/agentpvm.toml` — default TaskSpec consumed by `agentpvm run` when no `-config` is given.
- `webui/` — Nuxt 3 frontend (i18n en/zh + assistant console), embedded into the Go binary via `webui/embed.go`.
- `deploy/` — systemd units, docker-compose, Dockerfile, one-shot installer (`deploy/README.md` is the deployment guide); `api/openapi.yaml` — OpenAPI 3.1 spec (see `api/README.md`); `sdk/go/` — official Go SDK.
- `scripts/` — kernel build and integration/perf test shell scripts.
- `tests/` — numbered end-to-end shell suites (`01_test_e2b_api.sh` … `52_test_registry_policy.sh`). Suites `05`–`08`, `10`–`46`, `48`–`52` are CI-safe (no UML kernel/root needed); `47` requires root (bridge setup); `09` additionally requires root + a kernel rebuilt with `CONFIG_MEMCG`/`CONFIG_CGROUP_PIDS` (guest-side limit enforcement); `01`–`04` exercise kernel-adjacent paths.
- `*_test.go` — Go unit tests colocated with their packages.

## Build, Test, and Development Commands

```bash
go build ./cmd/umlctl                 # build the main CLI (CI default)
go build -o bin/umlctl ./cmd/umlctl   # build umlctl (integration script)
go build -o agentpvm ./cmd/agentpvm   # build the agentpvm management binary
go generate ./...                     # regenerate eBPF bytecode locally (requires clang/llvm/libbpf-dev);
                                      # Bazel builds generate it via //internal/network:bpf2go_* automatically
go test -v ./...                      # run all Go unit tests (CI default)
go vet ./...                          # static checks before pushing

./scripts/build_kernel.sh             # download + compile UML kernel (Linux 6.18.x) to bin/linux
./scripts/test_integration.sh         # boot a real UML container and assert init output
for s in tests/*.sh; do ./"$s"; done  # run the numbered integration suites serially

cd webui && npm install && npm run dev        # develop WebUI (http://localhost:3000)
cd webui && npm run generate                   # static-generate WebUI for embedding
./agentpvm webui --port 3000                   # serve the embedded WebUI from the binary
```

## Coding Style & Naming Conventions

- **Go**: follow `gofmt`/`goimports`; tabs, 80–100 col. Packages are lowercase, files `snake_case.go`. Exported types are `PascalCase`; constructors named `NewX`. Tests use `_test.go` with `func TestXxx(t *testing.T)`.
- **eBPF C** (`bpf/`): kernel C style; CI runs `clang-tidy bpf/egress.c`. Never hand-edit generated `*_bpfeb.go`/`*_bpfel.go` — regenerate with `go generate`.
- **WebUI**: Vue 3 `<script setup>` + Nuxt 3; pages live in `webui/pages/`. Keep the glassmorphism design tokens consistent.

## Testing Guidelines

- Add a `*_test.go` next to the package under test; aim to cover public functions in `internal/`. Use table-driven tests and `t.Run` subtests.
- Cross-plane and adversarial tests live in dedicated packages: `internal/integrationtest/` (spec→task→audit, incident→revoke, pool→quota, policy→approval, artifact gate) and `internal/securitytest/` (ledger tamper, token forge, SSRF, secret leak, quota bypass). Per-plane deepening tests are `*_matrix_test.go` / `*_edge_test.go`.
- Run the full CI-equivalent set locally: `go generate ./... && go build ./cmd/umlctl && go test -v ./...`.

## Commit & Pull Request Guidelines

This repo uses **Conventional Commits** (verified against `git log`): `feat:`, `fix:`, `ci:`, `docs:`, `test:`. Scope is optional, e.g. `fix(umlctl): ...`.

- Keep one logical change per PR; reference the issue in the description if applicable.
- Title the PR like the squashed commit (e.g. `feat: add X for Y`).
- Confirm CI (`go test -v ./...`, eBPF generate, `test_integration.sh`) passes locally before requesting review.
- Generated files (`bpf_bpf*.go`, `webui/.output/`) must not be hand-edited; rerun code generation instead.

## Security Trust Boundaries (console exec & evidence)

- `console.Session.Exec` (marker protocol) results are **guest-attested, not host-verified**: a guest watching its console stream can capture the random marker token and forge both stdout and exit code. `policy.ConsoleExecutor` marks this explicitly via `Result["guest_attested"] = true`; governance consumers (approvals, gates, dashboards) must treat `OK=true` as the guest's claim, never as cryptographic evidence. Upgrading this requires a signed guest-side agent — do not "fix" it by strengthening the marker alone. Full analysis: `docs/attested-exec.md`.
- `artifact.TestsRerunVerifier` in evidence mode (no `tests.command`) reads guest-controlled console text; only the `tests.command` re-run path executes on the host and is host-verified. Specs that must actually bar an untrusted guest should set `tests.command`.
- Audit signing is ON by default (`PVM_AUDIT_SIGNING=0` opts out); the ed25519 key is generated on first use under the audit root.

## Performance Notes (evaluated paths)

- **virtio-blk multi-queue is N/A here by design**: the UML frontend (`virtio_uml` driver) negotiates a single virtqueue, so a multi-queue vhost-user backend would be dead code — see the scope note in `internal/vhost/vu/proto.go`. Parallel IO is achieved per-device instead (one vhost-user-blk backend per task/disk), plus host-side parallelism in the CoW layer.
- **Snapshot incrementality is already structural**: disk captures are qcow2 CoW branches (`cow.CreateOverlay` — O(1) metadata, zero cluster copies) and memory dumps chain CRIU `--track-mem` incremental images when `PVM_SNAPSHOT_INCREMENTAL=1` (see `internal/snapshot/event.go`). Full-file copying only exists as a fallback and in tar export (pigz-accelerated when available).
- **`state.RootDir` is atomic** (`state.Root()`/`state.SetRoot()`): background sweepers read it every tick and tests reassign it between cases; a plain global there is a data race under `-race`. New code must use the accessors, never a package-level variable of its own for the same reason.
