# Repository Guidelines

Contributor guide for **PVM** (`uml-container`), a User-Mode Linux (UML) container manager written in Go with a Nuxt 3 WebUI and eBPF networking.

## Project Structure & Module Organization

- `cmd/` — entry points: `umlctl` (thin UML container launcher: start/image/logs/ps/network; supports `-config` for launch fields only), `agentpvm` (the real agent sandbox: run/api/webui/snapshot/cow/cgroup/network + new gate/approval/pool subcommands).
- `internal/` — core Go packages:
  - **Launch & runtime**: `uml/` (kernel launcher), `container/` (`Start` legacy + `StartTask` TaskSpec-driven), `vhost/`, `image/`, `filesystem/`, `cow/` (qcow2 block-level CoW).
  - **Control plane (plan.md §3-§11)**: `spec/` (TaskSpec + TOML), `state/` (lifecycle FSM), `audit/` (tamper-evident ledger), `identity/` (Credential Broker), `network/egress/` (L7 proxy) + `network/` (bridge/TAP/eBPF), `policy/` (Tool Gateway), `artifact/` (Artifact Gate), `approval/` (human tickets), `incident/` (Incident Controller), `pool/` (Warm Pool + Quota).
  - `api/` (E2B-compatible REST server, Echo; `/api/exec` is the Tool Gateway), `config/`, `log/`, `cgroup/`, `snapshot/`, `ebpf/`, `pkg/`.
- `bpf/` — eBPF C sources (`egress.c`: SSRF IP-floor); compiled into `internal/network/` via `bpf2go`.
- `uml/agentpvm.toml` — default TaskSpec consumed by `agentpvm run` when no `-config` is given.
- `webui/` — Nuxt 3 frontend, embedded into the Go binary via `webui/embed.go`.
- `scripts/` — kernel build and integration/perf test shell scripts.
- `tests/` — numbered end-to-end shell suites (`01_test_e2b_api.sh` … `09_test_cgroup_limits.sh`). Suites `05`–`08` are CI-safe (no UML kernel/root needed); `09` additionally requires root + a kernel rebuilt with `CONFIG_MEMCG`/`CONFIG_CGROUP_PIDS` (guest-side limit enforcement); `01`–`04` exercise kernel-adjacent paths.
- `*_test.go` — Go unit tests colocated with their packages.

## Build, Test, and Development Commands

```bash
go build ./cmd/umlctl                 # build the main CLI (CI default)
go build -o bin/umlctl ./cmd/umlctl   # build umlctl (integration script)
go build -o agentpvm ./cmd/agentpvm   # build the agentpvm management binary
go generate ./...                     # regenerate eBPF bytecode (requires clang/llvm/libbpf-dev)
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
