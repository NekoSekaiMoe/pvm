# Repository Guidelines

Contributor guide for **PVM** (`uml-container`), a User-Mode Linux (UML) container manager written in Go with a Nuxt 3 WebUI and eBPF networking.

## Project Structure & Module Organization

- `cmd/` — entry points: `umlctl` (container lifecycle CLI: start/image/logs/ps/network), `agentpvm` (advanced/management: run/api/webui/snapshot/cow/cgroup/network).
- `internal/` — core Go packages: `api/` (E2B-compatible REST server, Echo), `container/`, `uml/` (kernel launcher), `image/`, `filesystem/` (ext4/overlay), `network/` (bridge/TAP/eBPF), `cgroup/`, `cow/`, `snapshot/`, `vhost/`, `state/`, `config/`, `log/`, `daemon/`.
- `bpf/` — eBPF C sources (e.g. `egress.c`); compiled into `internal/network/` via `bpf2go`.
- `webui/` — Nuxt 3 frontend, embedded into the Go binary via `webui/embed.go`.
- `scripts/` — kernel build and integration/perf test shell scripts.
- `tests/` — numbered end-to-end shell suites (`01_test_e2b_api.sh`, etc.).
- `*_test.go` — Go unit tests colocated with their packages (e.g. `internal/cgroup/manager_test.go`).

## Build, Test, and Development Commands

```bash
go build ./cmd/umlctl                 # build the main CLI (CI default)
go build -o bin/umlctl ./cmd/umlctl   # build umlctl (integration script)
go build -o agentpvm ./cmd/agentpvm   # build the agentpvm management binary
go generate ./...                     # regenerate eBPF bytecode (requires clang/llvm/libbpf-dev)
go test -v ./...                      # run all Go unit tests (CI default)
go vet ./...                          # static checks before pushing

./scripts/build_kernel.sh             # download + compile UML kernel (Linux 6.6.9) to bin/linux
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
- End-to-end checks are shell scripts under `tests/` prefixed with a two-digit order id (`NN_test_*.sh`); each must `exit 1` on failure.
- Run the full CI-equivalent set locally: `go generate ./... && go build ./cmd/umlctl && go test -v ./...`.

## Commit & Pull Request Guidelines

This repo uses **Conventional Commits** (verified against `git log`): `feat:`, `fix:`, `ci:`, `docs:`, `test:`. Scope is optional, e.g. `fix(umlctl): ...`.

- Keep one logical change per PR; reference the issue in the description if applicable.
- Title the PR like the squashed commit (e.g. `feat: add X for Y`).
- Confirm CI (`go test -v ./...`, eBPF generate, `test_integration.sh`) passes locally before requesting review.
- Generated files (`bpf_bpf*.go`, `webui/.output/`) must not be hand-edited; rerun code generation instead.
