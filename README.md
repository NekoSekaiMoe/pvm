# PVM (UML Container Manager)

PVM is a lightweight, User-Mode Linux (UML) based container management system. It provides strong isolation for processes by leveraging virtualized Linux kernels while maintaining a container-like CLI and experience.

## Features

- **UML Isolation**: Runs applications inside dedicated User-Mode Linux instances for VM-level security.
- **REST API**: Built-in HTTP server (`internal/api`) for remote orchestration, compatible with E2B SDK patterns.
- **Modern WebUI**: An embedded, glassmorphism-designed WebUI (built with Nuxt 3) for visually managing containers, images, and logs.
- **Networking**: Bridge and TAP interface management for UML networking.
- **Image Management**: Seamless pulling of Docker base images to be used as container rootfs via OverlayFS.

## Quick Start

```bash
# Build the project
go build ./cmd/umlctl

# Start the WebUI
./umlctl webui --port 3000

# Start a container via CLI
./umlctl start -name my-container -rootfs alpine
```

## Repository Structure

- [`bpf/`](./bpf/): eBPF programs for advanced networking and security.
- [`cmd/`](./cmd/): Main executables (e.g., `umlctl`).
- [`internal/`](./internal/): Core Go packages and logic.
- [`scripts/`](./scripts/): Utility scripts for building and setup.
- [`tests/`](./tests/): Test suites.
- [`webui/`](./webui/): Frontend Nuxt 3 source code for the Web Dashboard.
