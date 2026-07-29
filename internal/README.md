# Internal Packages (`internal/`)

The `internal/` directory contains the core business logic of PVM. Following Go conventions, these packages are private to this repository and cannot be imported by external projects.

## Architecture

- **`api/`**: The Echo-based REST API server (`e2b_server.go`) that exposes container management endpoints and serves the embedded Nuxt WebUI.
- **`config/`**: Data structures representing container and system configurations.
- **`container/`**: The lifecycle manager for containers (start, stop, logging).
- **`image/`**: Handles downloading container images from Docker registries and setting up OverlayFS layers.
- **`log/`**: Internal logging utilities.
- **`network/`**: Configures host bridges, TAP devices, and handles IP allocations.
- **`state/`**: Manages the persistence of container state (PID, status) in `/var/lib/uml-container`.
- **`uml/`**: The core launcher that spawns and manages the underlying User-Mode Linux kernel process.
