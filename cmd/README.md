# Commands (`cmd/`)

This directory houses the main entry points (executables) for the PVM project. 

## `umlctl`

The primary CLI tool for interacting with the PVM system.

**Key Commands:**
- `umlctl start`: Launch a new UML container.
- `umlctl ps`: List running and stopped containers.
- `umlctl image`: Manage base images (e.g., pull from Docker Hub).
- `umlctl network`: Manage virtual network bridges.
- `umlctl logs`: View the console output of a running container.
- `umlctl webui`: Start the embedded Web Dashboard and REST API.
