# Tests (`tests/`)

This directory contains integration and end-to-end (E2E) tests for the PVM system.

While unit tests in Go are typically placed alongside the code they test (e.g., `manager_test.go` in `internal/container/`), this directory is reserved for tests that require a full system setup, network configurations, or complex container lifecycles.
