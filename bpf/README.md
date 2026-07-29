# BPF (Berkeley Packet Filter)

This directory contains eBPF programs and loaders utilized by PVM.

## Purpose

eBPF is used in PVM for:
- **Advanced Networking**: Accelerating packet forwarding between the host bridge and UML TAP devices.
- **Security & Observability**: Enforcing fine-grained egress traffic whitelist filtering without modifying the kernel.

## Development

BPF programs are typically written in restricted C and compiled via Clang/LLVM to BPF bytecode, which is then loaded by the Go manager (using libraries like `cilium/ebpf`).
