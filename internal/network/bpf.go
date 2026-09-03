package network

import "errors"

// ErrBpfNotGenerated is returned by the bpf2go load shims when the compiled
// BPF objects are absent — i.e. `go generate ./internal/network` (clang +
// libbpf headers) has not run in this checkout. Tests that need the real
// ELF skip on this sentinel; CI always regenerates first.
var ErrBpfNotGenerated = errors.New("bpf objects not generated (run `go generate ./internal/network` with clang installed)")

//go:generate bash -c "go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/egress.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu -O2"
//go:generate bash -c "go run github.com/cilium/ebpf/cmd/bpf2go tapdp ../../bpf/tap_dataplane.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu -O2"
