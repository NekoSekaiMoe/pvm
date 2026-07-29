package network

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/egress.c -- -I/usr/include -I/usr/include/aarch64-linux-gnu -O2
