package network

//go:generate bash -c "go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/egress.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu -O2"
//go:generate bash -c "go run github.com/cilium/ebpf/cmd/bpf2go tapdp ../../bpf/tap_dataplane.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu -O2"
