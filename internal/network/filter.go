package network

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var WhitelistMap *ebpf.Map

func AttachEgressFilter(tapName string) error {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", tapName, err)
	}

	// Add clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	// Ignore err if clsact is already there
	_ = netlink.QdiscAdd(qdisc)

	// Attach filter to egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.EgressFilter.FD(),
		Name:         "egress_filter",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to attach BPF filter: %w", err)
	}

	// Expose map globally
	WhitelistMap = objs.WhitelistMap
	return nil
}
