package vhost

import (
	"fmt"
	"sync"
	"syscall"
)

type MappedRegion struct {
	VhostUserMemoryRegion
	MmapAddr []byte
	Fd       int
}

// Memory holds the guest physical memory regions mmap'd into this process.
//
// Regions are read by ring-processor goroutines (ProcessRing/StartRX/StartTX)
// via GuestToHost and mutated by the vhost-user request handler (MapRegion on
// SET_MEM_TABLE, UnmapAll on re-negotiation / teardown). A mutex serializes
// all access so that UnmapAll can never Munmap a region while a processor is
// still dereferencing its MmapAddr (use-after-unmap), and so that GuestToHost
// never observes a half-built Regions slice.
type Memory struct {
	mu      sync.RWMutex
	Regions []MappedRegion
}

// MapRegion mmaps a file descriptor shared by the UML guest into the host Go process
func (m *Memory) MapRegion(region VhostUserMemoryRegion, fd int) error {
	b, err := syscall.Mmap(fd, int64(region.MmapOffset), int(region.MemorySize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap fd %d: %v", fd, err)
	}

	// Attempt to use Transparent Huge Pages (THP) / HugeTLB for this region
	// This drastically reduces TLB misses for the VM's physical memory
	_ = syscall.Madvise(b, syscall.MADV_HUGEPAGE)

	m.mu.Lock()
	m.Regions = append(m.Regions, MappedRegion{
		VhostUserMemoryRegion: region,
		MmapAddr:              b,
		Fd:                    fd,
	})
	m.mu.Unlock()
	return nil
}

// GuestToHost translates a Guest Physical Address to a slice of memory in the
// Go process. The returned slice aliases mmap'd guest memory and is only valid
// while the region remains mapped; callers must not retain it across
// re-negotiation. It is safe for concurrent use.
func (m *Memory) GuestToHost(gpa uint64, size uint64) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.Regions {
		// Does this memory region contain the entire requested range?
		if gpa >= r.GuestPhysAddr && gpa+size <= r.GuestPhysAddr+r.MemorySize {
			offset := gpa - r.GuestPhysAddr
			return r.MmapAddr[offset : offset+size], nil
		}
	}
	return nil, fmt.Errorf("GPA 0x%x (size %d) not found in memory regions", gpa, size)
}

// UnmapAll cleans up memory regions when connection closes. It must only be
// called after all ring processors that may touch these regions have been
// stopped (see Server.stopProcessors); otherwise processors could
// use-after-unmap. Safe for concurrent use with GuestToHost.
func (m *Memory) UnmapAll() {
	m.mu.Lock()
	regions := m.Regions
	m.Regions = nil
	m.mu.Unlock()

	for _, r := range regions {
		syscall.Munmap(r.MmapAddr)
		syscall.Close(r.Fd)
	}
}
