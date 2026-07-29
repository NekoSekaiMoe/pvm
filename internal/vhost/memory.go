package vhost

import (
	"fmt"
	"syscall"
)

type MappedRegion struct {
	VhostUserMemoryRegion
	MmapAddr []byte
	Fd       int
}

type Memory struct {
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

	m.Regions = append(m.Regions, MappedRegion{
		VhostUserMemoryRegion: region,
		MmapAddr:              b,
		Fd:                    fd,
	})
	return nil
}

// GuestToHost translates a Guest Physical Address to a slice of memory in the Go process
func (m *Memory) GuestToHost(gpa uint64, size uint64) ([]byte, error) {
	for _, r := range m.Regions {
		// Does this memory region contain the entire requested range?
		if gpa >= r.GuestPhysAddr && gpa+size <= r.GuestPhysAddr+r.MemorySize {
			offset := gpa - r.GuestPhysAddr
			return r.MmapAddr[offset : offset+size], nil
		}
	}
	return nil, fmt.Errorf("GPA 0x%x (size %d) not found in memory regions", gpa, size)
}

// UnmapAll cleans up memory regions when connection closes
func (m *Memory) UnmapAll() {
	for _, r := range m.Regions {
		syscall.Munmap(r.MmapAddr)
		syscall.Close(r.Fd)
	}
	m.Regions = nil
}
