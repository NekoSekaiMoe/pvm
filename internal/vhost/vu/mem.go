package vu

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// memRegion is one mapped chunk of guest memory (VhostUserMemoryRegion).
type memRegion struct {
	gpa  uint64 // guest physical base
	size uint64
	data []byte // mmap'd contents
	fd   int
}

// memTable maps guest physical addresses to host memory shared by the
// frontend (UML passes its physmem fd(s) in VHOST_USER_SET_MEM_TABLE).
type memTable struct {
	regions []memRegion
}

func (mt *memTable) close() {
	for _, r := range mt.regions {
		if r.data != nil {
			unix.Munmap(r.data)
		}
		if r.fd >= 0 {
			unix.Close(r.fd)
		}
	}
	mt.regions = nil
}

// setMemTable parses a SET_MEM_TABLE payload: u32 nregions, u32 pad, then
// per-region { u64 gpa; u64 size; u64 userspace_addr; u64 mmap_offset },
// with one fd per region passed out-of-band.
func (mt *memTable) setMemTable(payload []byte, fds []int) error {
	if len(payload) < 8 {
		return fmt.Errorf("vu: short SET_MEM_TABLE payload")
	}
	n := binary.LittleEndian.Uint32(payload[0:])
	if int(n) > len(fds) {
		return fmt.Errorf("vu: SET_MEM_TABLE wants %d regions but only %d fds", n, len(fds))
	}
	if len(payload) < 8+int(n)*32 {
		return fmt.Errorf("vu: SET_MEM_TABLE payload too small for %d regions", n)
	}
	mt.close()
	mt.regions = make([]memRegion, 0, n)
	for i := 0; i < int(n); i++ {
		p := payload[8+i*32:]
		r := memRegion{
			gpa:  binary.LittleEndian.Uint64(p[0:]),
			size: binary.LittleEndian.Uint64(p[8:]),
			// userspace_addr (p[16:]) is the frontend's own mapping; we
			// ignore it and mmap the fd ourselves.
			fd: fds[i],
		}
		mmapOff := binary.LittleEndian.Uint64(p[24:])
		data, err := unix.Mmap(r.fd, int64(mmapOff), int(r.size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			mt.close()
			return fmt.Errorf("vu: mmap region %d (size %#x): %w", i, r.size, err)
		}
		r.data = data
		mt.regions = append(mt.regions, r)
	}
	return nil
}

// translate returns the host bytes backing guest range [gpa, gpa+size).
// The range must not cross a region boundary (virtio guarantees this for
// individual descriptors; vring tables are likewise inside one region).
func (mt *memTable) translate(gpa, size uint64) ([]byte, error) {
	for _, r := range mt.regions {
		if gpa >= r.gpa && gpa+size <= r.gpa+r.size {
			return r.data[gpa-r.gpa : gpa-r.gpa+size], nil
		}
	}
	return nil, fmt.Errorf("vu: guest address %#x+%#x outside memory table", gpa, size)
}
