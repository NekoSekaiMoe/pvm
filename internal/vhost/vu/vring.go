package vu

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"unsafe"
)

// Split-virtqueue descriptor flags (uapi/linux/virtio_ring.h).
const (
	descFlagNext     = 1
	descFlagWrite    = 2 // device-writable (driver→device data if clear)
	descFlagIndirect = 4
)

const vringAvailFNoInterrupt = 1

// elem is one popped request: a descriptor chain split into out (driver→
// device) and in (device→driver) scatter-gather lists over guest memory.
type elem struct {
	head  uint32
	outSG [][]byte
	inSG  [][]byte
	raw   []rawDesc // descriptors pending translation (cleared by translateSG)
}

// vring is one split virtqueue living in guest memory.
type vring struct {
	num   uint32 // queue size (power of two)
	desc  []byte // descriptor table: num * 16 bytes
	avail []byte // avail ring: 4 + num*2 bytes
	used  []byte // used ring: 4 + num*8 bytes

	lastAvail uint32
	usedIdx   uint32

	kick    *eventfd // frontend → us
	call    *eventfd // us → frontend (interrupt)
	err     *eventfd
	enabled bool
}

// setup binds the vring tables from a SET_VRING_ADDR message.
func (v *vring) setup(mt *memTable, a vringAddr) error {
	var err error
	if v.num == 0 {
		return fmt.Errorf("vu: SET_VRING_ADDR before SET_VRING_NUM")
	}
	if v.desc, err = mt.translate(a.desc, uint64(v.num)*16); err != nil {
		return fmt.Errorf("vu: desc table: %w", err)
	}
	if v.avail, err = mt.translate(a.avail, 4+uint64(v.num)*2); err != nil {
		return fmt.Errorf("vu: avail ring: %w", err)
	}
	if v.used, err = mt.translate(a.used, 4+uint64(v.num)*8); err != nil {
		return fmt.Errorf("vu: used ring: %w", err)
	}
	return nil
}

// availFlagsIdx atomically reads {flags, idx} as one u32 (LE: flags low,
// idx high). 16-bit atomics don't exist in sync/atomic; the two fields are
// adjacent and 4-byte-aligned, so a u32 load covers both.
func (v *vring) availIdx() uint16 {
	v32 := atomic.LoadUint32((*uint32)(unsafe.Pointer(&v.avail[0])))
	return uint16(v32 >> 16)
}

// pop returns the next request element or nil when the queue is empty.
func (v *vring) pop(mt *memTable) (*elem, error) {
	if v.desc == nil {
		return nil, fmt.Errorf("vu: pop on unconfigured vring")
	}
	avail := v.availIdx()
	if uint32(avail) == v.lastAvail {
		return nil, nil
	}
	head := binary.LittleEndian.Uint16(v.avail[4+uint64(v.lastAvail%v.num)*2:])
	v.lastAvail++
	return v.walkChain(mt, uint32(head))
}

// walkChain follows a descriptor chain starting at head, expanding indirect
// tables, and splits it into out/in scatter-gather lists.
func (v *vring) walkChain(mt *memTable, head uint32) (*elem, error) {
	e := &elem{head: head}
	idx := head
	seen := 0
	for {
		if seen > int(v.num)*2 { // chain longer than the ring: bail
			return nil, fmt.Errorf("vu: descriptor chain loop (head %d)", head)
		}
		seen++
		d, err := v.descAt(idx)
		if err != nil {
			return nil, err
		}
		flags := binary.LittleEndian.Uint16(d[12:])
		if flags&descFlagIndirect != 0 {
			// Indirect: addr/len point at a table of descriptors.
			taddr := binary.LittleEndian.Uint64(d[0:])
			tlen := binary.LittleEndian.Uint32(d[8:])
			if flags&descFlagNext != 0 {
				return nil, fmt.Errorf("vu: indirect descriptor with NEXT")
			}
			if tlen%16 != 0 {
				return nil, fmt.Errorf("vu: indirect table len %d not multiple of 16", tlen)
			}
			tbl, err := mt.translate(taddr, uint64(tlen))
			if err != nil {
				return nil, err
			}
			if err := e.walkTable(tbl, int(tlen/16)); err != nil {
				return nil, err
			}
			break // indirect is always the last in the outer chain
		}
		if err := e.addDesc(d); err != nil {
			return nil, err
		}
		if flags&descFlagNext == 0 {
			break
		}
		idx = uint32(binary.LittleEndian.Uint16(d[14:]))
	}
	if len(e.raw) == 0 {
		return nil, fmt.Errorf("vu: empty descriptor chain (head %d)", head)
	}
	return e, nil
}

func (v *vring) descAt(idx uint32) ([]byte, error) {
	if idx >= v.num {
		return nil, fmt.Errorf("vu: descriptor index %d >= queue size %d", idx, v.num)
	}
	return v.desc[uint64(idx)*16 : uint64(idx)*16+16], nil
}

// walkTable walks an indirect descriptor table (16-byte entries, NEXT-chained
// by position).
func (e *elem) walkTable(tbl []byte, count int) error {
	for i := 0; i < count; i++ {
		d := tbl[i*16:]
		if err := e.addDesc(d); err != nil {
			return err
		}
		if binary.LittleEndian.Uint16(d[12:])&descFlagNext == 0 {
			return nil
		}
	}
	return fmt.Errorf("vu: indirect table ran off end without clearing NEXT")
}

func (e *elem) addDesc(d []byte) error {
	addr := binary.LittleEndian.Uint64(d[0:])
	length := binary.LittleEndian.Uint32(d[8:])
	flags := binary.LittleEndian.Uint16(d[12:])
	if length == 0 {
		return fmt.Errorf("vu: zero-length descriptor")
	}
	// The caller resolves the slice AFTER translation; here we only record
	// the raw descriptor and translate lazily so the same code serves
	// direct and indirect tables.
	e.raw = append(e.raw, rawDesc{addr: addr, length: length, write: flags&descFlagWrite != 0})
	return nil
}

// rawDesc is a not-yet-translated descriptor.
type rawDesc struct {
	addr   uint64
	length uint32
	write  bool
}

// translateSG resolves raw descriptors into guest-memory slices. Must be
// called before use (kept separate so walkChain stays allocation-light).
func (e *elem) translateSG(mt *memTable) error {
	for _, d := range e.raw {
		b, err := mt.translate(d.addr, uint64(d.length))
		if err != nil {
			return err
		}
		if d.write {
			e.inSG = append(e.inSG, b)
		} else {
			e.outSG = append(e.outSG, b)
		}
	}
	e.raw = nil
	return nil
}

// push posts a completed element to the used ring and interrupts the guest
// unless it masked interrupts (VRING_AVAIL_F_NO_INTERRUPT).
func (v *vring) push(e *elem, usedLen uint32) error {
	slot := v.usedIdx % v.num
	binary.LittleEndian.PutUint32(v.used[4+uint64(slot)*8:], e.head)
	binary.LittleEndian.PutUint32(v.used[4+uint64(slot)*8+4:], usedLen)
	v.usedIdx++
	// Release-store the index AFTER the entry (cross-process shared memory).
	// The u32 at used[0] is {flags u16, idx u16}; CAS to preserve flags
	// while publishing the new idx with release ordering.
	p := (*uint32)(unsafe.Pointer(&v.used[0]))
	for {
		old := atomic.LoadUint32(p)
		new := (old & 0xFFFF) | uint32(uint16(v.usedIdx))<<16
		if atomic.CompareAndSwapUint32(p, old, new) {
			break
		}
	}
	return nil
}

// notify kicks the guest if it hasn't masked interrupts.
func (v *vring) notify() error {
	flags := binary.LittleEndian.Uint16(v.avail[0:])
	if flags&vringAvailFNoInterrupt != 0 || v.call == nil {
		return nil
	}
	return v.call.signal()
}
