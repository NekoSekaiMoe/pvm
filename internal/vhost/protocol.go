package vhost

import (
	"encoding/binary"
	"fmt"
)

// Virtio device IDs as defined in the kernel's virtio_ids.h.
// Used by the UML virtio_uml driver command line:
//   virtio_uml.device=<socket>:<virtio_id>
const (
	VirtioIDNet     = 1
	VirtioIDBlock   = 2
	VirtioIDConsole = 3
	VirtioIDRNG     = 4
)

// Vhost-user request types
const (
	VhostUserNone                = 0
	VhostUserGetFeatures         = 1
	VhostUserSetFeatures         = 2
	VhostUserSetOwner            = 3
	VhostUserResetOwner          = 4
	VhostUserSetMemTable         = 5
	VhostUserSetLogBase          = 6
	VhostUserSetLogFd            = 7
	VhostUserSetVringNum         = 8
	VhostUserSetVringAddr        = 9
	VhostUserSetVringBase        = 10
	VhostUserGetVringBase        = 11
	VhostUserSetVringKick        = 12
	VhostUserSetVringCall        = 13
	VhostUserSetVringErr         = 14
	VhostUserGetProtocolFeatures = 15
	VhostUserSetProtocolFeatures = 16
	VhostUserGetQueueNum         = 17
	VhostUserSetVringEnable      = 18
	VhostUserGetConfig           = 24
	VhostUserSetConfig           = 25
)

// Vhost-user message flags
const (
	VhostUserReplyMask   = 0x1 << 2
	VhostUserNeedReply   = 0x1 << 3
)

// VhostUserMsgHeader is the 12-byte header of a vhost-user message
type VhostUserMsgHeader struct {
	Request uint32
	Flags   uint32
	Size    uint32
}

func (h *VhostUserMsgHeader) Decode(b []byte) error {
	if len(b) < 12 {
		return fmt.Errorf("message too short for header")
	}
	h.Request = binary.LittleEndian.Uint32(b[0:4])
	h.Flags = binary.LittleEndian.Uint32(b[4:8])
	h.Size = binary.LittleEndian.Uint32(b[8:12])
	return nil
}

func (h *VhostUserMsgHeader) Encode(b []byte) {
	binary.LittleEndian.PutUint32(b[0:4], h.Request)
	binary.LittleEndian.PutUint32(b[4:8], h.Flags)
	binary.LittleEndian.PutUint32(b[8:12], h.Size)
}

// Memory Region definition in vhost-user
type VhostUserMemoryRegion struct {
	GuestPhysAddr uint64
	MemorySize    uint64
	UserspaceAddr uint64
	MmapOffset    uint64
}

// Virtqueue Address setup
type VhostUserVringAddr struct {
	Index uint32
	Flags uint32
	Desc  uint64
	Used  uint64
	Avail uint64
	Log   uint64
}

// Virtqueue State
type VhostUserVringState struct {
	Index uint32
	Num   uint32
}
