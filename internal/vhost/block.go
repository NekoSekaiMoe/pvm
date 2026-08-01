package vhost

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/iceber/iouring-go"
	"golang.org/x/sys/unix"
)

const (
	VirtioBlkTIn    = 0
	VirtioBlkTOut   = 1
	VirtioBlkTFlush = 4

	VirtioBlkSOk     = 0
	VirtioBlkSIoErr  = 1
	VirtioBlkSUnsupp = 2
)

type BlockDevice struct {
	file *os.File
	iour *iouring.IOURing
}

func NewBlockDevice(path string) (*BlockDevice, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	// Reject non-block backends up front. A character device or other oddity
	// would otherwise reach Size() where the BLKGETSIZE64 ioctl is undefined;
	// limiting the backend to regular files and block devices keeps that ioctl
	// applied only where it is valid.
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	mode := fi.Mode()
	if mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0 {
		f.Close()
		return nil, fmt.Errorf("%s is a character device, not a usable block backend", path)
	}
	if mode&os.ModeDevice != 0 && mode&os.ModeNamedPipe != 0 {
		f.Close()
		return nil, fmt.Errorf("%s is not a block device", path)
	}

	// Create IOURing with 256 entries
	iour, err := iouring.New(256)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &BlockDevice{
		file: f,
		iour: iour,
	}, nil
}

// IOUR returns the underlying IOURing instance
func (b *BlockDevice) IOUR() *iouring.IOURing {
	return b.iour
}

func (b *BlockDevice) Fd() int {
	return int(b.file.Fd())
}

// Size returns the backing size in bytes. virtio-blk GET_CONFIG needs the
// total sector count (size/512); without it the guest refuses to probe the
// device ("Couldn't determine size of device's file").
//
// For a regular image file Stat().Size() is correct, but for a block-device
// backend (e.g. /dev/nvme0n1) Stat().Size() returns 0 on Linux; in that case
// fall back to the BLKGETSIZE64 ioctl.
func (b *BlockDevice) Size() (int64, error) {
	fi, err := b.file.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeDevice != 0 {
		var bytes uint64
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, b.file.Fd(), uintptr(unix.BLKGETSIZE64), uintptr(unsafe.Pointer(&bytes))); errno != 0 {
			return 0, fmt.Errorf("BLKGETSIZE64 on %s: %v", b.file.Name(), errno)
		}
		// Guard against a malformed ioctl return producing a negative
		// capacity (which the guest would interpret as a huge positive
		// number after truncation).
		if bytes > uint64(1<<63-1) {
			return 0, fmt.Errorf("BLKGETSIZE64 on %s returned out-of-range size %d", b.file.Name(), bytes)
		}
		return int64(bytes), nil
	}
	return fi.Size(), nil
}

func (b *BlockDevice) ReadAt(p []byte, off int64) (n int, err error) {
	return b.file.ReadAt(p, off)
}

func (b *BlockDevice) WriteAt(p []byte, off int64) (n int, err error) {
	return b.file.WriteAt(p, off)
}

func (b *BlockDevice) Sync() error {
	return b.file.Sync()
}

func (b *BlockDevice) Close() error {
	if b.iour != nil {
		b.iour.Close()
	}
	return b.file.Close()
}
