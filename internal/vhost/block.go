package vhost

import (
	"os"

	"github.com/iceber/iouring-go"
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
