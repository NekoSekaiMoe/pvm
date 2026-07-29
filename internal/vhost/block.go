package vhost

import (
	"os"
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
}

func NewBlockDevice(path string) (*BlockDevice, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	return &BlockDevice{file: f}, nil
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
	return b.file.Close()
}
