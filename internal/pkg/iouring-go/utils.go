// +build linux

package iouring

import (
	"syscall"
	"unsafe"
)

var zero uintptr

func bytes2iovec(bs [][]byte) []syscall.Iovec {
	iovecs := make([]syscall.Iovec, len(bs))
	for i, b := range bs {
		iovecs[i].SetLen(len(b))
		if len(b) > 0 {
			iovecs[i].Base = &b[0]
		} else {
			iovecs[i].Base = (*byte)(unsafe.Pointer(&zero))
		}
	}
	return iovecs
}

func sockaddr(addr syscall.Sockaddr) (unsafe.Pointer, uint32, error) { return nil, 0, nil }

func anyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) { return nil, nil }
