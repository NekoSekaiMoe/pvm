//go:build linux
// +build linux

package iouring

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	iouring_syscall "github.com/iceber/iouring-go/syscall"
)

func (iour *IOURing) SubmitLinkRequests(requests []PrepRequest, ch chan<- Result) (RequestSet, error) {
	return iour.submitLinkRequest(requests, ch, false)
}

func (iour *IOURing) SubmitHardLinkRequests(requests []PrepRequest, ch chan<- Result) (RequestSet, error) {
	return iour.submitLinkRequest(requests, ch, true)
}

func (iour *IOURing) submitBatch(requests []PrepRequest, ch chan<- Result, decorate func(sqe iouring_syscall.SubmissionQueueEntry, i int)) (RequestSet, error) {
	if decorate != nil && len(requests) > int(*iour.sq.entries) {
		return nil, errors.New("too many requests")
	}

	iour.submitLock.Lock()
	defer iour.submitLock.Unlock()

	if iour.IsClosed() {
		return nil, ErrIOURingClosed
	}

	var sqeN uint32
	var submittedDataIdx int
	userDatas := make([]*UserData, 0, len(requests))

	for i := range requests {
		sqe := iour.sq.getSQEntry()
		if sqe == nil {
			iour.userDataLock.Lock()
			for j := submittedDataIdx; j < len(userDatas); j++ {
				data := userDatas[j]
				iour.userDatas[data.id] = data
			}
			iour.userDataLock.Unlock()

			if _, err := iour.submit(); err != nil {
				iour.userDataLock.Lock()
				for _, data := range userDatas {
					delete(iour.userDatas, data.id)
				}
				iour.userDataLock.Unlock()

				for _, data := range userDatas {
					userDataPool.Put(data)
				}
				return nil, err
			}
			submittedDataIdx = len(userDatas)
			sqeN = 0
			sqe = iour.getSQEntry()
		}

		sqeN++

		userData, err := iour.doRequest(sqe, requests[i], ch)
		if err != nil {
			iour.sq.fallback(sqeN)
			for _, data := range userDatas[submittedDataIdx:] {
				userDataPool.Put(data)
			}
			return nil, err
		}
		userDatas = append(userDatas, userData)

		if decorate != nil {
			decorate(sqe, i)
		}
	}

	// must be located before the lock operation to
	// avoid the compiler's adjustment of the code order.
	// issue: https://github.com/Iceber/iouring-go/issues/8
	rset := newRequestSet(userDatas)

	iour.userDataLock.Lock()
	for j := submittedDataIdx; j < len(userDatas); j++ {
		data := userDatas[j]
		iour.userDatas[data.id] = data
	}
	iour.userDataLock.Unlock()

	if _, err := iour.submit(); err != nil {
		iour.userDataLock.Lock()
		for _, data := range userDatas {
			delete(iour.userDatas, data.id)
		}
		iour.userDataLock.Unlock()

		for _, data := range userDatas {
			userDataPool.Put(data)
		}
		return nil, err
	}

	return rset, nil
}

func (iour *IOURing) submitLinkRequest(requests []PrepRequest, ch chan<- Result, hard bool) (RequestSet, error) {
	flags := iouring_syscall.IOSQE_FLAGS_IO_LINK
	if hard {
		flags = iouring_syscall.IOSQE_FLAGS_IO_HARDLINK
	}

	return iour.submitBatch(requests, ch, func(sqe iouring_syscall.SubmissionQueueEntry, i int) {
		sqe.CleanFlags(iouring_syscall.IOSQE_FLAGS_IO_HARDLINK | iouring_syscall.IOSQE_FLAGS_IO_LINK)
		if i < len(requests)-1 {
			sqe.SetFlags(flags)
		}
	})
}

func linkTimeout(t time.Duration) PrepRequest {
	timespec := unix.NsecToTimespec(t.Nanoseconds())

	return func(sqe iouring_syscall.SubmissionQueueEntry, userData *UserData) {
		userData.hold(&timespec)
		userData.request.resolver = timeoutResolver

		sqe.PrepOperation(iouring_syscall.IORING_OP_LINK_TIMEOUT, -1, uint64(uintptr(unsafe.Pointer(&timespec))), 1, 0)
	}
}
