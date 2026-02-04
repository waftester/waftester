//go:build linux

// Package iouring provides io_uring-based async I/O for Linux 5.1+.
// This enables significantly faster file and network I/O by reducing
// syscall overhead through batched submission and completion queues.
//
// io_uring provides:
// - Batched syscalls (submit many operations at once)
// - Zero-copy I/O (avoids kernel-userspace memory copies)
// - Async completion (operations complete in background)
//
// Usage:
//
//	ring, err := iouring.New(1024)  // 1024 entry queue
//	if err != nil {
//	    // Fall back to standard I/O
//	}
//	defer ring.Close()
//
//	// Async read
//	data, err := ring.Read(fd, buf)
package iouring

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"
)

// Ring represents an io_uring instance
type Ring struct {
	fd         int
	sqRing     *submissionQueue
	cqRing     *completionQueue
	sqesMapped []byte
	cqesMapped []byte
	mu         sync.Mutex
	closed     bool
}

// submissionQueue holds the submission ring buffer
type submissionQueue struct {
	head    *uint32
	tail    *uint32
	mask    uint32
	entries uint32
	sqes    unsafe.Pointer
}

// completionQueue holds the completion ring buffer
type completionQueue struct {
	head    *uint32
	tail    *uint32
	mask    uint32
	entries uint32
	cqes    unsafe.Pointer
}

// sqe is a submission queue entry
type sqe struct {
	opcode      uint8
	flags       uint8
	ioprio      uint16
	fd          int32
	off         uint64
	addr        uint64
	len         uint32
	opcodeFlags uint32
	userData    uint64
	bufIndex    uint16
	personality uint16
	spliceFdIn  int32
	pad2        [2]uint64
}

// cqe is a completion queue entry
type cqe struct {
	userData uint64
	res      int32
	flags    uint32
}

// io_uring syscall numbers (Linux 5.1+)
const (
	SYS_IO_URING_SETUP   = 425
	SYS_IO_URING_ENTER   = 426
	SYS_IO_URING_REGISTER = 427
)

// io_uring operations
const (
	IORING_OP_NOP      = 0
	IORING_OP_READV    = 1
	IORING_OP_WRITEV   = 2
	IORING_OP_READ     = 22
	IORING_OP_WRITE    = 23
	IORING_OP_SEND     = 26
	IORING_OP_RECV     = 27
	IORING_OP_CONNECT  = 16
	IORING_OP_ACCEPT   = 19
)

// io_uring flags
const (
	IORING_ENTER_GETEVENTS = 1 << 0
	IORING_ENTER_SQ_WAKEUP = 1 << 1
)

// io_uring_params from linux/io_uring.h
type ioUringParams struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32
	sqOff        sqRingOffsets
	cqOff        cqRingOffsets
}

type sqRingOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	resv2       uint64
}

type cqRingOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	resv2       uint64
}

// ErrNotSupported indicates io_uring is not available
var ErrNotSupported = errors.New("io_uring not supported on this system")

// ErrRingClosed indicates the ring has been closed
var ErrRingClosed = errors.New("io_uring ring is closed")

// Supported returns true if io_uring is available on this system
func Supported() bool {
	// Try to create a minimal ring to test support
	var params ioUringParams
	fd, _, errno := syscall.Syscall(SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return false
	}
	syscall.Close(int(fd))
	return true
}

// New creates a new io_uring instance with the specified queue size.
// The size should be a power of 2, typically 256, 512, or 1024.
// Returns ErrNotSupported if io_uring is not available.
func New(size uint32) (*Ring, error) {
	if size == 0 {
		size = 256
	}

	var params ioUringParams
	fd, _, errno := syscall.Syscall(SYS_IO_URING_SETUP, uintptr(size), uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		if errno == syscall.ENOSYS {
			return nil, ErrNotSupported
		}
		return nil, errno
	}

	ring := &Ring{
		fd: int(fd),
	}

	// Map submission and completion queues
	if err := ring.mapQueues(&params); err != nil {
		syscall.Close(ring.fd)
		return nil, err
	}

	return ring, nil
}

// mapQueues maps the submission and completion queue memory
func (r *Ring) mapQueues(params *ioUringParams) error {
	// Calculate sizes
	sqRingSize := params.sqOff.array + params.sqEntries*4
	cqRingSize := params.cqOff.cqes + params.cqEntries*uint32(unsafe.Sizeof(cqe{}))
	sqesSize := params.sqEntries * uint32(unsafe.Sizeof(sqe{}))

	// Map SQ ring
	sqRingPtr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(sqRingSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(r.fd),
		0, // IORING_OFF_SQ_RING = 0
	)
	if errno != 0 {
		return errno
	}

	// Map CQ ring (shared with SQ ring in most cases, but separate offset)
	cqRingPtr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(cqRingSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(r.fd),
		0x8000000, // IORING_OFF_CQ_RING
	)
	if errno != 0 {
		syscall.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(sqRingPtr)), sqRingSize))
		return errno
	}

	// Map SQEs
	sqesPtr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(sqesSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(r.fd),
		0x10000000, // IORING_OFF_SQES
	)
	if errno != 0 {
		syscall.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(sqRingPtr)), sqRingSize))
		syscall.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(cqRingPtr)), cqRingSize))
		return errno
	}

	// Initialize submission queue pointers
	r.sqRing = &submissionQueue{
		head:    (*uint32)(unsafe.Pointer(sqRingPtr + uintptr(params.sqOff.head))),
		tail:    (*uint32)(unsafe.Pointer(sqRingPtr + uintptr(params.sqOff.tail))),
		mask:    *(*uint32)(unsafe.Pointer(sqRingPtr + uintptr(params.sqOff.ringMask))),
		entries: *(*uint32)(unsafe.Pointer(sqRingPtr + uintptr(params.sqOff.ringEntries))),
		sqes:    unsafe.Pointer(sqesPtr),
	}

	// Initialize completion queue pointers
	r.cqRing = &completionQueue{
		head:    (*uint32)(unsafe.Pointer(cqRingPtr + uintptr(params.cqOff.head))),
		tail:    (*uint32)(unsafe.Pointer(cqRingPtr + uintptr(params.cqOff.tail))),
		mask:    *(*uint32)(unsafe.Pointer(cqRingPtr + uintptr(params.cqOff.ringMask))),
		entries: *(*uint32)(unsafe.Pointer(cqRingPtr + uintptr(params.cqOff.ringEntries))),
		cqes:    unsafe.Pointer(cqRingPtr + uintptr(params.cqOff.cqes)),
	}

	return nil
}

// Close releases all resources associated with the ring
func (r *Ring) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	// Unmap memory regions
	if r.sqesMapped != nil {
		syscall.Munmap(r.sqesMapped)
	}
	if r.cqesMapped != nil {
		syscall.Munmap(r.cqesMapped)
	}

	return syscall.Close(r.fd)
}

// submitAndWait submits pending entries and waits for at least one completion
func (r *Ring) submitAndWait(minComplete uint32) error {
	if r.closed {
		return ErrRingClosed
	}

	_, _, errno := syscall.Syscall6(
		SYS_IO_URING_ENTER,
		uintptr(r.fd),
		1,                         // submit 1
		uintptr(minComplete),      // wait for completions
		IORING_ENTER_GETEVENTS,
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// Read performs an async read operation
func (r *Ring) Read(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, ErrRingClosed
	}

	// Get next SQE slot
	tail := *r.sqRing.tail
	index := tail & r.sqRing.mask
	sqePtr := (*sqe)(unsafe.Pointer(uintptr(r.sqRing.sqes) + uintptr(index)*unsafe.Sizeof(sqe{})))

	// Fill in the SQE
	sqePtr.opcode = IORING_OP_READ
	sqePtr.fd = int32(fd)
	sqePtr.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqePtr.len = uint32(len(buf))
	sqePtr.off = 0
	sqePtr.userData = uint64(tail)

	// Advance tail
	*r.sqRing.tail = tail + 1

	// Submit and wait
	if err := r.submitAndWait(1); err != nil {
		return 0, err
	}

	// Get completion
	cqHead := *r.cqRing.head
	cqePtr := (*cqe)(unsafe.Pointer(uintptr(r.cqRing.cqes) + uintptr(cqHead&r.cqRing.mask)*unsafe.Sizeof(cqe{})))
	result := cqePtr.res
	*r.cqRing.head = cqHead + 1

	if result < 0 {
		return 0, syscall.Errno(-result)
	}
	return int(result), nil
}

// Write performs an async write operation
func (r *Ring) Write(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, ErrRingClosed
	}

	// Get next SQE slot
	tail := *r.sqRing.tail
	index := tail & r.sqRing.mask
	sqePtr := (*sqe)(unsafe.Pointer(uintptr(r.sqRing.sqes) + uintptr(index)*unsafe.Sizeof(sqe{})))

	// Fill in the SQE
	sqePtr.opcode = IORING_OP_WRITE
	sqePtr.fd = int32(fd)
	sqePtr.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqePtr.len = uint32(len(buf))
	sqePtr.off = 0
	sqePtr.userData = uint64(tail)

	// Advance tail
	*r.sqRing.tail = tail + 1

	// Submit and wait
	if err := r.submitAndWait(1); err != nil {
		return 0, err
	}

	// Get completion
	cqHead := *r.cqRing.head
	cqePtr := (*cqe)(unsafe.Pointer(uintptr(r.cqRing.cqes) + uintptr(cqHead&r.cqRing.mask)*unsafe.Sizeof(cqe{})))
	result := cqePtr.res
	*r.cqRing.head = cqHead + 1

	if result < 0 {
		return 0, syscall.Errno(-result)
	}
	return int(result), nil
}
