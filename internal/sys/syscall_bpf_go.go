//go:build !windows && !(linux && cgo)

package sys

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

func bpfSyscall(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, unix.Errno) {
	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	return r1, errno
}
