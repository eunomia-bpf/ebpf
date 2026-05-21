//go:build linux && cgo

package sys

/*
#cgo noescape bpfrejit_libc_bpf_syscall
#cgo nocallback bpfrejit_libc_bpf_syscall
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static long bpfrejit_libc_bpf_syscall(unsigned int cmd, void *attr,
				      unsigned long size, int *err_out) {
	errno = 0;
	long ret = syscall(SYS_bpf, cmd, attr, size);
	*err_out = errno;
	return ret;
}
*/
import "C"

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

func bpfSyscall(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, unix.Errno) {
	var errno C.int
	ret := C.bpfrejit_libc_bpf_syscall(C.uint(cmd), attr, C.ulong(size), &errno)
	if ret >= 0 {
		return uintptr(ret), 0
	}
	return uintptr(ret), unix.Errno(errno)
}
