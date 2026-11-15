//go:build freebsd

package run

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// procctl(2) on FreeBSD: sys/procctl.h and sys/wait.h.
const (
	idtypePID           = 0 // P_PID; id 0 is the calling process
	procTraceCtl        = 7 // PROC_TRACE_CTL
	procTraceStatus     = 8 // PROC_TRACE_STATUS
	procTraceCtlDisable = 2 // PROC_TRACE_CTL_DISABLE
	traceStatusDisabled = -1
)

func procctlSelf(command uintptr, data *int32) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PROCCTL, idtypePID, 0, command, uintptr(unsafe.Pointer(data)), 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// DenyTracing turns off, for this process, the ways another process of its
// own user has of looking into it: ptrace(2), ktrace(2), the debugging
// sysctls, dtrace(1) and core files. The companion runs as an unprivileged
// user that other daemons on the device run as too, and a process may trace
// another of its own user: without this, any of them could read a session's
// keys out of the companion's memory (measured on OPNsense 26.7: a memory
// dump of one such process by another succeeds, and of the companion fails).
// Root is not held by it, and has other ways into any process's memory.
//
// It fails when the process is being traced already, and when the kernel
// does not then say tracing is off.
func DenyTracing() error {
	disable := int32(procTraceCtlDisable)
	if err := procctlSelf(procTraceCtl, &disable); err != nil {
		if errors.Is(err, syscall.EBUSY) {
			return errors.New("the process is being traced")
		}
		return fmt.Errorf("tracing could not be turned off: %v", err)
	}
	status := int32(0)
	if err := procctlSelf(procTraceStatus, &status); err != nil {
		return fmt.Errorf("the tracing status could not be read: %v", err)
	}
	if status != traceStatusDisabled {
		return errors.New("tracing is still on after it was turned off")
	}
	return nil
}
