package directpeer

import "syscall"

// endWithParent has the kernel kill the companion when the agent's process
// ends, however it ends. The companion also exits by itself when its stdin
// closes; this covers one that is stuck.
func endWithParent(attr *syscall.SysProcAttr) {
	attr.Pdeathsig = syscall.SIGKILL
}
