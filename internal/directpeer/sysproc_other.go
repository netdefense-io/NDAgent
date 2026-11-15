//go:build !freebsd

package directpeer

import "syscall"

// endWithParent does nothing off FreeBSD, where the agent is only built for
// development: the companion exits when its stdin closes.
func endWithParent(*syscall.SysProcAttr) {}
