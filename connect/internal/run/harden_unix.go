//go:build unix

package run

import (
	"os/signal"
	"syscall"
)

// hardenProcess keeps the session's keys from leaving the process when it
// ends badly. Core files are turned off. SIGQUIT is ignored: the runtime
// answers it with every goroutine's stack and the first words of each call's
// arguments, whatever the crash report setting says. And a write to a closed
// pipe fails as an error: by default the runtime lets SIGPIPE end the process
// for stdout and stderr, and the session would end with no reason given.
func hardenProcess() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	signal.Ignore(syscall.SIGPIPE, syscall.SIGQUIT)
}
