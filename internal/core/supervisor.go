package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// SupervisorPidfileEnv is the environment variable through which the rc.d
// script tells the agent where the daemon(8) that supervises it keeps its pid.
const SupervisorPidfileEnv = "NDAGENT_SUPERVISOR_PIDFILE"

var (
	supervisorParentPID = os.Getppid
	signalSupervisor    = func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
)

// endSupervision asks the daemon(8) that supervises the agent not to start it
// again: daemon(8) forwards the SIGTERM it receives to the agent and exits
// instead of restarting it. It reports whether a supervisor was asked. Only
// the agent's own parent is ever signalled, so an agent started by hand, or by
// an earlier package's rc.d script, which sets no pidfile, signals nothing.
func endSupervision() (bool, error) {
	path := os.Getenv(SupervisorPidfileEnv)
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read the supervisor pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return false, fmt.Errorf("the supervisor pidfile %s holds no pid", path)
	}
	if parent := supervisorParentPID(); pid != parent {
		return false, fmt.Errorf("the supervisor pidfile %s names pid %d, not the agent's parent (pid %d)", path, pid, parent)
	}
	if err := signalSupervisor(pid); err != nil {
		return false, fmt.Errorf("signal the supervisor (pid %d): %w", pid, err)
	}
	return true, nil
}
