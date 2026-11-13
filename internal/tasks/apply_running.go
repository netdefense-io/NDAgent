package tasks

// OPNsense answers a reconfigure ok for a start that failed (Unbound's start
// action ignores unbound's exit status, Zabbix's exits 0 once zabbix_agentd has
// forked, 26.1 answers ok in any case), so the Unbound and Zabbix applies are
// also judged by the service's status (NDAgent-go#248).

import (
	"context"
	"fmt"
	"time"

	"github.com/netdefense-io/ndagent/internal/util"
)

// Overridable by tests.
var (
	serviceStartWait  = 10 * time.Second
	serviceStatusPoll = time.Second
	// serviceStatusReadMin is the least time a status read is given, also
	// once the wait is nearly over.
	serviceStatusReadMin = 5 * time.Second
)

// reconfigureRunning runs a service's reconfigure and then checks that the
// service took it (confirmRunning).
func reconfigureRunning(ctx context.Context, reconfigure func(context.Context) error, status func(context.Context) (string, error)) error {
	if err := reconfigure(ctx); err != nil {
		return err
	}
	return confirmRunning(ctx, status)
}

// confirmRunning reads the status of a service whose reconfigure answered ok.
// "disabled", a service that is not enabled (the reconfigure stops it), is an
// apply that took effect. So is "running" read twice in a row a poll apart: a
// Zabbix agent that fails after its fork is still running at the first read.
// Any other status, or a status that cannot be read, is read again for
// serviceStartWait, for a start still under way, and is then a failed apply.
func confirmRunning(ctx context.Context, status func(context.Context) (string, error)) error {
	deadline := time.Now().Add(serviceStartWait)
	running := false
	for {
		readTime := max(time.Until(deadline), serviceStatusReadMin)
		readCtx, cancel := context.WithTimeout(ctx, readTime)
		got, err := status(readCtx)
		cancel()
		switch {
		case err == nil && got == "disabled":
			return nil
		case err == nil && got == "running":
			if running {
				return nil
			}
			running = true
		default:
			running = false
		}
		if ctx.Err() == nil && (running || time.Now().Before(deadline)) {
			if util.ShutdownAwareSleep(ctx, serviceStatusPoll) == nil {
				continue
			}
		}
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("answered ok, but the service status could not be read: %w", err)
		}
		return fmt.Errorf("answered ok, but the service is not running (status %q); its log on the device says why", got)
	}
}
