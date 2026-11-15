// Command ndagent-connect carries one remote access session of the
// "direct-peer + encrypted relay" transport for ndagent, which starts it,
// sends its configuration on stdin and stops it at the end of the session.
// It is not meant to be run by hand.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/netdefense-io/ndagent/connect/internal/ipc"
	"github.com/netdefense-io/ndagent/connect/internal/run"
)

// Set at build time; ndagent refuses a companion whose version is not its own.
var (
	version = "dev"
	commit  = ""
)

func main() {
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
			fmt.Printf("ndagent-connect %s (protocol %d)\n", version, ipc.Protocol)
			return
		}
		fmt.Fprintln(os.Stderr, "usage: ndagent-connect [--version]\n\nStarted by ndagent, which sends its configuration on stdin.")
		os.Exit(2)
	}

	// The Go runtime's report of a crash lists every call on every stack
	// with the first words of its arguments, and the session's keys are among
	// them. The report can only be turned off from the environment the
	// process starts in (a program can raise its level, not lower it), so
	// ndagent starts the companion with this one variable, and the companion
	// takes no session without it.
	if os.Getenv("GOTRACEBACK") != "none" {
		fmt.Fprintln(os.Stderr, "ndagent-connect: not started with GOTRACEBACK=none. It is started by ndagent, which sets it.")
		os.Exit(2)
	}

	// Before anything is read: the session's keys arrive on stdin, and from
	// here no other process of the same user can look into this one.
	if err := run.DenyTracing(); err != nil {
		fmt.Fprintf(os.Stderr, "ndagent-connect: %v. It takes no session it cannot keep to itself.\n", err)
		os.Exit(2)
	}

	run.Setup()

	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		close(stop)
	}()

	os.Exit(run.Run(run.Options{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Version: version,
		Commit:  commit,
		Stop:    stop,
	}))
}
