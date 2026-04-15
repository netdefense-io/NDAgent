// Package core provides core lifecycle and shutdown management for NDAgent.
package core

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

const (
	// GracefulShutdownTimeout is the maximum time to wait for graceful shutdown.
	GracefulShutdownTimeout = 15 * time.Second
)

// ShutdownCoordinator manages graceful shutdown of the agent.
type ShutdownCoordinator struct {
	// ctx is the main context that gets cancelled on shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// shutdownOnce ensures shutdown logic runs only once
	shutdownOnce sync.Once

	// shutdownRequested tracks if first signal was received
	shutdownRequested bool
	mu                sync.Mutex

	// wg tracks active goroutines for graceful shutdown
	wg sync.WaitGroup

	// done signals when shutdown is complete
	done chan struct{}
}

// NewShutdownCoordinator creates a new shutdown coordinator.
func NewShutdownCoordinator() *ShutdownCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &ShutdownCoordinator{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

// Context returns the context that will be cancelled on shutdown.
func (s *ShutdownCoordinator) Context() context.Context {
	return s.ctx
}

// Add adds delta to the wait group counter.
func (s *ShutdownCoordinator) Add(delta int) {
	s.wg.Add(delta)
}

// Done decrements the wait group counter.
func (s *ShutdownCoordinator) Done() {
	s.wg.Done()
}

// SetupSignalHandlers registers signal handlers for SIGINT and SIGTERM.
func (s *ShutdownCoordinator) SetupSignalHandlers() {
	log := logging.Named("shutdown")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for sig := range sigChan {
			s.mu.Lock()
			if s.shutdownRequested {
				// Second signal - force exit
				s.mu.Unlock()
				log.Warnw("Force shutdown - terminating process immediately",
					"signal", sig.String())
				os.Exit(1)
			}

			// First signal - graceful shutdown
			s.shutdownRequested = true
			s.mu.Unlock()

			log.Infow("Shutdown requested. Gracefully stopping agent. Press Ctrl+C again to force exit.",
				"signal", sig.String())

			// Cancel the context to signal all goroutines to stop
			s.cancel()
		}
	}()
}

// RequestShutdown initiates a graceful shutdown programmatically.
func (s *ShutdownCoordinator) RequestShutdown() {
	log := logging.Named("shutdown")

	s.mu.Lock()
	if s.shutdownRequested {
		s.mu.Unlock()
		return
	}
	s.shutdownRequested = true
	s.mu.Unlock()

	log.Info("Shutdown requested programmatically")
	s.cancel()
}

// IsShutdownRequested returns whether shutdown has been requested.
func (s *ShutdownCoordinator) IsShutdownRequested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdownRequested
}

// WaitForShutdown waits for all goroutines to complete with a timeout.
// Returns true if shutdown completed gracefully, false if timed out.
func (s *ShutdownCoordinator) WaitForShutdown() bool {
	log := logging.Named("shutdown")

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("Graceful shutdown complete")
		return true
	case <-time.After(GracefulShutdownTimeout):
		log.Warnw("Graceful shutdown timed out",
			"timeout", GracefulShutdownTimeout.String())
		return false
	}
}

// ShutdownAwareSleep sleeps for the specified duration but returns early if shutdown is requested.
// Returns nil if sleep completed, context.Canceled if interrupted by shutdown.
// Note: This is a convenience wrapper. For code without circular dependency issues,
// you can also use util.ShutdownAwareSleep directly.
func ShutdownAwareSleep(ctx context.Context, duration time.Duration) error {
	// Sleep in small chunks so we can respond to shutdown quickly
	const chunkSize = 100 * time.Millisecond
	elapsed := time.Duration(0)

	for elapsed < duration {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sleepTime := chunkSize
		if remaining := duration - elapsed; remaining < chunkSize {
			sleepTime = remaining
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepTime):
			elapsed += sleepTime
		}
	}

	return nil
}

// RunWithShutdown runs a function with shutdown awareness.
// The function receives a context that will be cancelled on shutdown.
// Returns the error from the function or context.Canceled if shutdown was requested.
func (s *ShutdownCoordinator) RunWithShutdown(name string, fn func(ctx context.Context) error) error {
	log := logging.Named("shutdown")

	s.Add(1)
	defer s.Done()

	log.Debugw("Starting task", "name", name)

	err := fn(s.ctx)

	if err != nil && err != context.Canceled {
		log.Debugw("Task completed with error", "name", name, "error", err)
	} else {
		log.Debugw("Task completed", "name", name)
	}

	return err
}
