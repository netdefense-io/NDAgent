// Package util provides utility functions for NDAgent.
package util

import (
	"context"
	"time"
)

// ShutdownAwareSleep sleeps for the specified duration but returns early if context is cancelled.
// Returns nil if sleep completed, context.Canceled if interrupted.
func ShutdownAwareSleep(ctx context.Context, duration time.Duration) error {
	// Sleep in small chunks so we can respond to cancellation quickly
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
