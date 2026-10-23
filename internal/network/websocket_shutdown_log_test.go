package network

import (
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// waitReading waits until the command loop runs (its first heartbeat arrived)
// and gives the command receiver a moment to be blocked in its read.
func waitReading(b *testbroker.Broker) {
	b.WaitForHeartbeats(1, 5*time.Second)
	time.Sleep(100 * time.Millisecond)
}

// dispatcherReadEnd waits for the command receiver to log how its read ended.
func dispatcherReadEnd(t *testing.T, logs *observer.ObservedLogs) []observer.LoggedEntry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ended := logs.Filter(func(e observer.LoggedEntry) bool {
			_, hasErr := e.ContextMap()["error"]
			return e.LoggerName == "dispatcher" && hasErr
		}).All()
		if len(ended) > 0 || time.Now().After(deadline) {
			return ended
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A graceful shutdown closes the connection under the command receiver's read.
// The read error that follows is the shutdown, not a fault: nothing of it, or of
// anything else in the shutdown, is logged at ERROR.
func TestAGracefulShutdownLogsNoError(t *testing.T) {
	logs := captureLogs(t)
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	cancel, wait := connectOnce(t, w)
	waitReading(b)

	cancel()
	wait()

	ended := dispatcherReadEnd(t, logs)
	if len(ended) == 0 {
		t.Fatal("the command receiver logged nothing about its read ending, so the test shows nothing")
	}
	for _, e := range ended {
		if e.Level != zapcore.DebugLevel {
			t.Errorf("the read ended by the shutdown was logged at %s: %q %v", e.Level, e.Message, e.ContextMap())
		}
	}
	for _, e := range logs.FilterLevelExact(zapcore.ErrorLevel).All() {
		t.Errorf("a graceful shutdown logged at ERROR: %s %q %v", e.LoggerName, e.Message, e.ContextMap())
	}
}

// A read that fails while the connection is meant to be up is still an ERROR.
func TestAReadFailureWhileConnectedIsStillAnError(t *testing.T) {
	logs := captureLogs(t)
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	_, wait := connectOnce(t, w)
	waitReading(b)

	b.Drop()
	wait()

	ended := dispatcherReadEnd(t, logs)
	if len(ended) != 1 || ended[0].Level != zapcore.ErrorLevel || ended[0].Message != "Error reading WebSocket message" {
		t.Fatalf("read end logged as %+v, want one ERROR \"Error reading WebSocket message\"", ended)
	}
}
