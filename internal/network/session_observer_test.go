package network

import (
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// recordingObserver records the events of the connection in order.
type recordingObserver struct {
	mu     sync.Mutex
	events []string
}

func (o *recordingObserver) add(e string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}
func (o *recordingObserver) SessionStarted(time.Time) { o.add("started") }
func (o *recordingObserver) SessionAlive(time.Time)   { o.add("alive") }
func (o *recordingObserver) SessionEnded(time.Time)   { o.add("ended") }
func (o *recordingObserver) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

// The dead-man runs on the contact the broker accepted: it starts when the
// broker authenticates the agent, goes on with every heartbeat, and ends with
// the connection.
func TestSessionObserver_FollowsTheAcceptedConnection(t *testing.T) {
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	obs := &recordingObserver{}
	w.SetSessionObserver(obs)

	cancel, wait := connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	// The observer is told after the heartbeat is written, so the broker can count
	// the heartbeat before the agent has recorded that it sent it.
	b.WaitFor("the heartbeat to be recorded as contact", 5*time.Second, func() bool {
		return len(obs.snapshot()) >= 2
	})

	events := obs.snapshot()
	if len(events) < 2 || events[0] != "started" || events[1] != "alive" {
		t.Fatalf("events %v: want started, then a heartbeat", events)
	}
	for _, e := range events {
		if e == "ended" {
			t.Fatalf("events %v: the connection is still up", events)
		}
	}

	cancel()
	wait()
	events = obs.snapshot()
	if events[len(events)-1] != "ended" {
		t.Fatalf("events %v: the connection ended", events)
	}
}

// A connection the broker refused is not a contact: a disabled device is refused
// at authentication, however long its agent runs.
func TestSessionObserver_ARefusedAuthenticationIsNoContact(t *testing.T) {
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	obs := &recordingObserver{}
	w.SetSessionObserver(obs)
	w.cfg.ServerURIWS = "ws://127.0.0.1:1/ws" // nobody answers

	_, wait := connectOnce(t, w)
	wait()
	if events := obs.snapshot(); len(events) != 0 {
		t.Fatalf("events %v: no connection was accepted", events)
	}
}
