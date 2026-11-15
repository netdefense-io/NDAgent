package directpeer

import (
	"context"
	"sync"
	"time"
)

// Limits bound one session. The agent enforces them by ending a session that
// passes one: the relay cannot cut a session that runs on a direct path.
type Limits struct {
	// Pairing is how long the companion listens for its client.
	Pairing time.Duration
	// Idle is how long a session may go with no frame but keepalives, in
	// either direction.
	Idle time.Duration
	// Lifetime is how long a session may last from the moment it listens,
	// the wait for the client included.
	Lifetime time.Duration
}

// MaxLimits are the agent's own limits. The control plane names a session's
// limits in the task; a lower value is honoured, a higher one never.
var MaxLimits = Limits{
	Pairing:  5 * time.Minute,
	Idle:     30 * time.Minute,
	Lifetime: 8 * time.Hour,
}

// LimitsFor is the limits of a session the control plane gave these three
// values, in seconds: each one, or the agent's own where that is lower. ok is
// false when a value is not above zero, which no task carries.
func LimitsFor(pairSeconds, idleSeconds, maxSeconds int) (limits Limits, ok bool) {
	if pairSeconds <= 0 || idleSeconds <= 0 || maxSeconds <= 0 {
		return Limits{}, false
	}
	seconds := func(n int, most time.Duration) time.Duration {
		if int64(n) >= int64(most/time.Second) {
			return most
		}
		return time.Duration(n) * time.Second
	}
	return Limits{
		Pairing:  seconds(pairSeconds, MaxLimits.Pairing),
		Idle:     seconds(idleSeconds, MaxLimits.Idle),
		Lifetime: seconds(maxSeconds, MaxLimits.Lifetime),
	}, true
}

// Watch waits until the session passes a limit and returns why it must end
// (EndNoClient, EndIdleTimeout or EndMaxDuration), or "" when ctx ends first.
// listeningAt is when the companion said it listens: the wait for the client
// and the session's lifetime are counted from it, whenever Watch is called.
// connected is closed once the client has connected; lastActivity is when the
// last frame other than a keepalive went either way, or the zero time before
// any. The idle time is compared on the monotonic clock: listeningAt and
// lastActivity both carry it.
func (l Limits) Watch(ctx context.Context, listeningAt time.Time, connected <-chan struct{}, lastActivity func() time.Time) string {
	sinceListening := time.Since(listeningAt)
	lifetime := time.NewTimer(max(l.Lifetime-sinceListening, 0))
	defer lifetime.Stop()
	pairing := time.NewTimer(max(l.Pairing-sinceListening, 0))
	defer pairing.Stop()
	pairingC := pairing.C

	var idle *time.Timer
	var idleC <-chan time.Time
	var connectedAt time.Time
	defer func() {
		if idle != nil {
			idle.Stop()
		}
	}()
	clientConnected := func() {
		connected, pairingC = nil, nil
		connectedAt = time.Now()
		idle = time.NewTimer(l.Idle)
		idleC = idle.C
	}

	for {
		select {
		case <-ctx.Done():
			return ""
		case <-lifetime.C:
			return EndMaxDuration
		case <-connected:
			clientConnected()
		case <-pairingC:
			// The client may have connected in the same instant.
			select {
			case <-connected:
				clientConnected()
			default:
				return EndNoClient
			}
		case <-idleC:
			last := lastActivity()
			if last.Before(connectedAt) {
				last = connectedAt
			}
			quiet := time.Since(last)
			if quiet >= l.Idle {
				return EndIdleTimeout
			}
			idle.Reset(l.Idle - quiet)
		}
	}
}

// MaxDeviceSessions is the most sessions this agent carries at once, whatever
// number the control plane allows the device. Each is a companion process
// that holds about as much memory as the agent itself.
const MaxDeviceSessions = 8

// Sessions counts the sessions a device carries.
type Sessions struct {
	mu   sync.Mutex
	open int
}

// Acquire takes a place for one more session when fewer than allowed are
// open, without waiting. allowed is the control plane's number for the
// device, held to MaxDeviceSessions. release gives the place back, once
// however often it is called.
func (s *Sessions) Acquire(allowed int) (release func(), ok bool) {
	if allowed > MaxDeviceSessions {
		allowed = MaxDeviceSessions
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open >= allowed {
		return func() {}, false
	}
	s.open++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.open--
			s.mu.Unlock()
		})
	}, true
}

// Open is how many sessions are carried now.
func (s *Sessions) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}
