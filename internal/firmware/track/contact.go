package track

import (
	"sync"
	"time"
)

// Contact tracks the agent's authenticated contact with the control plane, the
// clock the dead-man runs on. A contact is a connection NDBroker accepted: a
// device that is disabled, revoked or deleted is refused at authentication, so
// it has none however long its agent runs.
//
// While a connection is up, contact is continuous. When it ends, the silence
// counts from the moment it ended. The tracker keeps only what it saw in this
// process; the engine saves it into the state file so a restart does not forget
// it (and does not mistake a restart for a contact).
type Contact struct {
	mu      sync.Mutex
	last    time.Time
	started time.Time
	live    bool
}

// SessionStarted records that NDBroker accepted the agent's authentication.
func (c *Contact) SessionStarted(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last, c.started, c.live = now, now, true
}

// SessionAlive records a heartbeat sent over the accepted connection.
func (c *Contact) SessionAlive(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live {
		c.last = now
	}
}

// SessionEnded records that the accepted connection ended.
func (c *Contact) SessionEnded(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live {
		c.last, c.live = now, false
	}
}

// Last is the time of the last contact seen by this process (zero when there
// was none) and whether the connection is up now, in which case the silence is
// nil whatever last says.
func (c *Contact) Last() (last time.Time, live bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.live
}

// Started is when the latest connection NDBroker accepted began, zero when this
// process has had none. That is the moment the silence before it ended, which is
// what the dead-man measures that silence to, not the time a periodic round
// happened to notice it.
func (c *Contact) Started() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}
