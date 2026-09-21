package network

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/facts"
	"github.com/netdefense-io/ndagent/internal/telemetry"
)

// fakeClock is a hand-advanced time source for the facts resync window.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time          { return c.at }
func (c *fakeClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func factsWithHash(t *testing.T, hostname string) *facts.Facts {
	t.Helper()
	f := &facts.Facts{V: facts.Version, Hostname: hostname}
	f.Normalize()
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	return f
}

func TestFactsRideAlongOnlyWhenChanged(t *testing.T) {
	clock := &fakeClock{at: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)}
	h := NewHeartbeatManager("dev-uuid", time.Minute)
	h.clock = clock.now

	current := factsWithHash(t, "fw01")
	h.SetFactsProvider(func() *facts.Facts { return current })

	// First heartbeat of a connection carries the payload.
	if got := h.factsForHeartbeat(); got == nil {
		t.Fatal("first heartbeat should carry facts")
	}

	// Unchanged facts are omitted for the rest of the window.
	clock.advance(time.Minute)
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatalf("unchanged facts should be omitted, got %+v", got)
	}

	// A change puts them back on the wire immediately.
	clock.advance(time.Minute)
	current = factsWithHash(t, "fw02")
	got := h.factsForHeartbeat()
	if got == nil {
		t.Fatal("changed facts should be sent")
	}
	if got.Hostname != "fw02" {
		t.Fatalf("hostname = %q, want fw02", got.Hostname)
	}

	// And go quiet again.
	clock.advance(time.Minute)
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatalf("unchanged facts should be omitted, got %+v", got)
	}
}

func TestFactsResendHourly(t *testing.T) {
	clock := &fakeClock{at: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)}
	h := NewHeartbeatManager("dev-uuid", time.Minute)
	h.clock = clock.now

	current := factsWithHash(t, "fw01")
	h.SetFactsProvider(func() *facts.Facts { return current })

	if got := h.factsForHeartbeat(); got == nil {
		t.Fatal("first heartbeat should carry facts")
	}

	clock.advance(factsResyncInterval - time.Second)
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatal("facts resent before the resync window elapsed")
	}

	clock.advance(2 * time.Second)
	if got := h.factsForHeartbeat(); got == nil {
		t.Fatal("facts not resent after the resync window elapsed")
	}

	// The window restarts from the resend.
	clock.advance(time.Minute)
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatal("resync window did not restart")
	}
}

// The auth leg already delivered the payload, so the first heartbeat of
// the connection must not repeat it.
func TestNoteFactsSentSuppressesTheNextHeartbeat(t *testing.T) {
	clock := &fakeClock{at: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)}
	h := NewHeartbeatManager("dev-uuid", time.Minute)
	h.clock = clock.now

	current := factsWithHash(t, "fw01")
	h.SetFactsProvider(func() *facts.Facts { return current })
	h.NoteFactsSent(current.Hash)

	clock.advance(time.Minute)
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatalf("facts repeated right after the auth message, got %+v", got)
	}
}

func TestFactsOmittedWhenCollectionFails(t *testing.T) {
	h := NewHeartbeatManager("dev-uuid", time.Minute)
	h.SetFactsProvider(func() *facts.Facts { return nil })
	if got := h.factsForHeartbeat(); got != nil {
		t.Fatalf("expected no facts, got %+v", got)
	}

	h2 := NewHeartbeatManager("dev-uuid", time.Minute)
	if got := h2.factsForHeartbeat(); got != nil {
		t.Fatalf("expected no facts without a provider, got %+v", got)
	}
}

// Facts are additive on the wire: a frame without them serializes exactly
// as it did before the field existed.
func TestHeartbeatOmitsFactsKeyWhenAbsent(t *testing.T) {
	snap := telemetry.Collect()
	raw, err := json.Marshal(HeartbeatMessage{
		Type:      MsgTypeHeartbeat,
		Status:    "active",
		Sequence:  1,
		Telemetry: &snap,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := generic["facts"]; ok {
		t.Fatalf("facts key present on a frame without facts: %s", raw)
	}
}

const testConfigXML = `<?xml version="1.0"?>
<opnsense>
  <system><timezone>America/Sao_Paulo</timezone></system>
  <interfaces>
    <wan><if>em0</if><descr>WAN</descr><enable>1</enable></wan>
  </interfaces>
</opnsense>
`

// The auth message carries the facts the collector produced, and its JSON
// shape matches what NDBroker validates.
func TestAuthMessageCarriesFacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(testConfigXML), 0o600); err != nil {
		t.Fatalf("write config.xml: %v", err)
	}

	cfg := &config.Config{
		Token:         "token-uuid",
		DeviceUUID:    "device-uuid",
		ConfigXMLPath: path,
	}
	w := NewWebSocketClient(cfg, nil, nil, nil, map[string]ed25519.PublicKey{})

	collected := w.collectFacts()
	if collected == nil {
		t.Fatal("collectFacts returned nil")
	}
	if collected.Timezone == nil || collected.Timezone.Name != "America/Sao_Paulo" {
		t.Fatalf("timezone = %+v", collected.Timezone)
	}

	raw, err := json.Marshal(AuthMessage{
		Type:       MsgTypeAuthentication,
		TokenUUID:  cfg.Token,
		DeviceUUID: cfg.DeviceUUID,
		Version:    "1.17.0",
		Facts:      collected,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload, ok := generic["facts"].(map[string]any)
	if !ok {
		t.Fatalf("facts missing from the auth message: %s", raw)
	}
	if payload["v"] != float64(facts.Version) {
		t.Fatalf("v = %v, want %d", payload["v"], facts.Version)
	}
	if hash, _ := payload["hash"].(string); len(hash) != 16 {
		t.Fatalf("hash = %v, want 16 hex chars", payload["hash"])
	}

	// An auth message without facts keeps its pre-existing shape.
	raw, err = json.Marshal(AuthMessage{Type: MsgTypeAuthentication})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bare := map[string]any{}
	if err := json.Unmarshal(raw, &bare); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := bare["facts"]; ok {
		t.Fatalf("facts key present on an auth message without facts: %s", raw)
	}
}
