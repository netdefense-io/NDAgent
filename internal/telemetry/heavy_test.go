package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// fakeOPNsense answers the endpoints the collector reads and remembers which it
// was asked for.
type fakeOPNsense struct {
	srv *httptest.Server

	mu   sync.Mutex
	hits map[string]int
}

func newFakeOPNsense(t *testing.T) *fakeOPNsense {
	t.Helper()
	f := &fakeOPNsense{hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.Method+" "+r.URL.Path]++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/core/service/search":
			_, _ = w.Write([]byte(`{"rows":[{"name":"unbound","description":"DNS","running":1}]}`))
		case "/trust/cert/search":
			_, _ = w.Write([]byte(`{"rows":[]}`))
		case "/core/firmware/status":
			_, _ = w.Write([]byte(`{"status":"update","upgrade_packages":[{"name":"curl"}],"product":{"product_version":"26.7.4_1"}}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOPNsense) count(endpoint string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[endpoint]
}

func newCollector(t *testing.T, f *fakeOPNsense) *HeavyCollector {
	t.Helper()
	prev := firmwareCheckSettle
	firmwareCheckSettle = time.Millisecond
	t.Cleanup(func() { firmwareCheckSettle = prev })
	t.Cleanup(func() { firmware.Watch(0) })
	return NewHeavyCollector(opnapi.NewClient(f.srv.URL, "key", "secret", true))
}

// The firmware check takes the lock a running update needs and truncates the
// progress log the update is judged by, so the collector does not start one
// while a FIRMWARE_UPGRADE is in progress in this process.
func TestRefresh_SkipsTheFirmwareCheckWhileAnUpdateIsInProgress(t *testing.T) {
	f := newFakeOPNsense(t)
	h := newCollector(t, f)

	release, err := firmware.Acquire(context.Background(), nil) // a FIRMWARE_UPGRADE task holds the slot
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	h.refresh(context.Background())

	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested a firmware check %d times during an update", n)
	}
	if n := f.count("GET /core/firmware/status"); n != 0 {
		t.Fatalf("read the firmware status %d times without having asked for a check", n)
	}
	if f.count("GET /core/service/search") == 0 {
		t.Fatal("the rest of the refresh must still run")
	}
}

// The same holds while the reconciler waits for an update the previous process
// started.
func TestRefresh_SkipsTheFirmwareCheckWhileTheReconcilerWaits(t *testing.T) {
	f := newFakeOPNsense(t)
	h := newCollector(t, f)

	firmware.Watch(1)
	h.refresh(context.Background())

	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested a firmware check %d times while the reconciler waits", n)
	}
}

// What the dashboard showed stays up instead of turning "unavailable" for the
// length of the update.
func TestRefresh_KeepsThePreviousUpdatesReadingWhileItSkips(t *testing.T) {
	f := newFakeOPNsense(t)
	h := newCollector(t, f)

	h.refresh(context.Background()) // an ordinary refresh: check and read
	before := h.Snapshot()
	if before == nil || before.Updates == nil || before.Updates.OPNsenseVersion != "26.7.4_1" {
		t.Fatalf("the first refresh did not read the firmware status: %+v", before)
	}

	firmware.Watch(1)
	h.refresh(context.Background())
	after := h.Snapshot()
	if after == nil || after.Updates == nil || after.Updates.OPNsenseVersion != "26.7.4_1" {
		t.Fatalf("the update reading was dropped while the check was skipped: %+v", after)
	}
	if after.Updates.AsOf != before.Updates.AsOf {
		t.Fatal("a carried-over reading must keep its own as_of, not claim to be fresh")
	}
}

func TestRefresh_ChecksAsBeforeWhenNoUpdateIsInProgress(t *testing.T) {
	f := newFakeOPNsense(t)
	h := newCollector(t, f)

	h.refresh(context.Background())

	if f.count("POST /core/firmware/check") != 1 || f.count("GET /core/firmware/status") != 1 {
		t.Fatalf("check=%d status=%d, want one of each",
			f.count("POST /core/firmware/check"), f.count("GET /core/firmware/status"))
	}
}
