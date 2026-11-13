package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// writeServiceStatus answers a status read as OPNsense's service base does;
// an empty status is "running".
func writeServiceStatus(w http.ResponseWriter, status string) {
	if status == "" {
		status = "running"
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": status, "widget": map[string]string{"caption_start": "Start"}})
}

// serveRunning answers the status reads of path for a running service.
func serveRunning(t *testing.T, mux *http.ServeMux, path string) {
	shortServiceStartWait(t)
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		writeServiceStatus(w, "running")
	})
}

func shortServiceStartWait(t *testing.T) {
	t.Helper()
	wait, poll, read := serviceStartWait, serviceStatusPoll, serviceStatusReadMin
	serviceStartWait, serviceStatusPoll, serviceStatusReadMin = 60*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { serviceStartWait, serviceStatusPoll, serviceStatusReadMin = wait, poll, read })
}

func TestConfirmRunning(t *testing.T) {
	shortServiceStartWait(t)
	unreadable := errors.New("API error: status 500")
	for _, tc := range []struct {
		name      string
		answers   []string // successive status reads; "!" fails the read
		wantErr   string
		wantReads int // 0: more than one
	}{
		{"running", []string{"running"}, "", 2},
		{"disabled", []string{"disabled"}, "", 1},
		{"a start still under way", []string{"stopped", "stopped", "running"}, "", 4},
		{"a read that fails once", []string{"!", "running"}, "", 3},
		{"running, then it exits", []string{"running", "stopped"}, `not running (status "stopped"); its log on the device says why`, 0},
		{"stopped", []string{"stopped"}, `not running (status "stopped")`, 0},
		{"unknown", []string{"unknown"}, `not running (status "unknown")`, 0},
		{"no status", []string{""}, `not running (status "")`, 0},
		{"unreadable", []string{"!"}, "could not be read: API error: status 500", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			err := confirmRunning(context.Background(), func(context.Context) (string, error) {
				answer := tc.answers[min(reads, len(tc.answers)-1)]
				reads++
				if answer == "!" {
					return "", unreadable
				}
				return answer, nil
			})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want none", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.HasPrefix(err.Error(), "answered ok, but") {
				t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
			}
			if tc.wantReads > 0 && reads != tc.wantReads {
				t.Errorf("read the status %d times, want %d", reads, tc.wantReads)
			}
			if tc.wantReads == 0 && reads < 2 {
				t.Errorf("read the status %d times; a service not running is read again", reads)
			}
		})
	}
}

func TestConfirmRunning_ACancelledSYNCStopsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := confirmRunning(ctx, func(ctx context.Context) (string, error) { return "", ctx.Err() })
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v, want an error at once", err, time.Since(start))
	}
}

// A status read that hangs (a web GUI restarting) is cut short: the wait is
// bounded by serviceStartWait and serviceStatusReadMin, not by the client's own
// timeout.
func TestConfirmRunning_AHungReadIsCutShort(t *testing.T) {
	shortServiceStartWait(t)
	start := time.Now()
	err := confirmRunning(context.Background(), func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	if err == nil || !strings.Contains(err.Error(), "could not be read") || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v, want a failed read within the wait", err, time.Since(start))
	}
}

func TestReconfigureRunning_AFailedReconfigureReadsNoStatus(t *testing.T) {
	failed := errors.New("answered status=\"failed\"")
	err := reconfigureRunning(context.Background(),
		func(context.Context) error { return failed },
		func(context.Context) (string, error) {
			t.Error("the status was read after a failed reconfigure")
			return "running", nil
		})
	if !errors.Is(err, failed) {
		t.Fatalf("err = %v, want the reconfigure's", err)
	}
}

// OPNsense answers a reconfigure ok for an Unbound that did not start (26.7.8,
// e2e-a): the SYNC fails, the apply stays owed, and the next SYNC applies it
// with nothing to write (NDAgent-go#248).
func TestSyncUnbound_AnUnboundLeftStoppedStaysOwed(t *testing.T) {
	shortServiceStartWait(t)
	s := newUnboundStore(t)
	syncUnbound(t, s, noopUnboundSnippets(t, `["192.168.1.0/24","192.168.2.0/24"]`))
	s.takeReconfigures()

	changed := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	s.status = "stopped"
	failed := runUnbound(s, changed)
	if failed.Success || s.takeReconfigures() != 1 {
		t.Fatalf("an Unbound left stopped: success=%v errors=%v", failed.Success, failed.Errors)
	}
	item := applyItemOf(failed.Results, "unbound_apply")
	if item == nil || item.Status != "error" || !strings.Contains(item.Error, `"stopped"`) {
		t.Errorf("apply item = %+v, want an error naming the status", item)
	}
	if !recordOwes(t)[applyUnbound] {
		t.Fatal("an Unbound left stopped left nothing owed")
	}

	s.takeWrites()
	s.status = ""
	retried := syncUnbound(t, s, changed)
	if got := s.takeWrites(); len(got) != 0 {
		t.Errorf("the retry wrote %v", got)
	}
	if n := s.takeReconfigures(); n != 1 {
		t.Errorf("the retry reconfigured %d times, want once", n)
	}
	if item := applyItemOf(retried.Results, "unbound_apply"); item == nil || item.Code != codeApplyOwed {
		t.Errorf("apply item = %+v, want code %s", item, codeApplyOwed)
	}
	if recordOwes(t)[applyUnbound] {
		t.Error("the record still owes Unbound after the retry")
	}
}

// A disabled Unbound is stopped by its reconfigure, which took effect.
func TestSyncUnbound_ADisabledUnboundIsApplied(t *testing.T) {
	s := newUnboundStore(t)
	s.status = "disabled"
	syncUnbound(t, s, noopUnboundSnippets(t, `["192.168.1.0/24"]`))
	if recordOwes(t)[applyUnbound] {
		t.Error("the record owes the reconfigure of a disabled Unbound")
	}
}
