package directpeer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type ledgerClock struct{ at time.Time }

func (c *ledgerClock) now() time.Time          { return c.at }
func (c *ledgerClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newLedgerClock() *ledgerClock {
	return &ledgerClock{at: time.Unix(1794700000, 0)}
}

func openTestLedger(t *testing.T, path string, clock *ledgerClock) *Ledger {
	t.Helper()
	l, err := OpenLedger(path, clock.now)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	return l
}

func accept(t *testing.T, l *Ledger, id, task string, exp int64) Accepted {
	t.Helper()
	got, err := l.Accept(id, task, exp)
	if err != nil {
		t.Fatalf("Accept(%s, %s): %v", id, task, err)
	}
	return got
}

func TestASessionIDIsUsedOnceAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	exp := clock.at.Add(90 * time.Second).Unix()

	l := openTestLedger(t, path, clock)
	if got := accept(t, l, "id-a", "101", exp); got != AcceptedNew {
		t.Fatalf("first Accept = %v, want new", got)
	}
	if got := accept(t, l, "id-a", "101", exp); got != AcceptedSameTask {
		t.Fatalf("the same task again = %v, want the same task", got)
	}
	if got := accept(t, l, "id-a", "102", exp); got != AcceptedReplayed {
		t.Fatalf("another task with the id = %v, want replayed", got)
	}

	// Another process.
	l = openTestLedger(t, path, clock)
	if got := accept(t, l, "id-a", "102", exp); got != AcceptedReplayed {
		t.Fatalf("after a restart, another task with the id = %v, want replayed", got)
	}
	if got := accept(t, l, "id-a", "101", exp); got != AcceptedSameTask {
		t.Fatalf("after a restart, the same task = %v, want the same task", got)
	}
	if got := accept(t, l, "id-b", "103", exp); got != AcceptedNew {
		t.Fatalf("a new id = %v, want new", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the record's mode is %o, want 600", mode)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".sessions.json.*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestAcceptNeedsBothIDs(t *testing.T) {
	l := openTestLedger(t, filepath.Join(t.TempDir(), "s.json"), newLedgerClock())
	for _, c := range [][2]string{{"", "1"}, {"id", ""}, {"", ""}} {
		if got, err := l.Accept(c[0], c[1], 1<<40); err == nil || got == AcceptedNew {
			t.Errorf("Accept(%q, %q) = %v, %v: want an error", c[0], c[1], got, err)
		}
	}
}

func TestAnIDIsForgottenOnlyAfterItsExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	exp := clock.at.Add(90 * time.Second).Unix()
	l := openTestLedger(t, path, clock)
	accept(t, l, "id-a", "101", exp)

	// Right up to the expiry, and a clock margin past it, the id is used.
	clock.advance(90*time.Second + ledgerKeepPast - time.Second)
	accept(t, l, "other-1", "201", clock.at.Add(time.Hour).Unix())
	if got := accept(t, l, "id-a", "102", exp); got != AcceptedReplayed {
		t.Fatalf("before the expiry plus the margin: %v, want replayed", got)
	}

	clock.advance(3 * time.Second)
	accept(t, l, "other-2", "202", clock.at.Add(time.Hour).Unix())
	l = openTestLedger(t, path, clock)
	if got := accept(t, l, "id-a", "102", clock.at.Add(time.Hour).Unix()); got != AcceptedNew {
		t.Fatalf("past the expiry and the margin: %v, want new (forgotten)", got)
	}
}

func TestACloseIsRememberedUntilItsOwnExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	l := openTestLedger(t, path, clock)

	closeExp := clock.at.Add(8 * time.Hour).Unix()
	if err := l.RememberClosed("never-opened", closeExp); err != nil {
		t.Fatal(err)
	}
	l = openTestLedger(t, path, clock)
	if got := accept(t, l, "never-opened", "301", clock.at.Add(90*time.Second).Unix()); got != AcceptedReplayed {
		t.Fatalf("an open after its close = %v, want replayed", got)
	}

	// A close for an id an open brought keeps the id for the close's life.
	openExp := clock.at.Add(90 * time.Second).Unix()
	accept(t, l, "opened", "302", openExp)
	if err := l.RememberClosed("opened", closeExp); err != nil {
		t.Fatal(err)
	}
	clock.advance(7 * time.Hour)
	accept(t, l, "tick", "303", clock.at.Add(time.Hour).Unix())
	if got := accept(t, l, "opened", "304", clock.at.Add(time.Hour).Unix()); got != AcceptedReplayed {
		t.Fatalf("seven hours later = %v, want replayed", got)
	}
	// A shorter close never shortens what is kept.
	if err := l.RememberClosed("opened", openExp); err != nil {
		t.Fatal(err)
	}
	if got := accept(t, l, "opened", "304", clock.at.Add(time.Hour).Unix()); got != AcceptedReplayed {
		t.Fatalf("after a shorter close = %v, want replayed", got)
	}
	if got := accept(t, l, "opened", "302", openExp); got != AcceptedSameTask {
		t.Fatalf("the open task itself = %v, want the same task", got)
	}
}

func TestAnOpenSessionIsFoundByTheNextProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	l := openTestLedger(t, path, clock)
	exp := clock.at.Add(90 * time.Second).Unix()

	accept(t, l, "never-listened", "401", exp)
	accept(t, l, "ended", "402", exp)
	accept(t, l, "open", "403", exp)
	listening := clock.at
	for _, id := range []string{"ended", "open"} {
		if err := l.Listening(id, 1, listening); err != nil {
			t.Fatal(err)
		}
	}
	clock.advance(4 * time.Second)
	if err := l.Connected("open", clock.at); err != nil {
		t.Fatal(err)
	}
	if err := l.Path("open", PathDirect); err != nil {
		t.Fatal(err)
	}
	if err := l.Ended("ended"); err != nil {
		t.Fatal(err)
	}
	if got := l.Orphans(); len(got) != 0 {
		t.Fatalf("the process that opened a session calls it an orphan: %+v", got)
	}

	// The agent runs on for ten minutes, then dies; the next starts an hour later.
	clock.advance(10 * time.Minute)
	l.Touch()
	lastSeen := clock.at
	clock.advance(time.Hour)

	next := openTestLedger(t, path, clock)
	orphans := next.Orphans()
	if len(orphans) != 1 {
		t.Fatalf("orphans = %+v, want the one open session", orphans)
	}
	o := orphans[0]
	if o.ConnectID != "open" || o.TaskID != "403" || o.Protocol != 1 || o.Path != PathDirect {
		t.Errorf("orphan = %+v", o)
	}
	if !o.ListeningAt.Equal(listening) || !o.ConnectedAt.Equal(listening.Add(4*time.Second)) {
		t.Errorf("orphan times: listening %v connected %v", o.ListeningAt, o.ConnectedAt)
	}
	if !o.LastSeen.Equal(lastSeen) {
		t.Errorf("last seen %v, want %v (the last Touch, not the restart)", o.LastSeen, lastSeen)
	}

	// Until its end is recorded, every process finds it: an hour past the
	// id's expiry it is still there.
	again := openTestLedger(t, path, clock)
	accept(t, again, "tick", "404", clock.at.Add(time.Hour).Unix())
	if got := openTestLedger(t, path, clock).Orphans(); len(got) != 1 {
		t.Fatalf("a restart before the end was recorded lost the orphan: %+v", got)
	}

	if err := next.Ended("open"); err != nil {
		t.Fatal(err)
	}
	if got := next.Orphans(); len(got) != 0 {
		t.Fatalf("Ended left the orphan: %+v", got)
	}
	if got := openTestLedger(t, path, clock).Orphans(); len(got) != 0 {
		t.Fatalf("an ended session is an orphan of the next process: %+v", got)
	}
}

func TestASessionWithoutAClientIsAnOrphanWithoutOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	l := openTestLedger(t, path, clock)
	accept(t, l, "open", "1", clock.at.Add(time.Minute).Unix())
	if err := l.Listening("open", 1, clock.at); err != nil {
		t.Fatal(err)
	}
	// A file time before the session listened (a clock stepped back).
	old := clock.at.Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	orphans := openTestLedger(t, path, clock).Orphans()
	if len(orphans) != 1 || !orphans[0].ConnectedAt.IsZero() || orphans[0].Path != "" {
		t.Fatalf("orphans = %+v", orphans)
	}
	if orphans[0].LastSeen.Before(orphans[0].ListeningAt) {
		t.Errorf("last seen %v is before listening %v", orphans[0].LastSeen, orphans[0].ListeningAt)
	}
}

func TestAnUnusableRecordRefusesWhatItCouldHaveHeld(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":        "{\"v\":1,\"entries\":[{\"connect_id\":\"id-a\"",
		"empty":           "",
		"another version": `{"v":2,"entries":[]}`,
		"no version":      `{"entries":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sessions.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			clock := newLedgerClock()
			l, err := OpenLedger(path, clock.now)
			if err == nil {
				t.Fatal("OpenLedger said nothing of an unusable record")
			}
			if l == nil {
				t.Fatal("no Ledger")
			}

			// An open that expires inside the longest life of an open task
			// could carry an id the lost record held.
			soon := clock.at.Add(90 * time.Second).Unix()
			if got, err := l.Accept("id-a", "1", soon); !errors.Is(err, ErrLedgerBlind) || got == AcceptedNew {
				t.Fatalf("Accept = %v, %v: want ErrLedgerBlind", got, err)
			}
			edge := clock.at.Add(ledgerBlindFor).Unix()
			if _, err := l.Accept("id-b", "2", edge); !errors.Is(err, ErrLedgerBlind) {
				t.Fatalf("Accept at the edge: %v, want ErrLedgerBlind", err)
			}

			// The refusal survives a restart, and ends by itself.
			l = openTestLedger(t, path, clock)
			if _, err := l.Accept("id-a", "1", soon); !errors.Is(err, ErrLedgerBlind) {
				t.Fatalf("after a restart: %v, want ErrLedgerBlind", err)
			}
			clock.advance(ledgerBlindFor + time.Second)
			if got := accept(t, l, "id-c", "3", clock.at.Add(90*time.Second).Unix()); got != AcceptedNew {
				t.Fatalf("after the window: %v, want new", got)
			}
		})
	}
}

func TestTheLongestOpenTaskLifeIsInsideTheBlindWindow(t *testing.T) {
	// The control plane's open-task lifetime is a setting of 30 to 900 s.
	if ledgerBlindFor < 900*time.Second {
		t.Fatalf("ledgerBlindFor = %v, shorter than the longest open task (900 s)", ledgerBlindFor)
	}
}

func TestAnIDThatCannotBeWrittenIsNotAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone", "sessions.json")
	l := openTestLedger(t, path, newLedgerClock())
	if got, err := l.Accept("id-a", "1", 1<<40); err == nil || got == AcceptedNew {
		t.Fatalf("Accept without a directory = %v, %v: want an error", got, err)
	}
	if err := l.RememberClosed("id-b", 1<<40); err == nil {
		t.Fatal("RememberClosed without a directory succeeded")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("the directory was created")
	}

	// Once it can be written, neither id was taken by the failed attempt.
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := accept(t, l, "id-a", "1", 1<<40); got != AcceptedNew {
		t.Fatalf("Accept = %v, want new", got)
	}
	if got := accept(t, l, "id-b", "2", 1<<40); got != AcceptedNew {
		t.Fatalf("Accept of the id whose close failed = %v, want new", got)
	}
}

func TestTheRecordIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	clock := newLedgerClock()
	entries := make([]ledgerEntry, 0, ledgerMaxEntries)
	far := clock.at.Add(time.Hour).Unix()
	for i := 0; i < ledgerMaxEntries; i++ {
		entries = append(entries, ledgerEntry{ConnectID: fmt.Sprintf("id-%d", i), TaskID: "1", Until: far})
	}
	data, err := json.Marshal(ledgerFile{V: ledgerVersion, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	l := openTestLedger(t, path, clock)
	if _, err := l.Accept("one-more", "2", far); !errors.Is(err, ErrLedgerFull) {
		t.Fatalf("Accept on a full record: %v, want ErrLedgerFull", err)
	}
	if err := l.RememberClosed("one-more", far); !errors.Is(err, ErrLedgerFull) {
		t.Fatalf("RememberClosed on a full record: %v, want ErrLedgerFull", err)
	}
	// Expired ids make room.
	clock.advance(time.Hour + ledgerKeepPast + time.Second)
	if got := accept(t, l, "one-more", "2", clock.at.Add(time.Hour).Unix()); got != AcceptedNew {
		t.Fatalf("after the others expired: %v, want new", got)
	}
}
