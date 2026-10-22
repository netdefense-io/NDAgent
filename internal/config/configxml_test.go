package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

const completeConfigXML = "<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <hostname>fw</hostname>\n  </system>\n</opnsense>\n"

func writeConfigXMLFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// setConfigXMLTiming shortens the waits for a test and restores them after it.
func setConfigXMLTiming(t *testing.T, attempts int, lockWait time.Duration) {
	t.Helper()
	oldAttempts, oldDelay, oldWait, oldPoll := configXMLAttempts, configXMLRetryDelay, configXMLLockWait, configXMLLockPoll
	configXMLAttempts, configXMLRetryDelay, configXMLLockWait, configXMLLockPoll = attempts, time.Millisecond, lockWait, 5*time.Millisecond
	t.Cleanup(func() {
		configXMLAttempts, configXMLRetryDelay, configXMLLockWait, configXMLLockPoll = oldAttempts, oldDelay, oldWait, oldPoll
	})
}

// countConfigXMLAttempts counts the reads ReadConfigXML makes; before, when
// set, runs ahead of each one.
func countConfigXMLAttempts(t *testing.T, before func(attempt int, path string)) *int {
	t.Helper()
	calls := 0
	orig := readConfigXMLAttempt
	readConfigXMLAttempt = func(ctx context.Context, path string) ([]byte, error) {
		calls++
		if before != nil {
			before(calls, path)
		}
		return orig(ctx, path)
	}
	t.Cleanup(func() { readConfigXMLAttempt = orig })
	return &calls
}

// holdConfigXMLLock takes an flock on the file through a descriptor of its
// own, as OPNsense's Config does, until the returned func runs.
func holdConfigXMLLock(t *testing.T, path string, how int) func() {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { f.Close() }) }
	t.Cleanup(release)
	return release
}

func TestReadConfigXMLReturnsTheWholeFile(t *testing.T) {
	path := writeConfigXMLFile(t, completeConfigXML)
	data, err := ReadConfigXML(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadConfigXML: %v", err)
	}
	if string(data) != completeConfigXML {
		t.Fatalf("ReadConfigXML = %q, want the file as written", data)
	}
}

func TestReadConfigXMLRefusesAnEmptyOrCutShortFile(t *testing.T) {
	for name, content := range map[string]string{
		"empty":                   "",
		"only a newline":          "\n",
		"cut inside an element":   "<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <hostname>fw</host",
		"cut inside the last tag": "<?xml version=\"1.0\"?>\n<opnsense>\n</opnsen",
	} {
		t.Run(name, func(t *testing.T) {
			setConfigXMLTiming(t, 3, time.Second)
			calls := countConfigXMLAttempts(t, nil)
			path := writeConfigXMLFile(t, content)

			data, err := ReadConfigXML(context.Background(), path)
			if !errors.Is(err, ErrConfigXMLIncomplete) {
				t.Fatalf("ReadConfigXML error = %v, want ErrConfigXMLIncomplete", err)
			}
			if data != nil {
				t.Fatalf("ReadConfigXML returned %q with the error, want nothing", data)
			}
			if *calls != 3 {
				t.Fatalf("read %d times, want 3", *calls)
			}
		})
	}
}

func TestReadConfigXMLReadsAgainAfterAnIncompleteRead(t *testing.T) {
	setConfigXMLTiming(t, 3, time.Second)
	calls := countConfigXMLAttempts(t, func(attempt int, path string) {
		if attempt == 2 {
			if err := os.WriteFile(path, []byte(completeConfigXML), 0o600); err != nil {
				t.Error(err)
			}
		}
	})
	path := writeConfigXMLFile(t, "")

	data, err := ReadConfigXML(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadConfigXML: %v", err)
	}
	if string(data) != completeConfigXML || *calls != 2 {
		t.Fatalf("ReadConfigXML = %q after %d reads, want the whole file on the second", data, *calls)
	}
}

// Config::save() truncates and rewrites the file while it holds the lock. A
// read that does not wait for the lock sees the empty file.
func TestReadConfigXMLWaitsWhileAWriterHoldsTheLock(t *testing.T) {
	setConfigXMLTiming(t, 1, 10*time.Second)
	path := writeConfigXMLFile(t, completeConfigXML)
	release := holdConfigXMLLock(t, path, syscall.LOCK_EX)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}

	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := ReadConfigXML(context.Background(), path)
		done <- result{data, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("ReadConfigXML returned %q, %v while a writer held the lock", r.data, r.err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := os.WriteFile(path, []byte(completeConfigXML), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case r := <-done:
		if r.err != nil || string(r.data) != completeConfigXML {
			t.Fatalf("ReadConfigXML = %q, %v, want the file the writer finished", r.data, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadConfigXML did not return after the writer released the lock")
	}
}

// OPNsense's own loader reads under a shared lock: another reader must not
// hold this one up.
func TestReadConfigXMLDoesNotWaitForAnotherReader(t *testing.T) {
	setConfigXMLTiming(t, 1, 100*time.Millisecond)
	path := writeConfigXMLFile(t, completeConfigXML)
	holdConfigXMLLock(t, path, syscall.LOCK_SH)

	data, err := ReadConfigXML(context.Background(), path)
	if err != nil || string(data) != completeConfigXML {
		t.Fatalf("ReadConfigXML = %q, %v, want the file while another reader holds a shared lock", data, err)
	}
}

func TestReadConfigXMLGivesUpOnALockHeldPastTheWait(t *testing.T) {
	setConfigXMLTiming(t, 3, 100*time.Millisecond)
	calls := countConfigXMLAttempts(t, nil)
	path := writeConfigXMLFile(t, completeConfigXML)
	holdConfigXMLLock(t, path, syscall.LOCK_EX)

	start := time.Now()
	_, err := ReadConfigXML(context.Background(), path)
	if !errors.Is(err, ErrConfigXMLLocked) {
		t.Fatalf("ReadConfigXML error = %v, want ErrConfigXMLLocked", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("gave up after %s, before the wait was over", elapsed)
	}
	if *calls != 1 {
		t.Fatalf("read %d times, want 1: the wait is the bound", *calls)
	}
}

func TestReadConfigXMLStopsWaitingWhenTheContextEnds(t *testing.T) {
	setConfigXMLTiming(t, 1, 10*time.Second)
	path := writeConfigXMLFile(t, completeConfigXML)
	holdConfigXMLLock(t, path, syscall.LOCK_EX)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ReadConfigXML(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadConfigXML error = %v, want the context's", err)
	}
}

func TestReadConfigXMLReportsAMissingFile(t *testing.T) {
	_, err := ReadConfigXML(context.Background(), filepath.Join(t.TempDir(), "config.xml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadConfigXML error = %v, want os.ErrNotExist", err)
	}
}
