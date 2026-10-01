package pkgmgr

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestParseInstalledVersions(t *testing.T) {
	out := "opnsense 26.7.4_1\nos-netdefense 1.19.5\n\n  curl   8.9.1_1 \nnoversion\n \nos-wireguard 2.4_2,1\n"
	got, err := parseInstalledVersions(out)
	if err != nil {
		t.Fatalf("parseInstalledVersions: %v", err)
	}
	want := map[string]string{
		"opnsense":      "26.7.4_1",
		"os-netdefense": "1.19.5",
		"curl":          "8.9.1_1",
		"os-wireguard":  "2.4_2,1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (a line without a version is skipped)", got, want)
	}
}

// A query that ran but listed nothing did not really run: a device always has
// packages.
func TestParseInstalledVersions_EmptyOutputIsAnError(t *testing.T) {
	for _, out := range []string{"", "\n", "   \n\n"} {
		if _, err := parseInstalledVersions(out); err == nil {
			t.Errorf("parseInstalledVersions(%q) returned no error", out)
		}
	}
}

func TestInstalledVersions_PropagatesErrors(t *testing.T) {
	wantErr := errors.New("Cannot get a read lock on a database, it is locked by another process")
	prev := SetInstalledVersionsFunc(func(context.Context) (map[string]string, error) { return nil, wantErr })
	t.Cleanup(func() { SetInstalledVersionsFunc(prev) })

	got, err := InstalledVersions(context.Background())
	if !errors.Is(err, wantErr) || got != nil {
		t.Fatalf("got %v, %v; want the error, and no partial map", got, err)
	}
}

func TestInstalledVersions_ReturnsTheBackendsMap(t *testing.T) {
	want := map[string]string{"opnsense": "26.7.4_1"}
	prev := SetInstalledVersionsFunc(func(context.Context) (map[string]string, error) { return want, nil })
	t.Cleanup(func() { SetInstalledVersionsFunc(prev) })

	got, err := InstalledVersions(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
}

// An install holds the package lock for up to ten minutes. A caller with a
// deadline of its own must not sit behind it past that deadline: the
// FIRMWARE_UPGRADE reconciler sweeps inside the connect.
func TestInstalledVersions_DoesNotWaitForThePackageLockPastItsContext(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	prevInstall := SetInstallFunc(func(context.Context, string) MutateOutcome {
		close(entered)
		<-release
		return MutateOutcome{}
	})
	prevQuery := SetInstalledVersionsFunc(func(context.Context) (map[string]string, error) {
		return map[string]string{"opnsense": "26.7.4_1"}, nil
	})
	t.Cleanup(func() {
		SetInstallFunc(prevInstall)
		SetInstalledVersionsFunc(prevQuery)
	})
	installed := make(chan struct{})
	go func() { defer close(installed); Install(context.Background(), "some-package") }()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	type result struct {
		versions map[string]string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		v, err := InstalledVersions(ctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, context.DeadlineExceeded) || r.versions != nil {
			t.Fatalf("got %v, %v; want the context's error and no map", r.versions, r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("InstalledVersions was still waiting for the package lock long after its context ended")
	}

	close(release)
	<-installed
	// The lock is free again, and a query under a live context gets its answer.
	if v, err := InstalledVersions(context.Background()); err != nil || v["opnsense"] != "26.7.4_1" {
		t.Fatalf("after the install: %v, %v", v, err)
	}
}
