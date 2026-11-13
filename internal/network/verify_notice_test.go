package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

func TestWithVerifyNotice(t *testing.T) {
	notice := (&config.Config{}).IgnoredVerifyNotice()
	if notice != "" {
		t.Fatalf("a Config built in code names a setting: %q", notice)
	}
	notice = "Note: SSL Verification (ssl_verify=false) is off in this firewall's NetDefense settings and no longer honoured; " +
		"its connections to NetDefense are verified under TLS Mode system. " +
		"For a NetDefense server with a private CA, set TLS Mode to custom_ca."
	otherNotice := "Note: Pathfinder SSL Verification (pathfinder_tls_verify=false) is off in this firewall's NetDefense settings and no longer honoured; " +
		"its connections to NetDefense are verified under TLS Mode custom_ca. " +
		"For a NetDefense server with a private CA, set TLS Mode to custom_ca."
	cases := []struct {
		name, status, message, want string
	}{
		{"a plain-text result", TaskStatusCompleted, "pong", "pong. " + notice},
		{"one ending in a full stop", TaskStatusFailed, "The relay refused the session.", "The relay refused the session. " + notice},
		{"an empty message", TaskStatusCompleted, "", notice},
		{"a JSON object", TaskStatusCompleted, `{"applied":true,"to_version":"26.1.9"}`, `{"applied":true,"to_version":"26.1.9"}`},
		{"a JSON array", TaskStatusFailed, ` ["a","b"] `, ` ["a","b"] `},
		{"text that only starts like JSON", TaskStatusFailed, "{not json} failed", "{not json} failed. " + notice},
		{"a result that already carries it", TaskStatusCompleted, "pong. " + notice, "pong. " + notice},
		{"a replay written under other settings", TaskStatusCompleted, "pong. " + otherNotice, "pong. " + otherNotice},
		{"a multi-line message", TaskStatusFailed, "  2 errors:\n- one\n- two\n", "  2 errors:\n- one\n- two. " + notice},
		{"a progress message", TaskStatusInProgress, "working", "working"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := withVerifyNotice(notice, c.status, c.message); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	if got := withVerifyNotice("", TaskStatusCompleted, "pong"); got != "pong" {
		t.Errorf("without a notice: %q", got)
	}
}

// ignoringSSLVerify gives w the configuration a file with ssl_verify=false
// loads to, and returns the notice it carries.
func ignoringSSLVerify(t *testing.T, w *WebSocketClient) string {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "ndagent.conf")
	if err := os.WriteFile(conf, []byte("token=t\ndevice_uuid=d\nssl_verify=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	loaded.ServerURIWS, loaded.DeviceUUID, loaded.Token, loaded.DevicePrivKey =
		w.cfg.ServerURIWS, w.cfg.DeviceUUID, w.cfg.Token, w.cfg.DevicePrivKey
	*w.cfg = *loaded
	notice := w.cfg.IgnoredVerifyNotice()
	if !strings.Contains(notice, "ssl_verify=false") {
		t.Fatalf("notice = %q", notice)
	}
	return notice
}

// A device whose configuration turns ssl_verify off says so in every
// plain-text result it sends, a replayed one included, once; a JSON result
// and a progress message are sent as they are.
func TestTaskResultsNameAnIgnoredVerifySetting(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	notice := ignoringSSLVerify(t, w)

	_ = store.Begin("301", TaskTypePing, taskstore.LifecycleSynchronous)
	if err := w.SendTaskResponse("301", TaskStatusCompleted, "pong", nil); err == nil {
		t.Fatal("a response before the connection was written")
	}

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	if err := w.SendTaskResponse("302", TaskStatusCompleted, `{"applied":true}`, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.SendTaskResponse("303", TaskStatusInProgress, "working", nil); err != nil {
		t.Fatal(err)
	}
	b.WaitFor("three responses", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 3 })

	want := map[int64]string{301: "pong. " + notice, 302: `{"applied":true}`, 303: "working"}
	for _, got := range b.TaskResponses() {
		if got.Message != want[got.TaskID] {
			t.Errorf("task %d: message %q, want %q", got.TaskID, got.Message, want[got.TaskID])
		}
	}
}

// A result too large for the broker is answered with a small FAILED, and that
// one names the ignored setting too.
func TestAnOversizedResultsFailureNamesAnIgnoredVerifySetting(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	notice := ignoringSSLVerify(t, w)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	_ = store.Begin("304", TaskTypeBackup, taskstore.LifecycleSynchronous)

	if err := w.SendTaskResponse("304", TaskStatusCompleted, "Backup completed successfully", bigContent()); err != nil {
		t.Fatal(err)
	}
	b.WaitFor("the response", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	got := b.TaskResponses()
	if len(got) != 1 || got[0].Status != "FAILED" || !strings.Contains(got[0].Message, "could not be delivered") ||
		strings.Count(got[0].Message, notice) != 1 {
		t.Fatalf("task responses = %+v", got)
	}
}

// A completed PULL or BACKUP result carries content, and NDBroker replaces its
// message with its own: it gets no notice, so the size BACKUP refuses up front
// is the one measured without it. Its failure carries the notice.
func TestAResultWithContentGetsNoNotice(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	notice := ignoringSSLVerify(t, w)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	_ = store.Begin("305", TaskTypeBackup, taskstore.LifecycleSynchronous)
	_ = store.Begin("306", TaskTypeBackup, taskstore.LifecycleSynchronous)

	if err := w.SendTaskResponse("305", TaskStatusCompleted, "Backup completed successfully", map[string]interface{}{"content": "ZW5jcnlwdGVk"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SendTaskResponse("306", TaskStatusFailed, "Backup failed: config.xml is too large", nil); err != nil {
		t.Fatal(err)
	}
	b.WaitFor("two responses", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 2 })
	want := map[int64]string{305: "Backup completed successfully", 306: "Backup failed: config.xml is too large. " + notice}
	for _, got := range b.TaskResponses() {
		if got.Message != want[got.TaskID] {
			t.Errorf("task %d: message %q, want %q", got.TaskID, got.Message, want[got.TaskID])
		}
	}
}
