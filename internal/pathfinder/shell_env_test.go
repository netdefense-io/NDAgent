package pathfinder

import (
	"bytes"
	"testing"
	"time"
)

// An agent started by service(8) runs with PATH=/sbin:/bin:/usr/sbin:/usr/bin.
// The remote shell must still get the device PATH, so the console menu finds
// opnsense-version and ssh-keygen. The values are the contract's, spelled out.
func TestShellRun_EnvironmentUnderTheRcPath(t *testing.T) {
	t.Setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin")
	t.Setenv("HOME", "/nonexistent")
	t.Setenv("TERM", "dumb")

	sess, cap := newShellTestSession(t, "/bin/sh")
	go func() {
		// printf joins each marker to its value, so the PTY's echo of this line
		// cannot pass for the output.
		sess.shellStream.readBuf <- []byte(`printf 'P-%s\nH-%s\nU-%s\nT-%s\n' "$PATH" "$HOME" "$USER" "$TERM"; exit` + "\n")
	}()

	done := make(chan struct{})
	go func() {
		_ = sess.run()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not end within 10s")
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	for _, want := range []string{
		"P-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\r\n",
		"H-/root\r\n",
		"U-root\r\n",
		"T-xterm-256color\r\n",
	} {
		if !bytes.Contains(cap.data, []byte(want)) {
			t.Errorf("shell output lacks %q; got %q", want, cap.data)
		}
	}
}
