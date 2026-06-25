package pathfinder

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// opnsenseShell is the default shell path
const opnsenseShell = "/usr/local/sbin/opnsense-shell"

// outputDrainTimeout bounds how long run() waits for the PTY-output->client
// copy to flush the shell's final bytes before sending the stream CLOSE. The
// drain normally completes in microseconds once the PTY master is closed; the
// timeout only guards against a wedged relay write so the session can still
// tear down.
const outputDrainTimeout = 5 * time.Second

// Control message types for shell-ctl stream
const (
	CtlMsgResize byte = 0x01
	CtlMsgSetEnv byte = 0x02 // Reserved for future use
	CtlMsgClose  byte = 0xFF
)

// ShellSession manages a PTY shell session
type ShellSession struct {
	shellStream *Stream
	ctlStream   *Stream
	cmd         *exec.Cmd
	ptmx        *os.File
	shell       string
	dir         string // working directory; defaults to /root when empty (overridable in tests)
	log         *zap.SugaredLogger
}

// ShellManager manages shell stream pairing and sessions
type ShellManager struct {
	pendingShell    *Stream
	pendingShellCtl *Stream
	shell           string
	mu              sync.Mutex
	log             *zap.SugaredLogger
}

// NewShellManager creates a new shell manager.
// shell is the path to the shell to use; if empty, defaults to opnsense-shell.
func NewShellManager(shell string) *ShellManager {
	if shell == "" {
		shell = opnsenseShell
	}
	return &ShellManager{
		shell: shell,
		log:   logging.Named("pathfinder.shell"),
	}
}

// HandleShellStream stores the shell data stream and tries to start session.
func (sm *ShellManager) HandleShellStream(stream *Stream) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Debugw("Received shell data stream", "stream_id", stream.ID())
	sm.pendingShell = stream
	sm.tryStartShell()
	return nil
}

// HandleShellCtlStream stores the control stream and tries to start session.
func (sm *ShellManager) HandleShellCtlStream(stream *Stream) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Debugw("Received shell control stream", "stream_id", stream.ID())
	sm.pendingShellCtl = stream
	sm.tryStartShell()
	return nil
}

// tryStartShell starts a shell if both streams are ready.
// Must be called with sm.mu held.
func (sm *ShellManager) tryStartShell() {
	if sm.pendingShell == nil || sm.pendingShellCtl == nil {
		return
	}

	shellStream := sm.pendingShell
	ctlStream := sm.pendingShellCtl
	sm.pendingShell = nil
	sm.pendingShellCtl = nil

	sm.log.Debugw("Both shell streams received, starting shell session",
		"shell_stream_id", shellStream.ID(),
		"ctl_stream_id", ctlStream.ID(),
	)

	go func() {
		session := &ShellSession{
			shellStream: shellStream,
			ctlStream:   ctlStream,
			shell:       sm.shell,
			log:         sm.log.With("shell_stream_id", shellStream.ID()),
		}
		if err := session.run(); err != nil {
			sm.log.Errorw("Shell session ended with error", "error", err)
		} else {
			sm.log.Debugw("Shell session ended normally")
		}
	}()
}

// CloseAll closes any pending streams.
func (sm *ShellManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.pendingShell != nil {
		sm.pendingShell.Close()
		sm.pendingShell = nil
	}
	if sm.pendingShellCtl != nil {
		sm.pendingShellCtl.Close()
		sm.pendingShellCtl = nil
	}
}

func (s *ShellSession) run() error {
	s.log.Debugw("Starting shell session", "shell", s.shell)

	dir := s.dir
	if dir == "" {
		dir = "/root"
	}
	s.cmd = exec.Command(s.shell)
	s.cmd.Dir = dir
	s.cmd.Env = append(os.Environ(), "TERM=xterm-256color", "HOME=/root", "USER=root")

	var err error
	s.ptmx, err = pty.Start(s.cmd)
	if err != nil {
		return err
	}
	defer s.ptmx.Close()

	s.log.Debugw("Started shell session",
		"pid", s.cmd.Process.Pid,
		"shell", s.shell,
	)

	// Handle control stream (resize commands)
	go s.handleControlStream()

	// Bidirectional copy - PTY line discipline handles Ctrl+C/D/Z.
	//
	// outputDone is signalled when the PTY-output->client copy returns, i.e.
	// after every byte the shell wrote (including its final logout banner) has
	// been handed to s.shellStream.Write. We MUST wait for this before closing
	// the shell stream: on an immediate logout the shell process can exit (and
	// cmd.Wait() return) while the output copy is still draining the PTY's last
	// bytes. Closing the stream first sets s.shellStream.closed=true, which makes
	// the in-flight Write fail with "stream closed" — the final output is lost,
	// and worse, the CLOSE frame can be queued ahead of (or instead of) the last
	// DATA, so the client's io.Copy never observes the trailing output and the
	// stream teardown is unreliable. Draining first guarantees the client sees
	// all output and then a single, reliably-flushed CLOSE → EOF.
	outputDone := make(chan struct{})

	// PTY output -> client
	go func() {
		io.Copy(s.shellStream, s.ptmx)
		close(outputDone)
	}()

	// Client input -> PTY
	go func() {
		io.Copy(s.ptmx, s.shellStream)
	}()

	// Wait for shell to exit
	err = s.cmd.Wait()
	s.log.Debugw("Shell process exited",
		"pid", s.cmd.Process.Pid,
		"error", err,
	)

	// Close the PTY master now that the process is gone. This unblocks the
	// output copy goroutine (its Read on s.ptmx returns EOF/err) so outputDone
	// fires, and it unblocks the input copy goroutine's Write on s.ptmx. The
	// deferred s.ptmx.Close() would also do this, but doing it explicitly here
	// lets us wait for the output drain below before returning.
	s.ptmx.Close()

	// Wait for the output copy to finish flushing the shell's final bytes to the
	// client BEFORE we send the stream CLOSE. Bounded so a wedged relay write
	// can't hang the session forever (the deferred ptmx.Close + stream Close
	// still run on timeout).
	select {
	case <-outputDone:
		s.log.Debugw("Shell output drained to client")
	case <-time.After(outputDrainTimeout):
		s.log.Warnw("Timed out draining shell output before close")
	}

	// Emit the CLOSE frame for both streams UNCONDITIONALLY via SendCloseFrame
	// (not Close()). On a fast logout the client may have already closed these
	// streams toward the agent — which marks them closed locally and would make
	// Close() a no-op, suppressing the agent's own CLOSE. But the client's output
	// reader only observes EOF when it receives the AGENT's CLOSE (the relay does
	// not echo the client's own CLOSE back to it), so the agent MUST send its
	// shell-exit CLOSE regardless of local closed state. This is the
	// authoritative "shell process ended" signal the client needs to transition
	// to the webadmin keep-alive. Synchronously flushed under the client write
	// mutex; a send failure is logged rather than silent.
	if cerr := s.shellStream.SendCloseFrame(); cerr != nil {
		s.log.Warnw("Failed to send shell stream CLOSE frame", "error", cerr)
	}
	if cerr := s.ctlStream.SendCloseFrame(); cerr != nil {
		s.log.Warnw("Failed to send shell-ctl stream CLOSE frame", "error", cerr)
	}

	return err
}

func (s *ShellSession) handleControlStream() {
	buf := make([]byte, 16)
	for {
		n, err := s.ctlStream.Read(buf)
		if err != nil || n == 0 {
			return
		}

		switch buf[0] {
		case CtlMsgResize:
			if n >= 5 {
				rows := uint16(buf[1])<<8 | uint16(buf[2])
				cols := uint16(buf[3])<<8 | uint16(buf[4])
				s.resize(rows, cols)
			}
		case CtlMsgClose:
			return
		}
	}
}

func (s *ShellSession) resize(rows, cols uint16) {
	if s.ptmx == nil {
		return
	}
	err := pty.Setsize(s.ptmx, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
	if err != nil {
		s.log.Warnw("Failed to resize PTY", "error", err)
	} else {
		s.log.Debugw("Resized PTY", "rows", rows, "cols", cols)
	}
}
