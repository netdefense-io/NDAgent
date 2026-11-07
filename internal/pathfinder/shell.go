package pathfinder

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

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

	mu     sync.Mutex // guards killed, cmd and ptmx
	killed bool
	reaped bool // cmd.Wait returned; the session id may be reused, never signal it
}

// shellKillGrace is how long a hung-up shell and its jobs get to exit before
// SIGKILL.
const shellKillGrace = 300 * time.Millisecond

// kill ends the shell and everything it started: SIGHUP to every process in
// the shell's session, SIGKILL to those still there after shellKillGrace, and
// the PTY closed. pty.Start makes the shell a session leader, so the session id
// is its pid. The session, not the process group: an interactive shell puts
// each job in a group of its own. Safe to call at any time, including before
// the shell has started.
func (s *ShellSession) kill() {
	s.mu.Lock()
	s.killed = true
	var sid int
	if !s.reaped && s.cmd != nil && s.cmd.Process != nil {
		sid = s.cmd.Process.Pid
		s.signalSessionLocked(sid, syscall.SIGHUP)
	}
	ptmx := s.ptmx
	s.mu.Unlock()

	if sid > 0 {
		time.AfterFunc(shellKillGrace, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !s.reaped {
				s.signalSessionLocked(sid, syscall.SIGKILL)
			}
		})
	}
	if ptmx != nil {
		_ = ptmx.Close()
	}
}

// signalSessionLocked sends sig to every process whose session id is sid,
// falling back to the leader's process group if the process table cannot be
// listed. Called with s.mu held, so the check that the shell is not yet reaped
// stays true while signalling.
func (s *ShellSession) signalSessionLocked(sid int, sig syscall.Signal) {
	out, err := exec.Command("ps", "-ax", "-o", "pid=").Output()
	if err != nil {
		s.log.Warnw("Cannot list processes, signalling only the shell's process group",
			"error", err, "signal", sig.String())
		_ = syscall.Kill(-sid, sig)
		return
	}
	for _, field := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		if got, err := unix.Getsid(pid); err == nil && got == sid {
			_ = syscall.Kill(pid, sig)
		}
	}
}

// ShellManager manages shell stream pairing and sessions
type ShellManager struct {
	pendingShell    *Stream
	pendingShellCtl *Stream
	sessions        map[*ShellSession]struct{} // live shells
	closed          bool
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
		shell:    shell,
		sessions: make(map[*ShellSession]struct{}),
		log:      logging.Named("pathfinder.shell"),
	}
}

// HandleShellStream stores the shell data stream and tries to start session.
func (sm *ShellManager) HandleShellStream(stream *Stream) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Debugw("Received shell data stream", "stream_id", stream.ID())
	if sm.pendingShell != nil {
		sm.pendingShell.Close()
	}
	sm.pendingShell = stream
	sm.tryStartShell()
	return nil
}

// HandleShellCtlStream stores the control stream and tries to start session.
func (sm *ShellManager) HandleShellCtlStream(stream *Stream) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Debugw("Received shell control stream", "stream_id", stream.ID())
	if sm.pendingShellCtl != nil {
		sm.pendingShellCtl.Close()
	}
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

	session := &ShellSession{
		shellStream: shellStream,
		ctlStream:   ctlStream,
		shell:       sm.shell,
		log:         sm.log.With("shell_stream_id", shellStream.ID()),
	}
	if sm.closed {
		shellStream.Close()
		ctlStream.Close()
		return
	}
	sm.sessions[session] = struct{}{}

	go func() {
		defer func() {
			sm.mu.Lock()
			delete(sm.sessions, session)
			sm.mu.Unlock()
		}()
		if err := session.run(); err != nil {
			sm.log.Errorw("Shell session ended with error", "error", err)
		} else {
			sm.log.Debugw("Shell session ended normally")
		}
	}()
}

// CloseAll closes any pending streams and kills every live shell.
func (sm *ShellManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.closed = true
	for session := range sm.sessions {
		session.kill()
	}

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
	cmd := exec.Command(s.shell)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "HOME=/root", "USER=root")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	s.mu.Lock()
	s.cmd, s.ptmx = cmd, ptmx
	killed := s.killed
	s.mu.Unlock()
	if killed {
		s.kill()
	}

	// The client closing its shell stream (or the relay doing it) ends the
	// shell; exited stops this watcher once the shell is gone on its own.
	exited := make(chan struct{})
	defer close(exited)
	go func() {
		select {
		case <-s.shellStream.CloseChan():
			s.kill()
		case <-exited:
		}
	}()

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
	s.mu.Lock()
	if s.killed {
		// Jobs that outlived the hang-up go now, before the pid is free to reuse.
		s.signalSessionLocked(s.cmd.Process.Pid, syscall.SIGKILL)
	}
	s.reaped = true
	s.mu.Unlock()
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
	s.mu.Lock()
	ptmx := s.ptmx
	s.mu.Unlock()
	if ptmx == nil {
		return
	}
	err := pty.Setsize(ptmx, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
	if err != nil {
		s.log.Warnw("Failed to resize PTY", "error", err)
	} else {
		s.log.Debugw("Resized PTY", "rows", rows, "cols", cols)
	}
}
