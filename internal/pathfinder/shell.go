package pathfinder

import (
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// opnsenseShell is the default shell path
const opnsenseShell = "/usr/local/sbin/opnsense-shell"

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

	s.cmd = exec.Command(s.shell)
	s.cmd.Dir = "/root"
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

	// Bidirectional copy - PTY line discipline handles Ctrl+C/D/Z
	done := make(chan struct{}, 2)

	// PTY output -> client
	go func() {
		io.Copy(s.shellStream, s.ptmx)
		done <- struct{}{}
	}()

	// Client input -> PTY
	go func() {
		io.Copy(s.ptmx, s.shellStream)
		done <- struct{}{}
	}()

	// Wait for shell to exit
	err = s.cmd.Wait()
	s.log.Debugw("Shell process exited",
		"pid", s.cmd.Process.Pid,
		"error", err,
	)

	// Close both streams
	s.shellStream.Close()
	s.ctlStream.Close()

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
