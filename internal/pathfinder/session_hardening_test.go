package pathfinder

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/logging"
)

func newHardeningManager(sent *[]sentFrame, mu *sync.Mutex) *StreamManager {
	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func(data []byte) error {
		f, err := DecodeFrame(data)
		if err != nil {
			return err
		}
		mu.Lock()
		*sent = append(*sent, sentFrame{f.StreamID, f.Type})
		mu.Unlock()
		return nil
	}
	return mgr
}

type sentFrame struct {
	id  uint32
	typ byte
}

func addTestStream(mgr *StreamManager, id uint32, bufSize int) *Stream {
	s := &Stream{
		id:        id,
		readBuf:   make(chan []byte, bufSize),
		closeChan: make(chan struct{}),
		manager:   mgr,
		log:       logging.Named("test.stream"),
	}
	mgr.streams[id] = s
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readPID(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid, err == nil
}

// startBackgroundShell runs a shell session that backgrounds a long sleep
// and records its pid, returning the session, the sleep's pid and run's result.
func startBackgroundShell(t *testing.T) (*ShellSession, int, <-chan struct{}) {
	t.Helper()
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	dir := t.TempDir()
	sess := &ShellSession{
		shellStream: addTestStream(mgr, 1, 16),
		ctlStream:   addTestStream(mgr, 2, 16),
		shell:       "/bin/sh",
		dir:         dir,
		log:         logging.Named("test.shell"),
	}
	pidFile := filepath.Join(dir, "child.pid")
	sess.shellStream.readBuf <- []byte("sleep 300 & echo $! > " + pidFile + "\n")

	done := make(chan struct{})
	go func() {
		_ = sess.run()
		close(done)
	}()

	var pid int
	waitFor(t, "the background process to start", func() bool {
		var ok bool
		pid, ok = readPID(pidFile)
		return ok
	})
	return sess, pid, done
}

func TestShell_StreamCloseKillsTheProcessGroup(t *testing.T) {
	sess, childPID, done := startBackgroundShell(t)

	sess.shellStream.mu.Lock()
	sess.shellStream.closed = true
	close(sess.shellStream.closeChan)
	sess.shellStream.mu.Unlock()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not end after its stream closed")
	}
	waitFor(t, "the background process to be killed", func() bool { return processGone(childPID) })
}

func TestShellManager_CloseAllKillsLiveShells(t *testing.T) {
	sess, childPID, done := startBackgroundShell(t)
	sm := NewShellManager("/bin/sh")
	sm.sessions[sess] = struct{}{}

	sm.CloseAll()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not end after CloseAll")
	}
	waitFor(t, "the background process to be killed", func() bool { return processGone(childPID) })
}

func TestShellSession_KillBeforeStartPreventsTheShell(t *testing.T) {
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	sess := &ShellSession{
		shellStream: addTestStream(mgr, 1, 16),
		ctlStream:   addTestStream(mgr, 2, 16),
		shell:       "/bin/sh",
		dir:         t.TempDir(),
		log:         logging.Named("test.shell"),
	}
	sess.kill()

	done := make(chan struct{})
	go func() {
		_ = sess.run()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a shell killed before it started kept running")
	}
}

func TestShellManager_SecondShellStreamClosesTheFirst(t *testing.T) {
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	sm := NewShellManager("/bin/sh")
	first := addTestStream(mgr, 1, 4)
	second := addTestStream(mgr, 3, 4)

	_ = sm.HandleShellStream(first)
	_ = sm.HandleShellStream(second)

	if !first.IsClosed() {
		t.Error("the replaced pending shell stream was left open")
	}
	if second.IsClosed() {
		t.Error("the newest shell stream was closed")
	}
}

func TestExec_StreamCloseKillsTheRunningCommand(t *testing.T) {
	tc := newTestCapture()
	em := NewExecManager()
	pidFile := filepath.Join(t.TempDir(), "child.pid")

	done := make(chan struct{})
	go func() {
		em.HandleExecStream(context.Background(), tc.stream)
		close(done)
	}()
	tc.pushBytes(encodeReq("1", "sleep 300 & echo $! > "+pidFile+"; wait", 600))

	var pid int
	waitFor(t, "the command to start", func() bool {
		var ok bool
		pid, ok = readPID(pidFile)
		return ok
	})
	tc.closeInput()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleExecStream kept running after its stream closed")
	}
	waitFor(t, "the command's process to be killed", func() bool { return processGone(pid) })
}

func TestExec_ContextCancelKillsTheRunningCommand(t *testing.T) {
	tc := newTestCapture()
	em := NewExecManager()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		em.HandleExecStream(ctx, tc.stream)
		close(done)
	}()
	tc.pushBytes(encodeReq("1", "sleep 300 & echo $! > "+pidFile+"; wait", 600))

	var pid int
	waitFor(t, "the command to start", func() bool {
		var ok bool
		pid, ok = readPID(pidFile)
		return ok
	})
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleExecStream kept running after its context was cancelled")
	}
	waitFor(t, "the command's process to be killed", func() bool { return processGone(pid) })
}

func TestStream_FullReadBufferClosesTheStream(t *testing.T) {
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	s := addTestStream(mgr, 5, 2)

	for _, d := range []string{"a", "b", "c"} {
		mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeData, StreamID: 5, Data: []byte(d)}))
	}

	waitFor(t, "the stream to be closed", s.IsClosed)
	waitFor(t, "a CLOSE frame", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sent) == 1 && sent[0] == sentFrame{5, FrameTypeClose}
	})

	buf := make([]byte, 8)
	var got string
	for {
		n, err := s.Read(buf)
		got += string(buf[:n])
		if err != nil {
			if !errors.Is(err, ErrStreamOverflow) {
				t.Fatalf("Read ended with %v, want ErrStreamOverflow", err)
			}
			break
		}
	}
	if got != "ab" {
		t.Errorf("buffered data = %q, want %q (no frame dropped silently, none after the overflow)", got, "ab")
	}
}

func TestStream_RelayInitiatedCloseIsHandledCleanly(t *testing.T) {
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	s := addTestStream(mgr, 9, 4)
	allClosed := 0
	mgr.OnAllStreamsClosed(func() { allClosed++ })
	mgr.hadStreams = true

	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeData, StreamID: 9, Data: []byte("x")}))
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeClose, StreamID: 9}))
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeData, StreamID: 9, Data: []byte("late")}))
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeClose, StreamID: 9}))

	buf := make([]byte, 8)
	n, err := s.Read(buf)
	if err != nil || string(buf[:n]) != "x" {
		t.Fatalf("Read = %q, %v; want the data sent before the close", buf[:n], err)
	}
	if _, err := s.Read(buf); err != io.EOF {
		t.Fatalf("Read after close = %v, want io.EOF", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close after a relay close = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 0 {
		t.Errorf("agent sent %v back for a stream the relay closed", sent)
	}
	if mgr.ActiveStreamCount() != 0 {
		t.Error("the closed stream was not removed")
	}
	if allClosed < 1 {
		t.Error("onAllClosed did not fire")
	}
}

func TestHandleOpen_AckPrecedesTheHandlerAndDoesNotBlockTheReadLoop(t *testing.T) {
	var sent []sentFrame
	var mu sync.Mutex
	mgr := newHardeningManager(&sent, &mu)
	release := make(chan struct{})
	mgr.sendFrameFunc = func([]byte) error {
		<-release
		return nil
	}
	handled := make(chan struct{})
	mgr.OnNewStream(func(*Stream) { close(handled) })

	returned := make(chan struct{})
	go func() {
		mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 4, Data: []byte("webadmin")}))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("handleFrame blocked on the ACK write")
	}
	select {
	case <-handled:
		t.Fatal("the handler ran before the ACK was written")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}
}

func TestSendFrame_WriteDeadlineEndsAStalledWrite(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		<-release
	})
	defer cleanup()
	client.writeTimeout = 300 * time.Millisecond

	errc := make(chan error, 1)
	go func() {
		frame := make([]byte, 1<<20)
		for {
			if err := client.SendFrame(frame); err != nil {
				errc <- err
				return
			}
		}
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected a write error")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("SendFrame stayed blocked on a peer that reads nothing")
	}
}

func TestWaitForPairing_PeerOfflineEndsTheWait(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		sendPeerOffline(t, conn, nil)
		<-release
	})
	defer cleanup()

	start := time.Now()
	err := client.WaitForPairing(context.Background(), time.Minute)
	var ended *ErrSessionEndedCleanly
	if !errors.As(err, &ended) {
		t.Fatalf("WaitForPairing = %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if ended.Reason != ReasonClientDisconnected {
		t.Errorf("Reason = %q, want %q", ended.Reason, ReasonClientDisconnected)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("the agent waited out the pairing window")
	}
}

func TestRegistered_NoPeerYetIsNotAnEnd(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		time.Sleep(100 * time.Millisecond)
		_ = conn.WriteJSON(Message{Type: MsgTypePaired})
		<-release
	})
	defer cleanup()

	if err := client.WaitForPairing(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("a registered reply with peer_online=false must still wait for pairing, got %v", err)
	}
}

func TestRunFrameLoop_RelayCloseReasonsAreNaturalEndsWhateverTheText(t *testing.T) {
	cases := []struct {
		code   int
		reason string
	}{
		{websocket.CloseNormalClosure, "peer disconnected (client)"},
		{websocket.CloseNormalClosure, "peer disconnected (agent)"},
		{websocket.CloseNormalClosure, "session deleted"},
		{websocket.CloseGoingAway, "server restarting"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
				_ = conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(tc.code, tc.reason), time.Now().Add(time.Second))
			})
			defer cleanup()
			err := runFrameLoopWithin(t, client, 5*time.Second)
			var ended *ErrSessionEndedCleanly
			if !errors.As(err, &ended) || ended.Reason != tc.reason {
				t.Fatalf("RunFrameLoop = %v, want a clean end carrying %q", err, tc.reason)
			}
		})
	}
}
