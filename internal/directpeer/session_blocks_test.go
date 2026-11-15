package directpeer

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// The pieces a session is made of, put together as the CONNECT task puts
// them together: the companion's pipes carry the frames, the frame
// connection's clock feeds the idle limit, and ending the frame connection
// ends the companion.
func TestTheBlocksOfASessionWorkTogether(t *testing.T) {
	f := newFake(t, "ok") // echoes what it is sent, as a client that repeats every frame
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	conn := pathfinder.NewStreamConn(s.FromPeer, s.ToPeer)
	frames := make(chan []byte, 8)
	conn.OnFrame(func(frame []byte) { frames <- append([]byte(nil), frame...) })
	run := make(chan error, 1)
	go func() { run <- conn.Run(context.Background(), s.Connected()) }()

	sent := pathfinder.EncodeFrame(&pathfinder.Frame{Type: pathfinder.FrameTypeData, StreamID: 5, Data: []byte("to the client")})
	if err := conn.SendFrame(sent); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	select {
	case got := <-frames:
		if !bytes.Equal(got, sent) {
			t.Fatalf("the frame came back as %x, want %x", got, sent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the frame did not come back through the companion")
	}

	// Nothing more is said: the session passes its idle limit, counted from
	// that last frame.
	limits := Limits{Pairing: time.Minute, Idle: 300 * time.Millisecond, Lifetime: time.Hour}
	began := time.Now()
	if why := limits.Watch(context.Background(), s.ListeningAt, s.Connected(), conn.LastActivity); why != EndIdleTimeout {
		t.Fatalf("the session must end for %q, want %q", why, EndIdleTimeout)
	}
	if waited := time.Since(began); waited > 20*time.Second {
		t.Errorf("the idle limit of 300 ms was reported after %v", waited)
	}

	// Ending the frame connection closes the companion's stdin, which is how
	// it is told to end.
	conn.Close()
	select {
	case err := <-run:
		if err != nil {
			t.Errorf("Run = %v after Close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	waitClosed(t, "the companion ending", s.Done())
	if exit := s.Exit(); exit != (Exit{Reason: ReasonStdinClosed, Said: true}) {
		t.Errorf("the companion ended with %+v, want its own stdin_closed", exit)
	}
	s.Stop()
}
