package tasks

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// pipeClient is the client's end of a direct-peer session without the
// tunnel: it writes frames where the companion's stdout would be and reads
// them where its stdin would be.
type pipeClient struct {
	t      *testing.T
	send   *os.File
	frames chan *pathfinder.Frame
}

// newCarriedSession carries a session over two pipes and returns the
// client's end, the carrier and what its Run returned.
func newCarriedSession(t *testing.T, cfg streamServiceConfig) (*pipeClient, *streamCarrier, <-chan error) {
	t.Helper()
	toPeerR, toPeerW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fromPeerR, fromPeerW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range []*os.File{toPeerR, toPeerW, fromPeerR, fromPeerW} {
			_ = f.Close()
		}
	})

	carrier := newStreamCarrier(&directpeer.Session{ToPeer: toPeerW, FromPeer: fromPeerR}, cfg)
	connected := make(chan struct{})
	close(connected)
	done := make(chan error, 1)
	go func() { done <- carrier.Run(context.Background(), connected) }()

	c := &pipeClient{t: t, send: fromPeerW, frames: make(chan *pathfinder.Frame, 64)}
	go func() {
		defer close(c.frames)
		header := make([]byte, 9)
		for {
			if _, err := io.ReadFull(toPeerR, header); err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint32(header[5:9]))
			if _, err := io.ReadFull(toPeerR, data); err != nil {
				return
			}
			c.frames <- &pathfinder.Frame{Type: header[0], StreamID: binary.BigEndian.Uint32(header[1:5]), Data: data}
		}
	}()
	return c, carrier, done
}

func (c *pipeClient) write(frame *pathfinder.Frame) {
	c.t.Helper()
	if _, err := c.send.Write(pathfinder.EncodeFrame(frame)); err != nil {
		c.t.Fatal(err)
	}
}

// next is the next frame that is not a keepalive.
func (c *pipeClient) next(what string) *pathfinder.Frame {
	c.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				c.t.Fatalf("%s: the session ended", what)
			}
			if f.Type == pathfinder.FrameTypeKeepAlive {
				continue
			}
			return f
		case <-deadline:
			c.t.Fatalf("%s: no frame within 10 s", what)
		}
	}
}

func testServices(readOnly bool) streamServiceConfig {
	return streamServiceConfig{
		shell:              "/bin/sh",
		webadminUser:       "root",
		webadminSessionDir: os.TempDir(),
		webadminPort:       443,
		readOnly:           readOnly,
		policy:             config.RemoteAccessFull,
	}
}

// The services of a session are the same on this transport: a command sent
// on the exec stream runs and its output comes back, framed as on the relay.
func TestStreamCarrierServesTheSessionsStreams(t *testing.T) {
	client, carrier, done := newCarriedSession(t, testServices(false))

	client.write(&pathfinder.Frame{Type: pathfinder.FrameTypeOpen, StreamID: 7, Data: []byte("exec")})
	if ack := client.next("the open's acknowledgement"); ack.Type != pathfinder.FrameTypeAck || ack.StreamID != 7 {
		t.Fatalf("after the open: frame type %#x stream %d", ack.Type, ack.StreamID)
	}
	request, _ := json.Marshal(map[string]interface{}{"id": "r1", "command": "printf direct-peer"})
	client.write(&pathfinder.Frame{Type: pathfinder.FrameTypeData, StreamID: 7, Data: request})

	var output strings.Builder
	for {
		f := client.next("the command's answer")
		if f.Type != pathfinder.FrameTypeData || f.StreamID != 7 {
			t.Fatalf("frame type %#x stream %d", f.Type, f.StreamID)
		}
		var msg struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Data     string `json:"data"`
			ExitCode *int   `json:"exit_code"`
		}
		if err := json.Unmarshal(f.Data, &msg); err != nil || msg.ID != "r1" {
			t.Fatalf("answer %q: %v", f.Data, err)
		}
		if msg.Type == "stdout" {
			raw, _ := base64.StdEncoding.DecodeString(msg.Data)
			output.Write(raw)
			continue
		}
		// A zero exit code is left out of the result.
		if msg.Type != "result" || (msg.ExitCode != nil && *msg.ExitCode != 0) {
			t.Fatalf("answer %q", f.Data)
		}
		break
	}
	if output.String() != "direct-peer" {
		t.Fatalf("output %q", output.String())
	}
	if carrier.LastActivity().IsZero() {
		t.Error("frames went both ways and no activity was noted")
	}

	// Ending the session closes the stream toward the client, then the
	// connection: the client reads the close and then the end.
	carrier.Close()
	sawClose := false
	for f := range client.frames {
		if f.Type == pathfinder.FrameTypeClose && f.StreamID == 7 {
			sawClose = true
		}
	}
	if !sawClose {
		t.Error("the stream's close did not reach the client before the connection ended")
	}
	_ = client.send.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v after Close", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

// A read-only session serves the web interface only, on this transport too:
// a shell or a command stream is closed, whatever the client opens.
func TestStreamCarrierReadOnlySessionRefusesAShell(t *testing.T) {
	client, carrier, _ := newCarriedSession(t, testServices(true))
	defer carrier.Close()

	for id, service := range map[uint32]string{3: "shell", 5: "exec", 9: "ssh"} {
		client.write(&pathfinder.Frame{Type: pathfinder.FrameTypeOpen, StreamID: id, Data: []byte(service)})
		for {
			f := client.next("the answer to opening " + service)
			if f.StreamID != id {
				t.Fatalf("%s: a frame for stream %d", service, f.StreamID)
			}
			if f.Type == pathfinder.FrameTypeAck {
				continue
			}
			if f.Type != pathfinder.FrameTypeClose {
				t.Fatalf("%s: frame type %#x with %q, want the stream closed", service, f.Type, f.Data)
			}
			break
		}
	}
}

// The client closing the connection ends Run without an error: the session
// is over, and the companion's word says why.
func TestStreamCarrierEndsWhenTheClientsSideCloses(t *testing.T) {
	client, _, done := newCarriedSession(t, testServices(false))
	_ = client.send.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}
