package tunnel_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
	"github.com/netdefense-io/ndagent/connect/internal/tunneltest"
)

// A device whose network lets no UDP out still gets a session, all of it
// through the relay. The library looks at the network before its first
// connection to the relay, and with no answer to its UDP probes that look
// takes seconds longer: Start must wait it out, inside the companion's own
// wait of eight seconds, and must not return before the relay holds the
// connection.
func TestStartWaitsOutANetworkWithoutUDP(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	region := relay.Region.Clone()
	region.Nodes[0].STUNPort = tunneltest.UnusedPort(t) // nothing answers the UDP probes

	e := newEndpoint(region)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	began := time.Now()
	srv, err := tunnel.Start(ctx, e.config())
	if err != nil {
		t.Fatalf("Start on a network without UDP: %v (after %v)", err, time.Since(began).Round(time.Millisecond))
	}
	e.srv = srv
	t.Cleanup(srv.Close)
	t.Logf("the relay accepted the connection %v after the start, with no answer to the UDP probes", time.Since(began).Round(time.Millisecond))
	if !relay.Connected(e.serverKey.Public()) {
		t.Fatal("Start returned and the relay holds no connection from the server yet")
	}

	// The session works, relayed: the client is on the same kind of network.
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		conn, err := srv.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()
	peerConn, err := e.peer(t).DialTCPPort(dialCtx, servedPort)
	if err != nil {
		t.Fatalf("the client cannot connect through the relay: %v", err)
	}
	if _, err := peerConn.Write([]byte("relayed")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 7)
	_ = peerConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(peerConn, got); err != nil || string(got) != "relayed" {
		t.Fatalf("read %q, %v through the relay", got, err)
	}
	peerConn.Close()
	<-accepted
}
