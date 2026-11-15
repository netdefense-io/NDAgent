// Package tunneltest runs a relay inside a test and builds the peer of a
// session, so the companion's tests reach nothing outside the process. Only
// tests import it.
package tunneltest

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"

	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
)

// RegionID is the region number the test relay is given.
const RegionID = 900

// Hermetic keeps the tunnel library off the real network in a test binary,
// which links the probes a release build leaves out: without it every engine
// start asks the default gateway for a port mapping and makes captive-portal
// requests to hosts on the internet. It also shortens the keepalive, so a
// peer that vanishes is noticed in about ten seconds. Call it from TestMain.
func Hermetic() {
	envknob.Setenv("IN_TS_TEST", "true")
	netcheck.HookStartCaptivePortalDetection.SetForTest(func(ctx context.Context, c *netcheck.Client, dm *tailcfg.DERPMap, preferredDERP tailcfg.DERPRegionID, setCaptivePortal func(bool)) (done <-chan struct{}, stop func()) {
		return syncs.ClosedChan(), func() {}
	})
	tunnel.SetKeepalive(time.Second, time.Second)
}

// Relay is a relay running inside the test.
type Relay struct {
	Region *tailcfg.DERPRegion

	relay      *derpserver.Server
	listener   *trackingListener
	admissions atomic.Int64
}

// Connected reports whether the relay holds a connection from the node with
// public key k right now.
func (r *Relay) Connected(k key.NodePublic) bool { return r.relay.IsClientConnectedForTest(k) }

// Admissions is how many times the relay asked whether a key is admitted.
func (r *Relay) Admissions() int { return int(r.admissions.Load()) }

// DropConnections cuts every connection to the relay, as its restart would.
// The relay keeps listening, so its clients can come back.
func (r *Relay) DropConnections() { r.listener.closeAccepted() }

// trackingListener remembers the connections it accepted. The relay takes its
// connections over from the HTTP server, which then no longer knows them.
type trackingListener struct {
	net.Listener

	mu       sync.Mutex
	accepted []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.accepted = append(l.accepted, conn)
		l.mu.Unlock()
	}
	return conn, err
}

func (l *trackingListener) closeAccepted() {
	l.mu.Lock()
	accepted := l.accepted
	l.accepted = nil
	l.mu.Unlock()
	for _, conn := range accepted {
		conn.Close()
	}
}

// StartRelay runs a relay on the loopback interface.
func StartRelay(t testing.TB) *Relay {
	t.Helper()
	return startRelay(t, nil)
}

// StartRefusingRelay runs a relay that asks an admission endpoint about every
// key and is told no, and that refuses when it gets no answer: what a
// production relay does with a key nobody registered.
func StartRefusingRelay(t testing.TB) *Relay {
	t.Helper()
	deny := false
	return startRelay(t, &deny)
}

func startRelay(t testing.TB, admit *bool) *Relay {
	t.Helper()
	d := derpserver.New(key.NewNode(), logger.Discard)
	r := &Relay{relay: d}
	if admit != nil {
		answer := `{"Allow":false}`
		if *admit {
			answer = `{"Allow":true}`
		}
		admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			r.admissions.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, answer)
		}))
		t.Cleanup(admission.Close)
		d.SetVerifyClientURL(admission.URL)
		d.SetVerifyClientURLFailOpen(false)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.listener = &trackingListener{Listener: ln}
	server := httptest.NewUnstartedServer(derpserver.Handler(d))
	server.Listener.Close()
	server.Listener = r.listener
	server.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	server.StartTLS()
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		r.listener.closeAccepted()
		server.Close()
		d.Close()
		stunCleanup()
		ln.Close()
	})

	r.Region = InsecureRegion("test", "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, stunAddr.Port)
	return r
}

// InsecureRegion describes a relay on the loopback interface that presents a
// test certificate. It is tunnel.NewRegion plus the three fields only a test
// relay needs, so the tests run with the region the companion builds.
func InsecureRegion(id, host string, port, stunPort int) *tailcfg.DERPRegion {
	region := tunnel.NewRegion(id, RegionID, host, port, stunPort)
	node := region.Nodes[0]
	node.IPv4 = host
	node.IPv6 = "none"
	node.InsecureForTests = true
	node.STUNTestIP = host
	return region
}

// UnusedPort returns a loopback TCP port nothing listens on.
func UnusedPort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// Peer is the other end of a session: the client that dials the served port.
type Peer struct {
	Key key.NodePrivate
	*tailcat.Client
}

// NewPeer builds a client for the server whose keys and relay are given. The
// client learns the server from the same four values a real one is handed:
// the server's node key (from which both its public key and the key used to
// find a direct path follow), the pre-shared key and the relay.
func NewPeer(t testing.TB, serverKey key.NodePrivate, psk [32]byte, region *tailcfg.DERPRegion, peerKey key.NodePrivate) *Peer {
	t.Helper()
	info := tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: serverKey.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(serverKey),
		PresharedKey:      tailcat.PresharedKey(psk),
		Region:            []*tailcfg.DERPRegion{region},
	}
	p := &Peer{Key: peerKey, Client: &tailcat.Client{Server: info.Addr(), Key: peerKey, Logf: logger.Discard}}
	t.Cleanup(func() { p.Client.Close() })
	return p
}

// NewPSK returns a random pre-shared key.
func NewPSK() [32]byte { return [32]byte(tailcat.NewPresharedKey()) }
