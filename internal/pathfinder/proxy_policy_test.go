package pathfinder

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ndconfig "github.com/netdefense-io/ndagent/internal/config"
)

// The device-local remote-access ceiling has two enforcement points:
// HandleConnect (internal/tasks/connect.go), which refuses or clamps before
// a relay is dialed, and this proxy's per-stream chokepoint. These tests
// cover the second one specifically — deliberately constructing proxies
// WITHOUT going through HandleConnect, because the entire reason the second
// gate exists is that the guarantee must not depend on the first one having
// run. If these tests are ever "simplified" by routing through the connect
// handler, they stop testing the property they exist to protect.

// TestPolicyDisabledRefusesEveryService is the strongest assertion in this
// file: under a "disabled" ceiling, NOTHING is served — including webadmin,
// which the read-only gate deliberately permits. A device whose owner turned
// remote access off must not serve a web UI stream either.
func TestPolicyDisabledRefusesEveryService(t *testing.T) {
	services := []string{
		ServiceWebadmin, // the one the read-only gate lets through
		ServiceSSH,
		ServiceShell,
		ServiceShellCtl,
		ServiceExec,
		"arbitrary-service",
		"",
	}

	proxy := NewTCPProxyWithConfig(ProxyConfig{Policy: ndconfig.RemoteAccessDisabled})
	// Register the services anyway — the ceiling must win over registration.
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 22})
	proxy.AddService(ServiceConfig{Name: ServiceWebadmin, LocalHost: "127.0.0.1", LocalPort: 443})

	for _, svc := range services {
		t.Run("refuse_"+svc, func(t *testing.T) {
			err := proxy.ProxyStreamToLocal(newTestStream(svc))
			if err == nil {
				t.Fatalf("disabled policy must refuse service %q, got nil error", svc)
			}
			if !strings.Contains(err.Error(), "remote access is disabled on this device") {
				t.Fatalf("service %q refused with unexpected error: %v", svc, err)
			}
		})
	}
}

// TestPolicyReadOnlyRefusesShellWithoutClamp is the independence test. It
// constructs a proxy with the "readonly" ceiling but ReadOnly deliberately
// left false — simulating a caller that forgot to clamp. The chokepoint must
// still refuse a shell, because the ceiling is enforced where the stream is
// served, not only where it was requested.
func TestPolicyReadOnlyRefusesShellWithoutClamp(t *testing.T) {
	forbidden := []string{ServiceSSH, ServiceShell, ServiceShellCtl, ServiceExec}

	proxy := NewTCPProxyWithConfig(ProxyConfig{
		Policy:   ndconfig.RemoteAccessReadOnly,
		ReadOnly: false, // the clamp HandleConnect would normally apply is absent
	})
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 22})

	for _, svc := range forbidden {
		t.Run("refuse_"+svc, func(t *testing.T) {
			err := proxy.ProxyStreamToLocal(newTestStream(svc))
			if err == nil {
				t.Fatalf("readonly ceiling must refuse service %q even without the clamp, got nil error", svc)
			}
			if !strings.Contains(err.Error(), "not permitted in read-only session") {
				t.Fatalf("service %q refused with unexpected error: %v", svc, err)
			}
		})
	}
}

// TestPolicyReadOnlyRefusesExecStream calls out the MCP console path
// explicitly. The AI-facing ndcli.device.console_exec tool drives the "exec"
// stream (no PTY), which diverges from the interactive shell only AFTER this
// chokepoint. A regression that gated `shell` but not `exec` would leave an
// AI agent with a root shell on a device whose owner asked for read-only.
func TestPolicyReadOnlyRefusesExecStream(t *testing.T) {
	proxy := NewTCPProxyWithConfig(ProxyConfig{Policy: ndconfig.RemoteAccessReadOnly})

	err := proxy.ProxyStreamToLocal(newTestStream(ServiceExec))
	if err == nil {
		t.Fatal("readonly ceiling must refuse the exec stream (the MCP console path), got nil error")
	}
	if !strings.Contains(err.Error(), "not permitted in read-only session") {
		t.Fatalf("exec stream refused with unexpected error: %v", err)
	}
}

// TestPolicyFullDoesNotGate confirms the ceiling is opt-in: the default
// policy must not regress the normal admin path. This is the counterpart to
// the config-level default test — together they pin that an existing fleet
// upgrading to a build with the ceiling keeps working unchanged.
func TestPolicyFullDoesNotGate(t *testing.T) {
	proxy := NewTCPProxyWithConfig(ProxyConfig{Policy: ndconfig.RemoteAccessFull})
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 1})

	err := proxy.ProxyStreamToLocal(newTestStream(ServiceSSH))
	// Success isn't required (nothing listens on :1 in CI) — only that the
	// failure, if any, wasn't one of the ceiling refusals.
	if err != nil {
		if strings.Contains(err.Error(), "remote access is disabled") ||
			strings.Contains(err.Error(), "not permitted in read-only session") {
			t.Fatalf("full policy wrongly gated ssh: %v", err)
		}
	}
}

// TestZeroPolicyDoesNotGate pins the backward-compatibility contract stated
// on ProxyConfig.Policy: the zero value is not a valid policy and must be
// treated as unrestricted, so callers predating the ceiling (NewTCPProxy,
// existing tests) are unaffected. The agent never relies on this — config
// validation and GetRemoteAccessPolicy both guarantee a concrete value
// reaches production — but a silent behavior change for other callers would
// be a nasty surprise.
func TestZeroPolicyDoesNotGate(t *testing.T) {
	proxy := NewTCPProxy("/bin/sh")
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 1})

	err := proxy.ProxyStreamToLocal(newTestStream(ServiceSSH))
	if err != nil {
		if strings.Contains(err.Error(), "remote access is disabled") ||
			strings.Contains(err.Error(), "not permitted in read-only session") {
			t.Fatalf("zero-value policy wrongly gated ssh: %v", err)
		}
	}
}

// TestPolicyReadOnlyGatesWebadminRequestsWithoutClamp is the same independence test
// for the request denylist and the secret scrubber inside the webadmin stream: under
// a "readonly" ceiling they apply although ReadOnly was left false, so they do not
// depend on one caller having remembered to clamp either. The stream goes through
// ProxyStreamToLocal, as a real one does.
func TestPolicyReadOnlyGatesWebadminRequestsWithoutClamp(t *testing.T) {
	ts, hits := newSentinelBackend("acted")
	defer ts.Close()

	for _, tt := range []struct {
		name string
		cfg  ProxyConfig
		want bool
	}{
		{"ceiling readonly, not clamped", ProxyConfig{Policy: ndconfig.RemoteAccessReadOnly}, true},
		{"read-only session", ProxyConfig{ReadOnly: true}, true},
		{"both", ProxyConfig{Policy: ndconfig.RemoteAccessReadOnly, ReadOnly: true}, true},
		{"full", ProxyConfig{Policy: ndconfig.RemoteAccessFull}, false},
		{"no policy", ProxyConfig{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.WebadminSessionDir = t.TempDir()
			proxy := NewTCPProxyWithConfig(tt.cfg)
			if proxy.httpProxy.readOnly != tt.want {
				t.Fatalf("the webadmin proxy's read-only gate = %v, want %v", proxy.httpProxy.readOnly, tt.want)
			}
		})
	}

	proxy := NewTCPProxyWithConfig(ProxyConfig{Policy: ndconfig.RemoteAccessReadOnly, WebadminSessionDir: t.TempDir()})
	u := strings.TrimPrefix(ts.URL, "https://")
	host, port, _ := strings.Cut(u, ":")
	proxy.httpProxy.localHost = host
	fmt.Sscanf(port, "%d", &proxy.httpProxy.localPort)

	var requests []streamRequest
	for _, raw := range []string{
		rawRequest("POST", "/api/core/service/restart/openvpn", "", ""),
		rawRequest("GET", "/api/trust/ca/del/"+certUUID, "", ""),
		rawRequest("POST", "/api/trust/cert/generate_file/"+certUUID+"/prv", "", ""),
	} {
		requests = append(requests, streamRequest{raw, refused})
	}
	runs := make([]struct {
		stream *Stream
		cap    *handleStreamCapture
		done   chan error
	}, len(requests))
	for i, request := range requests {
		stream, cap := newHandleStreamTestStream()
		stream.serviceName = ServiceWebadmin
		done := make(chan error, 1)
		go func() { done <- proxy.ProxyStreamToLocal(stream) }()
		runs[i].stream, runs[i].cap, runs[i].done = stream, cap, done
		stream.readBuf <- []byte(request.raw)
	}
	for i, request := range requests {
		resp := waitForHandleStreamResponse(t, runs[i].cap)
		if resp.StatusCode != request.want {
			t.Errorf("%q: status = %d, want %d", strings.SplitN(request.raw, "\r\n", 2)[0], resp.StatusCode, request.want)
		}
	}
	waitNeverHit(t, 500*time.Millisecond, hits)
	for i := range runs {
		closeHandleStreamTestStream(runs[i].stream)
		<-runs[i].done
	}

	// The scrubber is on under the same ceiling: the secret in a response is blanked.
	secretBackend, _ := newSentinelBackend(userGetBody)
	defer secretBackend.Close()
	scrubbing := NewTCPProxyWithConfig(ProxyConfig{Policy: ndconfig.RemoteAccessReadOnly, WebadminSessionDir: t.TempDir()})
	host, port, _ = strings.Cut(strings.TrimPrefix(secretBackend.URL, "https://"), ":")
	scrubbing.httpProxy.localHost = host
	fmt.Sscanf(port, "%d", &scrubbing.httpProxy.localPort)
	stream, cap := newHandleStreamTestStream()
	stream.serviceName = ServiceWebadmin
	done := make(chan error, 1)
	go func() { done <- scrubbing.ProxyStreamToLocal(stream) }()
	stream.readBuf <- []byte(rawRequest("GET", "/api/auth/user/get/u1", "", ""))
	resp := waitForHandleStreamResponse(t, cap)
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusOK || string(body) != userGetCleaned {
		t.Errorf("under a readonly ceiling that was not clamped, the response was %d %s, want 200 %s", resp.StatusCode, body, userGetCleaned)
	}
	closeHandleStreamTestStream(stream)
	<-done
}
