package pathfinder

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// newTestStream builds a minimal Stream carrying just a service name — enough
// to exercise ProxyStreamToLocal's read-only gate, which decides purely on the
// service name before touching any stream I/O.
func newTestStream(service string) *Stream {
	return &Stream{
		id:          1,
		serviceName: service,
		log:         zap.NewNop().Sugar(),
	}
}

// TestReadOnlyProxyRefusesNonWebadmin is the core security assertion: in a
// read-only session, every shell/ssh/exec stream is refused by the proxy
// chokepoint regardless of what the client requested. A modified client that
// opens an "ssh" or "shell" stream must NOT get a terminal.
func TestReadOnlyProxyRefusesNonWebadmin(t *testing.T) {
	forbidden := []string{
		ServiceSSH,
		ServiceShell,
		ServiceShellCtl,
		ServiceExec,
		"arbitrary-service",
		"", // empty service name
	}

	proxy := NewTCPProxyWithConfig(ProxyConfig{ReadOnly: true})
	// Even if the ssh service were somehow registered, the gate must still win.
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 22})

	for _, svc := range forbidden {
		t.Run("refuse_"+svc, func(t *testing.T) {
			err := proxy.ProxyStreamToLocal(newTestStream(svc))
			if err == nil {
				t.Fatalf("read-only proxy must refuse service %q, got nil error (terminal would be exposed)", svc)
			}
			if !strings.Contains(err.Error(), "not permitted in read-only session") {
				t.Fatalf("service %q refused with unexpected error: %v", svc, err)
			}
		})
	}
}

// TestNonReadOnlyProxyDoesNotGate confirms the gate is read-only-only: a normal
// (RW/SU) session does NOT get the read-only refusal for shell/ssh — those
// proceed to their handlers (and fail later for unrelated reasons in this
// unit test, e.g. dial failure), proving we didn't regress the admin path.
func TestNonReadOnlyProxyDoesNotGate(t *testing.T) {
	proxy := NewTCPProxyWithConfig(ProxyConfig{ReadOnly: false})
	proxy.AddService(ServiceConfig{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 1}) // unlikely port

	err := proxy.ProxyStreamToLocal(newTestStream(ServiceSSH))
	// We don't require success (no sshd on :1 in CI) — we require that whatever
	// happened was NOT the read-only refusal.
	if err != nil && strings.Contains(err.Error(), "not permitted in read-only session") {
		t.Fatalf("non-read-only session wrongly gated ssh as read-only: %v", err)
	}
}

// TestReadOnlyServiceSetIsWebadminOnly guards the advertised service set.
func TestReadOnlyServiceSetIsWebadminOnly(t *testing.T) {
	svcs := ReadOnlyOPNsenseServices(8443)
	if len(svcs) != 1 || svcs[0].Name != ServiceWebadmin {
		t.Fatalf("read-only service set must be webadmin-only, got %+v", svcs)
	}
	for _, s := range svcs {
		if s.Name == ServiceSSH {
			t.Fatalf("read-only service set must not advertise ssh")
		}
	}

	// Sanity: the default (non-RO) set still includes both ssh and webadmin.
	def := DefaultOPNsenseServices(8443)
	var hasSSH, hasWeb bool
	for _, s := range def {
		if s.Name == ServiceSSH {
			hasSSH = true
		}
		if s.Name == ServiceWebadmin {
			hasWeb = true
		}
	}
	if !hasSSH || !hasWeb {
		t.Fatalf("default service set must include ssh and webadmin, got %+v", def)
	}
}
