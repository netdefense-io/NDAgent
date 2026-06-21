package pathfinder

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// ServiceName constants for the stream service identifiers the proxy routes.
const (
	ServiceWebadmin = "webadmin"
	ServiceSSH      = "ssh"
	ServiceShell    = "shell"
	ServiceShellCtl = "shell-ctl"
	ServiceExec     = "exec"
)

// ServiceConfig defines a service that can be proxied.
type ServiceConfig struct {
	Name      string // Service name (e.g., "ssh", "webadmin")
	LocalHost string // Local host (default: "127.0.0.1")
	LocalPort int    // Local port to connect to
}

// TCPProxy routes streams to local TCP services.
type TCPProxy struct {
	ctx          context.Context // connect-session context; used by exec streams
	services     map[string]ServiceConfig
	shellManager *ShellManager
	execManager  *ExecManager
	httpProxy    *HTTPProxy
	readOnly     bool // when true, only the webadmin service is proxied; all shell/exec/ssh streams are refused
	mu           sync.RWMutex

	log *zap.SugaredLogger
}

// ProxyConfig contains configuration options for the TCP proxy.
type ProxyConfig struct {
	Shell              string // Shell path for remote sessions (default: opnsense-shell)
	WebadminUser       string // Username for webadmin sessions (default: root)
	WebadminSessionDir string // PHP session directory (default: /var/lib/php/sessions)
	WebadminPort       int    // Webadmin port (default: 443)

	// ReadOnly gates the tunnel to webadmin-only. When true, the proxy
	// refuses every shell/shell-ctl/exec/ssh (and any other) stream and
	// proxies only the read-only webadmin HTTP service. This is the
	// server-side enforcement of read-only sessions: it holds regardless
	// of which stream/service the (possibly modified) client requests, so
	// an RO caller can never obtain a terminal/shell.
	ReadOnly bool
}

// NewTCPProxy creates a new TCP proxy.
// shell is the path to the shell to use for remote sessions; if empty, defaults to opnsense-shell.
func NewTCPProxy(shell string) *TCPProxy {
	return NewTCPProxyWithConfig(ProxyConfig{Shell: shell})
}

// NewTCPProxyWithConfig creates a new TCP proxy with full configuration options.
func NewTCPProxyWithConfig(cfg ProxyConfig) *TCPProxy {
	port := cfg.WebadminPort
	if port == 0 {
		port = 443
	}
	sessionMgr := NewSessionManager(cfg.WebadminUser, cfg.WebadminSessionDir)
	httpProxy := NewHTTPProxy("127.0.0.1", port, sessionMgr)

	return &TCPProxy{
		ctx:          context.Background(),
		services:     make(map[string]ServiceConfig),
		shellManager: NewShellManager(cfg.Shell),
		execManager:  NewExecManager(),
		httpProxy:    httpProxy,
		readOnly:     cfg.ReadOnly,
		log:          logging.Named("pathfinder.proxy"),
	}
}

// SetContext sets the context used for exec streams. Should be called once with
// the connect-session context before any streams are routed.
func (p *TCPProxy) SetContext(ctx context.Context) {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
}

// AddService registers a service for proxying.
func (p *TCPProxy) AddService(config ServiceConfig) {
	if config.LocalHost == "" {
		config.LocalHost = "127.0.0.1"
	}

	p.mu.Lock()
	p.services[config.Name] = config
	p.mu.Unlock()

	p.log.Debugw("Registered service",
		"name", config.Name,
		"local_host", config.LocalHost,
		"local_port", config.LocalPort,
	)
}

// GetService returns the configuration for a service.
func (p *TCPProxy) GetService(name string) (ServiceConfig, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	config, ok := p.services[name]
	return config, ok
}

// ProxyStreamToLocal connects a stream to a local service.
func (p *TCPProxy) ProxyStreamToLocal(stream *Stream) error {
	serviceName := stream.ServiceName()

	// Read-only enforcement chokepoint. Every stream — whatever service the
	// client names — passes through here. In a read-only session only the
	// webadmin HTTP service (constrained by the forged read-only OPNsense
	// ACL) is permitted; shell, shell-ctl, exec, ssh, and any other service
	// are refused. This is the server-side guarantee that an RO caller can
	// never obtain a terminal/root shell, independent of a modified client.
	if p.readOnly && serviceName != ServiceWebadmin {
		p.log.Warnw("Refusing non-webadmin stream in read-only session",
			"stream_id", stream.ID(),
			"service", serviceName,
		)
		return fmt.Errorf("service %q not permitted in read-only session", serviceName)
	}

	// Handle special services
	switch serviceName {
	case ServiceShell:
		return p.shellManager.HandleShellStream(stream)
	case ServiceShellCtl:
		return p.shellManager.HandleShellCtlStream(stream)
	case ServiceWebadmin:
		// Use HTTP proxy for webadmin with session injection
		return p.httpProxy.HandleStream(stream)
	case ServiceExec:
		// Persistent exec stream: one connection, many serialised commands.
		// The stream stays open until the client closes it.
		p.mu.RLock()
		ctx := p.ctx
		p.mu.RUnlock()
		go p.execManager.HandleExecStream(ctx, stream)
		return nil
	}

	p.mu.RLock()
	config, ok := p.services[serviceName]
	p.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown service: %s", serviceName)
	}

	addr := fmt.Sprintf("%s:%d", config.LocalHost, config.LocalPort)

	p.log.Debugw("Proxying stream to local service",
		"stream_id", stream.ID(),
		"service", serviceName,
		"addr", addr,
	)

	// Connect to local service
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	// Start bidirectional copy
	go p.proxyBidirectional(stream, conn, serviceName)

	return nil
}

// proxyBidirectional copies data bidirectionally between stream and connection.
func (p *TCPProxy) proxyBidirectional(stream *Stream, conn net.Conn, serviceName string) {
	defer conn.Close()
	defer stream.Close()

	log := p.log.With(
		"stream_id", stream.ID(),
		"service", serviceName,
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from stream to local connection
	go func() {
		defer wg.Done()
		n, err := io.Copy(conn, stream)
		if err != nil && !stream.IsClosed() {
			log.Debugw("Stream to local copy ended", "bytes", n, "error", err)
		} else {
			log.Debugw("Stream to local copy ended", "bytes", n)
		}
		// Close the write side of the connection to signal EOF
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Copy from local connection to stream
	go func() {
		defer wg.Done()
		n, err := io.Copy(stream, conn)
		if err != nil && !stream.IsClosed() {
			log.Debugw("Local to stream copy ended", "bytes", n, "error", err)
		} else {
			log.Debugw("Local to stream copy ended", "bytes", n)
		}
	}()

	wg.Wait()
	log.Debugw("Proxy session ended")
}

// DefaultOPNsenseServices returns the default services for OPNsense.
func DefaultOPNsenseServices(webadminPort int) []ServiceConfig {
	if webadminPort == 0 {
		webadminPort = 443
	}
	return []ServiceConfig{
		{Name: ServiceSSH, LocalHost: "127.0.0.1", LocalPort: 22},
		{Name: ServiceWebadmin, LocalHost: "127.0.0.1", LocalPort: webadminPort},
	}
}

// ReadOnlyOPNsenseServices returns the services offered in a read-only
// session: webadmin only. The ssh service is deliberately omitted so the
// shell is not even advertised. (The ProxyStreamToLocal chokepoint is the
// authoritative guard; this is defense-in-depth.)
func ReadOnlyOPNsenseServices(webadminPort int) []ServiceConfig {
	if webadminPort == 0 {
		webadminPort = 443
	}
	return []ServiceConfig{
		{Name: ServiceWebadmin, LocalHost: "127.0.0.1", LocalPort: webadminPort},
	}
}

// CloseAll closes all shell sessions, HTTP proxy sessions, and pending streams.
func (p *TCPProxy) CloseAll() {
	p.shellManager.CloseAll()
	p.execManager.CloseAll()
	p.httpProxy.Close()
}
