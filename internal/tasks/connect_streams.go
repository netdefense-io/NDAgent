package tasks

import (
	"context"
	"errors"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// streamServiceConfig is what a remote access session serves and as whom,
// whichever transport carries its frames.
type streamServiceConfig struct {
	shell              string
	webadminUser       string
	webadminSessionDir string
	webadminPort       int
	readOnly           bool
	policy             config.RemoteAccessPolicy
}

// serveStreams serves the streams a client opens over conn. ctx is the
// session's: exec streams take their timeouts and cancellation from it.
//
// A session's lifetime is its connection's, NOT its open-stream count. Nothing
// here cancels when the streams drop to zero: webadmin rides one short-lived
// stream per HTTP request, so the count legitimately returns to zero between
// requests and after a terminal stream closes. Tearing down then would kill
// the webadmin tunnel mid-session (and made read-only, terminal-less sessions
// unusable). The caller ends the session when its connection ends, and then
// calls CloseAll on both values, which destroys the forged PHP session.
func serveStreams(ctx context.Context, conn pathfinder.FrameConn, cfg streamServiceConfig) (*pathfinder.StreamManager, *pathfinder.TCPProxy) {
	log := logging.Named("CONNECT")

	streamMgr := pathfinder.NewStreamManager(conn)
	proxy := pathfinder.NewTCPProxyWithConfig(pathfinder.ProxyConfig{
		Shell:              cfg.shell,
		WebadminUser:       cfg.webadminUser,
		WebadminSessionDir: cfg.webadminSessionDir,
		WebadminPort:       cfg.webadminPort,
		ReadOnly:           cfg.readOnly,
		Policy:             cfg.policy,
	})
	proxy.SetContext(ctx)

	// Read-only sessions get webadmin only: the ssh service is not even
	// advertised. The proxy's ProxyStreamToLocal chokepoint is the
	// authoritative guard; this keeps the offered set honest.
	services := pathfinder.DefaultOPNsenseServices(cfg.webadminPort)
	if cfg.readOnly {
		services = pathfinder.ReadOnlyOPNsenseServices(cfg.webadminPort)
	}
	for _, svc := range services {
		proxy.AddService(svc)
	}

	streamMgr.OnNewStream(func(stream *pathfinder.Stream) {
		log.Debugw("New stream opened",
			"stream_id", stream.ID(),
			"service", stream.ServiceName(),
		)

		if err := proxy.ProxyStreamToLocal(stream); err != nil {
			log.Errorw("Failed to proxy stream",
				"stream_id", stream.ID(),
				"service", stream.ServiceName(),
				"error", err,
			)
			stream.Close()
		}
	})
	return streamMgr, proxy
}

// streamCarrier carries a direct-peer session: the session's frames over the
// companion's pipes, and the same stream services the websocket relay serves.
type streamCarrier struct {
	conn      *pathfinder.StreamConn
	streamMgr *pathfinder.StreamManager
	proxy     *pathfinder.TCPProxy
	cancel    context.CancelFunc
}

func newStreamCarrier(sess *directpeer.Session, cfg streamServiceConfig) *streamCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	conn := pathfinder.NewStreamConn(sess.FromPeer, sess.ToPeer)
	streamMgr, proxy := serveStreams(ctx, conn, cfg)
	return &streamCarrier{conn: conn, streamMgr: streamMgr, proxy: proxy, cancel: cancel}
}

func (c *streamCarrier) Run(ctx context.Context, connected <-chan struct{}) error {
	err := c.conn.Run(ctx, connected)
	if errors.Is(err, pathfinder.ErrPeerSilent) {
		return directpeer.ErrClientSilent
	}
	return err
}

func (c *streamCarrier) LastActivity() time.Time { return c.conn.LastActivity() }

// Close ends the streams first, so each one's close reaches the client, then
// the connection.
func (c *streamCarrier) Close() {
	c.streamMgr.CloseAll()
	c.proxy.CloseAll()
	c.cancel()
	_ = c.conn.Close()
}
