package main

import (
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/config"
)

// logControlPlaneTrust logs what the control-plane connections verify the
// server against, and every setting that is set and has no effect.
func logControlPlaneTrust(log *zap.SugaredLogger, cfg *config.Config) {
	switch {
	case cfg.TLSError != nil:
		log.Errorw("TLS Mode cannot be used: every connection to NetDefense is refused until it is fixed (NetDefense settings, Advanced, Control Plane)",
			"tls_mode", string(cfg.TLSMode),
			"error", cfg.TLSError,
		)
	case cfg.TLSMode == config.TLSModeSystem:
		if cfg.ExtraCAError != nil {
			log.Errorw("extra_ca_file could not be used; the control-plane connections trust the built-in roots only",
				"extra_ca_file", cfg.ExtraCAFile,
				"error", cfg.ExtraCAError,
			)
		}
		for _, ca := range cfg.ExtraCAs {
			log.Infow("extra_ca_file adds a CA to the control-plane roots",
				"extra_ca_file", cfg.ExtraCAFile,
				"subject", ca.Subject,
				"sha256", ca.SHA256,
				"not_after", ca.NotAfter.UTC().Format(time.RFC3339),
			)
		}
	case cfg.TLSMode == config.TLSModeCustomCA:
		for _, ca := range cfg.TLSCAs {
			log.Infow("TLS Mode custom_ca: the connections to NetDefense trust only the CAs of tls_ca_file",
				"tls_ca_file", cfg.TLSCAFile,
				"subject", ca.Subject,
				"sha256", ca.SHA256,
				"not_after", ca.NotAfter.UTC().Format(time.RFC3339),
			)
		}
	case cfg.TLSMode == config.TLSModeSPKIPinned:
		log.Infow("TLS Mode spki_pinned: the connections to NetDefense trust only the server keys tls_spki_hashes lists",
			"tls_spki_hashes", cfg.TLSSPKIHashes,
		)
	}
	if relay := relayHost(cfg.PathfinderHost); cfg.TLSError == nil && relay != "" && relay != cfg.ServerHost {
		switch cfg.TLSMode {
		case config.TLSModeCustomCA:
			log.Infow("TLS Mode custom_ca covers the relay too: the CA that issued the relay's certificate must be in tls_ca_file as well, or remote sessions fail",
				"server_host", cfg.ServerHost, "relay_host", relay)
		case config.TLSModeSPKIPinned:
			log.Infow("TLS Mode spki_pinned covers the relay too: the relay's key must be in tls_spki_hashes as well, or remote sessions fail",
				"server_host", cfg.ServerHost, "relay_host", relay)
		}
	}
	if cfg.ExtraCAFileIgnored() {
		log.Warnw("extra_ca_file is set and ignored: only TLS Mode system reads it",
			"tls_mode", string(cfg.TLSMode),
			"extra_ca_file", cfg.ExtraCAFile,
		)
	}
	if keys := cfg.IgnoredVerifyKeys(); len(keys) > 0 {
		log.Warnw(cfg.IgnoredVerifyNotice(), "ignored", keys)
	}
}

// relayHost is the host name of pathfinder_host, which may be a URL or a bare
// host.
func relayHost(pathfinderHost string) string {
	raw := strings.TrimSpace(pathfinderHost)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
