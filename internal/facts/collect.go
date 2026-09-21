package facts

import (
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
)

// OPNsenseVersionProvider returns the installed OPNsense version, or the
// empty string when it isn't known yet. The heavy-telemetry collector
// already fetches this every 15 min, so the agent reuses its cache rather
// than making a REST call of its own; before that collector's first
// refresh (or on agents without OPNsense API credentials) the opnsense
// sub-object is simply omitted.
type OPNsenseVersionProvider func() string

// Collector builds the facts payload. It is safe for concurrent use: the
// only mutable state is the injected provider, set once at wiring time.
type Collector struct {
	configXMLPath string
	opnsenseFn    OPNsenseVersionProvider

	// Injection points for tests. Nil means the real implementation.
	now          func() time.Time
	loadLocation func(string) (*time.Location, error)
	hostInfo     func() (platform string, version string, err error)
	hostname     func() (string, error)
}

// DefaultConfigXMLPath matches config.Load's `config_xml_path` default.
const DefaultConfigXMLPath = "/conf/config.xml"

// New returns a collector reading the given config.xml.
func New(configXMLPath string) *Collector {
	if configXMLPath == "" {
		configXMLPath = DefaultConfigXMLPath
	}
	return &Collector{configXMLPath: configXMLPath}
}

// Collect builds a facts payload from the default config.xml path with no
// OPNsense version provider wired. The agent uses the Collector form so
// the version cache and config path come from its own configuration.
func Collect() (*Facts, error) {
	return New(DefaultConfigXMLPath).Collect()
}

// SetOPNsenseVersionProvider wires the heavy-telemetry version cache.
// Safe to call at any point; nil means the sub-object stays omitted.
func (c *Collector) SetOPNsenseVersionProvider(fn OPNsenseVersionProvider) {
	c.opnsenseFn = fn
}

// Collect builds a normalized, hashed facts payload. Every probe is
// best-effort: a failure omits its sub-object and logs a WARN, and the
// error return is reserved for the case where no payload can be produced
// at all (a hash that cannot be computed, or a payload that stays over
// the contract size limit). Callers treat an error as "send nothing this
// cycle" and never fail the connect or heartbeat over it.
func (c *Collector) Collect() (*Facts, error) {
	log := logging.Named("facts")

	f := &Facts{V: Version}

	sys, err := config.ReadSystemFacts(c.configXMLPath)
	if err != nil {
		log.Warnw("Cannot read config.xml for device facts; timezone and interfaces omitted",
			"path", c.configXMLPath,
			"error", err,
		)
	} else {
		if tz := c.timezone(sys.Timezone); tz != nil {
			f.Timezone = tz
		}
		for _, iface := range sys.Interfaces {
			f.Interfaces = append(f.Interfaces, Interface{
				Role:    iface.Role,
				If:      iface.If,
				Descr:   iface.Descr,
				Enabled: iface.Enabled,
			})
		}
	}

	if c.opnsenseFn != nil {
		if version := strings.TrimSpace(c.opnsenseFn()); version != "" {
			f.OPNsense = &OPNsense{Version: version, Series: seriesOf(version)}
		}
	}

	platform, osVersion, err := c.readHostInfo()
	if err != nil {
		log.Warnw("Cannot read host info for device facts; os sub-object omitted", "error", err)
	} else if platform != "" || osVersion != "" {
		f.OS = &OS{Platform: platform, Version: osVersion}
	}

	if name, err := c.readHostname(); err != nil {
		log.Warnw("Cannot read hostname for device facts; hostname omitted", "error", err)
	} else {
		f.Hostname = name
	}

	if notes := f.Normalize(); len(notes) > 0 {
		log.Warnw("Device facts clamped to the contract bounds", "adjustments", notes)
	}
	if f.TooLarge() {
		return nil, errPayloadTooLarge
	}
	if err := f.SetHash(); err != nil {
		return nil, err
	}
	return f, nil
}

// timezone resolves the IANA name into name/offset/abbrev as of now.
// The offset is computed fresh on every collection, so a timezone change
// (or a DST transition) is reported without restarting the agent.
func (c *Collector) timezone(name string) *Timezone {
	log := logging.Named("facts")

	name = strings.TrimSpace(name)
	if name == "" {
		log.Warn("config.xml has no <system><timezone>; timezone omitted from device facts")
		return nil
	}

	loadLocation := c.loadLocation
	if loadLocation == nil {
		loadLocation = time.LoadLocation
	}
	loc, err := loadLocation(name)
	if err != nil {
		log.Warnw("Unknown timezone in config.xml; timezone omitted from device facts",
			"timezone", name,
			"error", err,
		)
		return nil
	}

	now := time.Now
	if c.now != nil {
		now = c.now
	}
	abbrev, offset := now().In(loc).Zone()
	return &Timezone{Name: name, UTCOffsetSec: offset, Abbrev: abbrev}
}

func (c *Collector) readHostInfo() (string, string, error) {
	if c.hostInfo != nil {
		return c.hostInfo()
	}
	info, err := host.Info()
	if err != nil {
		return "", "", err
	}
	return info.Platform, info.PlatformVersion, nil
}

func (c *Collector) readHostname() (string, error) {
	if c.hostname != nil {
		return c.hostname()
	}
	return os.Hostname()
}

// seriesOf derives the OPNsense series from a product version, mirroring
// the fallback in opnapi.GetFirmwareUpgradeStatus: "26.1.9" → "26.1".
func seriesOf(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}
