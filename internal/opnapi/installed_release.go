package opnapi

// installed_release.go — which OPNsense release is installed on this device.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/util"
)

const opnsenseVersionCommand = "/usr/local/sbin/opnsense-version"

var (
	versionFilePath = "/usr/local/opnsense/version/core"

	// opnsenseVersionTimeout bounds one run of opnsense-version.
	opnsenseVersionTimeout = 5 * time.Second

	// commandOutput runs a prepared command and returns its stdout; tests
	// replace it to inspect the command instead of running it.
	commandOutput = func(cmd *exec.Cmd) ([]byte, error) { return cmd.Output() }
)

// InstalledRelease reads the OPNsense release installed on this device. The
// first of these sources that yields a release wins:
//
//  1. /usr/local/opnsense/version/core, the JSON file the core package ships
//  2. `opnsense-version -n -v`, OPNsense's own reader of that file
//  3. GET /core/firmware/status, its `product` block
//
// The first two need no API credentials and no running web server, so they
// still answer while lighttpd or configd restart during an update. A nil
// *Client, which is what a device without API credentials has, is therefore a
// valid receiver: its third source fails and the error says so.
//
// The `product` block is built from that same file on every request; the
// top-level `product_version` of /status is not read, because it is the cached
// result of the last firmware check: stale after an update, absent after every
// flush.
//
// /core/firmware/info is deliberately not a source. Each call makes OPNsense
// run `pkg update` twice, and its ~350 KB reply is the response most exposed to
// the corruption described in read_retry.go.
//
// Nothing is cached: the release changes when the device is updated, so every
// call reads the current one. When every source fails the error names each
// failure.
func (c *Client) InstalledRelease(ctx context.Context) (ProductRelease, error) {
	sources := []struct {
		name string
		read func(context.Context) (ProductRelease, error)
	}{
		{"version file", readReleaseFile},
		{"opnsense-version", readReleaseCommand},
		{"firmware status", c.readReleaseStatus},
	}

	failures := make([]string, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return ProductRelease{}, err
		}
		release, err := source.read(ctx)
		if err == nil {
			if c != nil {
				c.log.Debugw("Installed release read", "source", source.name, "version", release.Raw)
			}
			return release, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", source.name, err))
	}

	if err := ctx.Err(); err != nil {
		return ProductRelease{}, err
	}
	return ProductRelease{}, fmt.Errorf("could not read the installed release (%s)", strings.Join(failures, "; "))
}

// InstalledReleaseFromFile reads the installed release from the version file
// alone: no command and no API call, so it can sit on a path that must not
// wait, such as the WebSocket connect.
func InstalledReleaseFromFile() (ProductRelease, error) {
	return readReleaseFile(context.Background())
}

func readReleaseFile(context.Context) (ProductRelease, error) {
	data, err := os.ReadFile(versionFilePath)
	if err != nil {
		return ProductRelease{}, err
	}

	var meta struct {
		ProductVersion string `json:"product_version"`
		ProductSeries  string `json:"product_series"`
		ProductID      string `json:"product_id"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return ProductRelease{}, fmt.Errorf("decode %s: %w", versionFilePath, err)
	}
	return releaseOf(meta.ProductVersion, meta.ProductSeries, meta.ProductID)
}

func readReleaseCommand(ctx context.Context) (ProductRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, opnsenseVersionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, opnsenseVersionCommand, "-n", "-v")
	cmd.Env = util.DeviceExecEnv()
	cmd.WaitDelay = time.Second

	out, err := commandOutput(cmd)
	if err != nil {
		return ProductRelease{}, err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	// It prints the fields asked for in that order, the package name first;
	// an empty name leaves the version alone.
	switch fields := strings.Fields(line); len(fields) {
	case 1:
		return releaseOf(fields[0], "", "")
	case 2:
		return releaseOf(fields[1], "", fields[0])
	default:
		return ProductRelease{}, fmt.Errorf("unexpected output %q", line)
	}
}

func (c *Client) readReleaseStatus(ctx context.Context) (ProductRelease, error) {
	if c == nil {
		return ProductRelease{}, errors.New("no API client")
	}

	body, err := c.doRequest(ctx, "GET", "/core/firmware/status", nil)
	if err != nil {
		return ProductRelease{}, err
	}

	var raw struct {
		Product struct {
			Version  string `json:"product_version"`
			Series   string `json:"product_series"`
			ID       string `json:"product_id"`
			CoreName string `json:"CORE_NAME"`
		} `json:"product"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ProductRelease{}, fmt.Errorf("decode: %w", err)
	}
	product := raw.Product.ID
	if strings.TrimSpace(product) == "" {
		product = raw.Product.CoreName
	}
	return releaseOf(raw.Product.Version, raw.Product.Series, product)
}

// releaseOf is releaseFromFields with the core package's name. The name comes
// from the source that gave the release: a version file without product_id
// leaves it empty, and no later source is asked for it.
func releaseOf(version, series, product string) (ProductRelease, error) {
	release, err := releaseFromFields(version, series)
	if err != nil {
		return ProductRelease{}, err
	}
	release.Product = strings.TrimSpace(product)
	return release, nil
}

// releaseFromFields prefers the full version and falls back to the series. A
// series carries no patch, so it reads as that series' first release: on the
// 26.1 series the floor is judged on a patch and this reads as below it, which is
// why the series is only a fallback for a version that is absent. A version that
// is present but unparseable is an error, never a reason to guess from the
// series: callers must be able to tell "below the floor" from "could not tell".
func releaseFromFields(version, series string) (ProductRelease, error) {
	candidate := strings.TrimSpace(version)
	if candidate == "" {
		candidate = strings.TrimSpace(series)
	}
	if candidate == "" {
		return ProductRelease{}, errors.New("no product version")
	}
	return ParseProductRelease(candidate)
}
