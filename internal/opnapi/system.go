package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// System / health probes used by the heavy telemetry collector.
//
// Three groups of fields:
//   - service running state — cheap, one GET
//   - pending firmware/package updates — async on OPNsense (POST /check, then
//     poll /status), so the collector triggers a check, sleeps, and reads
//   - certificate expiries — one POST search
//
// All return types are stable subsets of the OPNsense response so the
// caller doesn't pay for the (very large) full payload — `firmware/status`
// alone can be tens of KB when many packages are pending.

// ServiceEntry is one row from `/api/core/service/search`. `Running` is
// reported as 0/1 on the wire; this struct converts to a bool.
type ServiceEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Running     bool   `json:"running"`
}

// FirmwareStatus is the dashboard-relevant slice of `firmware/status`.
// `Status` is one of "none" (no check has been run yet), "update" (updates
// pending), "error", or "ok" (no updates). The counters are zero when the
// status field doesn't report a real result.
//
// `OPNsenseVersion` and `OPNsenseLatest` come from the response's `product`
// block (`product_version` / `product_latest`). The current version is
// present on every successful check; `OPNsenseLatest` only populates when
// the upstream pkg catalog actually has a newer release. Both are
// surfaced to the dashboard so NDManager can build a fleet distribution.
type FirmwareStatus struct {
	Status          string `json:"status"`
	StatusMsg       string `json:"status_msg"`
	LastCheck       string `json:"last_check"`
	UpgradeCount    int    `json:"upgrade_count"`
	NewCount        int    `json:"new_count"`
	ReinstallCount  int    `json:"reinstall_count"`
	RemoveCount     int    `json:"remove_count"`
	NeedsReboot     bool   `json:"needs_reboot"`
	Connection      string `json:"connection"`
	Repository      string `json:"repository"`
	OPNsenseVersion string `json:"opnsense_version,omitempty"`
	OPNsenseLatest  string `json:"opnsense_latest,omitempty"`
}

// CertEntry is one row from `/api/trust/cert/search`, trimmed to what the
// dashboard renders. `ValidTo` is the agent-parseable timestamp string;
// the broker / NDManager treat it opaquely and the agent computes
// `DaysLeft` so we don't ship the cert payload itself.
type CertEntry struct {
	Description string `json:"description"`
	DaysLeft    int    `json:"days_left"`
	ValidTo     string `json:"valid_to"`
	InUse       bool   `json:"in_use,omitempty"`
}

// ListServices returns all services known to OPNsense. The full list is
// always ≤ a few dozen rows; the collector filters/maps as it pleases.
func (c *Client) ListServices(ctx context.Context) ([]ServiceEntry, error) {
	body, err := c.doRequest(ctx, "GET", "/core/service/search", nil)
	if err != nil {
		return nil, fmt.Errorf("service search: %w", err)
	}
	var resp struct {
		Rows []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Running     int    `json:"running"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("service search decode: %w", err)
	}
	out := make([]ServiceEntry, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		out = append(out, ServiceEntry{
			Name:        r.Name,
			Description: r.Description,
			Running:     r.Running == 1,
		})
	}
	return out, nil
}

// TriggerFirmwareCheck kicks off an async check. OPNsense returns
// immediately with `{msg_uuid, status:"ok"}`; the actual catalog
// refresh runs in the background. The caller must wait
// (recommended: ~30 s) before reading `FirmwareStatus`.
func (c *Client) TriggerFirmwareCheck(ctx context.Context) error {
	_, err := c.doRequest(ctx, "POST", "/core/firmware/check", nil)
	if err != nil {
		return fmt.Errorf("firmware check: %w", err)
	}
	return nil
}

// GetFirmwareStatus reads the cached result of the most recent firmware
// check. Returns `status: "none"` if no check has run since boot.
//
// The OPNsense response is enormous when updates exist (it includes
// the full `all_packages` map with version diffs for every pending pkg);
// we only keep the counts and metadata. NDAgent can fetch the list on
// demand in a future task if the dashboard ever needs it.
func (c *Client) GetFirmwareStatus(ctx context.Context) (*FirmwareStatus, error) {
	body, err := c.doRequest(ctx, "GET", "/core/firmware/status", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware status: %w", err)
	}
	var resp struct {
		Status       string `json:"status"`
		StatusMsg    string `json:"status_msg"`
		LastCheck    string `json:"last_check"`
		Connection   string `json:"connection"`
		Repository   string `json:"repository"`
		NeedsReboot  string `json:"needs_reboot"`
		Upgrade      []json.RawMessage `json:"upgrade_packages"`
		New          []json.RawMessage `json:"new_packages"`
		Reinstall    []json.RawMessage `json:"reinstall_packages"`
		Remove       []json.RawMessage `json:"remove_packages"`
		// OPNsense returns its current + upstream version inside a
		// `product` block. Both fields are present when the catalog
		// has been fetched at least once; OPNsenseLatest is only set
		// when an upstream version exists that's newer than current.
		Product struct {
			Version string `json:"product_version"`
			Latest  string `json:"product_latest"`
		} `json:"product"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware status decode: %w", err)
	}
	return &FirmwareStatus{
		Status:          resp.Status,
		StatusMsg:       resp.StatusMsg,
		LastCheck:       resp.LastCheck,
		UpgradeCount:    len(resp.Upgrade),
		NewCount:        len(resp.New),
		ReinstallCount:  len(resp.Reinstall),
		RemoveCount:     len(resp.Remove),
		NeedsReboot:     resp.NeedsReboot == "1",
		Connection:      resp.Connection,
		Repository:      resp.Repository,
		OPNsenseVersion: resp.Product.Version,
		OPNsenseLatest:  resp.Product.Latest,
	}, nil
}

// ListCerts returns the cert search result with `valid_to` parsed into
// a days-until-expiry integer. The dashboard cares about *which* certs
// are about to expire, not the cert content itself, so the crt/csr/prv
// payload blobs are intentionally dropped here.
//
// OPNsense returns `valid_to` as a textual date like
// `"Jun 26 18:33:46 2025 GMT"`. Whatever parse fails leaves DaysLeft at
// 0 so the dashboard surfaces it as "expired" — that's the conservative
// read; missing data should not be silently dropped.
func (c *Client) ListCerts(ctx context.Context) ([]CertEntry, error) {
	body, err := c.doRequest(ctx, "POST", "/trust/cert/search", nil)
	if err != nil {
		return nil, fmt.Errorf("cert search: %w", err)
	}
	var resp struct {
		Rows []struct {
			Descr   string `json:"descr"`
			ValidTo string `json:"valid_to"`
			InUse   string `json:"in_use"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cert search decode: %w", err)
	}
	now := time.Now()
	out := make([]CertEntry, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		out = append(out, CertEntry{
			Description: r.Descr,
			DaysLeft:    daysUntilCertExpiry(r.ValidTo, now),
			ValidTo:     r.ValidTo,
			InUse:       r.InUse == "1",
		})
	}
	return out, nil
}

// daysUntilCertExpiry parses OPNsense's `valid_to` text into days from
// `now`. Negative for already-expired. Returns 0 on parse failure (which
// renders as "expired" in the dashboard — the right conservative call).
func daysUntilCertExpiry(validTo string, now time.Time) int {
	// OPNsense uses the OpenSSL `Mon DD HH:MM:SS YYYY ZONE` format.
	layouts := []string{
		"Jan _2 15:04:05 2006 MST",
		"Jan 02 15:04:05 2006 MST",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, validTo); err == nil {
			return int(t.Sub(now).Hours() / 24)
		}
	}
	return 0
}

// ─── Firmware upgrade API (FIRMWARE_UPGRADE task) ────────────────────────────

// FirmwareUpgradeStatus is the detailed /status response used by the
// FIRMWARE_UPGRADE task handler. It extends FirmwareStatus with the fields
// needed for mode classification and per-package reporting.
//
// Classification rules (from plan):
//   - upgrade_sets OR upgrade_major_version/upgrade_major_message non-empty → major available
//   - upgrade_packages non-empty (and no major signals) → minor available
//   - CORE_NEXT is informational only and is deliberately ignored here
type FirmwareUpgradeStatus struct {
	// Core version info
	ProductVersion string `json:"product_version"` // current installed version, e.g. "26.1.2"
	ProductLatest  string `json:"product_latest"`  // latest in same series, e.g. "26.1.9"
	ProductSeries  string `json:"product_series"`  // e.g. "26.1"
	ProductABI     string `json:"product_abi"`     // e.g. "26.1" (ABI label, not FreeBSD ABI)
	OSVersion      string `json:"os_version"`      // e.g. "FreeBSD 14.3-RELEASE-p8"
	ProductID      string `json:"product_id"`      // e.g. "opnsense"
	ProductTarget  string `json:"product_target"`  // e.g. "opnsense" (may differ for variants)

	// Overall status
	Status    string `json:"status"`     // "none", "update", "ok", "error"
	StatusMsg string `json:"status_msg"` // human readable

	// Reboot signals
	NeedsReboot        bool `json:"needs_reboot"`         // true if any pending item requires reboot
	UpgradeNeedsReboot bool `json:"upgrade_needs_reboot"` // true if upgrade set requires reboot

	// Minor (point release) indicator
	UpgradePackages []FirmwarePackageEntry `json:"upgrade_packages"` // non-empty → minor available

	// Major (series upgrade) indicators — non-empty = major available
	UpgradeSets         []json.RawMessage `json:"upgrade_sets"`
	UpgradeMajorVersion string            `json:"upgrade_major_version"`
	UpgradeMajorMessage string            `json:"upgrade_major_message"`

	// New/remove packages (informational, not used for classification)
	NewPackages       []FirmwarePackageEntry `json:"new_packages"`
	ReinstallPackages []FirmwarePackageEntry `json:"reinstall_packages"`
	RemovePackages    []FirmwarePackageEntry `json:"remove_packages"`

	// Connection and repo health
	Connection string `json:"connection"`
	Repository string `json:"repository"`
}

// FirmwarePackageEntry is one entry from upgrade_packages, new_packages, etc.
// OPNsense emits a richer object; we only keep the fields we need.
type FirmwarePackageEntry struct {
	Name           string `json:"name"`
	Repository     string `json:"repository"`
	CurrentVersion string `json:"current_version,omitempty"`
	NewVersion     string `json:"version,omitempty"` // new_packages uses "version"; upgrade uses "new_version"
	NewVersionAlt  string `json:"new_version,omitempty"`
}

// VersionString returns the best available new-version string regardless of
// which field OPNsense put it in.
func (e FirmwarePackageEntry) VersionString() string {
	if e.NewVersionAlt != "" {
		return e.NewVersionAlt
	}
	return e.NewVersion
}

// GetFirmwareUpgradeStatus reads the full /status response and returns the
// classified FirmwareUpgradeStatus. Callers should call TriggerFirmwareCheck
// and wait ~30 s before this call to get a fresh result.
func (c *Client) GetFirmwareUpgradeStatus(ctx context.Context) (*FirmwareUpgradeStatus, error) {
	body, err := c.doRequest(ctx, "GET", "/core/firmware/status", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware upgrade status: %w", err)
	}

	// OPNsense places product fields at both top-level and inside a "product"
	// block. We parse both to be robust across API versions.
	var raw struct {
		Status              string            `json:"status"`
		StatusMsg           string            `json:"status_msg"`
		NeedsReboot         string            `json:"needs_reboot"`          // "0" or "1"
		UpgradeNeedsReboot  string            `json:"upgrade_needs_reboot"` // "0" or "1"
		UpgradePackages     []json.RawMessage `json:"upgrade_packages"`
		UpgradeSets         []json.RawMessage `json:"upgrade_sets"`
		UpgradeMajorVersion string            `json:"upgrade_major_version"`
		UpgradeMajorMessage string            `json:"upgrade_major_message"`
		NewPackages         []json.RawMessage `json:"new_packages"`
		ReinstallPackages   []json.RawMessage `json:"reinstall_packages"`
		RemovePackages      []json.RawMessage `json:"remove_packages"`
		Connection          string            `json:"connection"`
		Repository          string            `json:"repository"`
		OSVersion           string            `json:"os_version"`
		ProductID           string            `json:"product_id"`
		ProductTarget       string            `json:"product_target"`
		ProductVersion      string            `json:"product_version"`
		ProductABI          string            `json:"product_abi"`
		// "product" sub-block carries the canonical values
		Product struct {
			Version  string `json:"product_version"`
			Latest   string `json:"product_latest"`
			Series   string `json:"CORE_SERIES"`
			COREABI  string `json:"CORE_ABI"`
			COREID   string `json:"product_id"`
			CoreArch string `json:"product_arch"`
		} `json:"product"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("firmware upgrade status decode: %w", err)
	}

	// Prefer top-level product_version (always present); fall back to product block.
	productVersion := raw.ProductVersion
	if productVersion == "" {
		productVersion = raw.Product.Version
	}
	productABI := raw.ProductABI
	if productABI == "" {
		productABI = raw.Product.COREABI
	}

	// Derive series from product_version if the product block CORE_SERIES is absent.
	series := raw.Product.Series
	if series == "" && productVersion != "" {
		// e.g. "26.1.2" → "26.1"
		parts := strings.SplitN(productVersion, ".", 3)
		if len(parts) >= 2 {
			series = parts[0] + "." + parts[1]
		}
	}

	parsePackages := func(msgs []json.RawMessage) []FirmwarePackageEntry {
		out := make([]FirmwarePackageEntry, 0, len(msgs))
		for _, m := range msgs {
			var e FirmwarePackageEntry
			if err := json.Unmarshal(m, &e); err == nil {
				out = append(out, e)
			}
		}
		return out
	}

	return &FirmwareUpgradeStatus{
		ProductVersion:      productVersion,
		ProductLatest:       raw.Product.Latest,
		ProductSeries:       series,
		ProductABI:          productABI,
		OSVersion:           raw.OSVersion,
		ProductID:           raw.ProductID,
		ProductTarget:       raw.ProductTarget,
		Status:              raw.Status,
		StatusMsg:           raw.StatusMsg,
		NeedsReboot:         raw.NeedsReboot == "1",
		UpgradeNeedsReboot:  raw.UpgradeNeedsReboot == "1",
		UpgradePackages:     parsePackages(raw.UpgradePackages),
		UpgradeSets:         raw.UpgradeSets,
		UpgradeMajorVersion: raw.UpgradeMajorVersion,
		UpgradeMajorMessage: raw.UpgradeMajorMessage,
		NewPackages:         parsePackages(raw.NewPackages),
		ReinstallPackages:   parsePackages(raw.ReinstallPackages),
		RemovePackages:      parsePackages(raw.RemovePackages),
		Connection:          raw.Connection,
		Repository:          raw.Repository,
	}, nil
}

// FirmwareUpdateResponse is the response from POST /core/firmware/update.
// OPNsense returns {"status":"ok","msg_uuid":"<uuid>"} on success.
// No request body is required — the endpoint checks isPost() only.
type FirmwareUpdateResponse struct {
	Status  string `json:"status"`
	MsgUUID string `json:"msg_uuid"`
}

// TriggerFirmwareUpdate triggers a minor (point-release) update via the REST
// API. OPNsense runs the update asynchronously; the caller monitors progress
// via GetFirmwareUpgradeProgress and GetFirmwareRunning. No request body is
// needed — the endpoint checks isPost() only (confirmed from OPNsense source).
func (c *Client) TriggerFirmwareUpdate(ctx context.Context) (*FirmwareUpdateResponse, error) {
	body, err := c.doRequest(ctx, "POST", "/core/firmware/update", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware update trigger: %w", err)
	}
	var resp FirmwareUpdateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware update response decode: %w", err)
	}
	return &resp, nil
}

// FirmwareUpgradeResponse is the response from POST /core/firmware/upgrade.
type FirmwareUpgradeResponse struct {
	Status  string `json:"status"`
	MsgUUID string `json:"msg_uuid"`
}

// TriggerFirmwareUpgrade triggers a major (series) upgrade via the REST API.
// Same semantics as TriggerFirmwareUpdate: no request body, async backend
// process, monitor via GetFirmwareUpgradeProgress.
func (c *Client) TriggerFirmwareUpgrade(ctx context.Context) (*FirmwareUpgradeResponse, error) {
	body, err := c.doRequest(ctx, "POST", "/core/firmware/upgrade", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware upgrade trigger: %w", err)
	}
	var resp FirmwareUpgradeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware upgrade response decode: %w", err)
	}
	return &resp, nil
}

// FirmwareProgressStatus is the progress state returned by /upgradestatus.
// OPNsense parses the log file for sentinel strings:
//
//	"done"    — process finished normally (sentinel: ***DONE***)
//	"reboot"  — process finished and wants a reboot (sentinel: ***REBOOT***)
//	"running" — still in progress (no sentinel yet)
//	"error"   — backend returned nothing (configd error)
type FirmwareProgressStatus struct {
	// Status is one of "done", "reboot", "running", "error".
	Status string `json:"status"`
	// Log is the accumulated log text since the update began.
	Log string `json:"log"`
}

// GetFirmwareUpgradeProgress reads the current progress log from OPNsense.
// This is a GET (safe, no side effects). Poll this during a reboot=true apply.
func (c *Client) GetFirmwareUpgradeProgress(ctx context.Context) (*FirmwareProgressStatus, error) {
	body, err := c.doRequest(ctx, "GET", "/core/firmware/upgradestatus", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware upgradestatus: %w", err)
	}
	var resp FirmwareProgressStatus
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware upgradestatus decode: %w", err)
	}
	return &resp, nil
}

// FirmwareRunning reports whether the firmware backend is busy.
// OPNsense returns {"status":"ready"} when idle and {"status":"<something-else>"}
// while a firmware operation is in progress.
type FirmwareRunning struct {
	// Status is "ready" when the firmware subsystem is idle.
	Status string `json:"status"`
}

// GetFirmwareRunning checks whether the OPNsense firmware backend is idle.
// Used at boot-time reconciliation to decide whether to defer or resolve
// an IN_PROGRESS FIRMWARE_UPGRADE row.
func (c *Client) GetFirmwareRunning(ctx context.Context) (*FirmwareRunning, error) {
	body, err := c.doRequest(ctx, "GET", "/core/firmware/running", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware running: %w", err)
	}
	var resp FirmwareRunning
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware running decode: %w", err)
	}
	return &resp, nil
}
