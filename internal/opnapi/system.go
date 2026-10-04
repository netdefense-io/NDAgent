package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// System / health probes used by the heavy telemetry collector.
//
// Three groups of fields:
//   - service running state — cheap, one GET
//   - pending firmware/package updates — GET /status returns the result of
//     the last check; a check (POST /check) runs in the background and holds
//     /running busy until its result is written
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
// `Status` is OPNsense's: "update" or "upgrade" (something is pending),
// "none" (nothing is pending, or no check has completed: then LastCheck is
// empty) or "error" (the check could not use the mirror; Connection and
// Repository say why). The counters are zero unless a completed check found
// something.
//
// `OPNsenseVersion` is the installed release (`product.product_version`,
// which OPNsense builds from the local version file on every request).
// `OPNsenseLatest` is the core package's candidate in the check's
// `upgrade_packages`, the installed release when a clean check lists none,
// and empty when the check did not complete, failed or ran against another
// release. It is never `product.product_latest`: OPNsense computes that from
// its changelog index and keeps the last newer entry in file order, not the
// newest (an installed 26.7 reads 26.7.2 while 26.7.5 is out), and no check
// moves it. `OPNsensePackage`, the installed core package, tells consumers
// the value has this meaning. `UpgradeMajorVersion` is the next series the
// mirror offers.
type FirmwareStatus struct {
	Status              string `json:"status"`
	StatusMsg           string `json:"status_msg"`
	LastCheck           string `json:"last_check"`
	UpgradeCount        int    `json:"upgrade_count"`
	NewCount            int    `json:"new_count"`
	ReinstallCount      int    `json:"reinstall_count"`
	RemoveCount         int    `json:"remove_count"`
	NeedsReboot         bool   `json:"needs_reboot"`
	Connection          string `json:"connection"`
	Repository          string `json:"repository"`
	OPNsenseVersion     string `json:"opnsense_version,omitempty"`
	OPNsenseLatest      string `json:"opnsense_latest,omitempty"`
	OPNsensePackage     string `json:"opnsense_package,omitempty"`
	UpgradeMajorVersion string `json:"upgrade_major_version,omitempty"`
	LastCheckUnix       int64  `json:"last_check_unix,omitempty"`

	// CheckedVersion is the release the check ran against (the top-level
	// `product_version`). Not sent.
	CheckedVersion string `json:"-"`
}

// Completed reports whether the reading is the result of a finished check.
// While a check runs, and after a reboot until one has run, OPNsense has no
// result and answers "none" without a last_check.
func (s *FirmwareStatus) Completed() bool {
	return s.LastCheck != ""
}

// Clean reports whether the reading is the result of a check that could use
// the mirror. A check that could not (status "error", or a connection or
// repository other than "ok") says nothing about what is pending.
func (s *FirmwareStatus) Clean() bool {
	return s.Completed() && s.Status != "error" && s.Connection == "ok" && s.Repository == "ok"
}

// Stale reports whether the check ran against another release than the
// installed one. Only a check rewrites its result, so after an update the
// reading describes the release that was replaced.
func (s *FirmwareStatus) Stale() bool {
	return s.CheckedVersion != "" && s.OPNsenseVersion != "" && s.CheckedVersion != s.OPNsenseVersion
}

// IsCorePackage reports whether name is OPNsense's own package, whose version
// is the release: "opnsense", or the business edition's or development
// flavour's name for it.
func IsCorePackage(name string) bool {
	switch name {
	case "opnsense", "opnsense-business", "opnsense-devel":
		return true
	}
	return false
}

// CertEntry is one row from `/api/trust/cert/search`, trimmed to what the
// dashboard renders. `ValidTo` is the expiry as an RFC 3339 UTC timestamp
// (the value as OPNsense sent it when it cannot be read); the broker /
// NDManager treat it opaquely and the agent computes `DaysLeft` so we don't
// ship the cert payload itself.
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
// refresh runs in the background, and /running reports busy until its
// result is written. A request that finds another firmware job running is
// dropped, and the answer is still "ok".
func (c *Client) TriggerFirmwareCheck(ctx context.Context) error {
	_, err := c.doRequest(ctx, "POST", "/core/firmware/check", nil)
	if err != nil {
		return fmt.Errorf("firmware check: %w", err)
	}
	return nil
}

// GetFirmwareStatus reads the result of the most recent firmware check. It
// starts no check. Without a result (no check since boot, or one running) the
// status is "none" and LastCheck is empty.
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
	return parseFirmwareStatus(body, time.Local)
}

// parseFirmwareStatus decodes a /status response. loc is the zone last_check
// is written in: the device's own, as `date` prints it.
func parseFirmwareStatus(body []byte, loc *time.Location) (*FirmwareStatus, error) {
	var resp struct {
		Status              string            `json:"status"`
		StatusMsg           string            `json:"status_msg"`
		LastCheck           string            `json:"last_check"`
		Connection          string            `json:"connection"`
		Repository          string            `json:"repository"`
		NeedsReboot         string            `json:"needs_reboot"`
		ProductVersion      string            `json:"product_version"`
		ProductID           string            `json:"product_id"`
		UpgradeMajorVersion string            `json:"upgrade_major_version"`
		Upgrade             []json.RawMessage `json:"upgrade_packages"`
		New                 []json.RawMessage `json:"new_packages"`
		Reinstall           []json.RawMessage `json:"reinstall_packages"`
		Remove              []json.RawMessage `json:"remove_packages"`
		// The `product` block is built from the installed version file on
		// every request; the top-level product fields are the check's.
		Product struct {
			Version  string `json:"product_version"`
			ID       string `json:"product_id"`
			CoreName string `json:"CORE_NAME"`
		} `json:"product"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware status decode: %w", err)
	}
	st := &FirmwareStatus{
		Status:              resp.Status,
		StatusMsg:           resp.StatusMsg,
		LastCheck:           resp.LastCheck,
		UpgradeCount:        len(resp.Upgrade),
		NewCount:            len(resp.New),
		ReinstallCount:      len(resp.Reinstall),
		RemoveCount:         len(resp.Remove),
		NeedsReboot:         resp.NeedsReboot == "1",
		Connection:          resp.Connection,
		Repository:          resp.Repository,
		OPNsenseVersion:     resp.Product.Version,
		OPNsensePackage:     firstCorePackage(resp.Product.ID, resp.Product.CoreName, resp.ProductID),
		UpgradeMajorVersion: strings.TrimSpace(resp.UpgradeMajorVersion),
		CheckedVersion:      resp.ProductVersion,
	}
	if checked, ok := parseCheckTime(resp.LastCheck, loc); ok {
		st.LastCheckUnix = checked.Unix()
	}
	if st.Clean() && !st.Stale() {
		st.OPNsenseLatest = coreCandidate(parsePackageEntries(resp.Upgrade), st.OPNsensePackage)
		if st.OPNsenseLatest == "" {
			st.OPNsenseLatest = st.OPNsenseVersion
		}
	}
	return st, nil
}

// firstCorePackage is the first of names that is a core package name, or "".
func firstCorePackage(names ...string) string {
	for _, name := range names {
		if IsCorePackage(name) {
			return name
		}
	}
	return ""
}

// coreCandidate is the version the check offers for the core package: the
// entry for the installed one, else any core entry (a flavour switch lists
// the target's), or "" when the check offers none.
func coreCandidate(upgrades []FirmwarePackageEntry, installed string) string {
	candidate := ""
	for _, e := range upgrades {
		if !IsCorePackage(e.Name) {
			continue
		}
		if e.Name == installed {
			return e.VersionString()
		}
		if candidate == "" {
			candidate = e.VersionString()
		}
	}
	return candidate
}

// parseCheckTime reads last_check. check.sh stores `date`'s output, as in
// "Sun Oct  4 03:02:47 UTC 2026", in the device's zone; an abbreviation loc
// does not know is read as UTC.
func parseCheckTime(text string, loc *time.Location) (time.Time, bool) {
	t, err := time.ParseInLocation(time.UnixDate, strings.TrimSpace(text), loc)
	return t, err == nil
}

// ListCerts returns the cert search result with `valid_to` parsed into
// a days-until-expiry integer. The dashboard cares about *which* certs
// are about to expire, not the cert content itself, so the crt/csr/prv
// payload blobs are intentionally dropped here.
func (c *Client) ListCerts(ctx context.Context) ([]CertEntry, error) {
	body, err := c.doRequest(ctx, "POST", "/trust/cert/search", nil)
	if err != nil {
		return nil, fmt.Errorf("cert search: %w", err)
	}
	return certEntries(body, time.Now())
}

// certEntries decodes a `/trust/cert/search` response, counting the days left
// from now.
//
// OPNsense sends `valid_to` as Unix seconds in a string ("1782000000"): the
// trust model copies openssl_x509_parse's validTo_time_t into a text field. A
// value that cannot be read leaves DaysLeft at 0, which the dashboard counts
// as expired: missing data should not be silently dropped. A row with no
// certificate at all, a signing request waiting for one, has no expiry and is
// left out.
func certEntries(body []byte, now time.Time) ([]CertEntry, error) {
	var resp struct {
		Rows []struct {
			Descr      string          `json:"descr"`
			ValidTo    json.RawMessage `json:"valid_to"`
			InUse      string          `json:"in_use"`
			Crt        json.RawMessage `json:"crt"`
			CrtPayload json.RawMessage `json:"crt_payload"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cert search decode: %w", err)
	}
	out := make([]CertEntry, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		if blankJSON(r.Crt) && blankJSON(r.CrtPayload) && blankJSON(r.ValidTo) {
			continue
		}
		entry := CertEntry{Description: r.Descr, InUse: r.InUse == "1"}
		if expiry, ok := certExpiry(r.ValidTo); ok {
			entry.ValidTo = expiry.UTC().Format(time.RFC3339)
			entry.DaysLeft = daysLeft(expiry, now)
		} else {
			entry.ValidTo = certValidToText(r.ValidTo)
		}
		out = append(out, entry)
	}
	return out, nil
}

// blankJSON reports whether a field is absent, null or "".
func blankJSON(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", `""`:
		return true
	}
	return false
}

// certTextLayouts are the textual forms a valid_to has been seen in besides
// Unix seconds: OpenSSL's `Mon DD HH:MM:SS YYYY ZONE` and RFC 3339.
var certTextLayouts = []string{
	"Jan _2 15:04:05 2006 MST",
	"Jan 02 15:04:05 2006 MST",
	time.RFC3339,
}

// certExpiry reads a valid_to value: Unix seconds as a JSON string or number,
// or one of certTextLayouts.
func certExpiry(raw json.RawMessage) (time.Time, bool) {
	text := certValidToText(raw)
	if text == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseInt(text, 10, 64); err == nil {
		return time.Unix(seconds, 0), true
	}
	for _, layout := range certTextLayouts {
		if t, err := time.Parse(layout, text); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// certValidToText returns a valid_to string, or the digits of a number, and ""
// for anything else.
func certValidToText(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return ""
}

// daysLeft counts the days from now to expiry, rounded up: 1 while any part of
// the last day remains, 0 or less once the certificate has expired. That is the
// split the dashboard draws between expired (days_left <= 0) and expiring soon.
func daysLeft(expiry, now time.Time) int {
	return int(math.Ceil(expiry.Sub(now).Hours() / 24))
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
	ProductLatest  string `json:"product_latest"`  // the series' last newer changelog entry in file order, not the newest
	ProductSeries  string `json:"product_series"`  // e.g. "26.1"
	ProductABI     string `json:"product_abi"`     // e.g. "26.1" (ABI label, not FreeBSD ABI)
	OSVersion      string `json:"os_version"`      // e.g. "FreeBSD 14.3-RELEASE-p8"
	ProductID      string `json:"product_id"`      // e.g. "opnsense"
	ProductTarget  string `json:"product_target"`  // e.g. "opnsense" (may differ for variants)

	// Overall status
	Status    string `json:"status"`     // "none", "update", "upgrade", "error"
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
// classified FirmwareUpgradeStatus. For a fresh result, call
// TriggerFirmwareCheck first and wait for /running to report "ready".
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
		NeedsReboot         string            `json:"needs_reboot"`         // "0" or "1"
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
		UpgradePackages:     parsePackageEntries(raw.UpgradePackages),
		UpgradeSets:         raw.UpgradeSets,
		UpgradeMajorVersion: raw.UpgradeMajorVersion,
		UpgradeMajorMessage: raw.UpgradeMajorMessage,
		NewPackages:         parsePackageEntries(raw.NewPackages),
		ReinstallPackages:   parsePackageEntries(raw.ReinstallPackages),
		RemovePackages:      parsePackageEntries(raw.RemovePackages),
		Connection:          raw.Connection,
		Repository:          raw.Repository,
	}, nil
}

// parsePackageEntries decodes a package list, skipping an entry it cannot read.
func parsePackageEntries(msgs []json.RawMessage) []FirmwarePackageEntry {
	out := make([]FirmwarePackageEntry, 0, len(msgs))
	for _, m := range msgs {
		var e FirmwarePackageEntry
		if err := json.Unmarshal(m, &e); err == nil {
			out = append(out, e)
		}
	}
	return out
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

// GetFirmwareRunning checks whether the OPNsense firmware backend is idle: the
// launcher's lock is not held, so no update, upgrade or check is running. The
// FIRMWARE_UPGRADE handler and reconciler read it to decide whether a run is
// still under way; an error or an empty status means "cannot tell", never idle.
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

// MinSupportedOPNsenseMajor / MinSupportedOPNsenseMinor / MinSupportedOPNsensePatch
// are NDAgent's supported OPNsense floor: 26.1.11.
//
// The floor has two reasons, one for each part.
//
// The series, 26.1: SYNC_API's rule discovery depends on 26.1's `searchRule`
// semantics — an omitted `interface` key returns every rule, where 25.x returned
// only the floating view — and without that a VPN teardown cannot enumerate, and
// therefore cannot delete, the auto firewall rules bound to the `wireguard`
// group once that group disappears. See RuleSearchRequest in types.go for the
// per-release behaviour.
//
// The patch, 11: 26.1.11 carries OPNsense's fixes for privilege escalation
// through privileges the admin-equivalence catalog classifies as ordinary (its
// floor_dependent_ids, classified for assumes_min_opnsense, which a test holds
// equal to this floor). Below it such a privilege can lead to administrator
// rights, so the agent's checks count it as administrator-equivalent there. See
// ElevateFloorDependentPrivsBelowFloor.
const (
	MinSupportedOPNsenseMajor = 26
	MinSupportedOPNsenseMinor = 1
	MinSupportedOPNsensePatch = 11
)

// ProductRelease is the installed OPNsense release.
//
// Raw is the version string exactly as OPNsense reported it, for logs; Major,
// Minor and Patch are the parsed release used for comparison. A FreeBSD-style
// suffix ("26.1.9_1") is ignored, and a release with no patch component is the
// first of its series: "26.1" is 26.1.0.
type ProductRelease struct {
	Raw   string
	Major int
	Minor int
	Patch int
}

// AtLeast reports whether the release is at or above major.minor.patch.
func (r ProductRelease) AtLeast(major, minor, patch int) bool {
	switch {
	case r.Major != major:
		return r.Major > major
	case r.Minor != minor:
		return r.Minor > minor
	default:
		return r.Patch >= patch
	}
}

// String renders the release for logs, preferring what OPNsense reported.
func (r ProductRelease) String() string {
	if r.Raw != "" {
		return r.Raw
	}
	return fmt.Sprintf("%d.%d.%d", r.Major, r.Minor, r.Patch)
}

// ParseProductRelease extracts the major, minor and patch numbers from an
// OPNsense version string such as "26.1.11", "26.1" or "25.7.11_9". The patch is
// 0 when the string has none, or when its third component does not start with a
// digit (a development build such as "27.1.a").
func ParseProductRelease(version string) (ProductRelease, error) {
	trimmed := strings.TrimSpace(version)
	parts := strings.SplitN(trimmed, ".", 3)
	if len(parts) < 2 {
		return ProductRelease{}, fmt.Errorf("unrecognised OPNsense version %q", version)
	}

	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return ProductRelease{}, fmt.Errorf("unrecognised OPNsense version %q: bad major", version)
	}

	// The minor component may carry a suffix on a two-part version
	// ("25.7_1"); take the leading digits.
	minor, err := strconv.Atoi(leadingDigits(strings.TrimSpace(parts[1])))
	if err != nil {
		return ProductRelease{}, fmt.Errorf("unrecognised OPNsense version %q: bad minor", version)
	}

	patch := 0
	if len(parts) == 3 {
		if digits := leadingDigits(strings.TrimSpace(parts[2])); digits != "" {
			if patch, err = strconv.Atoi(digits); err != nil {
				return ProductRelease{}, fmt.Errorf("unrecognised OPNsense version %q: bad patch", version)
			}
		}
	}

	return ProductRelease{Raw: trimmed, Major: major, Minor: minor, Patch: patch}, nil
}

// leadingDigits returns the run of ASCII digits s starts with.
func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}
