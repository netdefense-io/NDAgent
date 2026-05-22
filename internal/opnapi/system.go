package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
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
