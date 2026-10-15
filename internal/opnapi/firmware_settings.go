package opnapi

// firmware_settings.go — OPNsense's firmware settings (System > Firmware >
// Settings), the model at //system/firmware: mirror, flavour, type,
// subscription, reboot, aux. The agent reads them to decide whether a device may
// be pinned and writes exactly one of them, the flavour, to pin it.
//
// The subscription is a licence key that sits in the mirror URL. It is read
// through redacting code only: the struct below has no field for its value, so
// no log line, error or result can carry it, however it is formatted.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// FirmwareSettings is the part of the firmware settings the track code needs.
type FirmwareSettings struct {
	// Mirror is the custom mirror URL ("" is OPNsense's default mirror).
	Mirror string
	// Flavour is the repository path override ("" is the default). A slash
	// flavour such as 26.7/MINT/26.7.3/latest replaces everything after the ABI
	// in the generated repository URLs.
	Flavour string
	// Type is the release type ("" is the community edition).
	Type string
	// SubscriptionSet says a subscription key is configured. The key itself is
	// never kept.
	SubscriptionSet bool
	// Reboot is the "always reboot after an update" setting.
	Reboot bool
	// Aux says the aux repository is enabled.
	Aux bool
}

// GetFirmwareSettings reads the firmware settings.
func (c *Client) GetFirmwareSettings(ctx context.Context) (*FirmwareSettings, error) {
	body, err := c.doRequest(ctx, "GET", "/core/firmware/get", nil)
	if err != nil {
		return nil, fmt.Errorf("firmware settings: %w", err)
	}
	return parseFirmwareSettings(body)
}

func parseFirmwareSettings(body []byte) (*FirmwareSettings, error) {
	var resp struct {
		Firmware map[string]json.RawMessage `json:"firmware"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("firmware settings decode: %w", err)
	}
	if resp.Firmware == nil {
		return nil, fmt.Errorf("firmware settings decode: no firmware node in the answer")
	}
	node := resp.Firmware
	return &FirmwareSettings{
		Mirror:          settingText(node["mirror"]),
		Flavour:         settingText(node["flavour"]),
		Type:            settingText(node["type"]),
		SubscriptionSet: settingText(node["subscription"]) != "",
		Reboot:          settingFlag(node["reboot"]),
		Aux:             settingFlag(node["aux"]),
	}, nil
}

// settingText reads a model field the way the API serves it: a plain string, or
// for a select field an option map whose selected entry is the value.
func settingText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var options map[string]json.RawMessage
	if json.Unmarshal(raw, &options) == nil {
		for key, opt := range options {
			var o struct {
				Selected interface{} `json:"selected"`
			}
			if json.Unmarshal(opt, &o) != nil {
				continue
			}
			switch v := o.Selected.(type) {
			case bool:
				if v {
					return key
				}
			case float64:
				if v != 0 {
					return key
				}
			case string:
				if v == "1" || v == "true" {
					return key
				}
			}
		}
	}
	return ""
}

func settingFlag(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	switch settingText(raw) {
	case "1", "true":
		return true
	}
	return false
}

// flavourPattern is every character a flavour needs: the release path
// `<series>/MINT/<dir>/latest`. OPNsense passes what it is given through
// FILTER_SANITIZE_URL, which would change anything else without a word.
var flavourPattern = regexp.MustCompile(`\A[0-9A-Za-z._/-]{0,128}\z`)

// SetFirmwareFlavour sets the firmware flavour and nothing else. The call is a
// partial /set: OPNsense applies the keys it is sent, so the mirror, type,
// subscription and the rest stay as they are, which the GUI's six-field form
// would not guarantee (it round-trips the subscription and races with GUI edits).
// It answers `status`, not `result`.
//
// A set cuts a config revision, flushes the cached check result and reloads the
// repository files; it fetches no catalog, so a check has to follow. The empty
// flavour is OPNsense's default.
func (c *Client) SetFirmwareFlavour(ctx context.Context, flavour string) error {
	if !flavourPattern.MatchString(flavour) {
		return fmt.Errorf("refusing to set the firmware flavour: %q is not a release path", flavour)
	}
	body, err := c.doRequest(ctx, "POST", "/core/firmware/set", map[string]interface{}{
		"firmware": map[string]string{"flavour": flavour},
	})
	if err != nil {
		return fmt.Errorf("set firmware flavour: %w", err)
	}
	var resp struct {
		Status    string          `json:"status"`
		StatusMsg json.RawMessage `json:"status_msg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("set firmware flavour: decode: %w", err)
	}
	if resp.Status != "ok" {
		return fmt.Errorf("set firmware flavour: OPNsense answered status %q (%s)", resp.Status, compactMessages(resp.StatusMsg))
	}
	return nil
}

// compactMessages flattens OPNsense's status_msg (a list, or a map of field to
// message) into one short line for an error.
func compactMessages(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "no message"
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, "; ")
	}
	var byField map[string]string
	if json.Unmarshal(raw, &byField) == nil {
		parts := make([]string, 0, len(byField))
		for field, msg := range byField {
			parts = append(parts, field+": "+msg)
		}
		return strings.Join(parts, "; ")
	}
	return string(raw)
}
