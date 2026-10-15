package opnapi

// firmware_major.go — the reads and the one write a series upgrade makes beyond the
// firmware backend: the HA signals (a member of a CARP pair is never upgraded), the
// boot environments (ZFS snapshots of the root, made before the upgrade when there
// is room) and nothing else.
//
// The VIP list and the hasync model both carry a password: every row of the first
// has a `password` key and the answer of the second a `password` field. Nothing
// here decodes either into anything that has a place for it, keeps a response
// body, or puts one in an error: a failed read says the endpoint and the status,
// and a decode that fails says that it did and not what it saw.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ReadError is a failed request of this file: the endpoint and the HTTP status,
// or the class of transport failure, and never the answer.
type ReadError struct {
	Op         string
	StatusCode int
	Class      string
}

func (e *ReadError) Error() string {
	switch {
	case e.StatusCode != 0:
		return fmt.Sprintf("%s: status %d", e.Op, e.StatusCode)
	case e.Class != "":
		return fmt.Sprintf("%s: %s", e.Op, e.Class)
	}
	return e.Op + ": failed"
}

// IsNotFound reports whether the endpoint answered 404 (the plugin or the feature
// is not on this device).
func (e *ReadError) IsNotFound() bool { return e.StatusCode == 404 }

// readError reduces an error of doRequest to one that carries no body.
func readError(op string, err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return &ReadError{Op: op, StatusCode: apiErr.StatusCode}
	}
	return &ReadError{Op: op, Class: errorWithoutText(err).Error()}
}

// flexText is a JSON string or number read as text; anything else is empty.
type flexText string

func (f *flexText) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexText(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexText(n.String())
		return nil
	}
	*f = ""
	return nil
}

// flexInt is a JSON number or a string of digits read as an integer; anything else
// is zero.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	var t flexText
	_ = t.UnmarshalJSON(b)
	if n, err := strconv.Atoi(string(t)); err == nil && n >= 0 {
		*f = flexInt(n)
	} else {
		*f = 0
	}
	return nil
}

// VIPRow is the part of a virtual IP row an HA check reads: its mode and its vhid.
type VIPRow struct {
	Mode string
	VHID string
}

// IsCARP reports whether the row is a CARP address: its mode says so, or it names
// a vhid (a CARP group id).
func (r VIPRow) IsCARP() bool {
	return strings.EqualFold(r.Mode, "carp") || r.VHID != ""
}

// VIPList is the virtual IP list of the device: every row it holds and the total
// the device reported.
type VIPList struct {
	Total int
	Rows  []VIPRow
}

// vipPageSize is the page the VIP list is read in. The list of a device that has
// any is a handful of rows, so one page is the usual case.
const vipPageSize = 200

// vipMaxPages bounds the paging against a device that never reports a total it
// can reach.
const vipMaxPages = 50

// GetVIPList reads GET /interfaces/vip_settings/searchItem, paging until the rows
// held equal the total. Each row is decoded into a struct that has no password:
// a CARP row's password never reaches this process's memory as a field, let alone
// a log line.
func (c *Client) GetVIPList(ctx context.Context) (VIPList, error) {
	const op = "interfaces/vip_settings/searchItem"
	var list VIPList
	for page := 1; page <= vipMaxPages; page++ {
		q := url.Values{}
		q.Set("current", strconv.Itoa(page))
		q.Set("rowCount", strconv.Itoa(vipPageSize))
		body, err := c.doRequest(ctx, "GET", "/interfaces/vip_settings/searchItem?"+q.Encode(), nil)
		if err != nil {
			return VIPList{}, readError(op, err)
		}
		var resp struct {
			Total flexInt `json:"total"`
			Rows  []struct {
				Mode flexText `json:"mode"`
				VHID flexText `json:"vhid"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return VIPList{}, readError(op, err)
		}
		list.Total = int(resp.Total)
		for _, row := range resp.Rows {
			list.Rows = append(list.Rows, VIPRow{Mode: string(row.Mode), VHID: string(row.VHID)})
		}
		if len(resp.Rows) == 0 || len(list.Rows) >= list.Total {
			return list, nil
		}
	}
	return VIPList{}, &ReadError{Op: op, Class: "paging did not reach the total"}
}

// HASync is the part of the hasync model an HA check reads: the interface pfsync
// runs on and the address the configuration is synchronized to.
type HASync struct {
	PfsyncInterface string
	SynchronizeToIP string
}

// GetHASync reads GET /core/hasync/get. A model field comes back as a plain string
// or as an option map whose selected entry is the value; the answer's `password`
// field has no place in what is decoded.
func (c *Client) GetHASync(ctx context.Context) (HASync, error) {
	const op = "core/hasync/get"
	body, err := c.doRequest(ctx, "GET", "/core/hasync/get", nil)
	if err != nil {
		return HASync{}, readError(op, err)
	}
	var resp struct {
		HASync *struct {
			PfsyncInterface json.RawMessage `json:"pfsyncinterface"`
			SynchronizeToIP json.RawMessage `json:"synchronizetoip"`
		} `json:"hasync"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.HASync == nil {
		return HASync{}, &ReadError{Op: op, Class: "unreadable answer"}
	}
	return HASync{
		PfsyncInterface: selectedOrText(resp.HASync.PfsyncInterface),
		SynchronizeToIP: selectedOrText(resp.HASync.SynchronizeToIP),
	}, nil
}

// selectedOrText reads a model field: a string or number as itself, an option map
// as the key of its selected entry, anything else as empty.
func selectedOrText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '{' {
		var options map[string]struct {
			Selected json.RawMessage `json:"selected"`
		}
		if json.Unmarshal(raw, &options) != nil {
			return ""
		}
		for key, option := range options {
			switch strings.TrimSpace(string(option.Selected)) {
			case "1", "true", `"1"`, `"true"`:
				return key
			}
		}
		return ""
	}
	var t flexText
	_ = t.UnmarshalJSON(raw)
	return string(t)
}

// BootEnvironment is a ZFS boot environment as the snapshots API lists it.
type BootEnvironment struct {
	UUID string
	Name string
	// Active is OPNsense's flag column: "NR" for the environment that is running
	// and is the next boot's, "-" for one that is neither.
	Active string
}

// SnapshotsSupported reads GET /core/snapshots/isSupported: whether the device's
// root is on ZFS, where boot environments exist.
func (c *Client) SnapshotsSupported(ctx context.Context) (bool, error) {
	const op = "core/snapshots/isSupported"
	body, err := c.doRequest(ctx, "GET", "/core/snapshots/isSupported", nil)
	if err != nil {
		return false, readError(op, err)
	}
	var resp struct {
		Supported *bool `json:"supported"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Supported == nil {
		return false, &ReadError{Op: op, Class: "unreadable answer"}
	}
	return *resp.Supported, nil
}

// ListBootEnvironments reads GET /core/snapshots/search.
func (c *Client) ListBootEnvironments(ctx context.Context) ([]BootEnvironment, error) {
	const op = "core/snapshots/search"
	body, err := c.doRequest(ctx, "GET", "/core/snapshots/search", nil)
	if err != nil {
		return nil, readError(op, err)
	}
	var resp struct {
		Rows []struct {
			UUID   flexText `json:"uuid"`
			Name   flexText `json:"name"`
			Active flexText `json:"active"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, readError(op, err)
	}
	out := make([]BootEnvironment, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		out = append(out, BootEnvironment{UUID: string(row.UUID), Name: string(row.Name), Active: string(row.Active)})
	}
	return out, nil
}

// ErrBootEnvironmentExists is the refusal of an add whose name is taken: the API
// answers "A snapshot already exists by this name".
var ErrBootEnvironmentExists = errors.New("a boot environment already exists by this name")

// CreateBootEnvironment makes a boot environment through POST /core/snapshots/add,
// which runs `bectl create`: a clone of a snapshot of the running environment, a
// few hundred KiB when made, whose snapshot then keeps every block the upgrade
// replaces. The answer carries no uuid; ListBootEnvironments finds it by name.
func (c *Client) CreateBootEnvironment(ctx context.Context, name, note string) error {
	const op = "core/snapshots/add"
	body, err := c.doRequest(ctx, "POST", "/core/snapshots/add", map[string]string{"name": name, "note": note})
	if err != nil {
		return readError(op, err)
	}
	var resp struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
		Errors json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return readError(op, err)
	}
	if strings.EqualFold(resp.Status, "ok") {
		return nil
	}
	if strings.Contains(strings.ToLower(string(resp.Result)+string(resp.Errors)), "already exists") {
		return ErrBootEnvironmentExists
	}
	return &ReadError{Op: op, Class: "refused (status " + resp.Status + ")"}
}
