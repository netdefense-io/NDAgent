package opnapi

// device_privs.go — the privilege IDs the device itself defines.
//
// OPNsense grants a page through the URL masks of the privilege IDs in its ACL
// catalog (ACL::getPrivList(): core plus the installed plugins) and ignores an ID
// that is not in it: a group that holds an ID which the running release no longer
// defines, or which belongs to a plugin that is not installed, is granted nothing
// by it. That is the catalog's view of the live rows; it is not the view of
// snippet content, where an ID the agent cannot classify stays administrator-
// equivalent because what a snippet writes is judged before the device is asked.

import (
	"context"
	"encoding/json"
	"fmt"
)

// devicePrivsMinEntries is how few IDs a catalog can have and still be the real
// one: core alone ships well over this many on every supported release. A list
// shorter than that, or without the two IDs every release defines, is not read as
// the catalog.
const devicePrivsMinEntries = 100

var devicePrivAnchors = []string{"page-all", "user-config-readonly"}

// DevicePrivs is the set of privilege IDs a device defines. A nil *DevicePrivs
// means the catalog could not be read, and the callers that take one then treat
// every ID the agent does not know as administrator-equivalent.
type DevicePrivs struct {
	ids map[string]struct{}
}

// NewDevicePrivs returns the catalog of ids, or an error when it is not a
// plausible one (see devicePrivsMinEntries): a truncated or empty answer must
// fail closed, never read as "the device defines almost nothing".
func NewDevicePrivs(ids []string) (*DevicePrivs, error) {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	if len(set) < devicePrivsMinEntries {
		return nil, fmt.Errorf("the privilege catalog lists %d IDs, fewer than any real release", len(set))
	}
	for _, anchor := range devicePrivAnchors {
		if _, ok := set[anchor]; !ok {
			return nil, fmt.Errorf("the privilege catalog does not list %q", anchor)
		}
	}
	return &DevicePrivs{ids: set}, nil
}

// Defines reports whether the device defines the privilege ID. OPNsense looks an
// ID up by exact spelling, so a differently cased or padded one is not defined.
func (d *DevicePrivs) Defines(id string) bool {
	_, ok := d.ids[id]
	return ok
}

// DevicePrivs reads the device's privilege catalog from auth/priv/search, which
// lists what ACL::getPrivList() returns, in one search POST (no rowCount is sent,
// so the controller's default of 9999 rows applies). An error, a row without an
// ID, a listing that is cut short and a catalog that is not plausible are all
// errors.
func (c *Client) DevicePrivs(ctx context.Context) (*DevicePrivs, error) {
	body, err := c.doRequest(ctx, "POST", "/auth/priv/search", SearchRequest{})
	if err != nil {
		return nil, fmt.Errorf("listing the privilege catalog: %w", err)
	}
	var resp SearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing the privilege catalog: %w", err)
	}
	if resp.Total > len(resp.Rows) {
		return nil, fmt.Errorf("the privilege catalog was cut short: %d of %d IDs", len(resp.Rows), resp.Total)
	}
	ids := make([]string, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		id, ok := row["id"].(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("a row of the privilege catalog has no ID")
		}
		ids = append(ids, id)
	}
	return NewDevicePrivs(ids)
}
