package opnapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// RowHolds reports whether a row, as an OPNsense search grid returns it (each
// field's stored value), already holds what writing wire would set, so the
// write can be skipped. It compares the keys the write sends: a field the wire
// struct leaves out (omitempty) is not sent, the device keeps its value, and so
// it is not compared. A row value that is not a string never matches.
func RowHolds(wire interface{}, row map[string]interface{}) bool {
	body, err := json.Marshal(wire)
	if err != nil {
		return false
	}
	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		return false
	}
	for key, value := range sent {
		want, ok := value.(string)
		if !ok {
			return false
		}
		got, ok := row[key].(string)
		if !ok || got != want {
			return false
		}
	}
	return true
}

// UserRowHolds is RowHolds for a user: its group_memberships (gids) and priv
// are lists, compared as sets, since the device may keep them in another order.
//
// The row holds authorizedkeys in base64 (StoreB64Field), which OPNsense makes
// of the text it is sent, so the write's keys are compared encoded. Every
// other field is always sent; the password, left out when there is none, is
// the one key that can go uncompared.
func UserRowHolds(user User, row map[string]interface{}) bool {
	if user.AuthorizedKeys != "" {
		user.AuthorizedKeys = base64.StdEncoding.EncodeToString([]byte(user.AuthorizedKeys))
	}
	return rowHoldsWithLists(user, row, "group_memberships", "priv")
}

// GroupRowHolds is RowHolds for a group: its priv and member (uids) are lists,
// compared as sets. A member the write does not send (nil) is not compared.
func GroupRowHolds(group Group, row map[string]interface{}) bool {
	return rowHoldsWithLists(group, row, "priv", "member")
}

// rowHoldsWithLists is RowHolds with the named keys compared as sets of their
// entries (sameCSVSet). Every value the write sends must be a string.
func rowHoldsWithLists(wire interface{}, row map[string]interface{}, lists ...string) bool {
	body, err := json.Marshal(wire)
	if err != nil {
		return false
	}
	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		return false
	}
	isList := map[string]bool{}
	for _, key := range lists {
		isList[key] = true
	}
	for key, value := range sent {
		want, ok := value.(string)
		if !ok {
			return false
		}
		got, ok := row[key].(string)
		if !ok {
			return false
		}
		if isList[key] {
			if !sameCSVSet(got, want) {
				return false
			}
		} else if got != want {
			return false
		}
	}
	return true
}

// sameCSVSet reports whether two comma-separated lists hold the same entries,
// in any order and with duplicates counted once. Entries are compared as
// written: OPNsense neither trims them nor drops an empty one, and a write
// with such an entry fails its validation, which a skip would hide.
func sameCSVSet(a, b string) bool {
	set := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, item := range strings.Split(s, ",") {
			out[item] = true
		}
		return out
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

// UserExpired reports whether a user row's expiry has passed by OPNsense's
// rule (auth.inc, Auth\Local): the day after the date, in the device's zone.
// OPNsense locks an expired account's shell and removes its authorized keys
// only when the user is written or at boot, so such a user is written on every
// sync. A date it stores in another form than MM/DD/YYYY counts as passed, as
// it does for OPNsense when the date cannot be read.
func UserExpired(row map[string]interface{}, now time.Time) bool {
	expires, _ := row["expires"].(string)
	if expires == "" {
		return false
	}
	date, err := time.ParseInLocation("01/02/2006", expires, now.Location())
	if err != nil {
		return true
	}
	return now.AddDate(0, 0, -1).After(date)
}
