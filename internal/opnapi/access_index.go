package opnapi

// access_index.go — which local accounts and groups are administrator-equivalent
// on THIS device, from the live rows.
//
// The catalog says which privileges are; only the device knows which groups hold
// them and who belongs to those groups. An account is administrator-equivalent
// when it is uid 0, a protected user, system-scoped, holds such a privilege
// directly, is flagged is_admin by OPNsense itself, or belongs to an
// administrator-equivalent group. A group is when it is protected (admins,
// netdefense-readonly), has the built-in admins gid, or holds such a privilege.
//
// A privilege ID counts only if the device defines it (DevicePrivs): OPNsense
// ignores one its ACL catalog does not have, so a row that holds only such IDs
// grants nothing and is not elevated by them.
//
// Membership is read both ways OPNsense keeps it, and the two are united: a
// group row's `member` (a CSV of uids, what OPNsense's ACL reads) and a user
// row's `group_memberships` (a CSV of gids, derived from the same lists). A uid
// with no user row, which a deleted user leaves behind in a group, names nobody.
//
// OPNsense sends every field this file classifies by as a string. A row with one
// of them in another shape (a list, an object, a bool where text belongs) cannot
// be classified, so it is administrator-equivalent: reading it as empty would
// blind the gate to the row it could not read.

import (
	"strconv"
	"strings"
)

// Reasons an account or group is administrator-equivalent. They are stable
// strings for logs and for callers that branch on the kind; none carries a
// submitted value (a privilege is named only when the catalog names it).
const (
	ReasonUID0             = "uid-0"
	ReasonProtectedUser    = "protected-user"
	ReasonProtectedGroup   = "protected-group"
	ReasonBuiltinAdminsGID = "builtin-admins-gid"
	ReasonSystemScope      = "system-scope"
	ReasonIsAdmin          = "is-admin"
	ReasonPlanned          = "planned"
	ReasonPrivPrefix       = "priv:"
	ReasonMemberOfPrefix   = "member-of:"
	ReasonPrivUnrecognized = ReasonPrivPrefix + "unrecognized"

	// ReasonPlannedMemberOfPrefix marks an account that a group of the same sync,
	// administrator-equivalent once applied, is about to make a member of.
	ReasonPlannedMemberOfPrefix = "planned-member-of:"

	// ReasonUnreadablePrefix marks a row whose field (named after the prefix) is
	// not in a shape OPNsense sends.
	ReasonUnreadablePrefix = "unreadable:"
)

type accessEntry struct {
	name    string
	reasons []string
}

// AccessIndex is built from one snapshot of the device's user and group rows.
// Lookups are by name, trimmed and lowercased: a spelling that only differs in
// case or padding is the same account as far as a gate is concerned.
type AccessIndex struct {
	groups map[string]*accessEntry
	users  map[string]*accessEntry

	// members is, for every live group, the names of the accounts the live rows
	// place in it: group name (normalized) -> account name (normalized) -> as shown.
	members map[string]map[string]string
}

// BuildAccessIndex indexes the rows of /auth/user/search and /auth/group/search.
// Either may be nil: the index then knows nothing and every lookup answers "not
// elevated".
//
// defined is the device's own privilege catalog. A privilege ID in a live row that
// the device does not define grants nothing there (OPNsense ignores it), so it is
// inert: it makes no row elevated. An ID the device defines that the agent's
// catalog does not know stays elevated, as an unreviewed plugin privilege. With a
// nil defined, because the catalog could not be read, every such ID is elevated,
// as it is in snippet content.
func BuildAccessIndex(users, groups []map[string]interface{}, policy PrivPolicy, defined *DevicePrivs) *AccessIndex {
	ix := &AccessIndex{
		groups:  map[string]*accessEntry{},
		users:   map[string]*accessEntry{},
		members: map[string]map[string]string{},
	}

	userNameByUID := map[string]string{}
	for _, row := range users {
		if uid, name := rowString(row, "uid"), rowString(row, "name"); uid != "" && name != "" {
			userNameByUID[uid] = name
		}
	}
	groupNameByGID := map[string]string{}
	for _, row := range groups {
		if gid, name := rowString(row, "gid"), rowString(row, "name"); gid != "" && name != "" {
			groupNameByGID[gid] = name
		}
	}

	elevatedGroupByGID := map[string]string{} // gid -> the group's own name
	memberOf := map[string][]string{}         // uid -> elevated group names
	for _, row := range groups {
		name := rowString(row, "name")
		uids := CSVToStrings(rowString(row, "member"))
		for _, uid := range uids {
			if member, ok := userNameByUID[uid]; ok {
				ix.addMember(name, member)
			}
		}

		var reasons []string
		if _, ok := ProtectedGroupCanonicalName(name); ok {
			reasons = append(reasons, ReasonProtectedGroup)
		}
		gid := rowString(row, "gid")
		if gid == BuiltinAdminGID {
			reasons = append(reasons, ReasonBuiltinAdminsGID)
		}
		reasons = append(reasons, privReasons(policy, defined, rowString(row, "priv"))...)
		reasons = append(reasons, unreadableReasons(row, false, "gid", "priv", "member")...)

		if len(reasons) == 0 {
			continue
		}
		ix.add(ix.groups, name, reasons)
		if gid != "" {
			elevatedGroupByGID[gid] = name
		}
		for _, uid := range uids {
			memberOf[uid] = append(memberOf[uid], name)
		}
	}

	for _, row := range users {
		name := rowString(row, "name")
		uid := rowString(row, "uid")

		var reasons []string
		if uid == "0" {
			reasons = append(reasons, ReasonUID0)
		}
		if ProtectedUsernames[name] {
			reasons = append(reasons, ReasonProtectedUser)
		}
		if rowString(row, "scope") == "system" {
			reasons = append(reasons, ReasonSystemScope)
		}
		reasons = append(reasons, privReasons(policy, defined, rowString(row, "priv"))...)
		if rowTruthy(row, "is_admin") {
			reasons = append(reasons, ReasonIsAdmin)
		}
		reasons = append(reasons, unreadableReasons(row, false, "uid", "scope", "priv", "group_memberships")...)
		reasons = append(reasons, unreadableReasons(row, true, "is_admin")...)

		joined := map[string]bool{}
		join := func(group string) {
			if !joined[group] {
				joined[group] = true
				reasons = append(reasons, ReasonMemberOfPrefix+group)
			}
		}
		if uid != "" {
			for _, group := range memberOf[uid] {
				join(group)
			}
		}
		for _, gid := range CSVToStrings(rowString(row, "group_memberships")) {
			if group, ok := groupNameByGID[gid]; ok {
				ix.addMember(group, name)
			}
			if group, ok := elevatedGroupByGID[gid]; ok {
				join(group)
			}
		}

		if len(reasons) > 0 {
			ix.add(ix.users, name, reasons)
		}
	}
	return ix
}

// AddPlannedGroup records a group that is about to become administrator-
// equivalent, because a desired element of the same sync gives it such a
// privilege. A USER in that sync that names it is judged against what the group
// will be, not what it is now, and so is every account that will be a member of
// it once applied: the members the element declares, and the ones the group has
// now, which a sync that declares none leaves as they are.
func (ix *AccessIndex) AddPlannedGroup(name string, declaredMembers []string) {
	key := normalizeAccountName(name)
	if key == "" {
		return
	}
	ix.add(ix.groups, name, []string{ReasonPlanned})

	reason := []string{ReasonPlannedMemberOfPrefix + strings.Trim(name, privTrimSet)}
	// The accounts that exist come first, so one that is also declared keeps the
	// name it has on the device.
	for _, member := range ix.members[key] {
		ix.add(ix.users, member, reason)
	}
	for _, member := range declaredMembers {
		ix.add(ix.users, strings.Trim(member, privTrimSet), reason)
	}
}

// ElevatedGroup returns the live group's own name and why it is administrator-
// equivalent, or "" and nil when it is not (or is unknown).
func (ix *AccessIndex) ElevatedGroup(name string) (string, []string) {
	return lookup(ix.groups, name)
}

// ElevatedUser returns the live account's own name and why it is
// administrator-equivalent, or "" and nil when it is not (or is unknown).
func (ix *AccessIndex) ElevatedUser(name string) (string, []string) {
	return lookup(ix.users, name)
}

// HasMembershipReason reports whether any of reasons says the account belongs to
// an administrator-equivalent group.
func HasMembershipReason(reasons []string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, ReasonMemberOfPrefix) {
			return true
		}
	}
	return false
}

// PlannedMembership reports, for the reasons an account is administrator-
// equivalent, whether they are all of the planned kind (the account is not, but a
// group of the same sync is about to make it one), and through which group.
func PlannedMembership(reasons []string) (group string, only bool) {
	if len(reasons) == 0 {
		return "", false
	}
	for _, r := range reasons {
		if !strings.HasPrefix(r, ReasonPlannedMemberOfPrefix) {
			return "", false
		}
		if group == "" {
			group = strings.TrimPrefix(r, ReasonPlannedMemberOfPrefix)
		}
	}
	return group, true
}

// What makes an entry administrator-equivalent when its operator cannot see it
// on the device. OPNsense ignores a privilege ID its ACL does not define and does
// not list it, so a group that holds only such an ID looks ordinary in the GUI.
const (
	CauseUnrecognizedPriv = "unrecognized-priv"
	CauseUnreadable       = "unreadable"
)

// OpaqueCause says why the reasons make an account or group administrator-
// equivalent when that is the whole reason and is one the operator cannot read
// off the device: an ID the catalog does not know, or a row the agent could not
// read. For an account that is a member of such a group it also returns the
// group. Any other reason, a privilege the catalog names included, is one the
// refusal message already spells out, and the cause is "".
func (ix *AccessIndex) OpaqueCause(reasons []string) (cause, viaGroup string) {
	if len(reasons) == 0 {
		return "", ""
	}
	for _, r := range reasons {
		var c, via string
		switch {
		case r == ReasonPrivUnrecognized:
			c = CauseUnrecognizedPriv
		case strings.HasPrefix(r, ReasonUnreadablePrefix):
			c = CauseUnreadable
		case strings.HasPrefix(r, ReasonMemberOfPrefix):
			via = strings.TrimPrefix(r, ReasonMemberOfPrefix)
			_, groupReasons := ix.ElevatedGroup(via)
			if c = opaqueOnly(groupReasons); c == "" {
				return "", ""
			}
		default:
			return "", ""
		}
		if cause == "" {
			cause, viaGroup = c, via
		}
	}
	return cause, viaGroup
}

// opaqueOnly is the cause when every one of a group's reasons is opaque.
func opaqueOnly(reasons []string) string {
	cause := ""
	for _, r := range reasons {
		switch {
		case r == ReasonPrivUnrecognized:
			if cause == "" {
				cause = CauseUnrecognizedPriv
			}
		case strings.HasPrefix(r, ReasonUnreadablePrefix):
			cause = CauseUnreadable
		default:
			return ""
		}
	}
	return cause
}

func (ix *AccessIndex) addMember(group, member string) {
	key, memberKey := normalizeAccountName(group), normalizeAccountName(member)
	if key == "" || memberKey == "" {
		return
	}
	if ix.members[key] == nil {
		ix.members[key] = map[string]string{}
	}
	ix.members[key][memberKey] = member
}

func (ix *AccessIndex) add(into map[string]*accessEntry, name string, reasons []string) {
	key := normalizeAccountName(name)
	if key == "" {
		return
	}
	entry := into[key]
	if entry == nil {
		entry = &accessEntry{name: name}
		into[key] = entry
	}
	for _, r := range reasons {
		if !containsString(entry.reasons, r) {
			entry.reasons = append(entry.reasons, r)
		}
	}
}

func lookup(from map[string]*accessEntry, name string) (string, []string) {
	if entry := from[normalizeAccountName(name)]; entry != nil {
		return entry.name, append([]string(nil), entry.reasons...)
	}
	return "", nil
}

func privReasons(policy PrivPolicy, defined *DevicePrivs, privCSV string) []string {
	names, unrecognized := policy.elevatedTokens(liveTokens(defined, privCSV))
	var reasons []string
	for _, n := range names {
		reasons = append(reasons, ReasonPrivPrefix+n)
	}
	if unrecognized > 0 {
		reasons = append(reasons, ReasonPrivUnrecognized)
	}
	return reasons
}

// liveTokens are the privilege tokens of a live row's priv CSV that count. With
// the device's catalog they are the IDs it defines, read as OPNsense reads them:
// split on commas, looked up by exact spelling, so a padded or differently cased
// ID is not defined and grants nothing. Without the catalog they are every token,
// normalized, as in snippet content.
func liveTokens(defined *DevicePrivs, privCSV string) []string {
	if defined == nil {
		return privTokens(privCSV)
	}
	var tokens []string
	for _, raw := range strings.Split(privCSV, ",") {
		if raw != "" && defined.Defines(raw) {
			tokens = append(tokens, normalizePrivToken(raw))
		}
	}
	return tokens
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// rowString reads a field of a search row. OPNsense sends model fields as
// strings; a number is read as its integer form so a fixture or a future release
// that sends one still names the same uid or gid. A field of any other shape
// reads as empty here, and unreadableReasons is what says it was not.
func rowString(row map[string]interface{}, key string) string {
	switch v := row[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	}
	return ""
}

func rowTruthy(row map[string]interface{}, key string) bool {
	switch v := row[key].(type) {
	case string:
		return v == "1" || strings.EqualFold(v, "true")
	case bool:
		return v
	case float64:
		return v != 0
	}
	return false
}

// unreadableReasons names the fields of a row that are present in a shape
// rowString (or rowTruthy, for flags) does not read. An absent field, a null and
// an empty list or object are nothing set, not unreadable.
func unreadableReasons(row map[string]interface{}, flags bool, keys ...string) []string {
	var reasons []string
	for _, key := range keys {
		unreadable := false
		switch v := row[key].(type) {
		case nil, string, float64:
		case bool:
			unreadable = !flags
		case []interface{}:
			unreadable = len(v) > 0
		case map[string]interface{}:
			unreadable = len(v) > 0
		default:
			unreadable = true
		}
		if unreadable {
			reasons = append(reasons, ReasonUnreadablePrefix+key)
		}
	}
	return reasons
}
