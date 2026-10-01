package tasks

// sync_user_prune.go — deleting a managed user also takes it out of its groups.
//
// OPNsense's auth/user/del removes the account and nothing else: the uid stays in
// the `member` list of every group the user belonged to, the admins group
// included. The stale uid fails the model validation of that group on every later
// update, and OPNsense hands the freed uid to the next local account that takes
// one, including the account a directory login creates, which does not reconcile
// groups: that account is an administrator the moment it exists. So the sweep
// first posts an explicit empty group_memberships for the user, which OPNsense
// reconciles through the same code the GUI uses, and only then deletes it.
//
// That code takes one occurrence of the uid out of a member list per save, and a
// list can hold a uid twice (the directory login that edits it has to loop over
// duplicates for the same reason), so a save that succeeds can leave the uid
// behind. The sweep therefore reads the groups again and saves again, up to
// pruneMaxRounds times, and reports a uid that is still listed.

import (
	"context"
	"fmt"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// pruneMaxRounds bounds how many times the sweep saves a user's empty group list.
const pruneMaxRounds = 3

// orphanMemberships tells, for the users the sweep is about to delete, whether
// they belong to any group and whether any of those is administrator-equivalent.
// It is built from the rows the sync last read: the users after Phase 3, whose
// own group lists OPNsense derives from the current member lists, and the groups
// after Phase 2, which is the last phase that changes a group's members for a
// user that already exists. Each is enough on its own, so a group read that
// failed leaves the user's own list.
type orphanMemberships struct {
	memberOfAny map[string]bool // uid -> listed in some group's member list
	index       *opnapi.AccessIndex
}

func newOrphanMemberships(users, groups []map[string]interface{}, policy opnapi.PrivPolicy, defined *opnapi.DevicePrivs) *orphanMemberships {
	m := &orphanMemberships{
		memberOfAny: map[string]bool{},
		index:       opnapi.BuildAccessIndex(users, groups, policy, defined),
	}
	for _, group := range groups {
		member, _ := group["member"].(string)
		for _, uid := range opnapi.CSVToStrings(member) {
			m.memberOfAny[uid] = true
		}
	}
	return m
}

// of reports whether the user belongs to any group, and to an administrator-
// equivalent one.
func (m *orphanMemberships) of(user map[string]interface{}) (member, elevated bool) {
	uid, _ := user["uid"].(string)
	groupList, _ := user["group_memberships"].(string)
	member = (uid != "" && m.memberOfAny[uid]) || len(opnapi.CSVToStrings(groupList)) > 0

	name, _ := user["name"].(string)
	_, reasons := m.index.ElevatedUser(name)
	return member, opnapi.HasMembershipReason(reasons)
}

// anyElevated reports whether any of the named groups is administrator-equivalent.
func (m *orphanMemberships) anyElevated(groupNames []string) bool {
	for _, name := range groupNames {
		if _, reasons := m.index.ElevatedGroup(name); len(reasons) > 0 {
			return true
		}
	}
	return false
}

// pruneMemberships takes the user out of every group and checks that it worked.
// It returns the names of the groups that still list the uid after the last
// round. A group listing that cannot be read leaves nothing to check against, and
// is not an error: the prune itself did not fail.
func pruneMemberships(ctx context.Context, client *opnapi.Client, uuid, name, uid string) ([]string, error) {
	var left []string
	for round := 0; round < pruneMaxRounds; round++ {
		if err := client.ClearUserGroupMemberships(ctx, uuid, name); err != nil {
			return nil, err
		}
		if uid == "" {
			return nil, nil
		}
		groups, err := client.ListAllGroups(ctx)
		if err != nil {
			return nil, nil
		}
		if left = groupsListing(groups, uid); len(left) == 0 {
			return nil, nil
		}
	}
	return left, nil
}

// groupsListing returns the names of the groups whose member list names the uid.
func groupsListing(groups []map[string]interface{}, uid string) []string {
	var names []string
	for _, group := range groups {
		member, _ := group["member"].(string)
		for _, listed := range opnapi.CSVToStrings(member) {
			if listed == uid {
				name, _ := group["name"].(string)
				names = append(names, name)
				break
			}
		}
	}
	return names
}

// stillListedError describes a uid that the prune left in these groups.
func stillListedError(groupNames []string) error {
	quoted := make([]string, len(groupNames))
	for i, n := range groupNames {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Errorf("OPNsense still lists its uid in %s after %d attempts", strings.Join(quoted, ", "), pruneMaxRounds)
}

// pruneMembershipsFailure is what a failed prune becomes. The delete still goes
// ahead: the account is what the operator removed, and keeping an administrator
// account that was detached is the worse outcome. A failure that leaves the uid
// in an administrator-equivalent group fails the task, with an item and the same
// text in errors; one that leaves it in ordinary groups is a warning.
func pruneMembershipsFailure(name, uuid string, elevated bool, err error) (SyncAPIItemResult, string) {
	where := "its groups"
	if elevated {
		where = "an administrator-equivalent group"
	}
	msg := fmt.Sprintf("User %s: could not remove it from %s before deleting it, so its uid may be left in a group member list: %v", name, where, err)
	item := SyncAPIItemResult{
		Type:   "user",
		UUID:   uuid,
		Name:   name,
		Action: "remove_group_memberships",
		Status: "warning",
		Error:  msg,
	}
	if elevated {
		item.Status = "error"
		return item, msg
	}
	return item, ""
}
