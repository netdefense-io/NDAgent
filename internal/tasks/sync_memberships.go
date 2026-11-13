package tasks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
	"go.uber.org/zap"
)

// membershipPlan is the rule both sides of a group membership follow: a group's
// members are the members its GROUP declares plus every USER that names the
// group, and a list a snippet leaves out declares nothing from its side, so it
// never removes what the other side declares. A group no GROUP of the sync names
// follows the USERs' lists. A group a GROUP names whose members the sync does not
// write (the GROUP was refused, or is external) keeps the members it has, plus
// what USERs add.
//
// A user's own write adds a membership only the GROUP declares once that GROUP's
// write has gone through, so a group's privileges and its new members land
// together: the GROUP was judged with both. A member new to a group whose
// members the sync writes waits for the AUTH exclusion to cover its name,
// whichever side declares it.
type membershipPlan struct {
	written map[string]opnapi.APIGroupPayload // the groups whose member list this sync writes
	single  map[string]bool                   // groups exactly one GROUP element of the sync names
	landed  map[string]bool                   // written groups whose own write went through
	sent    map[string]string                 // the member list each landed group's write sent
	named   map[string]bool                   // every group a GROUP of the sync names
	users   map[string]opnapi.APIUserPayload  // the USERs this sync applies
	desired map[string]bool                   // every USER of the sync, applied or not
	live    map[string]map[string]bool        // each group's members before the sync
	auth    authDeferralInfo
}

func newMembershipPlan(applyUsers, users []opnapi.APIUserPayload, applyGroups, groups []opnapi.APIGroupPayload, live map[string]map[string]bool, auth authDeferralInfo) membershipPlan {
	p := membershipPlan{
		written: map[string]opnapi.APIGroupPayload{},
		single:  map[string]bool{},
		landed:  map[string]bool{},
		sent:    map[string]string{},
		named:   map[string]bool{},
		users:   map[string]opnapi.APIUserPayload{},
		desired: map[string]bool{},
		live:    live,
		auth:    auth,
	}
	for _, g := range groups {
		p.named[g.Name] = true
	}
	count := map[string]int{}
	for _, g := range applyGroups {
		count[g.Name]++
		if !g.ExternalMembers {
			p.written[g.Name] = g
		}
	}
	for name, n := range count {
		p.single[name] = n == 1
	}
	for _, u := range users {
		p.desired[u.Name] = true
	}
	for _, u := range applyUsers {
		p.users[u.Name] = u
	}
	return p
}

func (p membershipPlan) heldBack(group, user string) bool {
	_, written := p.written[group]
	return written && !p.live[group][user] && p.auth.isDeferred(user)
}

// noteGroupWritten records that the group's own write went through. Two GROUP
// elements of one name write the same group in turn, and which privileges it is
// left with is not this one's to say, so such a group never counts as landed.
func (p membershipPlan) noteGroupWritten(name, memberCSV string) {
	if _, written := p.written[name]; written && p.single[name] {
		p.landed[name] = true
		p.sent[name] = memberCSV
	}
}

// alreadySent says whether the group's own write already sent this member
// list, so writing it again would only cut another config revision. The lists
// compare in order, which groupMembers keeps stable: the declared members in
// their order, then the rest sorted.
func (p membershipPlan) alreadySent(name string, memberCSV *string) bool {
	sent, ok := p.sent[name]
	return ok && memberCSV != nil && sent == *memberCSV
}

// userGroups is the full list of groups the USER is a member of once the sync
// is applied, as names.
func (p membershipPlan) userGroups(u opnapi.APIUserPayload) []string {
	set := map[string]bool{}
	for _, g := range u.Groups {
		if !p.heldBack(g, u.Name) {
			set[g] = true
		}
	}
	for name, g := range p.written {
		live := p.live[name][u.Name]
		if containsName(g.Members, u.Name) && !p.heldBack(name, u.Name) && (live || p.landed[name]) {
			set[name] = true
		}
	}
	for name, members := range p.live {
		if _, written := p.written[name]; members[u.Name] && p.named[name] && !written {
			set[name] = true
		}
	}
	return sortedNames(set)
}

// userHeldBack is the groups the USER names itself that its membership in
// waits for the AUTH exclusion. The ones its GROUP also declares are reported
// with the GROUP.
func (p membershipPlan) userHeldBack(u opnapi.APIUserPayload) []string {
	set := map[string]bool{}
	for _, g := range u.Groups {
		if p.heldBack(g, u.Name) && !containsName(p.written[g].Members, u.Name) {
			set[g] = true
		}
	}
	return sortedNames(set)
}

// groupMembers is the full member list of a group whose members this sync
// writes, as names: what the GROUP declares first, in its order, then the
// rest sorted. Before the users are written (phase 2) a USER of the sync is
// left where it is: its own write adds it or takes it out, or tells why it did
// not.
func (p membershipPlan) groupMembers(g opnapi.APIGroupPayload, beforeUsers bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range g.Members {
		if !seen[m] && !p.heldBack(g.Name, m) {
			seen[m] = true
			out = append(out, m)
		}
	}
	rest := map[string]bool{}
	for name, u := range p.users {
		if containsName(u.Groups, g.Name) && !p.heldBack(g.Name, name) && (!beforeUsers || p.live[g.Name][name]) {
			rest[name] = true
		}
	}
	for name := range p.live[g.Name] {
		_, applied := p.users[name]
		if (p.desired[name] && !applied) || (beforeUsers && applied) {
			rest[name] = true
		}
	}
	for _, name := range sortedNames(rest) {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

// refuseUnknownUserGroups drops from the apply set a USER that names a group
// the device does not have and this sync does not create. The element fails the
// task and stays in the desired set, like every reject gate; its status is
// "error", not "blocked": what it asks for cannot be applied, whoever saved it.
func refuseUnknownUserGroups(applyUsers []opnapi.APIUserPayload, known, refused map[string]bool, log *zap.SugaredLogger) (kept []opnapi.APIUserPayload, results []SyncAPIItemResult, errs []string) {
	for _, u := range applyUsers {
		var missing, withheld []string
		for _, g := range u.Groups {
			switch {
			case known[g]:
			case refused[g]:
				withheld = append(withheld, fmt.Sprintf("%q", g))
			default:
				missing = append(missing, fmt.Sprintf("%q", g))
			}
		}
		if len(missing) == 0 && len(withheld) == 0 {
			kept = append(kept, u)
			continue
		}
		var why []string
		if len(missing) > 0 {
			why = append(why, fmt.Sprintf("group %s, which the device does not have and this sync does not create", strings.Join(missing, ", ")))
		}
		if len(withheld) > 0 {
			why = append(why, fmt.Sprintf("group %s, whose GROUP snippet this sync refused", strings.Join(withheld, ", ")))
		}
		msg := fmt.Sprintf("%s for user %q names %s; the user was not changed",
			snippetLabelFrom("user", u.SnippetName, u.SnippetIndex), u.Name, strings.Join(why, ", and "))
		log.Warnw("SYNC_API: refused a USER that names a group the device does not have", "name", u.Name, "missing", missing, "refused", withheld)
		results = append(results, SyncAPIItemResult{
			Type: "user", Name: u.Name, Action: "rejected", Status: "error", Code: userGroupUnknownCode, Error: msg,
		})
		errs = append(errs, msg)
	}
	return kept, results, errs
}

// memberCandidates is who a GROUP of the sync can have as a member: an account
// on the device, and a USER the sync applies that exists or can be created.
// The sync's other USERs are the ones it does not apply.
func memberCandidates(allUsers []map[string]interface{}, applyUsers, users []opnapi.APIUserPayload) (known, notApplied map[string]bool) {
	known = map[string]bool{}
	for _, raw := range allUsers {
		if name, _ := raw["name"].(string); name != "" {
			known[name] = true
		}
	}
	for _, u := range applyUsers {
		if known[u.Name] || u.Password != "" {
			known[u.Name] = true
		}
	}
	notApplied = map[string]bool{}
	for _, u := range users {
		if !known[u.Name] {
			notApplied[u.Name] = true
		}
	}
	return known, notApplied
}

// refuseUnknownGroupMembers drops from the apply set a GROUP that names a
// member that is neither an account on the device nor a USER of the sync: a
// mistake in the GROUP, which used to be left out of the list without a word.
// Like every reject gate it fails the task and stays in the desired set.
func refuseUnknownGroupMembers(applyGroups []opnapi.APIGroupPayload, known, notApplied map[string]bool, log *zap.SugaredLogger) (kept []opnapi.APIGroupPayload, results []SyncAPIItemResult, errs []string) {
	for _, g := range applyGroups {
		if g.ExternalMembers {
			kept = append(kept, g)
			continue
		}
		var missing []string
		for _, m := range g.Members {
			if !known[m] && !notApplied[m] {
				missing = append(missing, fmt.Sprintf("%q", m))
			}
		}
		if len(missing) == 0 {
			kept = append(kept, g)
			continue
		}
		msg := fmt.Sprintf("%s for group %q names member %s, which the device does not have and this sync does not create; the group was not changed",
			snippetLabelFrom("group", g.SnippetName, g.SnippetIndex), g.Name, strings.Join(missing, ", "))
		log.Warnw("SYNC_API: refused a GROUP that names a member the device does not have", "name", g.Name, "missing", missing)
		results = append(results, SyncAPIItemResult{
			Type: "group", Name: g.Name, Action: "rejected", Status: "error", Code: groupMemberUnknownCode, Error: msg,
		})
		errs = append(errs, msg)
	}
	return kept, results, errs
}

// reportUnappliedMembers says, for each member a GROUP declares that the sync
// would create and does not (its USER is refused, or is new without a
// password), that the group is written without it. The GROUP itself applies:
// the reason is the USER's, which has its own item.
func reportUnappliedMembers(applyGroups []opnapi.APIGroupPayload, notApplied map[string]bool) (results []SyncAPIItemResult, errs []string) {
	for _, g := range applyGroups {
		if g.ExternalMembers {
			continue
		}
		seen := map[string]bool{}
		for _, m := range g.Members {
			if !notApplied[m] || seen[m] {
				continue
			}
			seen[m] = true
			msg := fmt.Sprintf("%s for group %q names member %q, whose USER snippet this sync does not apply; the group does not get it",
				snippetLabelFrom("group", g.SnippetName, g.SnippetIndex), g.Name, m)
			results = append(results, SyncAPIItemResult{
				Type: "group_member", Name: g.Name + "/" + m, Action: "skipped", Status: "error", Code: groupMemberNotAppliedCode, Error: msg,
			})
			errs = append(errs, msg)
		}
	}
	return results, errs
}

// refuseInvalidGroups drops a GROUP whose content cannot be applied as written.
// Like every reject gate it fails the task and stays in the desired set.
func refuseInvalidGroups(groups []opnapi.APIGroupPayload) (kept []opnapi.APIGroupPayload, results []SyncAPIItemResult, errs []string) {
	for _, g := range groups {
		if g.ContentError == "" {
			kept = append(kept, g)
			continue
		}
		msg := fmt.Sprintf("%s for group %q: %s; the group was not changed",
			snippetLabelFrom("group", g.SnippetName, g.SnippetIndex), g.Name, g.ContentError)
		results = append(results, SyncAPIItemResult{
			Type: "group", Name: g.Name, Action: "rejected", Status: "error", Code: groupContentInvalidCode, Error: msg,
		})
		errs = append(errs, msg)
	}
	return kept, results, errs
}

// noteUserNotWritten treats a USER phase 3 did not write like a refused one:
// the memberships it has stay, and a group's write adds it nowhere.
func (p membershipPlan) noteUserNotWritten(name string) {
	delete(p.users, name)
}

// refuseInvalidUsers drops a USER whose content cannot be applied as written.
// Like every reject gate it fails the task and stays in the desired set.
func refuseInvalidUsers(users []opnapi.APIUserPayload) (kept []opnapi.APIUserPayload, results []SyncAPIItemResult, errs []string) {
	for _, u := range users {
		if u.ContentError == "" {
			kept = append(kept, u)
			continue
		}
		msg := fmt.Sprintf("%s for user %q: %s; the user was not changed",
			snippetLabelFrom("user", u.SnippetName, u.SnippetIndex), u.Name, u.ContentError)
		results = append(results, SyncAPIItemResult{
			Type: "user", Name: u.Name, Action: "rejected", Status: "error", Code: userContentInvalidCode, Error: msg,
		})
		errs = append(errs, msg)
	}
	return kept, results, errs
}

// phase4Groups is what phase 4 rewrites the members of: nothing when the users
// could not be listed again after phase 3.
func phase4Groups(applyGroups []opnapi.APIGroupPayload, usersListed bool) []opnapi.APIGroupPayload {
	if !usersListed {
		return nil
	}
	return applyGroups
}

const (
	userContentInvalidCode    = "USER_CONTENT_INVALID"
	userGroupUnknownCode      = "USER_GROUP_UNKNOWN"
	userGroupUnresolvedCode   = "USER_GROUP_UNRESOLVED"
	groupContentInvalidCode   = "GROUP_CONTENT_INVALID"
	groupMemberUnknownCode    = "GROUP_MEMBER_UNKNOWN"
	groupMemberNotAppliedCode = "GROUP_MEMBER_NOT_APPLIED"
)

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
