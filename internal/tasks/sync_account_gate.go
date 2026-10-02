package tasks

// sync_account_gate.go — the per-element pre-flight USER and GROUP elements pass
// through before anything is written.
//
// Three checks apply, in this order, and the first to refuse an element wins:
//
//  1. The password contract (USER only, once the live rows are known): a
//     password is plaintext, never a hash. See checkPasswordShape.
//  2. Superuser clearance. The control plane attests, per snippet and inside the
//     signed SYNC payload, that a Superuser authored the content as delivered
//     (content_clearance "org:su"). An element without it may not give an account
//     administrator rights or take one over: add membership in an administrator-
//     equivalent group, grant an administrator-equivalent privilege, make a group
//     administrator-equivalent, or modify any field of an existing
//     administrator-equivalent user or group (the agent adopts an existing
//     account by name, so the password, the disabled flag or a description are
//     all a takeover). Which groups and accounts are administrator-equivalent is
//     decided from the live rows, which only the device has, and from the other
//     elements of the same sync: one without clearance may not share its name
//     with one that has it, and may not change an account that a group of the
//     sync makes administrator-equivalent. This refusal does not depend on
//     reject_dangerous_snippets: the owner's switch cannot lift a rule the
//     control plane enforces for the org.
//  3. The device owner's policy, reject_dangerous_snippets, which only adds
//     refusals and applies to Superuser-cleared elements too.
//
// An element that passes all three then has its password settled: one the stored
// hash already verifies is left out (see dropUnchangedPassword). That costs a
// password hash computation, so it comes last, after every cheap refusal.
//
// A refused element is dropped from the create/update pass, recorded as a
// blocked item whose message is also appended to the task's errors, and stays in
// the desired set, so the orphan sweep never deletes what a refusal merely
// declined to rewrite. The gate is evaluated twice per sync: before discovery,
// with the rows it needs none of (protected names, privileges), so a refusal
// survives a discovery failure; and after discovery, with the live rows. A
// refusal that needs no rows is therefore found in the first pass, ahead of the
// password check, which needs the stored hash.

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// storedPasswordVerifies is the test seam for the one expensive step of the gate.
var storedPasswordVerifies = opnapi.StoredPasswordVerifies

const (
	// snippetClearanceKey is the per-snippet key of the clearance NDManager
	// seals into a USER/GROUP entry of the signed SYNC payload. The value is
	// exactly snippetClearanceSuperuser when a Superuser cleared the snippet and
	// the key is absent otherwise; anything else reads as not cleared.
	snippetClearanceKey       = "content_clearance"
	snippetClearanceSuperuser = "org:su"

	// codeAdminEquivalentRequiresSuperuser is the structured code of a refusal
	// for missing Superuser clearance, for consumers to key on.
	codeAdminEquivalentRequiresSuperuser = "ADMIN_EQUIVALENT_REQUIRES_SUPERUSER"

	// codeUserPasswordIsHash is the structured code of a refusal of a USER whose
	// password has the shape of a password hash.
	codeUserPasswordIsHash = "USER_PASSWORD_IS_HASH"

	// maxClauses caps how many reasons one refusal message spells out.
	maxClauses = 3
)

// snippetSuperuserCleared reads a SYNC payload snippet's clearance. Strict by
// construction: only the exact string grants it.
func snippetSuperuserCleared(snippet map[string]interface{}) bool {
	v, ok := snippet[snippetClearanceKey].(string)
	return ok && v == snippetClearanceSuperuser
}

// refusal is why an element was kept out of the apply passes.
type refusal struct {
	code    string
	message string
}

// clearedSnippet is where a Superuser-cleared element of the sync came from.
type clearedSnippet struct {
	name  string
	index int
}

type accountGate struct {
	policy          opnapi.PrivPolicy
	index           *opnapi.AccessIndex
	rejectDangerous bool
	log             *zap.SugaredLogger

	// storedPasswords is what the device holds for each user's password, by
	// exact name: OPNsense hashes the password it is sent, and a search row
	// returns the hash. Nil until the live rows are known.
	storedPasswords map[string]string

	// clearedUsers and clearedGroups are the Superuser-cleared elements of the
	// whole sync, by normalized name, whether or not each is applied.
	clearedUsers  map[string]clearedSnippet
	clearedGroups map[string]clearedSnippet
}

func newAccountGate(policy opnapi.PrivPolicy, rejectDangerous bool, log *zap.SugaredLogger) *accountGate {
	return &accountGate{
		policy:          policy,
		index:           opnapi.BuildAccessIndex(nil, nil, policy, nil),
		rejectDangerous: rejectDangerous,
		log:             log,
		clearedUsers:    map[string]clearedSnippet{},
		clearedGroups:   map[string]clearedSnippet{},
	}
}

// noteCleared records which elements of the sync a Superuser cleared, so one
// without clearance that shares its name with one of them is recognized: it would
// edit the account or group the Superuser provisioned, and whichever is written
// last wins.
func (g *accountGate) noteCleared(users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload) {
	for _, u := range users {
		if key := opnapi.AccountNameKey(u.Name); u.SuperuserCleared && key != "" {
			if _, seen := g.clearedUsers[key]; !seen {
				g.clearedUsers[key] = clearedSnippet{name: u.SnippetName, index: u.SnippetIndex}
			}
		}
	}
	for _, group := range groups {
		if key := opnapi.AccountNameKey(group.Name); group.SuperuserCleared && key != "" {
			if _, seen := g.clearedGroups[key]; !seen {
				g.clearedGroups[key] = clearedSnippet{name: group.SnippetName, index: group.SnippetIndex}
			}
		}
	}
}

// useLiveRows gives the gate what only the device knows: its rows, and the
// privilege IDs it defines (nil when that could not be read).
func (g *accountGate) useLiveRows(users, groups []map[string]interface{}, defined *opnapi.DevicePrivs) {
	g.index = opnapi.BuildAccessIndex(users, groups, g.policy, defined)
	g.storedPasswords = make(map[string]string, len(users))
	for _, row := range users {
		name, _ := row["name"].(string)
		if stored, _ := row["password"].(string); name != "" && stored != "" {
			g.storedPasswords[name] = stored
		}
	}
}

// planGroups records the desired GROUP elements that will be administrator-
// equivalent once applied, so a USER of the same sync that names one, or that is
// a member of one, is judged against what the group is about to make it.
func (g *accountGate) planGroups(groups []opnapi.APIGroupPayload) {
	for _, group := range groups {
		if g.policy.HasAdminEquivalentPriv(group.Priv) {
			g.index.AddPlannedGroup(group.Name, group.Members)
		}
	}
}

// filterUsers returns the USER elements the gate lets through; record is called
// once for each it refuses.
func (g *accountGate) filterUsers(users []opnapi.APIUserPayload, record func(kind, name string, r refusal)) []opnapi.APIUserPayload {
	accepted := make([]opnapi.APIUserPayload, 0, len(users))
	for _, u := range users {
		if r := g.checkUser(&u); r != nil {
			record("user", u.Name, *r)
			continue
		}
		accepted = append(accepted, u)
	}
	return accepted
}

// filterGroups is filterUsers for GROUP elements.
func (g *accountGate) filterGroups(groups []opnapi.APIGroupPayload, record func(kind, name string, r refusal)) []opnapi.APIGroupPayload {
	accepted := make([]opnapi.APIGroupPayload, 0, len(groups))
	for _, group := range groups {
		if r := g.checkGroup(group); r != nil {
			record("group", group.Name, *r)
			continue
		}
		accepted = append(accepted, group)
	}
	return accepted
}

// checkUser judges one USER element. It may also settle the element's password
// (see checkPasswordShape and dropUnchangedPassword), which is why it takes a
// pointer to the copy the caller keeps when the element is let through.
func (g *accountGate) checkUser(u *opnapi.APIUserPayload) *refusal {
	if g.storedPasswords != nil {
		if r := g.checkPasswordShape(u); r != nil {
			return r
		}
	}
	if !u.SuperuserCleared {
		if clauses := g.userClauses(*u); len(clauses) > 0 {
			g.log.Warnw("SYNC_API: refused USER element that needs Superuser clearance",
				"name", u.Name,
				"snippet", u.SnippetName,
				"clauses", clauses,
			)
			return &refusal{
				code:    codeAdminEquivalentRequiresSuperuser,
				message: clearanceRefusalMessage("user", u.Name, u.SnippetName, u.SnippetIndex, clauses),
			}
		}
	}
	if g.rejectDangerous {
		fields := opnapi.DangerousUserFields(*u, g.policy)
		if g.userJoinsElevatedGroup(*u) {
			fields = withGroupsField(fields)
		}
		if len(fields) > 0 {
			g.log.Warnw("SYNC_API: rejected USER snippet carrying dangerous field(s) (reject_dangerous_snippets enabled)",
				"name", u.Name,
				"fields", fields,
			)
			return &refusal{message: dangerousSnippetRejectionMessage("user", u.Name, fields)}
		}
	}
	if g.storedPasswords != nil {
		g.dropUnchangedPassword(u)
	}
	return nil
}

// checkPasswordShape applies the contract of a USER snippet's password: it is
// plaintext, because OPNsense hashes whatever it is sent, so a hash would become
// the password itself and lock the intended one out. An element whose password
// has the shape of a hash is refused, unless it is byte for byte the hash the
// device already holds for that user, which changes nothing: the password is
// then left out and the rest of the element applies.
func (g *accountGate) checkPasswordShape(u *opnapi.APIUserPayload) *refusal {
	if u.Password == "" || !opnapi.IsCryptHashShaped(u.Password) {
		return nil
	}
	if g.storedPasswords[u.Name] == u.Password {
		u.Password = ""
		return nil
	}
	g.log.Warnw("SYNC_API: refused USER element whose password has the shape of a hash",
		"name", u.Name,
		"snippet", u.SnippetName,
	)
	return &refusal{code: codeUserPasswordIsHash, message: passwordIsHashMessage(*u)}
}

// dropUnchangedPassword leaves out a plaintext that the stored hash already
// verifies. OPNsense re-hashes every password it is sent, with a new salt each
// time, so re-posting an unchanged one gives the account a new stored hash and
// resets its password-changed time on every SYNC. A stored hash that cannot be
// verified (see opnapi.StoredPasswordVerifies) leaves the plaintext to be posted
// as before. The check computes a password hash, which is why it runs only for an
// element that nothing refused.
func (g *accountGate) dropUnchangedPassword(u *opnapi.APIUserPayload) {
	if u.Password == "" {
		return
	}
	if storedPasswordVerifies(g.storedPasswords[u.Name], u.Password) {
		u.Password = ""
	}
}

// passwordIsHashMessage names the snippet and the user and states the remedy. It
// never contains the value.
func passwordIsHashMessage(u opnapi.APIUserPayload) string {
	return fmt.Sprintf(
		"rejected: %s for user %q carries a password with the shape of a password hash. OPNsense hashes whatever it is sent, so a hash would become the password itself and lock the intended one out; put the plaintext password in a secret variable (${NAME}) and sync again",
		snippetLabelFrom("user", u.SnippetName, u.SnippetIndex), u.Name,
	)
}

func (g *accountGate) checkGroup(group opnapi.APIGroupPayload) *refusal {
	if !group.SuperuserCleared {
		if clauses := g.groupClauses(group); len(clauses) > 0 {
			g.log.Warnw("SYNC_API: refused GROUP element that needs Superuser clearance",
				"name", group.Name,
				"snippet", group.SnippetName,
				"clauses", clauses,
			)
			return &refusal{
				code:    codeAdminEquivalentRequiresSuperuser,
				message: clearanceRefusalMessage("group", group.Name, group.SnippetName, group.SnippetIndex, clauses),
			}
		}
	}
	if g.rejectDangerous {
		if fields := opnapi.DangerousGroupFields(group, g.policy); len(fields) > 0 {
			g.log.Warnw("SYNC_API: rejected GROUP snippet carrying dangerous field(s) (reject_dangerous_snippets enabled)",
				"name", group.Name,
				"fields", fields,
			)
			return &refusal{message: dangerousSnippetRejectionMessage("group", group.Name, fields)}
		}
	}
	return nil
}

// userJoinsElevatedGroup reports whether any group a USER element names is, or
// this sync will make it, administrator-equivalent: the owner's policy refuses
// that even for a Superuser-cleared element.
func (g *accountGate) userJoinsElevatedGroup(u opnapi.APIUserPayload) bool {
	for _, entry := range u.Groups {
		for _, part := range opnapi.SplitGroupEntry(entry) {
			if _, ok := g.groupElevation(part); ok {
				return true
			}
		}
	}
	return false
}

// withGroupsField adds "groups" to dangerous fields in the place
// opnapi.DangerousUserFields puts it, after "priv", unless it is there already.
func withGroupsField(fields []string) []string {
	for _, f := range fields {
		if f == "groups" {
			return fields
		}
	}
	at := 0
	if len(fields) > 0 && fields[0] == "priv" {
		at = 1
	}
	out := append([]string{}, fields[:at]...)
	out = append(out, "groups")
	return append(out, fields[at:]...)
}

// groupElevation says whether name is, or this sync will make it, an
// administrator-equivalent group, and returns the name to show.
func (g *accountGate) groupElevation(name string) (string, bool) {
	shown, reasons := g.groupElevationReasons(name)
	return shown, len(reasons) > 0
}

// groupElevationReasons is groupElevation with the reasons, which are empty when
// the group is not administrator-equivalent.
func (g *accountGate) groupElevationReasons(name string) (string, []string) {
	if canonical, ok := opnapi.ProtectedGroupCanonicalName(name); ok {
		return canonical, []string{opnapi.ReasonProtectedGroup}
	}
	return g.index.ElevatedGroup(name)
}

// elevationNote is the parenthesis that explains an administrator-equivalent
// verdict the operator cannot read off the device: a privilege ID the catalog does
// not know (OPNsense ignores one its ACL does not define, and does not show it),
// or a row the agent could not read. A verdict with any other reason, a privilege
// the catalog names included, needs none and gets "".
func (g *accountGate) elevationNote(reasons []string) string {
	cause, via := g.index.OpaqueCause(reasons)
	if cause == "" {
		return ""
	}
	subject := "it"
	if via != "" {
		subject = fmt.Sprintf("group %q", via)
	}
	if cause == opnapi.CauseUnreadable {
		return fmt.Sprintf(" (%s has a row the agent could not read)", subject)
	}
	return fmt.Sprintf(" (%s holds a privilege ID the catalog does not know)", subject)
}

// sameNameClause is the clause of an element without clearance that shares its
// name, trimmed and case-insensitively, with a cleared element of the same kind.
func sameNameClause(kind string, other clearedSnippet) string {
	return fmt.Sprintf("shares its name with the Superuser-cleared %s", snippetLabelFrom(kind, other.name, other.index))
}

// userClauses lists what a USER element would do that only a Superuser may.
func (g *accountGate) userClauses(u opnapi.APIUserPayload) []string {
	var clauses []string

	if other, ok := g.clearedUsers[opnapi.AccountNameKey(u.Name)]; ok {
		clauses = append(clauses, sameNameClause("user", other))
	}

	seen := map[string]bool{}
	for _, entry := range u.Groups {
		for _, part := range opnapi.SplitGroupEntry(entry) {
			if group, reasons := g.groupElevationReasons(part); len(reasons) > 0 && !seen[group] {
				seen[group] = true
				clauses = append(clauses, fmt.Sprintf("would add membership in administrator-equivalent group %q%s", group, g.elevationNote(reasons)))
			}
		}
	}
	if clause := g.privClause(u.Priv); clause != "" {
		clauses = append(clauses, clause)
	}
	if strings.EqualFold(strings.TrimSpace(u.Scope), "system") {
		clauses = append(clauses, "would give the account the system scope")
	}
	if live, reasons := g.index.ElevatedUser(u.Name); len(reasons) > 0 {
		if group, planned := opnapi.PlannedMembership(reasons); planned {
			clauses = append(clauses, fmt.Sprintf("would change user %q, which this sync makes administrator-equivalent through group %q", live, group))
		} else {
			clauses = append(clauses, fmt.Sprintf("would modify existing administrator-equivalent user %q%s", live, g.elevationNote(reasons)))
		}
	}
	return clauses
}

// groupClauses lists what a GROUP element would do that only a Superuser may.
func (g *accountGate) groupClauses(group opnapi.APIGroupPayload) []string {
	var clauses []string
	if other, ok := g.clearedGroups[opnapi.AccountNameKey(group.Name)]; ok {
		clauses = append(clauses, sameNameClause("group", other))
	}
	if clause := g.privClause(group.Priv); clause != "" {
		clauses = append(clauses, clause)
	}
	if live, reasons := g.groupElevationReasons(group.Name); len(reasons) > 0 {
		clauses = append(clauses, fmt.Sprintf("would modify existing administrator-equivalent group %q%s", live, g.elevationNote(reasons)))
	}
	return clauses
}

// privClause names the administrator-equivalent privileges of a priv list. Only
// IDs the catalog names appear: any other elevated token is whatever the author
// typed, and is only counted.
func (g *accountGate) privClause(privs []string) string {
	names, unrecognized := g.policy.AdminEquivalentPrivNames(privs)
	if len(names) == 0 && unrecognized == 0 {
		return ""
	}

	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	switch {
	case len(names) == 1 && unrecognized == 0:
		return "would grant administrator-equivalent privilege " + quoted[0]
	case len(names) > 0 && unrecognized == 0:
		return "would grant administrator-equivalent privileges " + strings.Join(quoted, ", ")
	case len(names) == 0:
		return fmt.Sprintf("would grant %d privilege ID(s) the catalog does not know, which count as administrator-equivalent", unrecognized)
	default:
		return fmt.Sprintf("would grant administrator-equivalent privileges %s and %d ID(s) the catalog does not know",
			strings.Join(quoted, ", "), unrecognized)
	}
}

// clearanceRefusalMessage is the actionable text of a refusal for missing
// Superuser clearance. It names the snippet, the element and what it would do,
// and never a value.
func clearanceRefusalMessage(kind, name, snippetName string, snippetIndex int, clauses []string) string {
	shown := clauses
	more := 0
	if len(clauses) > maxClauses {
		shown, more = clauses[:maxClauses], len(clauses)-maxClauses
	}
	what := strings.Join(shown, " and ")
	if more > 0 {
		what += fmt.Sprintf(" and %d more", more)
	}
	return fmt.Sprintf(
		"rejected (Superuser clearance required): %s for %s %q %s. It carries no Superuser clearance, so a Superuser must save the snippet (and any variable it uses) again; turning on \"Allow All Snippet Content\" (reject_dangerous_snippets=false) does not lift this",
		snippetLabelFrom(kind, snippetName, snippetIndex), kind, name, what,
	)
}
