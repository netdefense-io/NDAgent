package tasks

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// TestAccountGate_PayloadsNeverLetContentWithoutClearanceReachAnAdministrator
// throws randomized payloads at the executor, with clearance mixed in, against a
// device that has accounts and groups of every kind, and holds the outcome to the
// property the gate exists for: what an element without clearance was let apply
// never ends up administrator-equivalent, and never rewrote something that
// already was.
//
// Names come from small pools so that elements collide with each other and with
// the live rows: same names in different spellings, members that exist and ones
// that do not, groups that are elevated only on this device. The oracle is the
// index the gate itself uses, read from the rows as they stand after the sync.
func TestAccountGate_PayloadsNeverLetContentWithoutClearanceReachAnAdministrator(t *testing.T) {
	userNames := []string{"carol", "nd-hm-plain", "alice-admin", "bob-usermgr", "gina-groupcsv", "hank-gidonly", "svc-a", "svc-b", "SVC-A", " svc-b "}
	groupNames := []string{"monitors", "nd-hm-usermgr", "nd-hm-all", "g-a", "g-b", "G-A"}
	groupRefs := append(append([]string{}, groupNames...), "admins", "Admins", "netdefense-readonly")
	privs := [][]string{nil, {"page-status-services"}, {"page-system-usermanager"}, {"page-all"}, {"page-not-reviewed-x"}, {"page-status-services", "page-system-groupmanager"}}

	pick := func(rng *rand.Rand, pool []string) string { return pool[rng.Intn(len(pool))] }
	subset := func(rng *rand.Rand, pool []string, max int) []string {
		var out []string
		for n := rng.Intn(max + 1); n > 0; n-- {
			out = append(out, pick(rng, pool))
		}
		return out
	}

	const iterations = 300
	for seed := int64(0); seed < iterations; seed++ {
		rng := rand.New(rand.NewSource(seed))

		var users []opnapi.APIUserPayload
		for i, n := 0, 1+rng.Intn(4); i < n; i++ {
			users = append(users, opnapi.APIUserPayload{
				Name:             pick(rng, userNames),
				Password:         fmt.Sprintf("pw-%d", i),
				Groups:           subset(rng, groupRefs, 2),
				Priv:             privs[rng.Intn(len(privs))],
				SuperuserCleared: rng.Intn(5) < 2,
				SnippetName:      fmt.Sprintf("u-%d", i),
				SnippetIndex:     i,
			})
		}
		var groups []opnapi.APIGroupPayload
		for i, n := 0, rng.Intn(4); i < n; i++ {
			groups = append(groups, opnapi.APIGroupPayload{
				Name:             pick(rng, groupNames),
				Priv:             privs[rng.Intn(len(privs))],
				Members:          subset(rng, userNames, 3),
				ExternalMembers:  rng.Intn(8) == 0,
				SuperuserCleared: rng.Intn(5) < 2,
				SnippetName:      fmt.Sprintf("g-%d", i),
				SnippetIndex:     10 + i,
			})
		}
		for i := range groups {
			if groups[i].ExternalMembers {
				groups[i].Members = nil
			}
		}

		liveUsers, liveGroups := liveAccounts()
		f := newFakeAccounts(t, liveUsers, liveGroups)
		before := map[string]bool{}
		for _, u := range liveUsers {
			name, _ := u["name"].(string)
			before["user "+opnapi.AccountNameKey(name)] = f.administratorEquivalent("user", name)
		}
		for _, g := range liveGroups {
			name, _ := g["name"].(string)
			before["group "+opnapi.AccountNameKey(name)] = f.administratorEquivalent("group", name)
		}

		result := runGate(t, f, users, groups, false)
		describe := func() string {
			return fmt.Sprintf("seed %d\nusers %+v\ngroups %+v\nwrites %v\nerrors %v", seed, users, groups, f.writes, result.Errors)
		}

		refused := func(kind, snippet string, index int) bool {
			label := fmt.Sprintf("%s snippet %q (index %d)", kind, snippet, index)
			for _, e := range result.Errors {
				if strings.Contains(e, label+" for "+kind) {
					return true
				}
			}
			return false
		}

		for _, u := range users {
			if u.SuperuserCleared || refused("user", u.SnippetName, u.SnippetIndex) {
				continue
			}
			key := opnapi.AccountNameKey(u.Name)
			if before["user "+key] {
				t.Fatalf("an element without clearance was let apply to an administrator-equivalent user %q\n%s", u.Name, describe())
			}
			if f.administratorEquivalent("user", u.Name) {
				t.Fatalf("an element without clearance was let apply and user %q ended up administrator-equivalent\n%s", u.Name, describe())
			}
			if other := firstClearedSameName(users, nil, "user", key); other != "" {
				t.Fatalf("an element without clearance was let apply next to the cleared %s of the same name\n%s", other, describe())
			}
		}
		for _, g := range groups {
			if g.SuperuserCleared || refused("group", g.SnippetName, g.SnippetIndex) {
				continue
			}
			key := opnapi.AccountNameKey(g.Name)
			if before["group "+key] {
				t.Fatalf("an element without clearance was let apply to an administrator-equivalent group %q\n%s", g.Name, describe())
			}
			if f.administratorEquivalent("group", g.Name) {
				t.Fatalf("an element without clearance was let apply and group %q ended up administrator-equivalent\n%s", g.Name, describe())
			}
			if other := firstClearedSameName(nil, groups, "group", key); other != "" {
				t.Fatalf("an element without clearance was let apply next to the cleared %s of the same name\n%s", other, describe())
			}
		}
		if !result.Success {
			assertErrorHasMatchingResultItem(t, fmt.Sprintf("seed %d", seed), result.Errors, result.Results)
		}
	}
}

// firstClearedSameName returns the snippet of a cleared element of this kind whose
// name is the same account as key, or "".
func firstClearedSameName(users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload, kind, key string) string {
	if kind == "user" {
		for _, u := range users {
			if u.SuperuserCleared && opnapi.AccountNameKey(u.Name) == key {
				return u.SnippetName
			}
		}
		return ""
	}
	for _, g := range groups {
		if g.SuperuserCleared && opnapi.AccountNameKey(g.Name) == key {
			return g.SnippetName
		}
	}
	return ""
}
