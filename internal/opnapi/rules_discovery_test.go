package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ruleSearchFixture serves /firewall/filter/searchRule with OPNsense 26.1's
// filtering semantics, modelled on `FilterController::searchRuleAction`
// rather than on an assumption about it:
//
//   - field present and non-empty: only rules bound to one of those
//     interfaces;
//   - field ABSENT: every rule, whatever it is bound to (this is the 26.1
//     behaviour NDAgent depends on; 25.x took the floating view here);
//   - field present but EMPTY: the floating view — only rules bound to zero
//     or to more than one interface. NDAgent never sends this shape thanks
//     to `omitempty`, so it is latent, but modelling it wrong would teach
//     the next reader that empty and absent are the same thing.
//
// Honouring the filter is the whole point. A fixture that ignores it reports
// that discovery works no matter what was queried — which is how the
// property under test could look covered while being false — and a fixture
// that encodes "unfiltered returns everything" as a definition rather than
// as one branch of a versioned controller makes the same mistake one level
// up.
type ruleSearchFixture struct {
	rules      []map[string]interface{}
	interfaces []string

	// lastInterfaceFilters records, per request, whether the field was
	// absent (recorded as absentFilter) or its literal value.
	lastInterfaceFilters []string
}

// absentFilter marks a request that omitted the `interface` key entirely,
// which 26.1 treats differently from a present-but-empty value.
const absentFilter = "<absent>"

// boundInterfaces splits a rule's interface field into its bound interfaces.
// An empty field means a floating rule: zero interfaces.
func boundInterfaces(ruleIface string) []string {
	var out []string
	for _, part := range strings.Split(ruleIface, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (f *ruleSearchFixture) client(t *testing.T) *Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		raw, present := req["interface"]
		filter, _ := raw.(string)
		if !present {
			f.lastInterfaceFilters = append(f.lastInterfaceFilters, absentFilter)
		} else {
			f.lastInterfaceFilters = append(f.lastInterfaceFilters, filter)
		}

		var rows []map[string]interface{}
		for _, rule := range f.rules {
			ruleIface, _ := rule["interface"].(string)
			bound := boundInterfaces(ruleIface)

			switch {
			case !present:
				// 26.1: key absent means every rule. (On 25.x this branch
				// took the floating view below, which is precisely why
				// NDAgent now requires 26.1 — see RuleSearchRequest.)
				rows = append(rows, rule)
			case filter == "":
				// Present but empty: the floating view, on 26.1 as well.
				if len(bound) == 0 || len(bound) > 1 {
					rows = append(rows, rule)
				}
			default:
				for _, want := range strings.Split(filter, ",") {
					if matchesAnyInterface(ruleIface, strings.TrimSpace(want)) {
						rows = append(rows, rule)
						break
					}
				}
			}
		}
		_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
	})

	mux.HandleFunc("/firewall/filter/getRule", func(w http.ResponseWriter, r *http.Request) {
		options := map[string]map[string]interface{}{}
		for _, iface := range f.interfaces {
			options[iface] = map[string]interface{}{"value": iface}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": map[string]interface{}{"interface": options},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "key", "secret", true)
}

// matchesAnyInterface reports whether a rule bound to ruleIface (which may
// itself be a comma-separated list) matches the single interface want.
func matchesAnyInterface(ruleIface, want string) bool {
	for _, bound := range strings.Split(ruleIface, ",") {
		if strings.TrimSpace(bound) == want {
			return true
		}
	}
	return false
}

// TestListAllRulesFindsRulesOnUnlistedInterfaces pins the property the
// SYNC_API orphan sweep depends on: a rule bound to an interface or group
// that is NO LONGER in the interface option list is still discovered.
//
// This is what makes it safe to realize VPN state before rules. A VPN
// teardown deletes the last WireGuard instance and reconfigures, so OPNsense
// drops the `wireguard` interface group; the `[nd-vpn:...]` rules bound to
// that group must still be enumerable, or the sweep cannot delete them and
// they are stranded on the device pointing at a group that no longer exists.
//
// This holds **on OPNsense 26.1+ only**, which is NDAgent's supported floor.
// ListAllRules' FIRST call omits the interface filter, and on 26.1 that
// returns every rule — which makes the second, interface-scoped call
// redundant for this purpose. On 25.x the unfiltered call took the floating
// view and excluded single-interface rules, so the second call was the only
// way such a rule was discovered; that is why ListAllRules makes two calls
// and dedupes. See RuleSearchRequest for the controller behaviour at each
// release.
//
// The test exists because nothing said any of this, and because the
// guarantee is easy to optimise away: read the second call, conclude
// discovery is interface-scoped, and a VPN teardown starts stranding rules.
func TestListAllRulesFindsRulesOnUnlistedInterfaces(t *testing.T) {
	fixture := &ruleSearchFixture{
		rules: []map[string]interface{}{
			{"uuid": "221f3268-auto", "interface": "wireguard", "description": "[nd-vpn:lab] auto peer"},
			{"uuid": "221f3268-lan", "interface": "lan", "description": "ordinary lan rule"},
			{"uuid": "221f3268-float", "interface": "", "description": "floating listener"},
		},
		// The WireGuard instance is gone, so the group is not offered.
		interfaces: []string{"lan", "wan"},
	}
	client := fixture.client(t)

	rules, err := client.ListAllRules(context.Background())
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}

	found := map[string]bool{}
	for _, r := range rules {
		uuid, _ := r["uuid"].(string)
		found[uuid] = true
	}

	if !found["221f3268-auto"] {
		t.Error("a rule bound to the absent `wireguard` group was not discovered; the orphan sweep could not delete it, so a VPN teardown would strand it on the device")
	}
	for _, uuid := range []string{"221f3268-lan", "221f3268-float"} {
		if !found[uuid] {
			t.Errorf("rule %s was not discovered", uuid)
		}
	}

	// Guard the reasoning as well as the result. The first call must OMIT the
	// field, not send it empty: on 26.1 those differ, and only the absent
	// form returns single-interface rules. If the first call ever stops being
	// the absent form, discovery becomes interface-bounded and the assertion
	// above would start passing only by luck of the fixture.
	if len(fixture.lastInterfaceFilters) == 0 || fixture.lastInterfaceFilters[0] != absentFilter {
		t.Errorf("expected the first search to omit the interface field entirely (that is what makes discovery interface-independent on 26.1; a present-but-empty value takes the floating view instead), got filters %q", fixture.lastInterfaceFilters)
	}
}

// TestRuleSearchAbsentAndEmptyInterfaceDiffer pins the 26.1 distinction the
// fixture models, so that branch is exercised rather than decorative: an
// ABSENT interface key returns every rule, while a PRESENT-but-EMPTY one
// takes the floating view and excludes single-interface rules.
//
// NDAgent only ever sends the absent form — RuleSearchRequest tags Interface
// `omitempty` — so this is latent for us today. It is pinned because the two
// shapes look identical in Go (both start life as an empty string) and a
// future caller that builds the body by hand, or a fixture that treats them
// as the same, would be silently wrong in the direction that loses rules.
func TestRuleSearchAbsentAndEmptyInterfaceDiffer(t *testing.T) {
	rules := []map[string]interface{}{
		{"uuid": "single", "interface": "wireguard"},
		{"uuid": "multi", "interface": "lan,opt2"},
		{"uuid": "floating", "interface": ""},
	}

	fixture := &ruleSearchFixture{rules: rules, interfaces: []string{"lan", "wan"}}
	client := fixture.client(t)

	// Absent: everything. This is what ListAllRules' first call sends.
	all, err := client.searchRulesWithParams(context.Background(), "", "")
	if err != nil {
		t.Fatalf("unfiltered search: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("absent interface returned %d rules, want all 3 (26.1 semantics)", len(all))
	}

	// Present but empty: the floating view — the single-interface rule drops
	// out. Built by hand because RuleSearchRequest cannot express it.
	floating := postRuleSearch(t, client, map[string]interface{}{
		"current": 1, "rowCount": -1, "sort": map[string]string{}, "interface": "",
	})
	for _, r := range floating {
		if uuid, _ := r["uuid"].(string); uuid == "single" {
			t.Error("a present-but-empty interface must take the floating view and exclude single-interface rules")
		}
	}
	if len(floating) != 2 {
		t.Errorf("present-but-empty interface returned %d rules, want 2 (floating + multi-interface)", len(floating))
	}
}

// postRuleSearch issues a hand-built search body, for shapes
// RuleSearchRequest deliberately cannot produce.
func postRuleSearch(t *testing.T, c *Client, body map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, err := c.doRequest(context.Background(), "POST", "/firewall/filter/searchRule", body)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	var resp SearchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Rows
}
