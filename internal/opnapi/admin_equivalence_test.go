package opnapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The shared files are copied byte for byte from NDDataModels. These digests are
// written out here, not read from the files or the implementation: a change to
// any of them is a deliberate re-copy of the whole set, never an edit.
const (
	pinnedAdminEquivalenceSHA256 = "ec5c0240f4cca491d764bcf624d0157d1dc82badb232ea691246841bc4b3ad62"
	pinnedAdminVectorsSHA256     = "7ade80421001da8c0e90d4c9199c0602729432d2a4b1bb67ccaf7dc45a5ec371"
	pinnedProtectedVectorsSHA256 = "64ec85673785d82ce59c03319e669bfacc8eaefacf38e4924c0af767383ec55c"
	pinnedCryptVectorsSHA256     = "2503004c6f5922576f943dd47f8dedce972e32b4617ffda1b718171579db01d2"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readTestdata fails, never skips, when a shared file is missing: a vector set
// that silently stops running is worse than one that fails.
func readTestdata(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("shared test data %s is missing: %v", path, err)
	}
	return b
}

func TestAdminEquivalenceCatalogIsPinned(t *testing.T) {
	if got := sha256Hex(adminEquivalenceJSON); got != pinnedAdminEquivalenceSHA256 {
		t.Fatalf("embedded catalog sha256 = %s, want %s: the file must stay byte-identical to NDDataModels' copy", got, pinnedAdminEquivalenceSHA256)
	}
	if got := AdminEquivalenceSHA256(); got != pinnedAdminEquivalenceSHA256 {
		t.Errorf("AdminEquivalenceSHA256() = %s, want %s", got, pinnedAdminEquivalenceSHA256)
	}
}

// TestAdminEquivalenceCatalogContent pins what the catalog says, literally, so
// that a re-copy that changes a classification shows up as a test change.
func TestAdminEquivalenceCatalogContent(t *testing.T) {
	wantAdmin := []string{
		"page-all",
		"page-diagnostics-backup-restore",
		"page-diagnostics-configurationhistory",
		"page-diagnostics-factorydefaults",
		"page-services-monit",
		"page-services-netdefense",
		"page-snapshots",
		"page-system-advanced-admin",
		"page-system-advanced-sysctl",
		"page-system-authservers",
		"page-system-cron",
		"page-system-firmware-manualupdate",
		"page-system-groupmanager",
		"page-system-hasync",
		"page-system-usermanager",
		"page-system-usermanager-addprivs",
		"page-wizard-system",
		"page-xmlrpclibrary",
	}
	var gotAdmin []string
	for token := range adminCatalog.adminEquivalent {
		gotAdmin = append(gotAdmin, token)
	}
	sort.Strings(gotAdmin)
	if !reflect.DeepEqual(gotAdmin, wantAdmin) {
		t.Errorf("admin_equivalent IDs = %v, want %v", gotAdmin, wantAdmin)
	}
	if got := len(adminCatalog.nonAdmin); got != 145 {
		t.Errorf("non_admin IDs = %d, want 145", got)
	}

	// 26.1 has the two split user-manager IDs, 26.7 merged them away: both stay
	// administrator-equivalent for good.
	for _, token := range []string{"page-system-groupmanager", "page-system-usermanager-addprivs", "page-system-usermanager"} {
		if !(PrivPolicy{}).IsAdminEquivalentPriv(token) {
			t.Errorf("%s must be administrator-equivalent", token)
		}
	}

	if got, want := adminCatalog.protectedGroups, []string{"admins", "netdefense-readonly"}; !reflect.DeepEqual(got, want) {
		t.Errorf("protected_groups = %v, want %v", got, want)
	}
	if got, want := adminCatalog.protectedUsers, []string{"netdefense-agent", "netdefense-readonly", "root"}; !reflect.DeepEqual(got, want) {
		t.Errorf("protected_users = %v, want %v", got, want)
	}
	if got := AdminEquivalenceAssumedMinRelease(); got != "26.1.11" {
		t.Errorf("assumes_min_opnsense = %q, want 26.1.11", got)
	}
}

type adminVectorsFile struct {
	FixtureSHA256 string `json:"fixture_sha256"`
	Entries       []struct {
		Entry           string `json:"entry"`
		AdminEquivalent bool   `json:"admin_equivalent"`
		Description     string `json:"description"`
	} `json:"entries"`
	CoreTokens []struct {
		Token           string `json:"token"`
		AdminEquivalent bool   `json:"admin_equivalent"`
	} `json:"core_tokens"`
	PluginTokens []struct {
		Token           string `json:"token"`
		AdminEquivalent bool   `json:"admin_equivalent"`
	} `json:"plugin_tokens"`
}

func TestAdminEquivalenceVectors(t *testing.T) {
	raw := readTestdata(t, "testdata/admin-equivalence/vectors.json")
	if got := sha256Hex(raw); got != pinnedAdminVectorsSHA256 {
		t.Fatalf("admin-equivalence vectors sha256 = %s, want %s", got, pinnedAdminVectorsSHA256)
	}
	var v adminVectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.FixtureSHA256 != pinnedAdminEquivalenceSHA256 {
		t.Fatalf("the vectors were generated from catalog %s, this package embeds %s", v.FixtureSHA256, pinnedAdminEquivalenceSHA256)
	}
	if len(v.Entries) != 31 || len(v.CoreTokens) != 150 || len(v.PluginTokens) != 89 {
		t.Fatalf("vector counts = %d/%d/%d entries/core/plugin, want 31/150/89", len(v.Entries), len(v.CoreTokens), len(v.PluginTokens))
	}

	policy := PrivPolicy{}
	for _, e := range v.Entries {
		if got := policy.IsAdminEquivalentPriv(e.Entry); got != e.AdminEquivalent {
			t.Errorf("entry %q (%s): admin-equivalent = %v, want %v", e.Entry, e.Description, got, e.AdminEquivalent)
		}
	}
	for _, c := range v.CoreTokens {
		if got := policy.IsAdminEquivalentPriv(c.Token); got != c.AdminEquivalent {
			t.Errorf("core token %q: admin-equivalent = %v, want %v", c.Token, got, c.AdminEquivalent)
		}
	}
	for _, c := range v.PluginTokens {
		if got := policy.IsAdminEquivalentPriv(c.Token); got != c.AdminEquivalent {
			t.Errorf("plugin token %q: admin-equivalent = %v, want %v", c.Token, got, c.AdminEquivalent)
		}
	}
}

// TestAdminEquivalencePredicate covers what the shared vectors leave out: the
// ASCII-only normalization, the structural floor on its own, and the packing of
// several IDs in one entry.
func TestAdminEquivalencePredicate(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  bool
	}{
		{"empty", "", false},
		{"only separators and spaces", " , ,\t,", false},
		{"reviewed ordinary ID", "page-firewall-rules", false},
		{"ordinary IDs, mixed case and padding", "  PAGE-Firewall-Rules , page-firewall-aliases ", false},
		{"admin flag", "page-all", true},
		{"one elevated ID among ordinary ones", "page-firewall-rules,page-system-cron,page-firewall-aliases", true},
		{"unknown ID", "page-never-heard-of-it", true},
		{"unknown ID that merely starts like an admin one", "page-all-foo", true},
		{"all-pages alias", "all-pages", true},
		{"structural floor: -all suffix", "network-all", true},
		{"structural floor: system and admin", "x-system-admin-y", true},
		{"no-break space after a reviewed ID is not stripped", "page-firewall-rules ", true},
		{"no-break space before a reviewed ID is not stripped", " page-firewall-rules", true},
		{"NUL after a reviewed ID", "page-firewall-rules\x00", true},
		{"vertical tab and form feed around a reviewed ID are stripped", "\v\fpage-firewall-rules\f\v", false},
		{"Kelvin sign lowercases to k only for a Unicode-aware fold", "page-diagnostics-bacKup-restore", true},
		{"Turkish dotted capital I is not an i", "page-İnterfaces", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (PrivPolicy{}).IsAdminEquivalentPriv(tt.entry); got != tt.want {
				t.Errorf("IsAdminEquivalentPriv(%q) = %v, want %v", tt.entry, got, tt.want)
			}
		})
	}

	if (PrivPolicy{}).HasAdminEquivalentPriv(nil) {
		t.Error("HasAdminEquivalentPriv(nil) = true, want false")
	}
	if !(PrivPolicy{}).HasAdminEquivalentPriv([]string{"page-firewall-rules", "page-all"}) {
		t.Error("HasAdminEquivalentPriv must see an elevated entry anywhere in the list")
	}
}

func TestAdminEquivalentPrivNamesOnlyNamesCatalogIDs(t *testing.T) {
	names, unrecognized := (PrivPolicy{}).AdminEquivalentPrivNames([]string{
		"page-firewall-rules, Page-System-UserManager",
		"page-secret-author-text,PAGE-SYSTEM-USERMANAGER",
		"network-all",
		"page-all",
	})
	if want := []string{"page-system-usermanager", "page-all"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v (catalog IDs only, in order of appearance, no repeats)", names, want)
	}
	if unrecognized != 2 {
		t.Errorf("unrecognized = %d, want 2 (the author's own token and network-all, which no message may name)", unrecognized)
	}

	names, unrecognized = (PrivPolicy{}).AdminEquivalentPrivNames([]string{"page-firewall-rules"})
	if len(names) != 0 || unrecognized != 0 {
		t.Errorf("an ordinary entry named %v / %d, want nothing", names, unrecognized)
	}
}

func TestFloorDependentPrivsFollowThePolicy(t *testing.T) {
	floorDependent := adminCatalog.floorDependent
	if len(floorDependent) != 12 || !floorDependent["page-filter-api"] {
		t.Fatalf("the catalog's floor-dependent IDs changed: %v", floorDependent)
	}
	for token := range floorDependent {
		if (PrivPolicy{}).IsAdminEquivalentPriv(token) {
			t.Errorf("%s must be ordinary under the default policy", token)
		}
		if !(PrivPolicy{FloorDependentElevated: true}).IsAdminEquivalentPriv("page-firewall-rules," + token) {
			t.Errorf("%s must be elevated when the policy says so", token)
		}
	}
	names, _ := (PrivPolicy{FloorDependentElevated: true}).AdminEquivalentPrivNames([]string{"page-filter-api"})
	if !reflect.DeepEqual(names, []string{"page-filter-api"}) {
		t.Errorf("a floor-dependent ID is a catalog ID and may be named, got %v", names)
	}
}

// TestElevationSwitchIsOn pins the operator's decision: on a release below the
// floor, which lacks the upstream fixes the floor-dependent IDs are ordinary
// because of, they count as administrator-equivalent.
func TestElevationSwitchIsOn(t *testing.T) {
	if !ElevateFloorDependentPrivsBelowFloor {
		t.Fatal("ElevateFloorDependentPrivsBelowFloor must stay true: turning it off makes every gate read the floor-dependent IDs " +
			"as ordinary on a device below the supported floor, where the upstream fixes they depend on are missing. " +
			"Plugin AdminEquivalence.php has no policy input either way, so the AUTH_SERVER shadowable-users count " +
			"reads them as ordinary whatever this says")
	}
}

func TestPrivPolicyForRelease(t *testing.T) {
	release := func(raw string) ProductRelease {
		r, err := ParseProductRelease(raw)
		if err != nil {
			t.Fatalf("ParseProductRelease(%q): %v", raw, err)
		}
		return r
	}

	tests := []struct {
		name    string
		release ProductRelease
		known   bool
		want    bool
	}{
		{"at the floor", release("26.1.11"), true, false},
		{"above the floor, same series", release("26.1.12_2"), true, false},
		{"next series", release("26.7.5"), true, false},
		{"below the floor, same series", release("26.1.10"), true, true},
		{"first release of the series", release("26.1"), true, true},
		{"older series", release("25.7.11_9"), true, true},
		{"unreadable", ProductRelease{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrivPolicyForRelease(tt.release, tt.known); got.FloorDependentElevated != tt.want {
				t.Errorf("PrivPolicyForRelease(%q, %v) elevated = %v, want %v", tt.release.Raw, tt.known, got.FloorDependentElevated, tt.want)
			}
		})
	}
}

// TestLoadPrivCatalogFailsClosed holds the loader to the same invariants the
// Python loader enforces: a catalog that is not whole must not classify anything.
func TestLoadPrivCatalogFailsClosed(t *testing.T) {
	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"schema": 1,
			"kind":   "opnsense-admin-equivalence",
			"meta": map[string]interface{}{
				"unknown_id_policy":    "admin_equivalent",
				"match":                "m",
				"assumes_min_opnsense": "26.1.11",
				"floor_dependent_ids":  []string{"page-b"},
				"sources":              map[string]interface{}{},
			},
			"admin_equivalent":      map[string]string{"page-a": "tag"},
			"non_admin":             map[string]string{"page-b": "ordinary"},
			"ro_backstop_allowlist": map[string]string{"page-c": "save-guard"},
			"protected_groups":      []string{"admins"},
			"protected_users":       []string{"root"},
		}
	}
	encode := func(doc map[string]interface{}) []byte {
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if _, err := loadPrivCatalog(encode(valid())); err != nil {
		t.Fatalf("the control document must load: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(doc map[string]interface{})
		raw    string
	}{
		{name: "not JSON", raw: "{"},
		{name: "unknown top-level key", mutate: func(d map[string]interface{}) { d["extra"] = 1 }},
		{name: "wrong schema", mutate: func(d map[string]interface{}) { d["schema"] = 2 }},
		{name: "wrong kind", mutate: func(d map[string]interface{}) { d["kind"] = "other" }},
		{name: "lenient unknown-ID policy", mutate: func(d map[string]interface{}) {
			d["meta"].(map[string]interface{})["unknown_id_policy"] = "non_admin"
		}},
		{name: "no assumed floor", mutate: func(d map[string]interface{}) {
			d["meta"].(map[string]interface{})["assumes_min_opnsense"] = ""
		}},
		{name: "an ID in both maps", mutate: func(d map[string]interface{}) {
			d["non_admin"] = map[string]string{"page-a": "ordinary", "page-b": "ordinary"}
		}},
		{name: "a key that is not normalized", mutate: func(d map[string]interface{}) {
			d["admin_equivalent"] = map[string]string{"Page-A": "tag"}
		}},
		{name: "a non-ASCII key", mutate: func(d map[string]interface{}) {
			d["admin_equivalent"] = map[string]string{"page-ä": "tag"}
		}},
		{name: "a key with a comma", mutate: func(d map[string]interface{}) {
			d["admin_equivalent"] = map[string]string{"page-a,page-b": "tag"}
		}},
		{name: "an empty admin map", mutate: func(d map[string]interface{}) { d["admin_equivalent"] = map[string]string{} }},
		{name: "a reviewed ordinary ID in the read-only allowlist", mutate: func(d map[string]interface{}) {
			d["ro_backstop_allowlist"] = map[string]string{"page-b": "save-guard"}
		}},
		{name: "a floor-dependent ID that is not ordinary", mutate: func(d map[string]interface{}) {
			d["meta"].(map[string]interface{})["floor_dependent_ids"] = []string{"page-a"}
		}},
		{name: "no protected groups", mutate: func(d map[string]interface{}) { d["protected_groups"] = []string{} }},
		{name: "a repeated protected user", mutate: func(d map[string]interface{}) { d["protected_users"] = []string{"root", "root"} }},
		{name: "a protected name that is not normalized", mutate: func(d map[string]interface{}) { d["protected_groups"] = []string{"Admins"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(tt.raw)
			if tt.mutate != nil {
				doc := valid()
				tt.mutate(doc)
				raw = encode(doc)
			}
			if _, err := loadPrivCatalog(raw); err == nil {
				t.Errorf("loadPrivCatalog accepted %s", strings.TrimSpace(string(raw)))
			}
		})
	}
}
