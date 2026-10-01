package tasks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// fakeAccounts is an OPNsense stand-in for the auth/user and auth/group
// endpoints executeSyncUsersGroups talks to, holding the live rows a test sets
// up and applying the writes it receives closely enough for the next phase to
// see them. Every mutating call is recorded, in order, as "<verb> <kind> <name>".
//
// It reconciles the groups' member lists on a user add and set the way
// UserController::setBaseHook does, one occurrence of the uid at a time. It does
// not derive a user row's group_memberships from the member lists the way
// GroupMembershipField does: a row keeps what the test set, which is what lets a
// test give the two views of one membership different values. What OPNsense
// itself does with them is checked only on a device.
type fakeAccounts struct {
	t      *testing.T
	mu     sync.Mutex
	users  []map[string]interface{}
	groups []map[string]interface{}
	writes []string
	bodies map[string][]map[string]interface{} // "<verb> <kind> <name>" -> decoded request bodies
	failed map[string]bool                     // "<verb> <kind>" -> answer 500
	// onGroupSearch, when set, is asked before each group listing whether to
	// answer it with a 500.
	onGroupSearch func() bool
	// keepMemberLists makes a user set answer "saved" without touching the groups'
	// member lists, for a prune that reports success and changes nothing.
	keepMemberLists bool
	nextID          int
	client          *opnapi.Client
	// privs, when set, is what /auth/priv/search lists: the privilege IDs the
	// device defines. Left nil the route answers 404, so the catalog is
	// unreadable and every verdict falls back to fail-closed.
	privs        []string
	privSearches int
}

type row = map[string]interface{}

func newFakeAccounts(t *testing.T, users, groups []row) *fakeAccounts {
	t.Helper()
	f := &fakeAccounts{
		t:      t,
		users:  users,
		groups: groups,
		bodies: map[string][]map[string]interface{}{},
		failed: map[string]bool{},
		nextID: 3000,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) { f.search(w, "user", f.users) })
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		if f.onGroupSearch != nil && f.onGroupSearch() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.search(w, "group", f.groups)
	})
	mux.HandleFunc("/auth/priv/search", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.privSearches++
		privs := f.privs
		f.mu.Unlock()
		if privs == nil {
			http.NotFound(w, r)
			return
		}
		rows := make([]row, len(privs))
		for i, id := range privs {
			rows[i] = row{"id": id, "name": "Name of " + id, "match": "ui/" + id, "users": []string{}, "groups": []string{}}
		}
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
	})
	mux.HandleFunc("/auth/user/add", func(w http.ResponseWriter, r *http.Request) { f.add(w, r, "user") })
	mux.HandleFunc("/auth/group/add", func(w http.ResponseWriter, r *http.Request) { f.add(w, r, "group") })
	mux.HandleFunc("/auth/user/set/", func(w http.ResponseWriter, r *http.Request) { f.set(w, r, "user") })
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) { f.set(w, r, "group") })
	mux.HandleFunc("/auth/user/del/", func(w http.ResponseWriter, r *http.Request) { f.del(w, r, "user") })
	mux.HandleFunc("/auth/group/del/", func(w http.ResponseWriter, r *http.Request) { f.del(w, r, "group") })

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	f.client = opnapi.NewClient(server.URL, "key", "secret", true)
	return f
}

func (f *fakeAccounts) search(w http.ResponseWriter, kind string, rows []row) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed["search "+kind] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
}

func (f *fakeAccounts) rows(kind string) *[]row {
	if kind == "user" {
		return &f.users
	}
	return &f.groups
}

func (f *fakeAccounts) record(verb, kind, name string, body map[string]interface{}) {
	key := verb + " " + kind + " " + name
	f.writes = append(f.writes, key)
	if body != nil {
		f.bodies[key] = append(f.bodies[key], body)
	}
}

func (f *fakeAccounts) decode(r *http.Request, kind string) map[string]interface{} {
	var wrapper map[string]map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&wrapper)
	return wrapper[kind]
}

func (f *fakeAccounts) saved(w http.ResponseWriter, uuid string) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": "saved", "uuid": uuid})
}

func (f *fakeAccounts) add(w http.ResponseWriter, r *http.Request, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := f.decode(r, kind)
	name, _ := body["name"].(string)
	f.record("add", kind, name, body)
	if f.failed["add "+kind] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	f.nextID++
	id := strconv.Itoa(f.nextID)
	created := row{"uuid": kind[:1] + "-" + name, "name": name}
	if kind == "user" {
		created["uid"] = id
		created["group_memberships"] = body["group_memberships"]
		created["priv"] = body["priv"]
		created["descr"] = body["descr"]
		created["scope"] = body["scope"]
		created["is_admin"] = "0"
	} else {
		created["gid"] = id
		created["member"] = body["member"]
		created["priv"] = body["priv"]
		created["description"] = body["description"]
	}
	rows := f.rows(kind)
	*rows = append(*rows, created)
	if kind == "user" {
		// OPNsense runs the same membership reconcile on add as on set.
		f.reconcileMemberships(created, body["group_memberships"])
	}
	f.saved(w, created["uuid"].(string))
}

func (f *fakeAccounts) find(kind, uuid string) row {
	for _, rw := range *f.rows(kind) {
		if rw["uuid"] == uuid {
			return rw
		}
	}
	return nil
}

func (f *fakeAccounts) set(w http.ResponseWriter, r *http.Request, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	body := f.decode(r, kind)
	target := f.find(kind, uuid)
	name := uuid
	if target != nil {
		name, _ = target["name"].(string)
	}
	f.record("set", kind, name, body)
	if f.failed["set "+kind] || target == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for k, v := range body {
		if k == "password" {
			continue
		}
		target[k] = v
	}
	if gm, posted := body["group_memberships"]; posted && kind == "user" && !f.keepMemberLists {
		f.reconcileMemberships(target, gm)
	}
	f.saved(w, uuid)
}

// reconcileMemberships does what OPNsense's UserController::setBaseHook does with
// a posted group_memberships: the user's uid is added to the member list of every
// group named and removed from every other group's. It removes the FIRST
// occurrence of the uid only (array_search and unset), so a member list that
// holds the uid twice still holds it once after one save.
func (f *fakeAccounts) reconcileMemberships(user row, posted interface{}) {
	uid, _ := user["uid"].(string)
	want := map[string]bool{}
	if csv, ok := posted.(string); ok {
		for _, gid := range strings.Split(csv, ",") {
			if gid = strings.TrimSpace(gid); gid != "" {
				want[gid] = true
			}
		}
	}
	for _, group := range f.groups {
		gid, _ := group["gid"].(string)
		csv, _ := group["member"].(string)
		var kept []string
		has, removed := false, false
		for _, m := range strings.Split(csv, ",") {
			if m = strings.TrimSpace(m); m == "" {
				continue
			} else if m == uid {
				has = true
				if !want[gid] && !removed {
					removed = true
					continue
				}
			}
			kept = append(kept, m)
		}
		if want[gid] && !has {
			kept = append(kept, uid)
		}
		group["member"] = strings.Join(kept, ",")
	}
}

func (f *fakeAccounts) del(w http.ResponseWriter, r *http.Request, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	target := f.find(kind, uuid)
	name := uuid
	if target != nil {
		name, _ = target["name"].(string)
	}
	f.record("del", kind, name, nil)
	rows := f.rows(kind)
	for i, rw := range *rows {
		if rw["uuid"] == uuid {
			*rows = append((*rows)[:i], (*rows)[i+1:]...)
			break
		}
	}
	_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
}

// userRow and groupRow return a copy of the live row with this exact name, or nil.
func (f *fakeAccounts) userRow(name string) row  { return f.rowNamed("user", name) }
func (f *fakeAccounts) groupRow(name string) row { return f.rowNamed("group", name) }

func (f *fakeAccounts) rowNamed(kind, name string) row {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rw := range *f.rows(kind) {
		if rw["name"] == name {
			cp := row{}
			for k, v := range rw {
				cp[k] = v
			}
			return cp
		}
	}
	return nil
}

// administratorEquivalent says, from the rows as they stand now, whether the
// account or group is administrator-equivalent: the same index the gate reads.
func (f *fakeAccounts) administratorEquivalent(kind, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ix := opnapi.BuildAccessIndex(f.users, f.groups, opnapi.PrivPolicy{}, nil)
	if kind == "user" {
		_, reasons := ix.ElevatedUser(name)
		return len(reasons) > 0
	}
	_, reasons := ix.ElevatedGroup(name)
	return len(reasons) > 0
}

// wrote reports whether any mutating call named the element.
func (f *fakeAccounts) wrote(verb, kind, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := verb + " " + kind + " " + name
	for _, w := range f.writes {
		if w == key {
			return true
		}
	}
	return false
}

// wroteAnythingFor reports whether any add or set call named the element.
func (f *fakeAccounts) wroteAnythingFor(kind, name string) bool {
	return f.wrote("add", kind, name) || f.wrote("set", kind, name)
}

// memberListsHolding returns the names of the groups whose member list still
// names the uid.
func (f *fakeAccounts) memberListsHolding(uid string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, group := range f.groups {
		csv, _ := group["member"].(string)
		for _, m := range strings.Split(csv, ",") {
			if strings.TrimSpace(m) == uid {
				name, _ := group["name"].(string)
				out = append(out, name)
			}
		}
	}
	return out
}

// writeIndex returns the position of the first write with this exact key, or -1.
func (f *fakeAccounts) writeIndex(verb, kind, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := verb + " " + kind + " " + name
	for i, w := range f.writes {
		if w == key {
			return i
		}
	}
	return -1
}

func (f *fakeAccounts) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// liveAccounts is a device the way the lab's e2e boxes are after a hand-made
// setup: the built-in admins group with a uid no user owns any more, the
// read-only identity, two hand-made groups that only this device knows about
// (one with page-all, one with the user manager), and accounts elevated by each
// of the ways the gate reads rows.
func liveAccounts() (users, groups []row) {
	users = []row{
		{"uuid": "uu-root", "uid": "0", "name": "root", "scope": "system", "priv": "", "group_memberships": "1999", "is_admin": "1", "descr": ""},
		{"uuid": "uu-agent", "uid": "2001", "name": "netdefense-agent", "scope": "user", "priv": "page-all", "group_memberships": "", "is_admin": "1", "descr": ""},
		{"uuid": "uu-ro", "uid": "2002", "name": "netdefense-readonly", "scope": "user", "priv": "", "group_memberships": "2101", "is_admin": "0", "descr": ""},
		{"uuid": "uu-alice", "uid": "2003", "name": "alice-admin", "scope": "user", "priv": "", "group_memberships": "1999,2110", "is_admin": "1", "descr": "hand-made admin"},
		{"uuid": "uu-bob", "uid": "2004", "name": "bob-usermgr", "scope": "user", "priv": "", "group_memberships": "2111", "is_admin": "0", "descr": ""},
		{"uuid": "uu-carol", "uid": "2005", "name": "carol", "scope": "user", "priv": "", "group_memberships": "2120", "is_admin": "0", "descr": ""},
		{"uuid": "uu-dave", "uid": "2006", "name": "dave-direct", "scope": "user", "priv": "page-diagnostics-backup-restore", "group_memberships": "", "is_admin": "0", "descr": ""},
		{"uuid": "uu-erin", "uid": "2007", "name": "erin-isadmin", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "1", "descr": ""},
		{"uuid": "uu-frank", "uid": "2008", "name": "nd-hm-plain", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": ""},
		{"uuid": "uu-gina", "uid": "2009", "name": "gina-groupcsv", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": ""},
		{"uuid": "uu-hank", "uid": "2010", "name": "hank-gidonly", "scope": "user", "priv": "", "group_memberships": "2111", "is_admin": "0", "descr": ""},
	}
	groups = []row{
		{"uuid": "gg-admins", "gid": "1999", "name": "admins", "scope": "system", "priv": "page-all", "member": "0,2003,2099", "description": ""},
		{"uuid": "gg-ro", "gid": "2101", "name": "netdefense-readonly", "scope": "user", "priv": "page-system-login-logout,user-config-readonly", "member": "2002", "description": ""},
		{"uuid": "gg-all", "gid": "2110", "name": "nd-hm-all", "scope": "user", "priv": "page-all", "member": "2003,2009", "description": "hand-made"},
		{"uuid": "gg-um", "gid": "2111", "name": "nd-hm-usermgr", "scope": "user", "priv": "page-system-usermanager", "member": "2004,2010", "description": "hand-made"},
		{"uuid": "gg-mon", "gid": "2120", "name": "monitors", "scope": "user", "priv": "page-status-services", "member": "2005", "description": ""},
	}
	return users, groups
}

// devicePrivIDs is the catalog of a device that defines what liveAccounts uses,
// the extras a test adds, and filler up to a real release's size.
func devicePrivIDs(extra ...string) []string {
	ids := []string{
		"page-all", "user-config-readonly", "page-system-login-logout", "page-system-usermanager",
		"page-status-services", "page-diagnostics-backup-restore",
	}
	ids = append(ids, extra...)
	for i := 0; i < 100; i++ {
		ids = append(ids, "page-filler-"+strconv.Itoa(i))
	}
	return ids
}

func (f *fakeAccounts) privSearchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.privSearches
}
