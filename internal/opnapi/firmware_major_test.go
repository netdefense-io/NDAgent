package opnapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// The status the 26.1.11_10 device answered with the 26.7 offer shown
// (testdata/firmware-status-offer-26.1.11_10.json): the major is offered with its
// three sets, the sizes are JSON strings, and the status says "upgrade" because
// nothing else is pending.
func TestFirmwareUpgradeStatus_DecodesTheMeasuredOffer(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "firmware-status-offer-26.1.11_10.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	st, err := NewClient(server.URL, "k", "s", true).GetFirmwareUpgradeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.UpgradeMajorVersion != "26.7" || st.Status != "upgrade" || !st.Clean() || st.Stale() {
		t.Fatalf("major %q status %q clean %v stale %v", st.UpgradeMajorVersion, st.Status, st.Clean(), st.Stale())
	}
	want := []FirmwareUpgradeSet{
		{Name: "packages", Size: 1142865408, CurrentVersion: "26.1.6_2", NewVersion: "26.7", Repository: "OPNsense"},
		{Name: "kernel", Size: 33428352, CurrentVersion: "26.1.11", NewVersion: "26.7", Repository: "OPNsense"},
		{Name: "base", Size: 98926556, CurrentVersion: "26.1.11", NewVersion: "26.7", Repository: "OPNsense"},
	}
	if len(st.UpgradeSets) != len(want) {
		t.Fatalf("%d sets: %+v", len(st.UpgradeSets), st.UpgradeSets)
	}
	for i := range want {
		got := st.UpgradeSets[i]
		if len(got.Raw) == 0 {
			t.Errorf("set %d keeps no raw entry for the log", i)
		}
		got.Raw = nil
		if !reflect.DeepEqual(got, want[i]) {
			t.Errorf("set %d: %+v, want %+v", i, got, want[i])
		}
	}
}

func TestParseUpgradeSets_SizesAndStrangeEntries(t *testing.T) {
	raw := func(s ...string) []json.RawMessage {
		var out []json.RawMessage
		for _, e := range s {
			out = append(out, json.RawMessage(e))
		}
		return out
	}
	got := parseUpgradeSets(raw(
		`{"name":"packages","size":"1142865408","new_version":"26.7"}`,
		`{"name":"kernel","size":33428352,"new_version":"26.7"}`,
		`{"name":"base","size":"not a number","new_version":"26.7"}`,
		`{"name":"x","size":"-5"}`,
		`{"name":"y"}`,
		`"just a string"`,
		`[1,2]`,
	))
	sizes := []int64{1142865408, 33428352, -1, -1, -1, -1, -1}
	names := []string{"packages", "kernel", "base", "x", "y", "", ""}
	if len(got) != len(sizes) {
		t.Fatalf("%d entries", len(got))
	}
	for i := range got {
		if got[i].Size != sizes[i] || got[i].Name != names[i] || len(got[i].Raw) == 0 {
			t.Errorf("entry %d: %+v, want size %d name %q", i, got[i], sizes[i], names[i])
		}
	}
	if got := parseUpgradeSets(nil); len(got) != 0 {
		t.Errorf("no sets: %+v", got)
	}
}

// --- the HA signals ----------------------------------------------------------------

// vipRow is a row of the VIP list as the lab read it: 20 keys, the password among
// them.
const vipRowCarp = `{"uuid":"ffbf2ca7-842c-4afc-9036-830714d52c0d","interface":"lan","mode":"carp","subnet":"192.168.3.250","subnet_bits":"24","vhid":"199","advbase":"1","advskew":"100","password":"SECRET-CARP-PASSWORD","descr":"x","address":"192.168.3.250/24"}`

func apiServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "k", "s", true)
}

func TestGetVIPList_ReadsModeAndVhidAndNeverTheRest(t *testing.T) {
	c := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/core/../interfaces/vip_settings/searchItem" && r.URL.Path != "/interfaces/vip_settings/searchItem" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"total":2,"rowCount":2,"current":1,"rows":[`+vipRowCarp+`,{"uuid":"u2","mode":"ipalias","vhid":"","password":""}]}`)
	})
	list, err := c.GetVIPList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := VIPList{Total: 2, Rows: []VIPRow{{Mode: "carp", VHID: "199"}, {Mode: "ipalias"}}}
	if !reflect.DeepEqual(list, want) {
		t.Fatalf("got %+v, want %+v", list, want)
	}
	if !list.Rows[0].IsCARP() || list.Rows[1].IsCARP() {
		t.Errorf("IsCARP: %v %v", list.Rows[0].IsCARP(), list.Rows[1].IsCARP())
	}
	if strings.Contains(strings.ToLower(reflect.TypeOf(VIPRow{}).String()+reflect.ValueOf(list).String()), "secret") {
		t.Error("the list holds a secret")
	}
}

func TestVIPRowIsCARP(t *testing.T) {
	for row, want := range map[VIPRow]bool{
		{Mode: "carp"}:                true,
		{Mode: "CARP"}:                true,
		{Mode: "ipalias", VHID: "12"}: true, // a vhid names a CARP group whatever the mode says
		{Mode: "ipalias"}:             false,
		{Mode: "proxyarp"}:            false,
		{Mode: "other", VHID: ""}:     false,
		{Mode: "", VHID: ""}:          false,
		{Mode: "carp", VHID: "199"}:   true,
	} {
		if got := row.IsCARP(); got != want {
			t.Errorf("%+v: %v, want %v", row, got, want)
		}
	}
}

func TestGetVIPList_PagesUntilItHoldsTheTotal(t *testing.T) {
	var mu sync.Mutex
	var pages []string
	c := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pages = append(pages, r.URL.Query().Get("current"))
		mu.Unlock()
		switch r.URL.Query().Get("current") {
		case "1":
			_, _ = io.WriteString(w, `{"total":3,"rows":[{"mode":"ipalias"},{"mode":"ipalias"}]}`)
		case "2":
			_, _ = io.WriteString(w, `{"total":3,"rows":[{"mode":"carp","vhid":7}]}`)
		default:
			_, _ = io.WriteString(w, `{"total":3,"rows":[]}`)
		}
	})
	list, err := c.GetVIPList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Rows) != 3 || list.Rows[2] != (VIPRow{Mode: "carp", VHID: "7"}) {
		t.Errorf("rows %+v: a CARP row on the second page was missed, or a numeric vhid not read", list.Rows)
	}
	if strings.Join(pages, ",") != "1,2" {
		t.Errorf("pages read: %v", pages)
	}
}

func TestGetVIPList_AnEmptyListAndAListThatNeverReachesItsTotal(t *testing.T) {
	c := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"total":0,"rowCount":0,"rows":[]}`)
	})
	if list, err := c.GetVIPList(context.Background()); err != nil || len(list.Rows) != 0 || list.Total != 0 {
		t.Errorf("an empty list: %+v, %v", list, err)
	}
	// A device that reports more than it ever serves is not read for ever.
	var calls int
	c = apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"total":5,"rows":[{"mode":"ipalias"}]}`)
	})
	if _, err := c.GetVIPList(context.Background()); err != nil {
		// one row per page for ever is fine until the cap; it must not hang
		t.Logf("capped: %v", err)
	}
	if calls > vipMaxPages {
		t.Errorf("%d requests", calls)
	}
}

// An error says where and with which status, and never what the device wrote: the
// body of these two endpoints carries passwords.
func TestHAReadsNeverPutABodyInAnError(t *testing.T) {
	const secret = "SECRET-IN-AN-ERROR-BODY"
	for name, call := range map[string]func(c *Client) error{
		"the VIP list": func(c *Client) error { _, err := c.GetVIPList(context.Background()); return err },
		"hasync":       func(c *Client) error { _, err := c.GetHASync(context.Background()); return err },
		"supported":    func(c *Client) error { _, err := c.SnapshotsSupported(context.Background()); return err },
		"the list":     func(c *Client) error { _, err := c.ListBootEnvironments(context.Background()); return err },
	} {
		for status, body := range map[int]string{500: secret, 200: `{"rows": "` + secret + `"`, 403: `{"password":"` + secret + `"}`} {
			c := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			})
			err := call(c)
			if err == nil {
				t.Errorf("%s, %d: no error", name, status)
				continue
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s, %d: the error quotes the body: %v", name, status, err)
			}
			var re *ReadError
			if !errors.As(err, &re) {
				t.Errorf("%s, %d: %T", name, status, err)
			}
		}
	}
}

func TestGetHASync_PlainStringsAndOptionMaps(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want HASync
	}{
		"nothing configured": {
			`{"hasync":{"pfsyncinterface":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0}},"synchronizetoip":"","pfsyncpeerip":"","disablepreempt":"0","username":"root","password":"SECRET"}}`,
			HASync{},
		},
		"pfsync on the lan": {
			`{"hasync":{"pfsyncinterface":{"":{"value":"None","selected":0},"lan":{"value":"LAN","selected":1}},"synchronizetoip":"","password":"SECRET"}}`,
			HASync{PfsyncInterface: "lan"},
		},
		"a sync address, an interface as a string": {
			`{"hasync":{"pfsyncinterface":"opt1","synchronizetoip":"192.168.3.2","password":"SECRET"}}`,
			HASync{PfsyncInterface: "opt1", SynchronizeToIP: "192.168.3.2"},
		},
		"selected as a boolean or a string": {
			`{"hasync":{"pfsyncinterface":{"lan":{"value":"LAN","selected":true},"wan":{"value":"WAN","selected":"0"}},"synchronizetoip":null}}`,
			HASync{PfsyncInterface: "lan"},
		},
	} {
		c := apiServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, tc.body) })
		got, err := c.GetHASync(context.Background())
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, tc.want)
		}
	}
	c := apiServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"result":"failed"}`) })
	if _, err := c.GetHASync(context.Background()); err == nil {
		t.Error("an answer with no hasync model was read as an empty one")
	}
}

// --- the boot environments --------------------------------------------------------

func TestBootEnvironmentCalls(t *testing.T) {
	var (
		mu    sync.Mutex
		added []map[string]string
	)
	c := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/core/snapshots/isSupported":
			_, _ = io.WriteString(w, `{"supported":true}`)
		case "/core/snapshots/search":
			_, _ = io.WriteString(w, `{"total":2,"rowCount":2,"current":1,"rows":[{"uuid":"33ab88e4","name":"default","active":"NR","mountpoint":"/","size":"1.25G","created":1791523980},{"uuid":"6f50742b","name":"ndagent-pre-26.7","active":"-","mountpoint":"-","size":"192K","created":1791835380}]}`)
		case "/core/snapshots/add":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			added = append(added, body)
			mu.Unlock()
			if body["name"] == "taken" {
				_, _ = io.WriteString(w, `{"status":"failed","errors":"A snapshot already exists by this name"}`)
				return
			}
			_, _ = io.WriteString(w, `{"status": "ok", "result": "bootenvironment executed create successfully"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()
	if ok, err := c.SnapshotsSupported(ctx); err != nil || !ok {
		t.Errorf("supported: %v, %v", ok, err)
	}
	list, err := c.ListBootEnvironments(ctx)
	if err != nil || len(list) != 2 || list[1] != (BootEnvironment{UUID: "6f50742b", Name: "ndagent-pre-26.7", Active: "-"}) || list[0].Active != "NR" {
		t.Errorf("list: %+v, %v", list, err)
	}
	if err := c.CreateBootEnvironment(ctx, "ndagent-pre-26.7", "before the upgrade to 26.7"); err != nil {
		t.Errorf("add: %v", err)
	}
	if err := c.CreateBootEnvironment(ctx, "taken", "x"); !errors.Is(err, ErrBootEnvironmentExists) {
		t.Errorf("a name that is taken: %v", err)
	}
	if len(added) != 2 || added[0]["name"] != "ndagent-pre-26.7" || added[0]["note"] != "before the upgrade to 26.7" {
		t.Errorf("the add bodies: %+v", added)
	}

	// A refusal that is not a name clash is an error of its own.
	c = apiServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"status":"failed"}`) })
	if err := c.CreateBootEnvironment(ctx, "x", "y"); err == nil || errors.Is(err, ErrBootEnvironmentExists) {
		t.Errorf("a failed add: %v", err)
	}
	c = apiServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"supported":false}`) })
	if ok, err := c.SnapshotsSupported(ctx); err != nil || ok {
		t.Errorf("not supported: %v, %v", ok, err)
	}
	c = apiServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{}`) })
	if _, err := c.SnapshotsSupported(ctx); err == nil {
		t.Error("an answer with no verdict was read as one")
	}
}
