package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

const secretSubscription = "11111111-2222-3333-4444-555555555555"

// get is the answer of GET /api/core/firmware/get on a community device: model
// fields as plain strings.
func settingsBody(flavour, mirror, typ, subscription string, reboot, aux string) string {
	return fmt.Sprintf(`{"firmware":{"mirror":%q,"flavour":%q,"plugins":"os-netdefense-dev","type":%q,"subscription":%q,"reboot":%q,"aux":%q}}`,
		mirror, flavour, typ, subscription, reboot, aux)
}

func TestParseFirmwareSettings_PlainStrings(t *testing.T) {
	got, err := parseFirmwareSettings([]byte(settingsBody("26.7/MINT/26.7.3/latest", "", "", "", "0", "1")))
	if err != nil {
		t.Fatal(err)
	}
	want := &FirmwareSettings{Flavour: "26.7/MINT/26.7.3/latest", Aux: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// A select field is served as an option map whose selected entry is the value;
// both shapes occur across releases, and a flag may be a number or a boolean.
func TestParseFirmwareSettings_OptionMapsAndFlagShapes(t *testing.T) {
	body := `{"firmware":{
		"mirror":{"":{"value":"(default)","selected":0},"https://mirror.example/opnsense":{"value":"Example","selected":1}},
		"flavour":{"":{"value":"(default)","selected":1},"OpenSSL":{"value":"OpenSSL","selected":0}},
		"type":{"":{"value":"OPNsense","selected":true}},
		"subscription":"",
		"reboot":1,
		"aux":true}}`
	got, err := parseFirmwareSettings([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := &FirmwareSettings{Mirror: "https://mirror.example/opnsense", Flavour: "", Type: "", Reboot: true, Aux: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseFirmwareSettings_Refusals(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":         `<html>`,
		"no firmware node": `{"status":"ok"}`,
		"null node":        `{"firmware":null}`,
	} {
		if _, err := parseFirmwareSettings([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The subscription is a licence key: nothing the client returns, formats or
// logs may carry it. The struct has no field for it.
func TestFirmwareSettingsNeverHoldTheSubscription(t *testing.T) {
	got, err := parseFirmwareSettings([]byte(settingsBody("", "https://mirror.example/opnsense", "business", secretSubscription, "0", "0")))
	if err != nil {
		t.Fatal(err)
	}
	if !got.SubscriptionSet || got.Type != "business" {
		t.Fatalf("got %+v: the subscription should read as set, the type as business", got)
	}
	for _, shown := range []string{fmt.Sprintf("%v", got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got)} {
		if strings.Contains(shown, secretSubscription) {
			t.Errorf("a formatting of the settings carries the subscription: %s", shown)
		}
	}
	typ := reflect.TypeOf(*got)
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); strings.EqualFold(f.Name, "subscription") && f.Type.Kind() == reflect.String {
			t.Errorf("field %s can hold the subscription", f.Name)
		}
	}
}

func TestGetFirmwareSettings_OverHTTP(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		_, _ = io.WriteString(w, settingsBody("", "", "", "", "0", "0"))
	}))
	defer server.Close()
	got, err := NewClient(server.URL, "k", "s", true).GetFirmwareSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if path != "GET /core/firmware/get" {
		t.Errorf("requested %q", path)
	}
	if got.Flavour != "" || got.SubscriptionSet {
		t.Errorf("got %+v", got)
	}
}

// The write is a partial set carrying one key, and it is sent once: a POST is
// never repeated, whatever the answer.
func TestSetFirmwareFlavour_SendsOnlyTheFlavourKey(t *testing.T) {
	var calls atomic.Int32
	var gotMethod, gotPath string
	var gotBody map[string]map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	if err := NewClient(server.URL, "k", "s", true).SetFirmwareFlavour(context.Background(), "26.7/MINT/26.7.3/latest"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotPath != "/core/firmware/set" {
		t.Errorf("sent %s %s", gotMethod, gotPath)
	}
	want := map[string]map[string]string{"firmware": {"flavour": "26.7/MINT/26.7.3/latest"}}
	if !reflect.DeepEqual(gotBody, want) {
		t.Errorf("body %v, want only the flavour: %v", gotBody, want)
	}
	if calls.Load() != 1 {
		t.Errorf("the set was sent %d times", calls.Load())
	}
}

func TestSetFirmwareFlavour_EmptyIsTheDefault(t *testing.T) {
	var gotBody map[string]map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	if err := NewClient(server.URL, "k", "s", true).SetFirmwareFlavour(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if v, ok := gotBody["firmware"]["flavour"]; !ok || v != "" {
		t.Errorf("body %v: the default must be sent as an empty flavour", gotBody)
	}
}

func TestSetFirmwareFlavour_RefusesWhatOPNsenseWouldRewrite(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k", "s", true)
	for _, bad := range []string{"26.7/MINT/26.7.3/latest\n", "26.7 MINT", "a;b", "26.7/MINT/٢/latest", strings.Repeat("a", 200)} {
		if err := client.SetFirmwareFlavour(context.Background(), bad); err == nil {
			t.Errorf("flavour %q was accepted", bad)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("a refused flavour reached the device %d times", calls.Load())
	}
}

// The answer is `status`, not `result`, and anything but ok is a refusal that
// names OPNsense's reason.
func TestSetFirmwareFlavour_AnythingButOKIsAnError(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"list of messages":  {`{"status":"failure","status_msg":["A valid subscription is required for this firmware mirror"]}`, "subscription is required"},
		"map of messages":   {`{"status":"failure","status_msg":{"flavour":"not allowed"}}`, "flavour: not allowed"},
		"no message":        {`{"status":"failure"}`, "no message"},
		"result not status": {`{"result":"saved"}`, `status ""`},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, tc.body)
		}))
		err := NewClient(server.URL, "k", "s", true).SetFirmwareFlavour(context.Background(), "26.7/MINT/26.7.3/latest")
		server.Close()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", name, err, tc.want)
		}
	}
}

func TestSetFirmwareFlavour_APIErrorIsNotSwallowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	if err := NewClient(server.URL, "k", "s", true).SetFirmwareFlavour(context.Background(), ""); err == nil {
		t.Fatal("a 500 was taken for success")
	}
}

// --- the check result fields the pin code reads ----------------------------------

func TestFirmwareUpgradeStatus_CheckQualityFields(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "firmware-status-e2e-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	st, err := NewClient(server.URL, "k", "s", true).GetFirmwareUpgradeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Completed() || st.LastCheck != "Sun Oct  4 03:02:47 UTC 2026" {
		t.Errorf("LastCheck = %q", st.LastCheck)
	}
	if !st.Clean() {
		t.Error("a check with connection ok and repository ok should be clean")
	}
	if st.InstalledVersion != "26.7" || st.ProductVersion != "26.7" || st.Stale() {
		t.Errorf("versions %q / %q, stale=%v", st.InstalledVersion, st.ProductVersion, st.Stale())
	}
	if st.CheckABI != "26.7" || st.InstalledABI != "26.7" || st.ABICrossing() {
		t.Errorf("ABI %q / %q, crossing=%v", st.CheckABI, st.InstalledABI, st.ABICrossing())
	}
	if len(st.DowngradePackages) != 0 {
		t.Errorf("downgrades: %+v", st.DowngradePackages)
	}
}

func TestFirmwareUpgradeStatus_FailedStaleAndCrossingChecks(t *testing.T) {
	cases := map[string]struct {
		body                           string
		clean, completed, stale, cross bool
		downgrades                     int
	}{
		"repository error": {
			body:      `{"status":"error","connection":"ok","repository":"error","last_check":"Sun Oct  4 03:02:47 UTC 2026","product_version":"26.7.3","product":{"product_version":"26.7.3"}}`,
			completed: true,
		},
		"no result yet": {
			body: `{"status":"none","status_msg":"Firmware status requires to check for update first","product":{"product_version":"26.7.3"}}`,
		},
		"result of the replaced release": {
			body:      `{"status":"none","connection":"ok","repository":"ok","last_check":"Sun Oct  4 03:02:47 UTC 2026","product_version":"26.7.3","product":{"product_version":"26.7.5"}}`,
			clean:     true,
			completed: true,
			stale:     true,
		},
		"another ABI": {
			body:      `{"status":"none","connection":"ok","repository":"ok","last_check":"Sun Oct  4 03:02:47 UTC 2026","product_version":"26.1.11","product_abi":"26.7","product":{"product_version":"26.1.11","product_abi":"26.1"}}`,
			clean:     true,
			completed: true,
			cross:     true,
		},
		"a downgrade": {
			body:       `{"status":"update","connection":"ok","repository":"ok","last_check":"Sun Oct  4 03:02:47 UTC 2026","downgrade_packages":[{"name":"curl","current_version":"8.22.0","new_version":"8.21.0","repository":"OPNsense"}],"product":{"product_version":"26.7.3"},"product_version":"26.7.3"}`,
			clean:      true,
			completed:  true,
			downgrades: 1,
		},
	}
	for name, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, tc.body)
		}))
		st, err := NewClient(server.URL, "k", "s", true).GetFirmwareUpgradeStatus(context.Background())
		server.Close()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if st.Clean() != tc.clean || st.Completed() != tc.completed || st.Stale() != tc.stale ||
			st.ABICrossing() != tc.cross || len(st.DowngradePackages) != tc.downgrades {
			t.Errorf("%s: clean=%v completed=%v stale=%v crossing=%v downgrades=%d; want %v %v %v %v %d", name,
				st.Clean(), st.Completed(), st.Stale(), st.ABICrossing(), len(st.DowngradePackages),
				tc.clean, tc.completed, tc.stale, tc.cross, tc.downgrades)
		}
	}
}
