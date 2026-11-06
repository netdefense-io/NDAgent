package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const testEnrollKey = "SECRETKEY0123456789abcdef"

type fakeCrowdsec struct {
	mu sync.Mutex

	notFound     bool
	getStatus    int
	model        map[string]string
	status       string
	sets         []map[string]string
	reconfigures int
	statusCalls  int

	validation       map[string]string
	dropKeys         bool
	reconfigureBody  string
	reconfigureAfter string // status the device reaches after a reconfigure
	blockReconfigure chan struct{}
	statusFails      bool
	failGetAfterSet  bool
	dropOnly         map[string]bool
	setDone          bool
}

func defaultCrowdsecModel() map[string]string {
	return map[string]string{
		"agent_enabled": "1", "lapi_enabled": "1", "firewall_bouncer_enabled": "1",
		"lapi_manual_configuration": "0", "lapi_listen_address": "127.0.0.1", "lapi_listen_port": "8080",
		"rules_enabled": "1", "rules_log": "0", "rules_tag": "", "enroll_key": "",
		"crowdsec_firewall_verbose": "0",
	}
}

func newFakeCrowdsec(t *testing.T) (*fakeCrowdsec, *opnapi.Client) {
	t.Helper()
	f := &fakeCrowdsec{model: defaultCrowdsecModel(), status: "running", reconfigureAfter: "running", reconfigureBody: `{"status":"ok"}`}

	oldPath, oldInt, oldTimeout, oldNow := crowdsecStatePath, crowdsecPollInterval, crowdsecPollTimeout, crowdsecNow
	crowdsecStatePath = t.TempDir() + "/crowdsec-apply.json"
	crowdsecPollInterval, crowdsecPollTimeout = time.Millisecond, 30*time.Millisecond
	t.Cleanup(func() {
		crowdsecStatePath, crowdsecPollInterval, crowdsecPollTimeout, crowdsecNow = oldPath, oldInt, oldTimeout, oldNow
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/crowdsec/general/get", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.notFound {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
			return
		}
		if f.failGetAfterSet && f.setDone {
			w.WriteHeader(500)
			return
		}
		if f.getStatus != 0 {
			w.WriteHeader(f.getStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"general": f.model})
	})
	mux.HandleFunc("/crowdsec/general/set", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.validation != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": "failed", "validations": f.validation})
			return
		}
		f.sets = append(f.sets, body["general"])
		f.setDone = true
		if !f.dropKeys {
			for k, v := range body["general"] {
				if !f.dropOnly[k] {
					f.model[k] = v
				}
			}
		}
		_, _ = w.Write([]byte(`{"result":"saved"}`))
	})
	mux.HandleFunc("/crowdsec/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reconfigures++
		f.status = f.reconfigureAfter
		body, block := f.reconfigureBody, f.blockReconfigure
		f.mu.Unlock()
		if block != nil {
			<-block
		}
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.statusCalls++
		if f.statusFails {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": f.status})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return f, opnapi.NewClient(server.URL, "key", "secret", true)
}

func desiredOf(name string, kv map[string]string) *crowdsecDesired {
	return &crowdsecDesired{Name: name, Values: kv}
}

func crowdsecPayload(snippets ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, len(snippets))
	for i, s := range snippets {
		arr[i] = s
	}
	return map[string]interface{}{"snippets": arr}
}

func crowdsecSnippet(name, content string) map[string]interface{} {
	return map[string]interface{}{"config_type": "CROWDSEC_SETTINGS", "snippet_name": name, "content": content}
}

func csItemsOf(r SyncAPIResult, typ string) []SyncAPIItemResult {
	var out []SyncAPIItemResult
	for _, it := range r.Results {
		if it.Type == typ {
			out = append(out, it)
		}
	}
	return out
}

// Every errors entry needs a matching failing item, and nothing may carry a secret.
func checkCrowdsecResult(t *testing.T, r SyncAPIResult) {
	t.Helper()
	failing := 0
	for _, it := range r.Results {
		if it.Status == "error" {
			failing++
		}
	}
	if failing != len(r.Errors) {
		t.Errorf("%d error items for %d errors: %+v / %v", failing, len(r.Errors), r.Results, r.Errors)
	}
	if r.Success != (len(r.Errors) == 0) {
		t.Errorf("success=%v with %d errors", r.Success, len(r.Errors))
	}
	blob, _ := json.Marshal(r)
	if strings.Contains(string(blob), testEnrollKey) {
		t.Errorf("the enrollment key leaked into the result: %s", blob)
	}
}

func TestParseCrowdsecSettings(t *testing.T) {
	d, err := parseAPICrowdsecSettings(crowdsecPayload(crowdsecSnippet("cs", `{"agent_enabled":true,"rules_log":false,"rules_tag":"nd","enroll_key":""}`)))
	if err != nil || d == nil {
		t.Fatalf("parse: %v %v", d, err)
	}
	want := map[string]string{"agent_enabled": "1", "rules_log": "0", "rules_tag": "nd", "enroll_key": ""}
	if len(d.Values) != len(want) {
		t.Fatalf("values = %v", d.Values)
	}
	for k, v := range want {
		if got, ok := d.Values[k]; !ok || got != v {
			t.Errorf("%s = %q (%v), want %q", k, got, ok, v)
		}
	}
	if d.Name != "cs" {
		t.Errorf("name = %q", d.Name)
	}

	none, err := parseAPICrowdsecSettings(crowdsecPayload(map[string]interface{}{"config_type": "RULE", "content": "{}"}))
	if err != nil || none != nil {
		t.Errorf("no snippet: %v %v", none, err)
	}
	if none, err = parseAPICrowdsecSettings(map[string]interface{}{}); err != nil || none != nil {
		t.Errorf("no snippets key: %v %v", none, err)
	}
}

func TestParseCrowdsecSettingsRejects(t *testing.T) {
	cases := map[string]struct {
		payload map[string]interface{}
		want    string
	}{
		"two snippets": {crowdsecPayload(crowdsecSnippet("a", `{"rules_log":true}`), crowdsecSnippet("b", `{"rules_log":false}`)), "only one CROWDSEC_SETTINGS snippet is allowed"},
		"unknown key":  {crowdsecPayload(crowdsecSnippet("a", `{"rules_logg":true}`)), "rules_logg"},
		"string bool":  {crowdsecPayload(crowdsecSnippet("a", `{"rules_log":"1"}`)), "rules_log"},
		"number tag":   {crowdsecPayload(crowdsecSnippet("a", `{"rules_tag":5}`)), "rules_tag"},
		"missing":      {crowdsecPayload(crowdsecSnippet("a", ``)), "missing content"},
		"invalid json": {crowdsecPayload(crowdsecSnippet("a", `{`)), "invalid content"},
		"trailing":     {crowdsecPayload(crowdsecSnippet("a", `{} {}`)), "trailing data"},
		"lapi keys":    {crowdsecPayload(crowdsecSnippet("a", `{"lapi_listen_port":"9"}`)), "lapi_listen_port"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseAPICrowdsecSettings(tc.payload)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), `"a"`) && name != "two snippets" {
				t.Errorf("error does not name the snippet: %v", err)
			}
		})
	}
	_, err := parseAPICrowdsecSettings(crowdsecPayload(crowdsecSnippet("a", `{"rules_log":true}`), crowdsecSnippet("b", `{}`)))
	if err == nil || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
		t.Errorf("the two-snippet error must name both: %v", err)
	}
}

func TestSyncCrowdsec_NoSnippetTouchesNothing(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.status = "stopped"
	r := executeSyncCrowdsec(context.Background(), client, nil)
	if !r.Success || len(r.Results) != 0 || f.reconfigures != 0 || f.statusCalls != 0 || len(f.sets) != 0 {
		t.Errorf("a missing snippet must do nothing: %+v %d", r, f.reconfigures)
	}
}

func TestSyncCrowdsec_PluginAbsentIsASkippedNoOp(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.notFound = true
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "1"}))
	checkCrowdsecResult(t, r)
	if !r.Success || len(r.Errors) != 0 {
		t.Fatalf("not a no-op: %+v", r)
	}
	items := csItemsOf(r, "crowdsec_settings")
	if len(items) != 1 || items[0].Status != "skipped" || items[0].Name != "cs" || !strings.Contains(items[0].Error, "not installed") {
		t.Errorf("skipped item = %+v", items)
	}
	if len(f.sets) != 0 || f.reconfigures != 0 {
		t.Error("nothing may be written")
	}
}

func TestSyncCrowdsec_DiscoveryErrorFails(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.getStatus = 500
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "1"}))
	checkCrowdsecResult(t, r)
	if r.Success || len(csItemsOf(r, "crowdsec_discovery")) != 1 || !strings.Contains(r.Errors[0], `"cs"`) {
		t.Errorf("discovery failure: %+v", r)
	}
}

func TestSyncCrowdsec_EqualStateWritesNothing(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.model["rules_tag"] = "nd"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd", "rules_log": "0", "agent_enabled": "1"}))
	checkCrowdsecResult(t, r)
	if !r.Success || len(r.Results) != 0 || len(f.sets) != 0 || f.reconfigures != 0 {
		t.Errorf("equal state must be a no-op: %+v sets=%d reconfigures=%d", r, len(f.sets), f.reconfigures)
	}
}

func TestSyncCrowdsec_ChangeSetsOnlyChangedKeysAndReconfiguresOnce(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd", "rules_enabled": "1"}))
	checkCrowdsecResult(t, r)
	if !r.Success {
		t.Fatalf("failed: %+v", r)
	}
	if len(f.sets) != 1 || len(f.sets[0]) != 1 || f.sets[0]["rules_tag"] != "nd" {
		t.Errorf("sets = %v, want one partial set with rules_tag only", f.sets)
	}
	if f.reconfigures != 1 {
		t.Errorf("reconfigures = %d", f.reconfigures)
	}
	items := csItemsOf(r, "crowdsec_settings")
	if len(items) != 1 || items[0].Action != "updated" || items[0].Status != "success" {
		t.Errorf("items = %+v", items)
	}
	if got := buildSyncSummary(r.Results, 0); !strings.Contains(got, "CrowdSec settings ~1") {
		t.Errorf("summary = %q", got)
	}

	again := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd", "rules_enabled": "1"}))
	if !again.Success || len(f.sets) != 1 || f.reconfigures != 1 {
		t.Errorf("a second SYNC must write nothing: sets=%d reconfigures=%d", len(f.sets), f.reconfigures)
	}
}

func TestSyncCrowdsec_BoolSpellingsOnTheDeviceAreNormalised(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.model["rules_log"] = "true"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "1"}))
	if !r.Success || len(f.sets) != 0 {
		t.Errorf("true and 1 are the same: %+v", f.sets)
	}
}

func TestSyncCrowdsec_ValidationFailureNamesFieldAndSkipsReconfigure(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.validation = map[string]string{"general.rules_tag": "A tag must only contain numbers and letters"}
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "bad tag"}))
	checkCrowdsecResult(t, r)
	if r.Success || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], `"cs"`) || !strings.Contains(r.Errors[0], "rules_tag") {
		t.Errorf("errors = %v", r.Errors)
	}
	if f.reconfigures != 0 {
		t.Error("no reconfigure after a refused write")
	}
}

func TestSyncCrowdsec_SilentlyDroppedKeyIsAnError(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.dropKeys = true
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if r.Success || !strings.Contains(r.Errors[0], "rules_tag") || f.reconfigures != 0 {
		t.Errorf("dropped key: %+v reconfigures=%d", r, f.reconfigures)
	}
}

func TestSyncCrowdsec_UnknownKeyOnTheDeviceIsAWarningAndNotSent(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	delete(f.model, "crowdsec_firewall_verbose")
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"crowdsec_firewall_verbose": "1", "rules_log": "1"}))
	checkCrowdsecResult(t, r)
	if !r.Success {
		t.Fatalf("a warning must not fail: %+v", r)
	}
	var warned bool
	for _, it := range r.Results {
		if it.Status == "warning" && strings.Contains(it.Error, "crowdsec_firewall_verbose") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning: %+v", r.Results)
	}
	if len(f.sets) != 1 || len(f.sets[0]) != 1 || f.sets[0]["rules_log"] != "1" {
		t.Errorf("sets = %v", f.sets)
	}
}

func TestSyncCrowdsec_OnlyUnknownKeysMeansNoWrite(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	delete(f.model, "crowdsec_firewall_verbose")
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"crowdsec_firewall_verbose": "1"}))
	if !r.Success || len(f.sets) != 0 || f.reconfigures != 0 {
		t.Errorf("%+v", r)
	}
}

func TestSyncCrowdsec_GuardRefusesLAPIOffWithAgentOrBouncer(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"lapi_enabled": "0"}))
	checkCrowdsecResult(t, r)
	if r.Success || len(f.sets) != 0 || f.reconfigures != 0 {
		t.Fatalf("guard must refuse: %+v", r)
	}
	for _, want := range []string{`"cs"`, "lapi_enabled=false", "agent_enabled=true", "firewall_bouncer_enabled=true"} {
		if !strings.Contains(r.Errors[0], want) {
			t.Errorf("error %q lacks %q", r.Errors[0], want)
		}
	}
}

func TestSyncCrowdsec_GuardAllowsLAPIOffWhenEverythingIsOffOrManual(t *testing.T) {
	t.Run("all off", func(t *testing.T) {
		f, client := newFakeCrowdsec(t)
		f.reconfigureAfter = "disabled"
		r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"lapi_enabled": "0", "agent_enabled": "0", "firewall_bouncer_enabled": "0"}))
		checkCrowdsecResult(t, r)
		if !r.Success || f.reconfigures != 1 {
			t.Errorf("%+v", r)
		}
	})
	t.Run("manual lapi configuration", func(t *testing.T) {
		f, client := newFakeCrowdsec(t)
		f.model["lapi_manual_configuration"] = "1"
		r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"lapi_enabled": "0"}))
		checkCrowdsecResult(t, r)
		if !r.Success || len(f.sets) != 1 {
			t.Errorf("%+v", r)
		}
	})
}

func TestSyncCrowdsec_ReconfigureErrorIsRememberedAndNotRetried(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureBody = `{"status":"error"}`
	f.reconfigureAfter = "stopped"
	desired := desiredOf("cs", map[string]string{"rules_tag": "nd"})

	r := executeSyncCrowdsec(context.Background(), client, desired)
	checkCrowdsecResult(t, r)
	if r.Success || len(csItemsOf(r, "crowdsec_apply")) != 1 || f.reconfigures != 1 {
		t.Fatalf("first run: %+v reconfigures=%d", r, f.reconfigures)
	}

	// The model now matches but the service is down: the heal is withheld.
	r = executeSyncCrowdsec(context.Background(), client, desired)
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 || !strings.Contains(r.Errors[0], "previous apply failed") {
		t.Fatalf("second run must not reconfigure again: %+v reconfigures=%d", r, f.reconfigures)
	}

	// A changed snippet is applied again.
	r = executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "other"}))
	if f.reconfigures != 2 {
		t.Errorf("a changed snippet must apply: reconfigures=%d", f.reconfigures)
	}

	// A changed device state is applied again.
	f.mu.Lock()
	f.model["rules_log"] = "1"
	f.mu.Unlock()
	executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "other"}))
	if f.reconfigures != 3 {
		t.Errorf("a changed device must be retried: reconfigures=%d", f.reconfigures)
	}
}

func TestSyncCrowdsec_FailedApplyMemoryExpires(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureBody = `{"status":"error"}`
	f.reconfigureAfter = "stopped"
	desired := desiredOf("cs", map[string]string{"rules_tag": "nd"})
	executeSyncCrowdsec(context.Background(), client, desired)
	executeSyncCrowdsec(context.Background(), client, desired)
	if f.reconfigures != 1 {
		t.Fatalf("reconfigures = %d", f.reconfigures)
	}
	crowdsecNow = func() time.Time { return time.Now().Add(crowdsecRetryAfter + time.Minute) }
	executeSyncCrowdsec(context.Background(), client, desired)
	if f.reconfigures != 2 {
		t.Errorf("an expired memory must allow one more try: reconfigures=%d", f.reconfigures)
	}
}

func TestSyncCrowdsec_SuccessClearsTheMemory(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureBody = `{"status":"error"}`
	f.reconfigureAfter = "stopped"
	executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	if _, err := os.Stat(crowdsecStatePath); err != nil {
		t.Fatalf("no memory written: %v", err)
	}
	f.reconfigureBody = `{"status":"ok"}`
	f.reconfigureAfter = "running"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "next"}))
	if !r.Success {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(crowdsecStatePath); !os.IsNotExist(err) {
		t.Errorf("memory not cleared: %v", err)
	}
	if fi, _ := os.Stat(crowdsecStatePath); fi != nil {
		t.Error("memory file still there")
	}
}

func TestSyncCrowdsec_StatusMismatchAfterReconfigureFails(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureAfter = "stopped"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 || !strings.Contains(r.Errors[0], `"stopped"`) || !strings.Contains(r.Errors[0], `"running"`) {
		t.Errorf("%+v", r)
	}
}

func TestSyncCrowdsec_StatusIsPolledUntilItSettles(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureAfter = "stopped"
	go func() {
		time.Sleep(8 * time.Millisecond)
		f.mu.Lock()
		f.status = "running"
		f.mu.Unlock()
	}()
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if !r.Success {
		t.Errorf("a service that comes up within the poll window is fine: %+v", r)
	}
}

func TestSyncCrowdsec_DisablingEverythingExpectsDisabled(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.reconfigureAfter = "running"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"agent_enabled": "0", "lapi_enabled": "0", "firewall_bouncer_enabled": "0"}))
	if r.Success || !strings.Contains(r.Errors[0], `expected "disabled"`) {
		t.Errorf("%+v", r)
	}
}

func TestSyncCrowdsec_ReconfigureTimeoutIsVerifiedWithStatus(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.blockReconfigure = make(chan struct{})
	t.Cleanup(func() { close(f.blockReconfigure) })
	client.SetHTTPTimeout(60 * time.Millisecond)
	f.reconfigureAfter = "running"

	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if !r.Success {
		t.Fatalf("a timeout with a running service is not a failure: %+v", r)
	}
	if f.reconfigures != 1 {
		t.Errorf("a timeout must not be retried: %d", f.reconfigures)
	}
	var warned bool
	for _, it := range csItemsOf(r, "crowdsec_apply") {
		warned = warned || it.Status == "warning"
	}
	if !warned {
		t.Errorf("the unknown outcome must be visible: %+v", r.Results)
	}
}

func TestSyncCrowdsec_ReconfigureTimeoutWithWrongStatusFails(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.blockReconfigure = make(chan struct{})
	t.Cleanup(func() { close(f.blockReconfigure) })
	client.SetHTTPTimeout(60 * time.Millisecond)
	f.reconfigureAfter = "stopped"

	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 {
		t.Errorf("%+v reconfigures=%d", r, f.reconfigures)
	}
}

func TestSyncCrowdsec_HealsOnceWhenModelMatchesButServiceIsDown(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.status = "stopped"
	desired := desiredOf("cs", map[string]string{"rules_log": "0"})

	r := executeSyncCrowdsec(context.Background(), client, desired)
	checkCrowdsecResult(t, r)
	if !r.Success || f.reconfigures != 1 || len(f.sets) != 0 {
		t.Fatalf("heal: %+v reconfigures=%d sets=%d", r, f.reconfigures, len(f.sets))
	}

	r = executeSyncCrowdsec(context.Background(), client, desired)
	if f.reconfigures != 1 || !r.Success {
		t.Errorf("a running service needs no heal: reconfigures=%d", f.reconfigures)
	}
}

func TestSyncCrowdsec_FailedHealIsNotRepeated(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.status = "stopped"
	f.reconfigureAfter = "stopped"
	desired := desiredOf("cs", map[string]string{"rules_log": "0"})

	r := executeSyncCrowdsec(context.Background(), client, desired)
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 {
		t.Fatalf("%+v", r)
	}
	r = executeSyncCrowdsec(context.Background(), client, desired)
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 {
		t.Errorf("a failed heal must wait: reconfigures=%d", f.reconfigures)
	}
}

func TestSyncCrowdsec_NoHealWhenEverythingIsOff(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.model["agent_enabled"], f.model["lapi_enabled"], f.model["firewall_bouncer_enabled"] = "0", "0", "0"
	f.status = "disabled"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "0"}))
	if !r.Success || f.reconfigures != 0 {
		t.Errorf("%+v", r)
	}
}

func TestSyncCrowdsec_UnreadableStatusDoesNotHeal(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.statusFails = true
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "0"}))
	if !r.Success || f.reconfigures != 0 {
		t.Errorf("an unknown status is not a reason to restart: %+v", r)
	}
}

func TestSyncCrowdsec_EnrollmentIsReportedAsRequestedWithoutTheKey(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"enroll_key": testEnrollKey}))
	checkCrowdsecResult(t, r)
	if !r.Success || f.sets[0]["enroll_key"] != testEnrollKey {
		t.Fatalf("%+v", r)
	}
	items := csItemsOf(r, "crowdsec_enrollment")
	if len(items) != 1 || items[0].Action != "requested" || !strings.Contains(items[0].Error, "CrowdSec Console") {
		t.Errorf("enrollment item = %+v", items)
	}

	// Clearing the key requests nothing.
	r = executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"enroll_key": ""}))
	if len(csItemsOf(r, "crowdsec_enrollment")) != 0 {
		t.Errorf("an emptied key must not report enrollment: %+v", r.Results)
	}
}

func TestPullCrowdsecSettings(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.model["rules_log"] = "1"
	f.model["rules_tag"] = "nd"
	got, err := pullCrowdsecSettings(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("keys = %v", got)
	}
	if v, ok := got["rules_log"].(bool); !ok || !v {
		t.Errorf("rules_log = %#v", got["rules_log"])
	}
	if v, ok := got["agent_enabled"].(bool); !ok || !v {
		t.Errorf("agent_enabled = %#v", got["agent_enabled"])
	}
	if v, ok := got["rules_tag"].(string); !ok || v != "nd" {
		t.Errorf("rules_tag = %#v", got["rules_tag"])
	}
	if _, has := got["lapi_listen_port"]; has {
		t.Error("only the eight snippet keys are pulled")
	}
}

func TestPullCrowdsecSettingsPluginAbsentIsNotFound(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.notFound = true
	content, err := pullCrowdsecSettings(context.Background(), client)
	if err != nil || content != nil {
		t.Errorf("got %v, %v", content, err)
	}
}

func TestPullConfigRoutesCrowdsecSettings(t *testing.T) {
	_, client := newFakeCrowdsec(t)
	content, _, err := pullConfig(context.Background(), client, "crowdsec_settings", "cs")
	if err != nil || content == nil {
		t.Fatalf("%v %v", content, err)
	}
}

func TestSyncCrowdsec_ReadBackFailureStillReconfiguresOnce(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.failGetAfterSet = true
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd"}))
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 || len(f.sets) != 1 {
		t.Fatalf("sets=%d reconfigures=%d %+v", len(f.sets), f.reconfigures, r)
	}
	if !strings.Contains(r.Errors[0], "read the settings back") {
		t.Errorf("errors = %v", r.Errors)
	}
}

func TestSyncCrowdsec_OneDroppedKeyStillReconfiguresForTheKeptOne(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.dropOnly = map[string]bool{"rules_log": true}
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_tag": "nd", "rules_log": "1"}))
	checkCrowdsecResult(t, r)
	if r.Success || f.reconfigures != 1 {
		t.Fatalf("reconfigures=%d %+v", f.reconfigures, r)
	}
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "rules_log") || strings.Contains(r.Errors[0], "rules_tag") {
		t.Errorf("only the dropped key is reported: %v", r.Errors)
	}
	if got := csItemsOf(r, "crowdsec_settings"); len(got) != 2 {
		t.Errorf("items = %+v", got)
	}
}

func TestSyncCrowdsec_HealIsRefusedWhenItWouldLeaveLAPIOff(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	f.model["lapi_enabled"] = "0"
	f.status = "stopped"
	r := executeSyncCrowdsec(context.Background(), client, desiredOf("cs", map[string]string{"rules_log": "0"}))
	checkCrowdsecResult(t, r)
	if !r.Success || f.reconfigures != 0 {
		t.Fatalf("%+v reconfigures=%d", r, f.reconfigures)
	}
	items := csItemsOf(r, "crowdsec_apply")
	if len(items) != 1 || items[0].Status != "warning" || !strings.Contains(items[0].Error, "lapi_enabled=false") {
		t.Errorf("items = %+v", items)
	}
}

func TestSyncCrowdsecFromPayload_BadSnippetFailsOnlyThisSection(t *testing.T) {
	f, client := newFakeCrowdsec(t)
	r := syncCrowdsecFromPayload(context.Background(), client,
		crowdsecPayload(crowdsecSnippet("a", `{"rules_log":true}`), crowdsecSnippet("b", `{"rules_log":false}`)))
	checkCrowdsecResult(t, r)
	if r.Success || len(csItemsOf(r, "crowdsec_settings")) != 1 || !strings.Contains(r.Errors[0], "only one CROWDSEC_SETTINGS") {
		t.Errorf("%+v", r)
	}
	if len(f.sets) != 0 || f.reconfigures != 0 {
		t.Error("nothing may be applied")
	}
	ok := syncCrowdsecFromPayload(context.Background(), client, crowdsecPayload(crowdsecSnippet("a", `{"rules_tag":"nd"}`)))
	if !ok.Success || len(f.sets) != 1 {
		t.Errorf("a valid payload applies: %+v", ok)
	}
}
