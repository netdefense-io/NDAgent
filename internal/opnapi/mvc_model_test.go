package opnapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// ruleTemplate26 is the rule template a 26.7 device answers getRule with,
// captured on the lab device, lab values replaced by documentation ones.
func ruleTemplate26(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rules", "rule-template-26.7.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wrapper map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper["rule"]
}

func TestParseEntityModel_RuleModel26(t *testing.T) {
	model := ParseEntityModel(ruleTemplate26(t))

	if model.Len() != 56 {
		t.Fatalf("fields = %d, want the 56 of the 26.7 rule model", model.Len())
	}

	var booleans []string
	for _, name := range model.Names() {
		if f, _ := model.Field(name); f.IsBoolean() {
			booleans = append(booleans, name)
		}
	}
	wantBooleans := []string{"allowopts", "destination_not", "disablereplyto", "enabled", "interfacenot", "log", "nopfsync", "nosync", "quick", "source_not", "tcpflags_any"}
	if !reflect.DeepEqual(booleans, wantBooleans) {
		t.Errorf("boolean fields = %v, want %v", booleans, wantBooleans)
	}

	defaults := map[string]string{
		"enabled":      "1",
		"quick":        "1",
		"log":          "0",
		"action":       "pass",
		"direction":    "in",
		"ipprotocol":   "inet",
		"protocol":     "any",
		"statetype":    "keep",
		"state-policy": "",
		"source_net":   "any",
		"interface":    "",
		"overload":     "",
		"description":  "",
	}
	for name, want := range defaults {
		f, ok := model.Field(name)
		if !ok {
			t.Errorf("model has no %q", name)
			continue
		}
		if f.Default != want {
			t.Errorf("%s default = %q, want %q", name, f.Default, want)
		}
	}

	for _, name := range []string{"action", "interface", "protocol", "statetype", "icmp6type", "tcpflags1", "overload", "categories"} {
		if f, _ := model.Field(name); !f.List {
			t.Errorf("%s is not a list field", name)
		}
	}
	for _, name := range []string{"source_net", "destination_port", "statetimeout", "tag", "description"} {
		if f, _ := model.Field(name); f.List || f.Nested {
			t.Errorf("%s should be a plain field", name)
		}
	}

	categories, _ := model.Field("categories")
	if len(categories.Options) != 0 {
		t.Errorf("categories offers %v; the device has none, which OPNsense sends as []", categories.Options)
	}

	iface, _ := model.Field("interface")
	if got := iface.OptionKeys(); !reflect.DeepEqual(got, []string{"lan", "wan", "wireguard"}) {
		t.Errorf("interface options = %v", got)
	}

	overload, _ := model.Field("overload")
	if overload.Options["221f3268-0000-4000-8000-00000000a001"] != "SOC_Hosts" {
		t.Errorf("overload should offer an alias by UUID with its name as the label, got %v", overload.Options)
	}
}

func TestParseEntityModel_Shapes(t *testing.T) {
	var template map[string]interface{}
	err := json.Unmarshal([]byte(`{
		"plain": "x",
		"multi": {"b": {"value": "B", "selected": 1}, "a": {"value": "A", "selected": true}, "c": {"value": "C", "selected": 0}},
		"empty": [],
		"container": {"inner": "y"}
	}`), &template)
	if err != nil {
		t.Fatal(err)
	}
	model := ParseEntityModel(template)

	multi, _ := model.Field("multi")
	if !multi.List || multi.Default != "a,b" {
		t.Errorf("multi = %+v, want a list field defaulting to a,b", multi)
	}
	empty, _ := model.Field("empty")
	if !empty.List || len(empty.Options) != 0 {
		t.Errorf("empty = %+v, want a list field without options", empty)
	}
	container, _ := model.Field("container")
	if !container.Nested {
		t.Errorf("container = %+v, want nested", container)
	}
}

func TestFlexibleValidation_PerFieldForm(t *testing.T) {
	var fv FlexibleValidation
	in := `{"rule.log":"Value should be a boolean (0,1).","rule.statetimeout":["Value must be a number.","Value is out of range."]}`
	if err := json.Unmarshal([]byte(in), &fv); err != nil {
		t.Fatal(err)
	}
	if !fv.HasErrors() {
		t.Fatal("HasErrors() = false")
	}

	got := fv.FieldMessages("rule.")
	want := []string{
		"log: Value should be a boolean (0,1).",
		"statetimeout: Value must be a number.",
		"statetimeout: Value is out of range.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FieldMessages() = %q, want %q", got, want)
	}
	if fv.String() == in {
		t.Error("String() should render the fields, not the raw JSON")
	}
}

// setRuleServer answers every setRule with this status and body, and keeps
// the last request body it received.
func setRuleServer(t *testing.T, status int, response string) (*Client, *[]byte) {
	t.Helper()
	var last []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		last = buf
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "key", "secret", true), &last
}

func TestSetRule_ValidationFailureIsTyped(t *testing.T) {
	client, _ := setRuleServer(t, http.StatusOK,
		`{"result":"failed","validations":{"rule.log":"Value should be a boolean (0,1)."}}`)

	err := client.SetRule(context.Background(), "221f3268-0001-4000-8000-000000000001", map[string]string{"log": "yes"})

	var refused *ValidationFailedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a *ValidationFailedError", err)
	}
	if got := refused.Messages(); !reflect.DeepEqual(got, []string{"log: Value should be a boolean (0,1)."}) {
		t.Errorf("Messages() = %q", got)
	}
}

func TestSetRule_FailedWithoutValidationsIsNotAValidationFailure(t *testing.T) {
	client, _ := setRuleServer(t, http.StatusOK, `{"result":"failed"}`)

	err := client.SetRule(context.Background(), "221f3268-0001-4000-8000-000000000001", map[string]string{})

	var refused *ValidationFailedError
	if err == nil || errors.As(err, &refused) {
		t.Fatalf("err = %v, want an error that is not a field validation", err)
	}
}

func TestSetRule_HTTP500IsAnAPIError(t *testing.T) {
	client, _ := setRuleServer(t, http.StatusInternalServerError, `{"errorMessage":"Unexpected error, check log for details"}`)

	err := client.SetRule(context.Background(), "221f3268-0001-4000-8000-000000000001", map[string]string{})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("err = %v, want an APIError with status 500", err)
	}
}

func TestSetRule_SendsStringsUnderTheRuleWrapper(t *testing.T) {
	client, last := setRuleServer(t, http.StatusOK, `{"result":"saved"}`)

	err := client.SetRule(context.Background(), "221f3268-0001-4000-8000-000000000001",
		map[string]string{"log": "1", "interface": "lan,wan", "sequence": "100"})
	if err != nil {
		t.Fatal(err)
	}

	want := `{"rule":{"interface":"lan,wan","log":"1","sequence":"100"}}`
	if string(*last) != want {
		t.Errorf("body = %s, want %s", *last, want)
	}
}

func TestGetRuleModel_ReadsTheTemplate(t *testing.T) {
	template := ruleTemplate26(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/firewall/filter/getRule" {
			t.Errorf("%s %s, want GET /firewall/filter/getRule", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": template})
	}))
	t.Cleanup(srv.Close)

	model, err := NewClient(srv.URL, "key", "secret", true).GetRuleModel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := model.Names()
	if !sort.StringsAreSorted(names) || len(names) != 56 {
		t.Errorf("Names() = %d sorted=%v", len(names), sort.StringsAreSorted(names))
	}
}

// TestGetRule_ValuesOrNotFound: getRule/<uuid> answers a rule in its
// template's shape, read as the rule's values, or [] for a uuid the device
// does not hold.
func TestGetRule_ValuesOrNotFound(t *testing.T) {
	const known = "7179a1de-88f9-428f-a5b7-d4814890be9f"
	rule := ruleTemplate26(t)
	rule["description"] = "Default allow LAN to any rule"
	rule["interface"] = map[string]interface{}{
		"lan": map[string]interface{}{"value": "LAN", "selected": 1},
		"wan": map[string]interface{}{"value": "WAN", "selected": 0},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/firewall/filter/getRule/" + known:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule})
		case "/firewall/filter/getRule/odd":
			_, _ = w.Write([]byte(`{"result":"failed"}`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, "key", "secret", true)

	values, found, err := client.GetRule(context.Background(), known)
	if err != nil || !found {
		t.Fatalf("known rule: found=%v err=%v", found, err)
	}
	if values["interface"] != "lan" || values["description"] != "Default allow LAN to any rule" || values["action"] != "pass" {
		t.Errorf("values = %v", values)
	}

	if _, found, err := client.GetRule(context.Background(), "221f3268-0000-4000-8000-000000000404"); found || err != nil {
		t.Errorf("missing rule: found=%v err=%v, want not found and no error", found, err)
	}
	if _, found, err := client.GetRule(context.Background(), "odd"); found || err == nil {
		t.Errorf("an answer that is neither a rule nor []: found=%v err=%v", found, err)
	}
}

func TestGetRuleModel_RefusesAnEmptyTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rule":{}}`))
	}))
	t.Cleanup(srv.Close)

	if _, err := NewClient(srv.URL, "key", "secret", true).GetRuleModel(context.Background()); err == nil {
		t.Error("an empty rule template must not read as a model")
	}
}

// aliasTemplate26 is the alias template of a 26.7 device, built from its alias
// model (Alias.xml) and AliasController::getItemAction, not captured.
func aliasTemplate26(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "aliases", "alias-template-26.7.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wrapper map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper["alias"]
}

func TestParseEntityModel_AliasModel26(t *testing.T) {
	model := ParseEntityModel(aliasTemplate26(t))
	if model.Len() != 27 {
		t.Fatalf("fields = %d, want 27: 15 settable and 12 statistics", model.Len())
	}

	typeField, _ := model.Field("type")
	if !typeField.List || typeField.Default != "" || len(typeField.Options) != 14 {
		t.Errorf("type = %+v; it has no usable default, so content must give it", typeField)
	}
	iface, _ := model.Field("interface")
	if _, blank := iface.Options[""]; !blank || iface.Default != "" {
		t.Errorf("interface = %+v, want an optional single choice", iface)
	}
	counters, _ := model.Field("counters")
	if !counters.IsBoolean() {
		t.Errorf("counters = %+v, want a boolean", counters)
	}
	content, _ := model.Field("content")
	if !content.List || content.Options["bogons"] != "bogons" {
		t.Errorf("content = %+v; its options are the alias names OPNsense suggests", content)
	}
}

func TestSetAlias_ValidationFailureIsTyped(t *testing.T) {
	client, last := setRuleServer(t, http.StatusOK,
		`{"result":"failed","validations":{"alias.name":"An alias with this name already exists."}}`)

	err := client.SetAlias(context.Background(), "221f3268-0001-4000-8000-000000000001", map[string]string{"name": "dup"})

	var refused *ValidationFailedError
	if !errors.As(err, &refused) || !reflect.DeepEqual(refused.Messages(), []string{"name: An alias with this name already exists."}) {
		t.Fatalf("err = %v", err)
	}
	if string(*last) != `{"alias":{"name":"dup"}}` {
		t.Errorf("body = %s", *last)
	}
}
