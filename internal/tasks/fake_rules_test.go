package tasks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// ruleFixture reads a response captured from an OPNsense 26.7 device (lab
// values replaced by documentation ones), kept with the opnapi package.
func ruleFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "opnapi", "testdata", "rules", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

// ruleTemplate is what getRule without a uuid answers on 26.7, under its
// "rule" wrapper, with each option applied to it.
func ruleTemplate(t *testing.T, options ...func(map[string]interface{})) map[string]interface{} {
	t.Helper()
	var wrapper map[string]map[string]interface{}
	if err := json.Unmarshal(ruleFixture(t, "rule-template-26.7.json"), &wrapper); err != nil {
		t.Fatalf("decode rule template: %v", err)
	}
	template := wrapper["rule"]
	for _, option := range options {
		option(template)
	}
	return template
}

// aliasTemplate is what getItem without a uuid answers for an alias on 26.7,
// under its "alias" wrapper. It is built from OPNsense's 26.7 alias model
// (Alias.xml) and AliasController::getItemAction, not captured from a device.
func aliasTemplate(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "opnapi", "testdata", "aliases", "alias-template-26.7.json"))
	if err != nil {
		t.Fatalf("read alias template: %v", err)
	}
	var wrapper map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("decode alias template: %v", err)
	}
	return wrapper["alias"]
}

// ruleModel26 is the 26.7 rule model, with each option applied to its template.
func ruleModel26(t *testing.T, options ...func(map[string]interface{})) opnapi.EntityModel {
	t.Helper()
	return opnapi.ParseEntityModel(ruleTemplate(t, options...))
}

// optionList builds OPNsense's option-list shape from key/label pairs.
func optionList(pairs ...string) map[string]interface{} {
	out := map[string]interface{}{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = map[string]interface{}{"value": pairs[i+1], "selected": 0}
	}
	return out
}

// withInterfaces replaces the interface options with these keys.
func withInterfaces(keys ...string) func(map[string]interface{}) {
	return func(template map[string]interface{}) {
		var pairs []string
		for _, key := range keys {
			pairs = append(pairs, key, strings.ToUpper(key))
		}
		template["interface"] = optionList(pairs...)
	}
}

// withCategories gives the device categories, as uuid/name pairs.
func withCategories(pairs ...string) func(map[string]interface{}) {
	return func(template map[string]interface{}) {
		template["categories"] = optionList(pairs...)
	}
}

// searchRows26 is the unfiltered searchRule answer captured on 26.7: OPNsense's
// automatic rows, legacy rows, the two default LAN rules and one managed rule.
func searchRows26(t *testing.T) []map[string]interface{} {
	t.Helper()
	var resp opnapi.SearchResponse
	if err := json.Unmarshal(ruleFixture(t, "search-rule-26.7.json"), &resp); err != nil {
		t.Fatalf("decode search rows: %v", err)
	}
	return resp.Rows
}

// fakeRuleDevice is an OPNsense stand-in for the firewall endpoints
// executeSyncAPI talks to. It applies the writes it receives to its rows, so a
// second sync sees what the first one left, and records every mutating call in
// order as "<verb> <uuid>" ("set", "del") or "apply".
type fakeRuleDevice struct {
	t  *testing.T
	mu sync.Mutex

	template     map[string]interface{}
	templateFail bool
	rows         []map[string]interface{}

	aliasTemplate     map[string]interface{}
	aliasTemplateFail bool
	aliases           []map[string]interface{}

	// groups are the interface groups the group search lists; an interface
	// option whose key is a group is listed as one. interfaceListFail and
	// groupSearchFail make that placement input answer HTTP 404, as on a
	// release without it.
	groups            []opnapi.InterfaceGroup
	interfaceListFail bool
	groupSearchFail   bool
	// rank, when set, is the section the device ranks a rule in, instead of
	// OPNsense's rule; it lets a test make the device disagree.
	rank     func(row map[string]interface{}) int
	searches int

	writes []string
	bodies map[string][]map[string]string
	// calls counts the getRule/<uuid>, setRule, delRule and toggleRule calls
	// per "<call> <uuid>", the current one included when before runs.
	calls map[string]int
	saves int

	// answer, when set, answers a setRule instead of saving it: the status
	// code and the JSON body to send. ok=false saves as usual.
	answer func(uuid string, body map[string]string) (status int, response interface{}, ok bool)
	// answerGet, when set, answers a getRule/<uuid> with this JSON body
	// instead of the rule; ok=false answers as usual.
	answerGet func(uuid string) (response interface{}, ok bool)
	// before, when set, runs with the lock held at the start of every
	// getRule/<uuid> ("get"), setRule ("set"), delRule ("del") and toggleRule
	// ("toggle"): a test changes the device there, between the agent's reads
	// and writes. A false return answers the call with HTTP 500 instead.
	before func(call, uuid string) bool

	client *opnapi.Client
}

func newFakeRuleDevice(t *testing.T, template map[string]interface{}, rows []map[string]interface{}) *fakeRuleDevice {
	t.Helper()
	f := &fakeRuleDevice{t: t, template: template, rows: rows, bodies: map[string][]map[string]string{}, calls: map[string]int{}, aliasTemplate: aliasTemplate(t)}

	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		phrase, _ := req["searchPhrase"].(string)
		var rows []map[string]interface{}
		for _, row := range f.aliases {
			if name, _ := row["name"].(string); phrase == "" || strings.Contains(name, phrase) {
				rows = append(rows, row)
			}
		}
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
	})
	// An alias written here becomes an overload option of the rule model at
	// once, as it does on OPNsense: the model reads the alias model from the
	// saved config.
	mux.HandleFunc("/firewall/alias/setItem/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		uuid := strings.TrimPrefix(r.URL.Path, "/firewall/alias/setItem/")
		var wrapper map[string]map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&wrapper)
		body := map[string]string{}
		for k, v := range wrapper["alias"] {
			s, ok := v.(string)
			if !ok {
				f.t.Errorf("setItem %s: %s is %T, OPNsense takes strings only", uuid, k, v)
			}
			body[k] = s
		}
		f.writes = append(f.writes, "alias "+uuid)
		f.bodies[uuid] = append(f.bodies[uuid], body)
		if f.answer != nil {
			if status, response, ok := f.answer(uuid, body); ok {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(response)
				return
			}
		}
		var target map[string]interface{}
		for _, row := range f.aliases {
			if row["uuid"] == uuid {
				target = row
			}
		}
		if target == nil {
			target = map[string]interface{}{"uuid": uuid}
			f.aliases = append(f.aliases, target)
		}
		for k, v := range body {
			target[k] = v
		}
		if overload, ok := f.template["overload"].(map[string]interface{}); ok {
			overload[uuid] = map[string]interface{}{"value": body["name"], "selected": 0}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
	})
	mux.HandleFunc("/firewall/alias/delItem/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		uuid := strings.TrimPrefix(r.URL.Path, "/firewall/alias/delItem/")
		f.writes = append(f.writes, "aliasdel "+uuid)
		for i, row := range f.aliases {
			if row["uuid"] == uuid {
				f.aliases = append(f.aliases[:i], f.aliases[i+1:]...)
				break
			}
		}
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/firewall/alias/getItem", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.aliasTemplateFail {
			http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"alias": f.aliasTemplate})
	})
	mux.HandleFunc("/firewall/alias/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/firewall/filter/getRule", f.getRule)
	mux.HandleFunc("/firewall/filter/getRule/", f.getOneRule)
	mux.HandleFunc("/firewall/filter/get_interface_list", f.interfaceList)
	mux.HandleFunc("/firewall/group/search_item", f.groupSearch)
	mux.HandleFunc("/firewall/filter/searchRule", f.searchRule)
	mux.HandleFunc("/firewall/filter/setRule/", f.setRule)
	mux.HandleFunc("/firewall/filter/delRule/", f.delRule)
	mux.HandleFunc("/firewall/filter/toggleRule/", f.toggleRule)
	mux.HandleFunc("/firewall/filter/apply", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.writes = append(f.writes, "apply")
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK\n\n"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	f.client = opnapi.NewClient(server.URL, "key", "secret", true)
	return f
}

func (f *fakeRuleDevice) getRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.templateFail {
		http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": f.template})
}

// getOneRule answers getRule/<uuid> as OPNsense does: the rule in its
// template's shape (each option list marking the row's keys selected, a
// container as stored, every field the row lacks at its default), with
// prio_group and sort_order derived anew as every model load does, or [] for
// a uuid it does not hold.
func (f *fakeRuleDevice) getOneRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid := strings.TrimPrefix(r.URL.Path, "/firewall/filter/getRule/")
	f.calls["get "+uuid]++
	if f.before != nil && !f.before("get", uuid) {
		http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
		return
	}
	if f.answerGet != nil {
		if response, ok := f.answerGet(uuid); ok {
			_ = json.NewEncoder(w).Encode(response)
			return
		}
	}
	stored := f.find(uuid)
	if stored == nil {
		_, _ = w.Write([]byte(`[]`))
		return
	}
	row := map[string]interface{}{}
	for k, v := range stored {
		row[k] = v
	}
	f.rankRow(row)
	rule := map[string]interface{}{}
	for key, field := range f.template {
		value, set := row[key].(string)
		options, isList := field.(map[string]interface{})
		switch {
		case isList && !isOptionList(options):
			if stamped, ok := row[key]; ok {
				rule[key] = stamped
			} else {
				rule[key] = field
			}
		case isList:
			selected := map[string]bool{}
			for _, k := range strings.Split(value, ",") {
				selected[k] = true
			}
			marked := map[string]interface{}{}
			for k, option := range options {
				pair, _ := option.(map[string]interface{})
				copied := map[string]interface{}{"value": pair["value"], "selected": 0}
				if set && selected[k] || !set && isSelected(pair["selected"]) {
					copied["selected"] = 1
				}
				marked[k] = copied
			}
			rule[key] = marked
		case set:
			rule[key] = value
		default:
			rule[key] = field
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule})
}

// isOptionList reports whether a template object is an option list, every
// member a {value, selected} pair, rather than a container.
func isOptionList(object map[string]interface{}) bool {
	for _, member := range object {
		pair, ok := member.(map[string]interface{})
		if !ok {
			return false
		}
		if _, ok := pair["value"]; !ok {
			return false
		}
	}
	return true
}

func isSelected(v interface{}) bool {
	switch s := v.(type) {
	case float64:
		return s != 0
	case bool:
		return s
	case string:
		return s == "1"
	}
	return false
}

func (f *fakeRuleDevice) isGroup(key string) bool {
	for _, g := range f.groups {
		if g.Name == key {
			return true
		}
	}
	return false
}

// interfaceList answers get_interface_list from the template's interface
// options, in OPNsense's sections.
func (f *fakeRuleDevice) interfaceList(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.interfaceListFail {
		http.NotFound(w, r)
		return
	}
	type item struct {
		Value string `json:"value"`
		Label string `json:"label"`
		Type  string `json:"type"`
	}
	var groups, interfaces []item
	options, _ := f.template["interface"].(map[string]interface{})
	for key := range options {
		if f.isGroup(key) {
			groups = append(groups, item{key, key, "group"})
		} else {
			interfaces = append(interfaces, item{key, key, "interface"})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"floating":   map[string]interface{}{"items": []item{{"__floating", "Floating", "floating"}}},
		"groups":     map[string]interface{}{"items": groups},
		"interfaces": map[string]interface{}{"items": interfaces},
		"any":        map[string]interface{}{"items": []item{{"__any", "All rules", "any"}}},
	})
}

func (f *fakeRuleDevice) groupSearch(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groupSearchFail {
		http.NotFound(w, r)
		return
	}
	rows := []map[string]interface{}{}
	for _, g := range f.groups {
		seq := ""
		if g.Sequence != 0 {
			seq = strconv.Itoa(g.Sequence)
		}
		rows = append(rows, map[string]interface{}{"ifname": g.Name, "sequence": seq, "members": strings.Join(g.Members, ",")})
	}
	_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
}

// rankRow sets a written row's prio_group and sort_order the way OPNsense
// derives them (FilterRuleField::getPriority); the caller holds the lock.
func (f *fakeRuleDevice) rankRow(row map[string]interface{}) {
	var section int
	if f.rank != nil {
		section = f.rank(row)
	} else {
		value, _ := row["interface"].(string)
		not, _ := row["interfacenot"].(string)
		interfaces := splitInterfaces(value)
		switch {
		case len(interfaces) != 1 || not == "1":
			section = sectionFloating
		case f.isGroup(interfaces[0]):
			section = sectionGroups
			for _, g := range f.groups {
				if g.Name == interfaces[0] {
					section += g.Sequence
				}
			}
		default:
			section = sectionInterface
		}
	}
	row["prio_group"] = strconv.Itoa(section)
	row["sort_order"] = fmt.Sprintf("%d.0%06d", section, rowSequence(row))
}

// searchRule answers one page of the search, as OPNsense pages it: rowCount
// rows from page current, or every row when rowCount is -1.
func (f *fakeRuleDevice) searchRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches++
	var req struct {
		Current  int `json:"current"`
		RowCount int `json:"rowCount"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	for _, row := range f.rows {
		// OPNsense derives an MVC rule's section whenever it loads the model.
		if legacy, _ := row["legacy"].(bool); !legacy {
			f.rankRow(row)
		}
	}
	page := f.rows
	if req.RowCount > 0 {
		first := min(max(req.Current-1, 0)*req.RowCount, len(f.rows))
		page = f.rows[first:min(first+req.RowCount, len(f.rows))]
	}
	rows := append([]map[string]interface{}{}, page...)
	_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(f.rows)})
}

func (f *fakeRuleDevice) setRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid := strings.TrimPrefix(r.URL.Path, "/firewall/filter/setRule/")

	var wrapper map[string]map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		f.t.Errorf("setRule %s: undecodable body: %v", uuid, err)
	}
	body := map[string]string{}
	for k, v := range wrapper["rule"] {
		s, ok := v.(string)
		if !ok {
			f.t.Errorf("setRule %s: %s is %T, OPNsense takes strings only", uuid, k, v)
		}
		body[k] = s
	}
	f.writes = append(f.writes, "set "+uuid)
	f.bodies[uuid] = append(f.bodies[uuid], body)
	f.calls["set "+uuid]++
	if f.before != nil && !f.before("set", uuid) {
		http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
		return
	}

	if f.answer != nil {
		if status, response, ok := f.answer(uuid, body); ok {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
	}

	// setRule is an upsert: a uuid the device does not hold becomes a new
	// rule holding the model's defaults, and then the body. A model with an
	// audit record (26.7.5) stamps it on every save.
	target := f.find(uuid)
	if target == nil {
		target = map[string]interface{}{"uuid": uuid}
		for name, value := range opnapi.ParseEntityModel(f.template).Values() {
			target[name] = value
		}
		f.rows = append(f.rows, target)
	}
	for k, v := range body {
		target[k] = v
	}
	if _, audited := f.template["audit"]; audited {
		f.saves++
		stamp := map[string]interface{}{"username": "root@192.0.2.9", "time": fmt.Sprintf("1791234806.%02d", f.saves), "description": "/api/firewall/filter/set_rule"}
		target["audit"] = map[string]interface{}{"created": stamp, "updated": stamp, "userdata": map[string]interface{}{"note": ""}}
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
}

func (f *fakeRuleDevice) delRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid := strings.TrimPrefix(r.URL.Path, "/firewall/filter/delRule/")
	f.writes = append(f.writes, "del "+uuid)
	f.calls["del "+uuid]++
	if f.before != nil && !f.before("del", uuid) {
		http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
		return
	}
	for i, rw := range f.rows {
		if rw["uuid"] == uuid {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			break
		}
	}
	_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
}

// toggleRule sets a rule's enabled flag as toggleRule/<uuid>/<0|1> does: never
// creating a rule, answering "failed" for a uuid it does not hold.
func (f *fakeRuleDevice) toggleRule(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uuid, enabled, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/firewall/filter/toggleRule/"), "/")
	f.writes = append(f.writes, "toggle "+uuid)
	f.calls["toggle "+uuid]++
	if f.before != nil && !f.before("toggle", uuid) {
		http.Error(w, `{"errorMessage":"Unexpected error, check log for details"}`, http.StatusInternalServerError)
		return
	}
	row := f.find(uuid)
	if row == nil {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "failed"})
		return
	}
	row["enabled"] = enabled
	result := "Disabled"
	if enabled == "1" {
		result = "Enabled"
	}
	_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: result})
}

// find returns the live row with this uuid; the caller holds the lock.
func (f *fakeRuleDevice) find(uuid string) map[string]interface{} {
	for _, rw := range f.rows {
		if rw["uuid"] == uuid {
			return rw
		}
	}
	return nil
}

// edit changes the live row with this uuid, as the device itself would.
func (f *fakeRuleDevice) edit(uuid string, change func(map[string]interface{})) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if found := f.find(uuid); found != nil {
		change(found)
	}
}

// row returns a copy of the live row with this uuid, or nil.
func (f *fakeRuleDevice) row(uuid string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := f.find(uuid)
	if found == nil {
		return nil
	}
	cp := map[string]interface{}{}
	for k, v := range found {
		cp[k] = v
	}
	return cp
}

// writesTo returns the recorded mutating calls naming uuid, in order.
func (f *fakeRuleDevice) writesTo(uuid string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, w := range f.writes {
		if strings.HasSuffix(w, " "+uuid) {
			out = append(out, w)
		}
	}
	return out
}

// lastBody returns the last setRule body sent for uuid, or nil.
func (f *fakeRuleDevice) lastBody(uuid string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	bodies := f.bodies[uuid]
	if len(bodies) == 0 {
		return nil
	}
	return bodies[len(bodies)-1]
}

// sequenceOf reads a live row's sequence.
func (f *fakeRuleDevice) sequenceOf(uuid string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if found := f.find(uuid); found != nil {
		return rowSequence(found)
	}
	return 0
}

func (f *fakeRuleDevice) setCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, w := range f.writes {
		if strings.HasPrefix(w, "set ") {
			n++
		}
	}
	return n
}

// desiredRule builds a desired rule the way parseAPIRules would from a RULE
// snippet with this content.
func desiredRule(t *testing.T, snippet string, position RulePosition, priority int, content string, templates ...string) APIRulePayload {
	t.Helper()
	rule, err := parseRuleContent(content, templates)
	if err != nil {
		t.Fatalf("parseRuleContent(%s): %v", content, err)
	}
	rule.Position = position
	rule.Priority = priority
	rule.SnippetName = snippet
	return rule
}

// desiredAlias builds a desired alias the way parseAPIAliases would from an
// ALIAS snippet with this content.
func desiredAlias(t *testing.T, snippet, content string, templates ...string) APIAliasPayload {
	t.Helper()
	alias, err := parseAliasContent(content, templates)
	if err != nil {
		t.Fatalf("parseAliasContent(%s): %v", content, err)
	}
	alias.SnippetName = snippet
	return alias
}
