package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// TestParseHostOverrideContent_NumbersAndListsAreNotDropped: a TTL given as a
// number used to reach the device as nothing at all.
func TestParseHostOverrideContent_NumbersAndListsAreNotDropped(t *testing.T) {
	override, err := parseHostOverrideContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"mail","domain":"example.com",
		"rr":"MX","mxprio":10,"mx":"mx1.example.com","ttl":300,"server":["192.0.2.25"],"description":"Mail"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct{ field, got, want string }{
		{"mxprio", override.MXPrio, "10"},
		{"ttl", override.TTL, "300"},
		{"server", override.Server, "192.0.2.25"},
		{"mx", override.MX, "mx1.example.com"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

func TestParseHostOverrideContent_AddPTR(t *testing.T) {
	cases := map[string]string{
		`"addptr":false,`:   "0",
		`"addptr":"0",`:     "0",
		`"addptr":"true",`:  "1",
		`"addptr":1,`:       "1",
		``:                  "",
		`"addptr":null,`:    "",
		`"addptr":"maybe",`: "maybe",
	}
	for field, want := range cases {
		override, err := parseHostOverrideContent(`{`+field+`"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"nas","domain":"lan","server":"192.0.2.5"}`, nil)
		if err != nil {
			t.Errorf("%s: %v", field, err)
			continue
		}
		if override.AddPTR != want {
			t.Errorf("%s: addptr = %q, want %q", field, override.AddPTR, want)
		}
	}
}

func TestParseUnboundContent_ObjectValueIsRefusedByName(t *testing.T) {
	cases := map[string]func() error{
		"ttl": func() error {
			_, err := parseHostOverrideContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"nas","domain":"lan","ttl":{"seconds":300}}`, nil)
			return err
		},
		"port": func() error {
			_, err := parseDomainForwardContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","domain":"corp","server":"192.0.2.53","port":{"n":853}}`, nil)
			return err
		},
		"parent_domain": func() error {
			_, err := parseHostAliasContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"www","domain":"lan","parent_domain":[["lan"]]}`, nil)
			return err
		},
		"networks": func() error {
			_, err := parseUnboundACLContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","name":"lan","action":"allow","networks":[{"cidr":"10.0.0.0/8"}]}`, nil)
			return err
		},
	}
	for field, parse := range cases {
		if err := parse(); err == nil || !strings.HasPrefix(err.Error(), field+":") {
			t.Errorf("%s: err = %v, want a refusal naming the field", field, err)
		}
	}
}

func TestParseDomainForwardAndACL_NumbersAndLists(t *testing.T) {
	forward, err := parseDomainForwardContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","domain":"corp","server":"192.0.2.53","type":"dot","port":853}`, nil)
	if err != nil || forward.Port != "853" {
		t.Errorf("forward port = %q, err %v", forward.Port, err)
	}

	acl, err := parseUnboundACLContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","name":"lan","action":"allow","networks":["10.0.0.0/8"," 192.0.2.0/24"]}`, nil)
	if err != nil || strings.Join(acl.Networks, "|") != "10.0.0.0/8|192.0.2.0/24" {
		t.Errorf("acl networks = %q, err %v", acl.Networks, err)
	}
}

// TestParseUnboundContent_FirstBadFieldIsNamed: content with two bad values is
// refused naming the first field the parser reads, every time.
func TestParseUnboundContent_FirstBadFieldIsNamed(t *testing.T) {
	for i := 0; i < 50; i++ {
		_, err := parseHostOverrideContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"nas","domain":"lan",
			"ttl":{"seconds":300},"rr":{"type":"A"}}`, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "rr:") {
			t.Fatalf("err = %v, want the refusal to name rr, read before ttl", err)
		}
	}
}

// TestParseUnboundContent_BooleanOnATextFieldIsRefused: true or false is no
// text field's value ("ttl": true read as "1" would apply a TTL of one
// second), so it is refused by name like an object. The boolean fields keep
// taking one.
func TestParseUnboundContent_BooleanOnATextFieldIsRefused(t *testing.T) {
	const uuid = `"uuid":"221f3268-0001-4000-8000-000000000001",`
	refused := map[string]func() error{
		"ttl": func() error {
			_, err := parseHostOverrideContent(`{`+uuid+`"hostname":"nas","domain":"lan","ttl":true}`, nil)
			return err
		},
		"port": func() error {
			_, err := parseDomainForwardContent(`{`+uuid+`"domain":"corp","server":"192.0.2.53","port":false}`, nil)
			return err
		},
		"parent_domain": func() error {
			_, err := parseHostAliasContent(`{`+uuid+`"hostname":"www","domain":"lan","parent_domain":true}`, nil)
			return err
		},
		"networks": func() error {
			_, err := parseUnboundACLContent(`{`+uuid+`"name":"lan","action":"allow","networks":true}`, nil)
			return err
		},
	}
	for field, parse := range refused {
		if err := parse(); err == nil || err.Error() != field+": takes text or a number, not true or false" {
			t.Errorf("%s: err = %v, want a refusal naming the field", field, err)
		}
	}

	override, err := parseHostOverrideContent(`{`+uuid+`"hostname":"nas","domain":"lan","enabled":false,"addptr":true}`, nil)
	if err != nil || override.Enabled || override.AddPTR != "1" {
		t.Errorf("host override booleans: %+v, err %v", override, err)
	}
	forward, err := parseDomainForwardContent(`{`+uuid+`"domain":"corp","server":"192.0.2.53","enabled":true,"forward_tcp_upstream":true,"forward_first":false}`, nil)
	if err != nil || !forward.Enabled || !forward.ForwardTCPUpstream || forward.ForwardFirst {
		t.Errorf("domain forward booleans: %+v, err %v", forward, err)
	}
}

// TestPullUnbound_NoTemplateList: a pulled UNBOUND element carries no template
// list: SYNC never reads one, and the description loses its template tags.
func TestPullUnbound_NoTemplateList(t *testing.T) {
	const uuid = "221f3268-0001-4000-8000-000000000001"
	rows := map[string]map[string]interface{}{
		"searchHostOverride": {"uuid": uuid, "enabled": "1", "hostname": "nas", "domain": "lan", "rr": "A", "server": "192.0.2.5", "description": "NAS [nd-template:dns]"},
		"searchForward":      {"uuid": uuid, "enabled": "1", "type": "forward", "domain": "corp", "server": "192.0.2.53", "description": "Corp [nd-template:dns]"},
		"searchHostAlias":    {"uuid": uuid, "enabled": "1", "host": uuid, "hostname": "files", "domain": "lan", "description": "Files [nd-template:dns]"},
		"searchAcl":          {"uuid": uuid, "enabled": "1", "name": "lan", "action": "allow", "networks": "192.0.2.0/24", "description": "LAN [nd-template:dns]"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var found []map[string]interface{}
		if row, ok := rows[strings.TrimPrefix(r.URL.Path, "/unbound/settings/")]; ok {
			found = append(found, row)
		}
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: found, RowCount: len(found), Total: len(found)})
	}))
	t.Cleanup(server.Close)
	client := opnapi.NewClient(server.URL, "key", "secret", true)
	ctx := context.Background()

	pulls := map[string]func() (map[string]interface{}, error){
		"host override":  func() (map[string]interface{}, error) { return pullHostOverride(ctx, client, "nas.lan") },
		"domain forward": func() (map[string]interface{}, error) { return pullDomainForward(ctx, client, "corp") },
		"host alias":     func() (map[string]interface{}, error) { return pullHostAlias(ctx, client, "files.lan") },
		"ACL":            func() (map[string]interface{}, error) { return pullUnboundACL(ctx, client, "lan") },
	}
	for name, pull := range pulls {
		content, err := pull()
		if err != nil || content == nil {
			t.Fatalf("%s: content %v, err %v", name, content, err)
		}
		if _, ok := content["templates"]; ok {
			t.Errorf("%s: PULL emits a template list: %v", name, content)
		}
		if description, _ := content["description"].(string); strings.Contains(description, "nd-template") {
			t.Errorf("%s: description = %q", name, description)
		}
	}
}
