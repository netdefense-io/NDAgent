package opnapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The hook runs for every request that is not an idempotent read, before the
// device sees it, and for no read.
func TestWriteHook_RunsBeforeEveryWriteAndNoRead(t *testing.T) {
	var noted []string
	var arrivedAfter []int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		arrivedAfter = append(arrivedAfter, len(noted))
		_, _ = w.Write([]byte(`{}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	c := NewClient(server.URL, "key", "secret", true)
	ctx := WithWriteHook(context.Background(), func(method, path string) {
		noted = append(noted, method+" "+path)
	})

	for _, read := range []struct{ method, path string }{
		{http.MethodGet, "/unbound/settings/getHostOverride/x"},
		{http.MethodPost, "/unbound/settings/searchHostOverride"},
		{http.MethodPost, "/firewall/filter/searchRule"},
	} {
		_, _ = c.doRequest(ctx, read.method, read.path, struct{}{})
	}
	if len(noted) != 0 {
		t.Fatalf("reads noted %v", noted)
	}

	writes := []string{"/unbound/settings/setHostOverride/x", "/firewall/filter/delRule/x", "/unbound/service/reconfigure"}
	for _, path := range writes {
		_, _ = c.doRequest(ctx, http.MethodPost, path, struct{}{})
	}
	if len(noted) != len(writes) || len(arrivedAfter) != 3+len(writes) {
		t.Fatalf("noted %v and %d requests, want each of %v and %d requests", noted, len(arrivedAfter), writes, 3+len(writes))
	}
	for i := range writes {
		if got := arrivedAfter[3+i]; got != i+1 {
			t.Errorf("write %d reached the device after %d notes, want %d", i, got, i+1)
		}
	}
}

func TestWriteHook_AContextWithoutOneIsUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	c := NewClient(server.URL, "key", "secret", true)
	if _, err := c.doRequest(context.Background(), http.MethodPost, "/unbound/settings/delAcl/x", struct{}{}); err != nil {
		t.Fatal(err)
	}
}

// An apply OPNsense answers as failed is an error: HTTP 200 comes back either
// way. The successful answers are the ones OPNsense 26.7.8 gave on e2e-b; the
// stable/26.1 controllers build the same ones (AliasController and the service
// base return status "ok", FilterBaseController::applyAction configd's output,
// the WireGuard ServiceController result "ok").
func TestApplyCallsReadTheirAnswer(t *testing.T) {
	calls := map[string]func(*Client) error{
		"/firewall/alias/reconfigure":    func(c *Client) error { return c.ReconfigureAliases(context.Background()) },
		"/firewall/filter/apply":         func(c *Client) error { return c.ApplyRules(context.Background()) },
		"/unbound/service/reconfigure":   func(c *Client) error { return c.ReconfigureUnbound(context.Background()) },
		"/wireguard/service/reconfigure": func(c *Client) error { return c.ReconfigureWireGuard(context.Background()) },
	}
	ok := map[string]string{
		"/firewall/alias/reconfigure":    `{"status":"ok"}`,
		"/firewall/filter/apply":         `{"status":"OK\n\n"}`,
		"/unbound/service/reconfigure":   `{"status":"ok"}`,
		"/wireguard/service/reconfigure": `{"result":"ok"}`,
	}
	failed := map[string]string{
		"/firewall/alias/reconfigure":    `{"status":"failed"}`,
		"/firewall/filter/apply":         `{"status":"Execute error"}`,
		"/unbound/service/reconfigure":   `{"status":"failed","status_msg":"Service \"unbound\" failed to start."}`,
		"/wireguard/service/reconfigure": `{"result":"failed"}`,
	}
	for path, call := range calls {
		for _, tc := range []struct {
			answer  string
			wantErr bool
		}{{ok[path], false}, {failed[path], true}, {`{}`, true}, {`not json`, true}} {
			answer := tc.answer
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(answer))
			}))
			err := call(NewClient(server.URL, "key", "secret", true))
			server.Close()
			if (err != nil) != tc.wantErr {
				t.Errorf("%s answered %s: err = %v, want error %v", path, answer, err, tc.wantErr)
			}
		}
	}
}

// A service's status is a GET of the service base's status action; the
// running answer is the one OPNsense 26.7.8 gave on e2e-a and e2e-b.
func TestServiceStatusReadsTheServiceBase(t *testing.T) {
	reads := map[string]func(*Client) (string, error){
		"/unbound/service/status":     func(c *Client) (string, error) { return c.UnboundStatus(context.Background()) },
		"/zabbixagent/service/status": func(c *Client) (string, error) { return c.ZabbixStatus(context.Background()) },
	}
	for path, read := range reads {
		for _, tc := range []struct {
			code    int
			answer  string
			want    string
			wantErr bool
		}{
			{http.StatusOK, `{"status":"running","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`, "running", false},
			{http.StatusOK, `{"status":"stopped","widget":{}}`, "stopped", false},
			{http.StatusOK, `not json`, "", true},
			{http.StatusInternalServerError, `{}`, "", true},
		} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != path {
					t.Errorf("read %s %s, want GET %s", r.Method, r.URL.Path, path)
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.answer))
			}))
			got, err := read(NewClient(server.URL, "key", "secret", true))
			server.Close()
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("%s answered %d %s: %q, %v; want %q, error %v", path, tc.code, tc.answer, got, err, tc.want, tc.wantErr)
			}
		}
	}
}
