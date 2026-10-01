package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// plausibleIDs is a catalog as long as a real release's: the anchors, the IDs the
// tests use, and filler up to well over the minimum.
func plausibleIDs(extra ...string) []string {
	ids := []string{"page-all", "user-config-readonly"}
	ids = append(ids, extra...)
	for i := 0; i < devicePrivsMinEntries; i++ {
		ids = append(ids, fmt.Sprintf("page-filler-%03d", i))
	}
	return ids
}

func plausibleCatalog(t testing.TB, extra ...string) *DevicePrivs {
	t.Helper()
	d, err := NewDevicePrivs(plausibleIDs(extra...))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewDevicePrivs_RejectsACatalogThatIsNotTheRealOne(t *testing.T) {
	filler := func(n int) []string {
		var ids []string
		for i := 0; i < n; i++ {
			ids = append(ids, fmt.Sprintf("page-filler-%03d", i))
		}
		return ids
	}
	tests := []struct {
		name string
		ids  []string
		ok   bool
	}{
		{"a real-sized catalog with both anchors", append([]string{"page-all", "user-config-readonly"}, filler(devicePrivsMinEntries)...), true},
		{"empty", nil, false},
		{"a handful of IDs", []string{"page-all", "user-config-readonly", "page-a"}, false},
		{"one short of the minimum", append([]string{"page-all", "user-config-readonly"}, filler(devicePrivsMinEntries-3)...), false},
		{"long enough but without page-all", append([]string{"user-config-readonly"}, filler(devicePrivsMinEntries)...), false},
		{"long enough but without the write backstop", append([]string{"page-all"}, filler(devicePrivsMinEntries)...), false},
		{"repeats count once", append(filler(10), filler(10)...), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDevicePrivs(tt.ids)
			if (err == nil) != tt.ok {
				t.Fatalf("NewDevicePrivs = %v, %v; ok = %v", d, err, tt.ok)
			}
		})
	}
}

// OPNsense looks a privilege up by exact spelling (array_key_exists on the catalog).
func TestDevicePrivs_DefinesIsExact(t *testing.T) {
	d := plausibleCatalog(t, "page-system-usermanager", "page-tailscale-config")
	for id, want := range map[string]bool{
		"page-all":                 true,
		"page-system-usermanager":  true,
		"page-tailscale-config":    true,
		"PAGE-ALL":                 false,
		" page-all":                false,
		"page-all ":                false,
		"page-system-groupmanager": false,
		"":                         false,
	} {
		if got := d.Defines(id); got != want {
			t.Errorf("Defines(%q) = %v, want %v", id, got, want)
		}
	}
}

func privSearchServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "testkey", "testsecret", true)
}

func privRows(ids []string) []map[string]interface{} {
	rows := make([]map[string]interface{}, len(ids))
	for i, id := range ids {
		// the controller adds what the holders and the URL masks are
		rows[i] = map[string]interface{}{"id": id, "name": "Name of " + id, "match": "ui/" + id + "*", "users": []string{}, "groups": []string{"admins"}}
	}
	return rows
}

func TestClientDevicePrivs(t *testing.T) {
	ids := plausibleIDs("page-system-usermanager")
	client := privSearchServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/auth/priv/search" {
			t.Errorf("request = %s %s, want POST /auth/priv/search", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(SearchResponse{Rows: privRows(ids), RowCount: len(ids), Total: len(ids)})
	})

	d, err := client.DevicePrivs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !d.Defines("page-system-usermanager") || !d.Defines("page-all") || d.Defines("page-system-groupmanager") {
		t.Errorf("the catalog was not read as listed")
	}
}

func TestClientDevicePrivs_FailsClosed(t *testing.T) {
	ids := plausibleIDs()
	tests := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{"the route is refused", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) }},
		{"a server error", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) }},
		{"not JSON", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>login</html>")) }},
		{"a row without an ID", func(w http.ResponseWriter, r *http.Request) {
			rows := privRows(ids)
			rows[5] = map[string]interface{}{"name": "no id"}
			_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
		}},
		{"an ID that is not text", func(w http.ResponseWriter, r *http.Request) {
			rows := privRows(ids)
			rows[5]["id"] = 7
			_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
		}},
		{"a listing that is cut short", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(SearchResponse{Rows: privRows(ids[:len(ids)-20]), RowCount: len(ids) - 20, Total: len(ids)})
		}},
		{"too few IDs", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(SearchResponse{Rows: privRows(ids[:30]), RowCount: 30, Total: 30})
		}},
		{"no rows", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"rows":[],"total":0}`)) }},
		{"the anchors are missing", func(w http.ResponseWriter, r *http.Request) {
			var without []string
			for _, id := range ids {
				if id != "page-all" {
					without = append(without, id)
				}
			}
			_ = json.NewEncoder(w).Encode(SearchResponse{Rows: privRows(without), RowCount: len(without), Total: len(without)})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := privSearchServer(t, tt.handler).DevicePrivs(context.Background())
			if err == nil || d != nil {
				t.Fatalf("DevicePrivs = %v, %v; want an error and no catalog", d, err)
			}
			if strings.Contains(err.Error(), "<html>") {
				t.Errorf("the error carries the body: %v", err)
			}
		})
	}
}
