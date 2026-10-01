package opnapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// coreVersionFile is /usr/local/opnsense/version/core as the core package's
// core.in renders it, for a 26.7 series device on package revision 26.7.4_1.
const coreVersionFile = `{
    "CORE_ABI": "26.7",
    "CORE_ARCH": "amd64",
    "CORE_COMMIT": "26.7.4_1 0 821598263",
    "CORE_CONFLICTS": "os-firewall os-firewall-devel os-wireguard os-wireguard-devel",
    "CORE_COPYRIGHT_HOLDER": "Deciso B.V.",
    "CORE_COPYRIGHT_WWW": "https://www.deciso.com/",
    "CORE_COPYRIGHT_YEARS": "2014-2026",
    "CORE_GID": "789",
    "CORE_GROUP": "wwwonly",
    "CORE_HASH": "821598263",
    "CORE_MAINTAINER": "project@opnsense.org",
    "CORE_NAME": "opnsense",
    "CORE_NEXT": "27.1",
    "CORE_NICKNAME": "Xenial Xenops",
    "CORE_PACKAGESITE": "https://pkg.opnsense.org",
    "CORE_PKGVERSION": "26.7.4_1",
    "CORE_PRODUCT": "OPNsense",
    "CORE_PYTHON_DOT": "3.13",
    "CORE_SERIES_FW": "26.7 ",
    "CORE_SERIES": "26.7",
    "CORE_SYSLOGNG": "4.12",
    "CORE_UID": "789",
    "CORE_USER": "wwwonly",
    "CORE_VERSION": "26.7.4",
    "CORE_WWW": "https://opnsense.org/",
    "product_abi": "26.7",
    "product_arch": "amd64",
    "product_conflicts": "os-firewall os-firewall-devel os-wireguard os-wireguard-devel",
    "product_copyright_owner": "Deciso B.V.",
    "product_copyright_url": "https://www.deciso.com/",
    "product_copyright_years": "2014-2026",
    "product_email": "project@opnsense.org",
    "product_hash": "821598263",
    "product_id": "opnsense",
    "product_name": "OPNsense",
    "product_nickname": "Xenial Xenops",
    "product_series": "26.7",
    "product_tier": "1",
    "product_version": "26.7.4_1",
    "product_website": "https://opnsense.org/"
}
`

func versionFileJSON(version, series string) string {
	meta := map[string]string{}
	if version != "" {
		meta["product_version"] = version
	}
	if series != "" {
		meta["product_series"] = series
	}
	out, _ := json.Marshal(meta)
	return string(out)
}

var errNoVersionCommand = errors.New("opnsense-version is not available")

// useLocalSources points the two local sources at a version file holding
// fileContent (absent when empty) and at run, a stand-in for opnsense-version.
// A nil run fails like a device without the binary.
func useLocalSources(t *testing.T, fileContent string, run func(*exec.Cmd) ([]byte, error)) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "core")
	if fileContent != "" {
		if err := os.WriteFile(path, []byte(fileContent), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(SetVersionFileForTest(path))

	if run == nil {
		run = func(*exec.Cmd) ([]byte, error) { return nil, errNoVersionCommand }
	}
	t.Cleanup(SetCommandOutputForTest(run))
}

// releaseAPI stands in for the OPNsense API. It records every request and
// fails the test if /core/firmware/info is ever asked for.
type releaseAPI struct {
	mu       sync.Mutex
	requests []string
}

func (r *releaseAPI) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

// newReleaseClient serves status for GET /core/firmware/status; everything
// else is a 404.
func newReleaseClient(t *testing.T, status http.HandlerFunc) (*Client, *releaseAPI) {
	t.Helper()

	api := &releaseAPI{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		api.requests = append(api.requests, r.Method+" "+r.URL.Path)
		api.mu.Unlock()

		switch {
		case r.URL.Path == "/core/firmware/info":
			t.Errorf("the installed release was read from /core/firmware/info")
			http.Error(w, "must not be called", http.StatusGone)
		case r.URL.Path == "/core/firmware/status" && status != nil:
			status(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return NewClient(srv.URL, "key", "secret", true), api
}

func statusBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}
}

func TestInstalledRelease_ReadsTheVersionFileFirst(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		wantRaw string
		major   int
		minor   int
	}{
		{"the real file layout", coreVersionFile, "26.7.4_1", 26, 7},
		{"general availability release", versionFileJSON("26.7", "26.7"), "26.7", 26, 7},
		{"patch release", versionFileJSON("26.1.9", "26.1"), "26.1.9", 26, 1},
		{"package revision suffix", versionFileJSON("26.7.4_1", "26.7"), "26.7.4_1", 26, 7},
		{"a two-digit minor is not below 26.1", versionFileJSON("26.10.1", "26.10"), "26.10.1", 26, 10},
		{"below the floor", versionFileJSON("25.7.9_1", "25.7"), "25.7.9_1", 25, 7},
		{"series only", versionFileJSON("", "25.7"), "25.7", 25, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useLocalSources(t, tc.file, func(*exec.Cmd) ([]byte, error) {
				t.Error("opnsense-version was run although the version file answered")
				return nil, errNoVersionCommand
			})
			client, api := newReleaseClient(t, nil)

			got, err := client.InstalledRelease(context.Background())
			if err != nil {
				t.Fatalf("InstalledRelease() error = %v", err)
			}
			if got.Raw != tc.wantRaw || got.Major != tc.major || got.Minor != tc.minor {
				t.Errorf("got %+v, want %s parsed as %d.%d", got, tc.wantRaw, tc.major, tc.minor)
			}
			if requests := api.seen(); len(requests) != 0 {
				t.Errorf("the API was asked %v although the version file answered", requests)
			}
		})
	}
}

func TestInstalledRelease_UnusableFileFallsThroughToTheCommand(t *testing.T) {
	cases := map[string]string{
		"missing file":              "",
		"not JSON":                  "CORE_VERSION=26.7",
		"empty object":              "{}",
		"empty fields":              `{"product_version":"","product_series":""}`,
		"unparseable version":       versionFileJSON("rolling", "26.7"),
		"a truncated write":         coreVersionFile[:len(coreVersionFile)/2],
		"object of the wrong shape": `["26.7"]`,
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			useLocalSources(t, file, func(*exec.Cmd) ([]byte, error) {
				calls++
				return []byte("26.7.4_1\n"), nil
			})
			client, api := newReleaseClient(t, nil)

			got, err := client.InstalledRelease(context.Background())
			if err != nil {
				t.Fatalf("InstalledRelease() error = %v", err)
			}
			if got.Raw != "26.7.4_1" || got.Major != 26 || got.Minor != 7 {
				t.Errorf("got %+v, want 26.7.4_1", got)
			}
			if calls != 1 {
				t.Errorf("opnsense-version run %d times, want 1", calls)
			}
			if requests := api.seen(); len(requests) != 0 {
				t.Errorf("the API was asked %v although opnsense-version answered", requests)
			}
		})
	}
}

// TestInstalledRelease_CommandInvocation pins how opnsense-version is run. The
// values are spelled out rather than referenced from the implementation: NDAgent
// runs under rc.d with PATH stripped of /usr/local/sbin, and opnsense-version
// itself calls binaries there by name.
func TestInstalledRelease_CommandInvocation(t *testing.T) {
	var got *exec.Cmd
	useLocalSources(t, "", func(cmd *exec.Cmd) ([]byte, error) {
		got = cmd
		return []byte("26.7\n"), nil
	})
	client, _ := newReleaseClient(t, nil)

	if _, err := client.InstalledRelease(context.Background()); err != nil {
		t.Fatalf("InstalledRelease() error = %v", err)
	}
	if got == nil {
		t.Fatal("opnsense-version was not run")
	}
	if got.Path != "/usr/local/sbin/opnsense-version" {
		t.Errorf("ran %q, want /usr/local/sbin/opnsense-version", got.Path)
	}
	if want := []string{"/usr/local/sbin/opnsense-version", "-v"}; strings.Join(got.Args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("args = %q, want %q", got.Args, want)
	}

	var paths []string
	for _, kv := range got.Env {
		if strings.HasPrefix(kv, "PATH=") {
			paths = append(paths, kv)
		}
	}
	if want := "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"; len(paths) != 1 || paths[0] != want {
		t.Errorf("PATH entries = %q, want exactly [%q]", paths, want)
	}

	// Once the deadline kills opnsense-version, a descendant still holding its
	// stdout would keep the read waiting; WaitDelay is what ends that wait.
	if got.WaitDelay != time.Second {
		t.Errorf("WaitDelay = %v, want 1s", got.WaitDelay)
	}
}

// TestInstalledRelease_CommandIsBounded pins that a hung opnsense-version
// cannot hold the lookup, and with it a SYNC, past its bound. The bound is
// shrunk for the run; the production value is asserted first.
func TestInstalledRelease_CommandIsBounded(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary to stand in for a hung opnsense-version")
	}

	if opnsenseVersionTimeout != 5*time.Second {
		t.Errorf("opnsense-version is bounded to %v, want 5s", opnsenseVersionTimeout)
	}
	prev := opnsenseVersionTimeout
	opnsenseVersionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { opnsenseVersionTimeout = prev })

	useLocalSources(t, "", func(cmd *exec.Cmd) ([]byte, error) {
		cmd.Path = sleep
		cmd.Args = []string{"sleep", "10"}
		return cmd.Output()
	})

	var client *Client
	start := time.Now()
	_, err = client.InstalledRelease(context.Background())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a hung opnsense-version held the lookup for %v", elapsed)
	}
	if err == nil {
		t.Error("a command that never answered was reported as a release")
	}
}

func TestInstalledRelease_CommandOutput(t *testing.T) {
	const status = `{"product":{"product_version":"26.7.4_1","product_series":"26.7"}}`

	cases := []struct {
		name     string
		out      string
		err      error
		wantRaw  string
		wantREST bool
	}{
		{"one line", "26.7.4_1\n", nil, "26.7.4_1", false},
		{"surrounding whitespace", "  26.1.9  \n", nil, "26.1.9", false},
		{"only the first line counts", "26.7\nunexpected second line\n", nil, "26.7", false},
		{"no output", "", nil, "26.7.4_1", true},
		{"blank output", "\n", nil, "26.7.4_1", true},
		{"a message instead of a version", "Missing /usr/local/opnsense/version/core\n", nil, "26.7.4_1", true},
		{"non-zero exit", "", errors.New("exit status 1"), "26.7.4_1", true},
		{"binary absent", "", errNoVersionCommand, "26.7.4_1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useLocalSources(t, "", func(*exec.Cmd) ([]byte, error) { return []byte(tc.out), tc.err })
			client, api := newReleaseClient(t, statusBody(status))

			got, err := client.InstalledRelease(context.Background())
			if err != nil {
				t.Fatalf("InstalledRelease() error = %v", err)
			}
			if got.Raw != tc.wantRaw {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.wantRaw)
			}
			if asked := len(api.seen()) > 0; asked != tc.wantREST {
				t.Errorf("API asked = %v, want %v (requests %v)", asked, tc.wantREST, api.seen())
			}
		})
	}
}

func TestInstalledRelease_StatusProductBlock(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantRaw string
	}{
		{"product block", `{"product":{"product_version":"26.7.4_1","product_series":"26.7"}}`, "26.7.4_1"},
		{"series only", `{"product":{"product_series":"25.7"}}`, "25.7"},
		{
			// The top-level fields are the cached result of the last firmware
			// check; the product block is read from the version file per request.
			"the live block wins over the cached top-level version",
			`{"product_version":"25.1","product":{"product_version":"26.7.4_1"}}`,
			"26.7.4_1",
		},
		{
			"a nested cached check is not the product version",
			`{"product":{"product_version":"26.7.4_1","product_check":{"product_version":"25.1"}}}`,
			"26.7.4_1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useLocalSources(t, "", nil)
			client, api := newReleaseClient(t, statusBody(tc.body))

			got, err := client.InstalledRelease(context.Background())
			if err != nil {
				t.Fatalf("InstalledRelease() error = %v", err)
			}
			if got.Raw != tc.wantRaw {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.wantRaw)
			}
			if want := []string{"GET /core/firmware/status"}; strings.Join(api.seen(), ",") != strings.Join(want, ",") {
				t.Errorf("requests = %v, want %v", api.seen(), want)
			}
		})
	}
}

// TestInstalledRelease_ErrorsRatherThanGuessing pins that an unusable answer is
// an ERROR, not a default. Callers must be able to tell "below the floor" from
// "could not tell"; defaulting either way makes one of those a lie.
func TestInstalledRelease_ErrorsRatherThanGuessing(t *testing.T) {
	fastRetries(t)

	cases := map[string]http.HandlerFunc{
		"empty object":               statusBody(`{}`),
		"empty product block":        statusBody(`{"product":{}}`),
		"cached top-level version":   statusBody(`{"product_version":"26.7"}`),
		"unparseable version":        statusBody(`{"product":{"product_version":"rolling"}}`),
		"not JSON":                   statusBody(`<html>`),
		"an API error":               func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"a missing status endpoint":  nil,
		"a status with a bad series": statusBody(`{"product":{"product_series":"next"}}`),
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			useLocalSources(t, "", nil)
			client, _ := newReleaseClient(t, status)

			got, err := client.InstalledRelease(context.Background())
			if err == nil {
				t.Fatalf("got %+v with no error; an unusable answer must not be reported as a release", got)
			}
			for _, source := range []string{"version file", "opnsense-version", "firmware status"} {
				if !strings.Contains(err.Error(), source) {
					t.Errorf("error %q does not name the %s failure", err, source)
				}
			}
		})
	}
}

// TestInstalledRelease_NeverAsksFirmwareInfo runs the worst case, every source
// consulted, against a server that fails the test on a /core/firmware/info
// request: only the cheap status endpoint may be asked, and only once.
func TestInstalledRelease_NeverAsksFirmwareInfo(t *testing.T) {
	useLocalSources(t, "", nil)
	client, api := newReleaseClient(t, statusBody(`{"product":{"product_version":"26.7"}}`))

	if _, err := client.InstalledRelease(context.Background()); err != nil {
		t.Fatalf("InstalledRelease() error = %v", err)
	}
	if want := []string{"GET /core/firmware/status"}; strings.Join(api.seen(), ",") != strings.Join(want, ",") {
		t.Errorf("requests = %v, want %v", api.seen(), want)
	}
}

// TestInstalledRelease_LocalSourcesNeedNoWebServer is the point of reading the
// device first: a web server that corrupts every response, or is down, cannot
// stop the release from being read.
func TestInstalledRelease_LocalSourcesNeedNoWebServer(t *testing.T) {
	fastRetries(t)
	useLocalSources(t, coreVersionFile, nil)

	srv := newScriptedServer(t, replayCorruptedReply(listBody(t)))
	got, err := newRetryClient(srv.URL).InstalledRelease(context.Background())
	if err != nil {
		t.Fatalf("InstalledRelease() error = %v", err)
	}
	if got.Raw != "26.7.4_1" {
		t.Errorf("Raw = %q, want 26.7.4_1", got.Raw)
	}
	if requests := srv.requests(); len(requests) != 0 {
		t.Errorf("the corrupt web server was asked %v", requests)
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := NewClient(closed.URL, "key", "secret", true).InstalledRelease(context.Background()); err != nil {
		t.Errorf("a web server that is down must not matter: %v", err)
	}
}

// TestInstalledRelease_StatusFallbackSurvivesACorruptChunk covers the last
// source on an affected box: /status is small on an up-to-date device but grows
// with the number of pending updates, and the retry makes the read dependable
// in the meantime.
func TestInstalledRelease_StatusFallbackSurvivesACorruptChunk(t *testing.T) {
	fastRetries(t)
	useLocalSources(t, "", nil)

	pending := make([]map[string]string, 1600)
	for i := range pending {
		pending[i] = map[string]string{"name": fmt.Sprintf("pkg-%d", i), "repository": "OPNsense", "current_version": "1.0", "new_version": "1.1"}
	}
	body, err := json.Marshal(map[string]interface{}{
		"product":          map[string]string{"product_version": "26.7.4_1", "product_series": "26.7"},
		"upgrade_packages": pending,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 2*lighttpdChunk {
		t.Fatalf("fixture is %d bytes, want more than two chunks", len(body))
	}

	srv := newScriptedServer(t, replayCorruptedReply(body), goodReply(body))
	got, err := newRetryClient(srv.URL).InstalledRelease(context.Background())
	if err != nil {
		t.Fatalf("InstalledRelease() error = %v", err)
	}
	if got.Raw != "26.7.4_1" {
		t.Errorf("Raw = %q, want 26.7.4_1", got.Raw)
	}
	want := []string{"GET /core/firmware/status", "GET /core/firmware/status"}
	if strings.Join(srv.requests(), ",") != strings.Join(want, ",") {
		t.Errorf("requests = %v, want %v", srv.requests(), want)
	}
}

// TestInstalledRelease_IsNotCached pins that every call reads the device again:
// the release changes when the device is updated, and a caller comparing before
// and after needs the current one.
func TestInstalledRelease_IsNotCached(t *testing.T) {
	useLocalSources(t, versionFileJSON("26.7", "26.7"), nil)
	client, _ := newReleaseClient(t, nil)

	first, err := client.InstalledRelease(context.Background())
	if err != nil || first.Raw != "26.7" {
		t.Fatalf("first read = %+v, %v; want 26.7", first, err)
	}

	if err := os.WriteFile(versionFilePath, []byte(versionFileJSON("26.7.4_1", "26.7")), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := client.InstalledRelease(context.Background())
	if err != nil || second.Raw != "26.7.4_1" {
		t.Errorf("second read = %+v, %v; want 26.7.4_1", second, err)
	}
}

func TestInstalledRelease_CancelledContext(t *testing.T) {
	useLocalSources(t, coreVersionFile, func(*exec.Cmd) ([]byte, error) {
		t.Error("a source was consulted after the context ended")
		return nil, errNoVersionCommand
	})
	client, api := newReleaseClient(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.InstalledRelease(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the cancellation", err)
	}
	if requests := api.seen(); len(requests) != 0 {
		t.Errorf("the API was asked %v after the context ended", requests)
	}
}

// TestInstalledRelease_NilClient pins that a nil *Client is a valid receiver:
// the two local sources need no API, and the FIRMWARE_UPGRADE boot reconcile
// holds no client on a device without API credentials.
func TestInstalledRelease_NilClient(t *testing.T) {
	var client *Client

	t.Run("the version file answers", func(t *testing.T) {
		useLocalSources(t, coreVersionFile, func(*exec.Cmd) ([]byte, error) {
			t.Error("opnsense-version was run although the version file answered")
			return nil, errNoVersionCommand
		})

		got, err := client.InstalledRelease(context.Background())
		if err != nil {
			t.Fatalf("InstalledRelease() error = %v", err)
		}
		if got.Raw != "26.7.4_1" || got.Major != 26 || got.Minor != 7 {
			t.Errorf("got %+v, want 26.7.4_1", got)
		}
	})

	t.Run("opnsense-version answers", func(t *testing.T) {
		useLocalSources(t, "", func(*exec.Cmd) ([]byte, error) { return []byte("26.1.9\n"), nil })

		got, err := client.InstalledRelease(context.Background())
		if err != nil {
			t.Fatalf("InstalledRelease() error = %v", err)
		}
		if got.Raw != "26.1.9" {
			t.Errorf("Raw = %q, want 26.1.9", got.Raw)
		}
	})

	t.Run("no source answers", func(t *testing.T) {
		useLocalSources(t, "", nil)

		got, err := client.InstalledRelease(context.Background())
		if err == nil {
			t.Fatalf("got %+v with no error; an unusable answer must not be reported as a release", got)
		}
		for _, source := range []string{"version file", "opnsense-version", "firmware status: no API client"} {
			if !strings.Contains(err.Error(), source) {
				t.Errorf("error %q does not name the %s failure", err, source)
			}
		}
	})
}
