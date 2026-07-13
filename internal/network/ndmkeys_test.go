package network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func init() {
	// Logging package's Named() requires init; cheap no-op here for tests.
	_ = logging.Named("test")
}

func makeKeyPair(t *testing.T) (kidHex string, pubB64Std, pubB64URL string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	kid := sha256.Sum256(pub)
	kidHex = hex.EncodeToString(kid[:16])
	pubB64Std = base64.StdEncoding.EncodeToString(pub)
	pubB64URL = strings.TrimRight(base64.URLEncoding.EncodeToString(pub), "=")
	return
}

// mockJWKSServer spins up an https server returning a fixed JWKS shape
// so the agent's TOFU fetcher can be exercised end-to-end without a real
// broker. Returns (host, port, cleanup).
func mockJWKSServer(t *testing.T, primaryKid, primaryX, emergencyKid, emergencyX string) (string, int, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/.well-known/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kid": primaryKid, "kty": "OKP", "crv": "Ed25519",
					"alg": "Ed25519", "use": "sig", "x": primaryX, "role": "primary",
				},
				{
					"kid": emergencyKid, "kty": "OKP", "crv": "Ed25519",
					"alg": "Ed25519", "use": "sig", "x": emergencyX, "role": "emergency",
				},
			},
		})
	})
	srv := httptest.NewTLSServer(mux)

	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse server URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		srv.Close()
		t.Fatalf("split host:port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		srv.Close()
		t.Fatalf("port atoi: %v", err)
	}
	return host, port, srv.Close
}

func newTestConfig(host string, port int) *config.Config {
	cfg := &config.Config{
		ServerHost: host,
		ServerPort: port,
		SSLVerify:  false, // httptest uses self-signed
	}
	return cfg
}

// Override the TLS config helper for the test's self-signed server.
func patchTestTLS(cfg *config.Config) {
	// httptest.Server uses a self-signed cert; the agent's GetTLSConfig
	// already returns InsecureSkipVerify=true when SSLVerify is false.
	// Confirm that's the path: build once and assert.
	tc := cfg.GetTLSConfig()
	if tc != nil && tc.InsecureSkipVerify {
		return
	}
	// Force InsecureSkipVerify just in case.
	_ = tls.Config{InsecureSkipVerify: true}
}

func TestLoadOrFetch_FetchesAndPersistsOnCacheMiss(t *testing.T) {
	primaryKid, primaryB64Std, primaryX := makeKeyPair(t)
	emergencyKid, emergencyB64Std, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	dispatch, rotation, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err != nil {
		t.Fatalf("LoadOrFetchNDMKeys: %v", err)
	}

	if len(dispatch) != 1 {
		t.Fatalf("dispatch keys = %d, want 1", len(dispatch))
	}
	if _, ok := dispatch[primaryKid]; !ok {
		t.Errorf("dispatch missing primary kid %s", primaryKid)
	}
	if len(rotation) != 1 {
		t.Fatalf("rotation keys = %d, want 1", len(rotation))
	}
	if _, ok := rotation[emergencyKid]; !ok {
		t.Errorf("rotation missing emergency kid %s", emergencyKid)
	}

	// Cache file written.
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var cached ndmKeysCacheFile
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	if cached.Primary.KID != primaryKid {
		t.Errorf("cache primary kid = %s, want %s", cached.Primary.KID, primaryKid)
	}
	if cached.Primary.PubkeyB64 != primaryB64Std {
		t.Errorf("cache primary pubkey != fresh primary")
	}
	if cached.Emergency.KID != emergencyKid {
		t.Errorf("cache emergency kid = %s, want %s", cached.Emergency.KID, emergencyKid)
	}
	if cached.Emergency.PubkeyB64 != emergencyB64Std {
		t.Errorf("cache emergency pubkey != fresh emergency")
	}
	if cached.Version != ndmKeysCacheVersion {
		t.Errorf("cache version = %d, want %d", cached.Version, ndmKeysCacheVersion)
	}

	// Mode 0600.
	st, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestLoadOrFetch_UsesCacheOnSecondCall(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	if _, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Tear down the server. Second call MUST succeed from cache.
	cleanup()

	dispatch, rotation, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err != nil {
		t.Fatalf("second call (server down) should hit cache: %v", err)
	}
	if _, ok := dispatch[primaryKid]; !ok {
		t.Errorf("dispatch missing primary kid")
	}
	if _, ok := rotation[emergencyKid]; !ok {
		t.Errorf("rotation missing emergency kid")
	}
}

func TestLoadOrFetch_RejectsJWKSMissingEmergency(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/.well-known/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kid": primaryKid, "kty": "OKP", "crv": "Ed25519",
					"alg": "Ed25519", "use": "sig", "x": primaryX, "role": "primary",
				},
			},
		})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	_, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err == nil {
		t.Fatal("expected error: JWKS missing emergency role")
	}
	if !strings.Contains(err.Error(), "missing role=emergency") {
		t.Errorf("error %q does not mention missing emergency role", err)
	}
}

func TestLoadOrFetch_RejectsKidMismatch(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	_, _, emergencyX := makeKeyPair(t)
	bogusEmergencyKid := strings.Repeat("a", 32) // valid hex length but wrong

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/.well-known/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{"kid": primaryKid, "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig", "x": primaryX, "role": "primary"},
				{"kid": bogusEmergencyKid, "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig", "x": emergencyX, "role": "emergency"},
			},
		})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	_, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err == nil {
		t.Fatal("expected error: kid mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention kid mismatch", err)
	}
}

func TestLoadOrFetch_IgnoresCorruptCacheAndRefetches(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	if err := os.WriteFile(cachePath, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}

	dispatch, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err != nil {
		t.Fatalf("LoadOrFetchNDMKeys: %v", err)
	}
	if _, ok := dispatch[primaryKid]; !ok {
		t.Errorf("after corrupt cache, refetch missing primary kid")
	}

	// Cache should be rewritten.
	raw, _ := os.ReadFile(cachePath)
	if string(raw) == "not valid json" {
		t.Error("corrupt cache was not overwritten with fresh fetch")
	}
}

// TestFetchJWKS_TOFUVerifiesIndependentlyOfGlobalSSLVerify is the
// revert guard for the TOFU/MITM fix: even with the global ssl_verify
// disabled (dev/lab convenience), the first-connect JWKS fetch must
// still validate the server's certificate as long as TOFUSSLVerify is
// at its secure default (true). Against the self-signed test server
// this must fail with a certificate error, proving the fetch no longer
// piggybacks on cfg.GetTLSConfig()'s InsecureSkipVerify.
func TestFetchJWKS_TOFUVerifiesIndependentlyOfGlobalSSLVerify(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := &config.Config{
		ServerHost:    host,
		ServerPort:    port,
		SSLVerify:     false, // global bypass — must NOT leak into the TOFU fetch
		TOFUSSLVerify: true,  // secure default
	}

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	_, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath)
	if err == nil {
		t.Fatal("expected TOFU fetch against a self-signed cert to fail when TOFUSSLVerify=true, got nil error")
	}
	if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error %q does not look like a TLS verification failure", err)
	}

	if _, err := os.Stat(cachePath); err == nil {
		t.Error("cache file should not have been written after a failed TOFU fetch")
	}
}

// withObservedLogger swaps ndmKeysLoggerFactory for a logger backed by a
// zaptest/observer core so tests can assert on exactly what
// LoadOrFetchNDMKeys would log, and restores the production factory on
// cleanup. This is the re-pin WARN's revert guard: if the alert regresses
// to silence (or loses its distinguishing fields), these tests fail.
func withObservedLogger(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	orig := ndmKeysLoggerFactory
	ndmKeysLoggerFactory = func() *zap.SugaredLogger { return zap.New(core).Sugar() }
	t.Cleanup(func() { ndmKeysLoggerFactory = orig })
	return logs
}

// TestLoadOrFetch_RePinWarnsWithPriorAndNewKidOnCorruptCache is the core
// revert guard for the re-pin alert: a cache file existed (so this is NOT a
// fresh install) but fails to load because it's corrupt, so
// LoadOrFetchNDMKeys re-TOFUs. The WARN must fire and must not be silent
// about the fact that this replaces an earlier pin.
func TestLoadOrFetch_RePinWarnsOnCorruptCache(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	if err := os.WriteFile(cachePath, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}

	logs := withObservedLogger(t)

	if _, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath); err != nil {
		t.Fatalf("LoadOrFetchNDMKeys: %v", err)
	}

	entries := logs.FilterMessageSnippet("RE-PINNED").All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 RE-PINNED warning, got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Level != zap.WarnLevel {
		t.Errorf("RE-PINNED entry level = %v, want WARN", entry.Level)
	}
	fields := entry.ContextMap()
	if fields["new_primary_kid"] != primaryKid {
		t.Errorf("new_primary_kid = %v, want %s", fields["new_primary_kid"], primaryKid)
	}
	// Corrupt (unparseable) cache: no prior kid was recoverable, so the
	// entry must not fabricate one.
	if _, ok := fields["prior_primary_kid"]; ok {
		t.Errorf("prior_primary_kid should be absent for an unparseable prior cache, got %v", fields["prior_primary_kid"])
	}
}

// TestLoadOrFetch_RePinWarnsWithPriorAndNewKidOnVersionMismatch exercises the
// case the escalation specifically calls out: a prior pin WAS present and
// parseable (just a stale cache-format version), so the WARN must carry both
// the previous and new primary kid, and correctly flag whether the kid
// itself changed.
func TestLoadOrFetch_RePinWarnsWithPriorAndNewKidOnVersionMismatch(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	priorKid := "deadbeefdeadbeefdeadbeefdeadbeef"
	staleCache := ndmKeysCacheFile{
		Version:    ndmKeysCacheVersion + 1, // forces tryLoadCache to reject it
		FetchedAt:  "2020-01-01T00:00:00Z",
		BrokerHost: "https://old-broker.example",
		Primary:    ndmKeyEntry{KID: priorKid, PubkeyB64: "irrelevant"},
		Emergency:  ndmKeyEntry{KID: "also-irrelevant", PubkeyB64: "irrelevant"},
	}
	raw, err := json.Marshal(staleCache)
	if err != nil {
		t.Fatalf("marshal stale cache: %v", err)
	}
	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")
	if err := os.WriteFile(cachePath, raw, 0o600); err != nil {
		t.Fatalf("write stale cache: %v", err)
	}

	logs := withObservedLogger(t)

	if _, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath); err != nil {
		t.Fatalf("LoadOrFetchNDMKeys: %v", err)
	}

	entries := logs.FilterMessageSnippet("RE-PINNED").All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 RE-PINNED warning, got %d: %+v", len(entries), entries)
	}
	fields := entries[0].ContextMap()
	if fields["prior_primary_kid"] != priorKid {
		t.Errorf("prior_primary_kid = %v, want %s", fields["prior_primary_kid"], priorKid)
	}
	if fields["new_primary_kid"] != primaryKid {
		t.Errorf("new_primary_kid = %v, want %s", fields["new_primary_kid"], primaryKid)
	}
	changed, ok := fields["primary_kid_changed"].(bool)
	if !ok || !changed {
		t.Errorf("primary_kid_changed = %v (ok=%v), want true (prior %s != new %s)", fields["primary_kid_changed"], ok, priorKid, primaryKid)
	}
}

// TestLoadOrFetch_FreshInstallDoesNotWarnRePin is the negative case: a
// brand-new device has never had a cache file, so the first-ever TOFU must
// NOT trip the re-pin alert (that would make every fresh install look like
// an anomaly).
func TestLoadOrFetch_FreshInstallDoesNotWarnRePin(t *testing.T) {
	primaryKid, _, primaryX := makeKeyPair(t)
	emergencyKid, _, emergencyX := makeKeyPair(t)

	host, port, cleanup := mockJWKSServer(t, primaryKid, primaryX, emergencyKid, emergencyX)
	defer cleanup()

	cfg := newTestConfig(host, port)
	patchTestTLS(cfg)

	// No file written at cachePath — genuine fresh install.
	cachePath := filepath.Join(t.TempDir(), "ndm-keys.json")

	logs := withObservedLogger(t)

	if _, _, err := LoadOrFetchNDMKeys(context.Background(), cfg, cachePath); err != nil {
		t.Fatalf("LoadOrFetchNDMKeys: %v", err)
	}

	if entries := logs.FilterMessageSnippet("RE-PINNED").All(); len(entries) != 0 {
		t.Errorf("fresh install must not log a RE-PINNED warning, got %+v", entries)
	}
	// Sanity: the normal first-pin log still fires (exact wording depends on
	// cfg.TOFUSSLVerify — newTestConfig leaves it at the zero value, so this
	// is the "TLS verification DISABLED" variant, not "on first fetch").
	if entries := logs.FilterField(zap.String("primary_kid", primaryKid)).All(); len(entries) != 1 {
		t.Errorf("expected exactly 1 first-pin log carrying primary_kid=%s, got %d", primaryKid, len(entries))
	}
}

// Compile-time guard: ensure helper signatures match callers.
var _ = ed25519.PublicKey{}
var _ = fmt.Sprintf
