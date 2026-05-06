// Package network — NDM trust set TOFU bootstrap.
//
// On first connect, the agent fetches the NDM trust set (primary +
// emergency Ed25519 pubkeys) from the broker's public JWKS endpoint
// over TLS and pins both to disk. Subsequent runs read from the cache
// and never poll. Rotation happens out-of-band via emergency-signed
// directives (see ROTATION-DIRECTIVE.md at the CoreCode root); the
// directive consumer is not yet implemented, so the manual escape
// hatch in beta is `rm /var/db/ndagent/ndm-keys.json && service
// ndagent restart` to force a re-TOFU against the current broker JWKS.
package network
import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/signing"
	"go.uber.org/zap"
)

// DefaultNDMKeysCachePath is where the agent persists the pinned NDM trust set.
const DefaultNDMKeysCachePath = "/var/db/ndagent/ndm-keys.json"

const (
	ndmKeysFetchTimeout    = 10 * time.Second
	ndmKeysFetchRetries    = 3
	ndmKeysFetchInitialBackoff = 1 * time.Second
	ndmKeysCacheVersion    = 1
)

// ndmKeysCacheFile is the persistent on-disk shape.
type ndmKeysCacheFile struct {
	Version    int    `json:"version"`
	FetchedAt  string `json:"fetched_at"`
	BrokerHost string `json:"broker_host"`
	Primary    ndmKeyEntry `json:"primary"`
	Emergency  ndmKeyEntry `json:"emergency"`
}

type ndmKeyEntry struct {
	KID       string `json:"kid"`
	PubkeyB64 string `json:"pubkey_b64"`
}

// jwksResponse mirrors broker's GET /api/v1/.well-known/keys response
// (also compatible with NDManager's existing JWKS endpoint).
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KID  string `json:"kid"`
	Kty  string `json:"kty"`
	Crv  string `json:"crv"`
	Alg  string `json:"alg"`
	Use  string `json:"use"`
	X    string `json:"x"`
	Role string `json:"role"`
}

// LoadOrFetchNDMKeys returns the NDM trust set as two kid→pubkey maps
// (dispatch = primary only, rotation = emergency only — caller must keep
// them separate per PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 7).
//
// The cache file at cachePath is consulted first; only on cache-miss
// (or unreadable cache) does the agent fetch from the broker over TLS.
// On a successful fetch, the cache is rewritten atomically.
func LoadOrFetchNDMKeys(
	ctx context.Context,
	cfg *config.Config,
	cachePath string,
) (dispatchKeys, rotationKeys map[string]ed25519.PublicKey, err error) {
	if cachePath == "" {
		cachePath = DefaultNDMKeysCachePath
	}
	log := logging.Named("ndmkeys")

	if cached, ok := tryLoadCache(cachePath, log); ok {
		return cacheToMaps(cached, log)
	}

	log.Infow("NDM trust set cache absent; fetching from broker via TOFU",
		"broker_host", cfg.ServerHost,
		"broker_port", cfg.ServerPort,
		"cache_path", cachePath,
	)
	jwks, err := fetchJWKSWithRetry(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ndm trust set TOFU fetch: %w", err)
	}
	cached, err := jwksToCacheFile(jwks, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ndm trust set TOFU parse: %w", err)
	}
	if err := writeCache(cachePath, cached); err != nil {
		return nil, nil, fmt.Errorf("ndm trust set cache write: %w", err)
	}
	log.Warnw("TOFU pinned NDM trust set on first fetch",
		"primary_kid", cached.Primary.KID,
		"emergency_kid", cached.Emergency.KID,
		"broker_host", cfg.ServerHost,
		"cache_path", cachePath,
	)
	return cacheToMaps(cached, log)
}

func tryLoadCache(cachePath string, log *zap.SugaredLogger) (*ndmKeysCacheFile, bool) {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnw("NDM trust set cache unreadable; will re-TOFU",
				"cache_path", cachePath,
				"error", err,
			)
		}
		return nil, false
	}
	var cached ndmKeysCacheFile
	if err := json.Unmarshal(raw, &cached); err != nil {
		log.Warnw("NDM trust set cache corrupt; will re-TOFU",
			"cache_path", cachePath,
			"error", err,
		)
		return nil, false
	}
	if cached.Version != ndmKeysCacheVersion {
		log.Warnw("NDM trust set cache version mismatch; will re-TOFU",
			"cache_path", cachePath,
			"got_version", cached.Version,
			"want_version", ndmKeysCacheVersion,
		)
		return nil, false
	}
	if cached.Primary.KID == "" || cached.Emergency.KID == "" {
		log.Warnw("NDM trust set cache missing one or both kids; will re-TOFU",
			"cache_path", cachePath,
		)
		return nil, false
	}
	log.Infow("NDM trust set loaded from cache",
		"primary_kid", cached.Primary.KID,
		"emergency_kid", cached.Emergency.KID,
		"cache_path", cachePath,
		"fetched_at", cached.FetchedAt,
	)
	return &cached, true
}

func fetchJWKSWithRetry(ctx context.Context, cfg *config.Config) (*jwksResponse, error) {
	url := fmt.Sprintf("https://%s:%d/api/v1/.well-known/keys", cfg.ServerHost, cfg.ServerPort)
	client := &http.Client{
		Timeout: ndmKeysFetchTimeout,
		Transport: &http.Transport{
			TLSClientConfig: cfg.GetTLSConfig(),
		},
	}
	backoff := ndmKeysFetchInitialBackoff
	var lastErr error
	for attempt := 1; attempt <= ndmKeysFetchRetries; attempt++ {
		jwks, err := fetchJWKSOnce(ctx, client, url)
		if err == nil {
			return jwks, nil
		}
		lastErr = err
		if attempt == ndmKeysFetchRetries {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("after %d attempts: %w", ndmKeysFetchRetries, lastErr)
}

func fetchJWKSOnce(ctx context.Context, client *http.Client, url string) (*jwksResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS has no keys")
	}
	return &jwks, nil
}

// jwkXToPubkeyB64 converts a JWK `x` claim (unpadded urlsafe base64) to
// standard base64 — that's what the rest of the agent's signing code
// (PublicKeyFromBase64, KidFromPubkey) expects.
func jwkXToPubkeyB64(x string) (string, []byte, error) {
	padding := strings.Repeat("=", (4-len(x)%4)%4)
	raw, err := base64.URLEncoding.DecodeString(x + padding)
	if err != nil {
		return "", nil, fmt.Errorf("decode JWK x: %w", err)
	}
	if len(raw) != 32 {
		return "", nil, fmt.Errorf("JWK x is %d bytes, want 32 (Ed25519 raw pubkey)", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), raw, nil
}

func jwksToCacheFile(jwks *jwksResponse, cfg *config.Config) (*ndmKeysCacheFile, error) {
	var primary, emergency *jwkKey
	for i := range jwks.Keys {
		k := &jwks.Keys[i]
		switch strings.ToLower(k.Role) {
		case "primary":
			primary = k
		case "emergency":
			emergency = k
		}
	}
	if primary == nil {
		return nil, fmt.Errorf("JWKS missing role=primary")
	}
	if emergency == nil {
		return nil, fmt.Errorf("JWKS missing role=emergency")
	}

	pPubB64, pRaw, err := jwkXToPubkeyB64(primary.X)
	if err != nil {
		return nil, fmt.Errorf("primary: %w", err)
	}
	pKid := strings.ToLower(strings.TrimSpace(primary.KID))
	pDerived := fmt.Sprintf("%x", signing.KidFromPubkey(pRaw))
	if pKid != pDerived {
		return nil, fmt.Errorf("primary kid mismatch: JWKS says %s but pubkey derives %s", pKid, pDerived)
	}

	ePubB64, eRaw, err := jwkXToPubkeyB64(emergency.X)
	if err != nil {
		return nil, fmt.Errorf("emergency: %w", err)
	}
	eKid := strings.ToLower(strings.TrimSpace(emergency.KID))
	eDerived := fmt.Sprintf("%x", signing.KidFromPubkey(eRaw))
	if eKid != eDerived {
		return nil, fmt.Errorf("emergency kid mismatch: JWKS says %s but pubkey derives %s", eKid, eDerived)
	}

	if pKid == eKid {
		return nil, fmt.Errorf("primary and emergency kids collide (%s); JWKS misconfiguration", pKid)
	}

	return &ndmKeysCacheFile{
		Version:    ndmKeysCacheVersion,
		FetchedAt:  time.Now().UTC().Format(time.RFC3339),
		BrokerHost: fmt.Sprintf("https://%s:%d", cfg.ServerHost, cfg.ServerPort),
		Primary:    ndmKeyEntry{KID: pKid, PubkeyB64: pPubB64},
		Emergency:  ndmKeyEntry{KID: eKid, PubkeyB64: ePubB64},
	}, nil
}

func cacheToMaps(cached *ndmKeysCacheFile, log *zap.SugaredLogger) (
	dispatchKeys, rotationKeys map[string]ed25519.PublicKey, err error,
) {
	pPub, err := signing.PublicKeyFromBase64(cached.Primary.PubkeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode cached primary pubkey: %w", err)
	}
	ePub, err := signing.PublicKeyFromBase64(cached.Emergency.PubkeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode cached emergency pubkey: %w", err)
	}
	dispatchKeys = map[string]ed25519.PublicKey{cached.Primary.KID: pPub}
	rotationKeys = map[string]ed25519.PublicKey{cached.Emergency.KID: ePub}
	return dispatchKeys, rotationKeys, nil
}

func writeCache(cachePath string, cached *ndmKeysCacheFile) error {
	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".ndm-keys.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if err := json.NewEncoder(tmp).Encode(cached); err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), cachePath); err != nil {
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}
