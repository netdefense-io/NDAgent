package state

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"
)

// validSeed returns a valid 32-byte Ed25519 seed encoded base64 — same
// format the agent persists.
func validSeed(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

func TestLoadOrEnsure_FileWinsOverConfFallback(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	fileSeed := validSeed(t)
	confSeed := validSeed(t)
	if err := writeKeyFile(keyPath, fileSeed); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, confSeed)
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyFromFile {
		t.Errorf("origin = %v, want PrivkeyFromFile", origin)
	}
	if got != fileSeed {
		t.Errorf("got %q, want %q (file should win over conf)", got, fileSeed)
	}
}

func TestLoadOrEnsure_MigratesFromConfWhenFileMissing(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	confSeed := validSeed(t)

	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, confSeed)
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyMigrated {
		t.Errorf("origin = %v, want PrivkeyMigrated", origin)
	}
	if got != confSeed {
		t.Errorf("got %q, want %q (migration should preserve conf seed verbatim)", got, confSeed)
	}

	// File should now exist with mode 0600 and contain the migrated seed.
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file after migration: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(keyPath)
	// File ends with a trailing newline — trim before compare.
	if got2 := string(raw); got2 != confSeed+"\n" {
		t.Errorf("file content mismatch: got %q, want %q", got2, confSeed+"\n")
	}
}

func TestLoadOrEnsure_GeneratesWhenNothingAvailable(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")

	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, "")
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyGenerated {
		t.Errorf("origin = %v, want PrivkeyGenerated", origin)
	}
	if got == "" {
		t.Fatal("got empty privkey")
	}
	// Decode and validate it's a 32-byte Ed25519 seed.
	seed, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode generated seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Errorf("seed len %d, want %d", len(seed), ed25519.SeedSize)
	}

	// Persisted to disk for the next call.
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not created: %v", err)
	}
}

func TestLoadOrEnsure_RejectsMalformedConfFallback(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")

	// Garbage value in conf — must NOT be migrated; must fall through to
	// fresh generation. A malformed conf line shouldn't poison the new
	// file location.
	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, "this is not a valid base64 ed25519 seed")
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyGenerated {
		t.Errorf("origin = %v, want PrivkeyGenerated (malformed conf must not migrate)", origin)
	}
	if got == "this is not a valid base64 ed25519 seed" {
		t.Error("garbage conf value was passed through verbatim — must fall through to generation")
	}
}

func TestLoadOrEnsure_TreatsCorruptedFileAsMissing(t *testing.T) {
	// Regression: the v1.4.1 pkg post-install used `printf '%s\n' "$PRIVKEY"`
	// which on FreeBSD's /bin/sh produced 4 bytes of a UTF-8 replacement
	// character (`\xef\xbf\xbd\x6e`) instead of the seed. The agent loaded
	// it as "valid" and silently broke response signing. Now: anything
	// that doesn't base64-decode to 32 bytes is treated as missing, and
	// the conf fallback / fresh generation path takes over.
	keyPath := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(keyPath, []byte("\xef\xbf\xbdn"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	confSeed := validSeed(t)

	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, confSeed)
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyMigrated {
		t.Errorf("origin = %v, want PrivkeyMigrated (corrupt file should fall through to conf)", origin)
	}
	if got != confSeed {
		t.Errorf("got %q, want %q", got, confSeed)
	}
}

func TestLoadOrEnsure_TreatsEmptyFileAsMissing(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	// Touch an empty file (could happen if a write was aborted partway).
	if err := os.WriteFile(keyPath, []byte("\n"), 0o600); err != nil {
		t.Fatalf("touch empty file: %v", err)
	}
	confSeed := validSeed(t)

	got, origin, err := LoadOrEnsureDevicePrivkey(keyPath, confSeed)
	if err != nil {
		t.Fatalf("LoadOrEnsure: %v", err)
	}
	if origin != PrivkeyMigrated {
		t.Errorf("origin = %v, want PrivkeyMigrated (empty file should not block migration)", origin)
	}
	if got != confSeed {
		t.Errorf("got %q, want %q", got, confSeed)
	}
}

func TestRotate_GeneratesFreshAndOverwrites(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	original := validSeed(t)
	if err := writeKeyFile(keyPath, original); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	rotated, err := RotateDevicePrivkey(keyPath)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated == original {
		t.Error("rotation returned the same seed — must be fresh")
	}

	// File should reflect the new seed.
	got, ok := readKeyFile(keyPath)
	if !ok || got != rotated {
		t.Errorf("file = %q, want %q", got, rotated)
	}

	// Decode + length check.
	seed, err := base64.StdEncoding.DecodeString(rotated)
	if err != nil {
		t.Fatalf("decode rotated seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Errorf("rotated seed len %d, want %d", len(seed), ed25519.SeedSize)
	}
}
