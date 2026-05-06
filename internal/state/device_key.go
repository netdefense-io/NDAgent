package state

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netdefense-io/ndagent/internal/signing"
)

// DefaultDeviceKeyPath is where the agent persists its Ed25519 signing seed
// on FreeBSD/OPNsense.
//
// Why this isn't in /usr/local/etc/ndagent.conf: the OPNsense plugin renders
// ndagent.conf from a Volt template via `configctl template reload
// OPNsense/NetDefense`. Any line not in the template gets wiped on every
// reload — including the agent's own `device_privkey=` line. That caused
// silent keypair regenerations whenever the operator hit Save in the
// NetDefense settings page, breaking response-signature verification on
// the broker side. See netdefense-io/NDAgent-go#15.
//
// /var/db/ndagent/ is outside configctl's reach, mode 0700, root-owned.
// Same lifetime semantics as state.json.
const DefaultDeviceKeyPath = "/var/db/ndagent/device.key"

// PrivkeyOrigin describes where the privkey came from on a given Load call.
// Reported back to the caller so lifecycle.go can log the right message
// (informational vs. operator-attention).
type PrivkeyOrigin int

const (
	// PrivkeyFromFile means the on-disk key file already existed and was
	// returned verbatim. Steady-state path; no operator action needed.
	PrivkeyFromFile PrivkeyOrigin = iota

	// PrivkeyMigrated means the file was missing but the legacy
	// `device_privkey=` value from ndagent.conf was promoted into the
	// file. Happens once per device on the v1.4.0 → v1.4.1 upgrade.
	// Server's bound device_pubkey still matches; no rebind needed.
	PrivkeyMigrated

	// PrivkeyGenerated means neither the file nor a conf fallback had a
	// seed available, so a fresh keypair was generated. If the device
	// was previously registered with NDManager under a different pubkey,
	// response signatures will fail until the operator re-binds via
	// `ndcli device rebind-token <name>`.
	PrivkeyGenerated
)

// LoadOrEnsureDevicePrivkey returns the agent's base64-encoded Ed25519 seed,
// reading from keyPath if present, migrating from confFallback if the file
// is missing, or generating a fresh keypair as a last resort.
//
// Origin tells the caller which path was taken so it can log the right
// message — see lifecycle.go.
//
// Atomic write semantics (temp + rename + chmod 0600) match state.json's
// persist() so the file mode is never world-readable, even briefly.
func LoadOrEnsureDevicePrivkey(keyPath, confFallback string) (privkey string, origin PrivkeyOrigin, err error) {
	if keyPath == "" {
		keyPath = DefaultDeviceKeyPath
	}

	// Step 1: file exists and parses → return as-is.
	if existing, ok := readKeyFile(keyPath); ok {
		return existing, PrivkeyFromFile, nil
	}

	// Step 2: legacy migration path. Honor a conf-supplied seed if one
	// is present, persist it to the file, and return it. Existing v1.4.0
	// devices upgrading via `pkg upgrade` hit this exactly once.
	if migrated := strings.TrimSpace(confFallback); migrated != "" {
		// Defensive: validate it parses as a real Ed25519 seed before
		// committing to disk. A malformed conf value should fall through
		// to fresh generation rather than write garbage.
		if _, decodeErr := signing.PrivateKeyFromBase64(migrated); decodeErr == nil {
			if err := writeKeyFile(keyPath, migrated); err != nil {
				return "", 0, fmt.Errorf("migrate device_privkey to %s: %w", keyPath, err)
			}
			return migrated, PrivkeyMigrated, nil
		}
	}

	// Step 3: generate a fresh keypair and persist it.
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		return "", 0, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	seed := base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv))
	if err := writeKeyFile(keyPath, seed); err != nil {
		return "", 0, fmt.Errorf("persist generated device_privkey to %s: %w", keyPath, err)
	}
	return seed, PrivkeyGenerated, nil
}

// RotateDevicePrivkey unconditionally generates a fresh Ed25519 keypair and
// writes it to keyPath. Used by the rebind-token ceremony in lifecycle.go.
// Returns the new base64-encoded seed.
func RotateDevicePrivkey(keyPath string) (string, error) {
	if keyPath == "" {
		keyPath = DefaultDeviceKeyPath
	}
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		return "", fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	seed := base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv))
	if err := writeKeyFile(keyPath, seed); err != nil {
		return "", fmt.Errorf("persist rotated device_privkey to %s: %w", keyPath, err)
	}
	return seed, nil
}

// readKeyFile returns the trimmed contents of the key file plus a presence
// flag. A missing, empty, or malformed file is treated as "no key" so
// callers fall through to the migration / generation paths.
//
// Defense against a corrupted file: if the file content doesn't decode
// to a valid 32-byte Ed25519 seed via signing.PrivateKeyFromBase64, we
// treat it as missing rather than handing garbage to the signing layer.
// (Real-world cause caught in dev: a buggy pkg post-install shell migration
// wrote 4 bytes of a UTF-8 replacement character into the file. The agent
// would otherwise have happily "loaded" that and silently produced
// unverifiable response signatures.)
func readKeyFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "", false
	}
	if _, err := signing.PrivateKeyFromBase64(trimmed); err != nil {
		return "", false
	}
	return trimmed, true
}

// writeKeyFile persists the seed atomically with mode 0600. Best-effort
// root ownership matches state.persist() — the chmod is the load-bearing
// guarantee in environments where ndagent doesn't run as root (tests).
func writeKeyFile(path, seed string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".devkey.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.WriteString(seed + "\n"); err != nil {
		return fmt.Errorf("write seed: %w", err)
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
	if os.Geteuid() == 0 {
		// Match state.persist(): only chown when running as root.
		_ = os.Chown(tmp.Name(), 0, 0)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}
