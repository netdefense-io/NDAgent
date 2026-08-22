package pkgrepo

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Apply reconciles the on-device repository configuration to `repos`.
//
// Returns Changed=true only when something was actually written. The caller
// uses that to decide whether a forced catalog refresh (`pkg update -f`) is
// warranted; forcing one on every sync would be a real cost on a production
// catalog, so "nothing changed" has to mean nothing was touched.
//
// allowUnverified is the organization's opt-in, carried inside the signed
// payload. This function re-checks it independently rather than trusting that
// NDManager already did — that independence is the whole point of the third
// enforcement layer: a poisoned database row must not be able to put an
// unverified repository on a device whose organization never opted in.
func Apply(repos []Repository, allowUnverified bool) (bool, error) {
	// Validate everything before writing anything. A policy carrying one bad
	// repository should not leave half its siblings applied.
	for _, r := range repos {
		if err := checkPermitted(r, allowUnverified); err != nil {
			return false, err
		}
	}

	changed := false
	for _, r := range repos {
		c, err := applyOne(r)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}
	return changed, nil
}

// checkPermitted enforces the agent-side half of the trust model.
func checkPermitted(r Repository, allowUnverified bool) error {
	if allowUnverified {
		return nil
	}
	if r.Signature.Type == SignatureNone {
		return fmt.Errorf(
			"repository %q declares signature type none, which this device's organization does not permit",
			r.Name,
		)
	}
	parsed, err := url.Parse(r.URL)
	if err != nil {
		return fmt.Errorf("repository %q has an unparseable url: %w", r.Name, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf(
			"repository %q uses %s, and this device's organization permits only https",
			r.Name, parsed.Scheme,
		)
	}
	return nil
}

func applyOne(r Repository) (bool, error) {
	changed := false

	switch r.Signature.Type {
	case SignatureFingerprints:
		c, err := writeFingerprints(r)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	case SignaturePubkey:
		c, err := writeIfDifferent(PubkeyPath(r.Name), []byte(r.Signature.Pubkey), 0o644)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}

	c, err := writeIfDifferent(ConfPath(r.Name), Render(r), 0o644)
	if err != nil {
		return changed, err
	}
	return changed || c, nil
}

// writeFingerprints materializes the trusted/ + revoked/ layout pkg expects.
// revoked/ is created empty on purpose: pkg complains about a missing
// directory rather than treating it as "nothing revoked".
func writeFingerprints(r Repository) (bool, error) {
	base := FingerprintDir(r.Name)
	trusted := filepath.Join(base, "trusted")
	revoked := filepath.Join(base, "revoked")
	for _, d := range []string{trusted, revoked} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return false, fmt.Errorf("creating %s: %w", d, err)
		}
	}

	changed := false
	wanted := map[string]bool{}
	for i, fp := range r.Signature.Fingerprints {
		// Name files by index rather than by fingerprint value: the value is
		// long, and the ordering the policy declares is the ordering we keep,
		// so re-applying an unchanged policy produces identical filenames.
		name := fmt.Sprintf("%s%s-%d", filePrefix, r.Name, i)
		wanted[name] = true
		body := fmt.Sprintf("function: %s\nfingerprint: %s\n", fp.Function, fp.Fingerprint)
		c, err := writeIfDifferent(filepath.Join(trusted, name), []byte(body), 0o644)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}

	// Drop fingerprints the policy no longer lists, so rotating a key actually
	// removes trust in the old one rather than leaving both trusted.
	entries, err := os.ReadDir(trusted)
	if err != nil {
		return changed, err
	}
	for _, e := range entries {
		if !wanted[e.Name()] {
			if err := os.Remove(filepath.Join(trusted, e.Name())); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	return changed, nil
}

// Prune removes managed files for repositories no longer in the policy.
//
// Confined to files carrying ManagedMarker: an administrator's own config is
// never removed by us, even if it happens to sit under our filename prefix.
func Prune(keep []string) error {
	keeping := map[string]bool{}
	for _, name := range keep {
		keeping[name] = true
	}

	entries, err := os.ReadDir(reposDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(e.Name(), filePrefix), ".conf")
		if keeping[name] {
			continue
		}

		path := filepath.Join(reposDir, e.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !IsManaged(content) {
			// Prefix matches but we did not write it. Leaving it alone is the
			// whole reason the marker exists.
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.RemoveAll(FingerprintDir(name)); err != nil {
			return err
		}
		if err := os.Remove(PubkeyPath(name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// writeIfDifferent writes only when the content actually differs, and does so
// atomically (temp file in the same directory, then rename) so a crash cannot
// leave pkg reading a half-written repo config.
//
// Returns false when the file already had exactly this content — that is what
// makes Apply's Changed flag meaningful.
func writeIfDifferent(path string, content []byte, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(content) {
		return false, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("creating %s: %w", dir, err)
	}

	// Same directory as the target so the rename stays within one filesystem;
	// a cross-device rename would fall back to a copy and lose atomicity.
	tmp, err := os.CreateTemp(dir, ".ndrepo-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	// Flush to disk before the rename: rename is atomic with respect to the
	// directory entry, not to the file's contents reaching storage.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return true, nil
}
