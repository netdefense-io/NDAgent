package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/pkgrepo"
)

// ============================================================================
// SoftwarePolicy SYNC handling (the "software" bucket inside SYNC_API payloads)
// ============================================================================
//
// Payload shape (set by NDManager's sync_service.build_payload):
//
//   "software": {"present": ["os-zabbix72-agent", "bash"],
//                "absent":  ["os-zabbix6-agent", "os-zabbix74-agent"]}
//
// NDManager already merged every SoftwarePolicy applicable to this device
// and applied "presence wins" — the agent receives two flat dedup'd lists
// and must NOT reapply merge logic. Absent runs first, then present, so an
// older plugin that conflicts with the desired newer one is gone before the
// install attempt.
//
// Defense in depth: the same package-name regex NDDataModels uses on write
// runs here too. A poisoned DB row or an in-flight tamper that survived the
// signed-hash check would still be filtered before reaching pkg(8).

// softwarePackageNamePattern mirrors
// NDDataModels.Schema.SOFTWARE_PACKAGE_NAME_PATTERN. Any change must land
// in both places — the validator only ever needs to be the *strictest* of
// the two, but they should agree to keep the failure path predictable.
var softwarePackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// softwarePackageVersionPattern is a pkg(8) version: digits, letters and the
// separators its versions use (1.2.3_1,1), with no glob character and no "-",
// which separates a name from its version. A version is compared with what pkg
// reports as it is, so one in another form never matches.
// A version of letters alone ("latest") passes: it names no build, and the
// archive's own version is compared instead (installExternal).
var softwarePackageVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._,+]*$`)

const softwarePackageNameMaxLen = 100

// softwarePackageVersionMaxLen bounds a version as a name is bounded.
const softwarePackageVersionMaxLen = softwarePackageNameMaxLen

// softwarePayload is the parsed shape of the "software" key.
type softwarePayload struct {
	Present []string
	Absent  []string

	// Repositories and External are omitted by NDManager when empty, so a
	// policy that uses neither produces exactly the payload this handler
	// has always received.
	Repositories []pkgrepo.Repository
	External     []externalPackage

	// AllowUnverified is the organization's opt-in, carried inside the
	// signed payload. The agent re-checks it independently rather than
	// trusting that NDManager already gated — that independence is the
	// point of the third enforcement layer.
	AllowUnverified bool
}

// externalPackage is one entry from external[]: a package installed straight
// from a URL rather than from a repository catalog.
//
// Name and Version are declared explicitly because `pkg add` records no
// repository origin, so the archive URL alone gives the reconciler no way to
// answer "is this already satisfied". The declared pair is the identity.
type externalPackage struct {
	Name    string
	Version string
	URL     string
	Force   bool
}

// parseSoftwarePayload extracts the "software" bucket from a SYNC_API
// payload. Returns (nil, nil) when the key is absent or null: NDManager sends
// no section only when no software policy applies to the device, and
// syncSoftwareSection then removes the repositories a policy wrote.
func parseSoftwarePayload(payload map[string]interface{}) (*softwarePayload, error) {
	raw, ok := payload["software"]
	if !ok || raw == nil {
		return nil, nil
	}
	asMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("software must be an object")
	}

	out := &softwarePayload{}
	for _, key := range []string{"present", "absent"} {
		listRaw, exists := asMap[key]
		if !exists || listRaw == nil {
			continue
		}
		listArr, ok := listRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("software.%s must be an array", key)
		}
		for idx, entry := range listArr {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("software.%s[%d] must be a string", key, idx)
			}
			if key == "present" {
				out.Present = append(out.Present, s)
			} else {
				out.Absent = append(out.Absent, s)
			}
		}
	}

	if flag, ok := asMap["allow_unverified"].(bool); ok {
		out.AllowUnverified = flag
	}

	repos, err := parseRepositories(asMap["repositories"])
	if err != nil {
		return nil, err
	}
	out.Repositories = repos

	ext, err := parseExternal(asMap["external"])
	if err != nil {
		return nil, err
	}
	out.External = ext

	// Deliberately NOT short-circuiting on an entirely empty section.
	//
	// When the only content was `present`/`absent`, empty genuinely meant
	// "nothing to do". It does not any more: this agent writes files it owns
	// (repository configs, fingerprint material), so an empty policy means
	// "remove everything I manage" — which is work, not the absence of it.
	// Returning nil here left a custom repository configured on the device
	// forever once it was dropped from the policy, with no way to remove it
	// through the product.
	//
	return out, nil
}

// parseRepositories decodes repositories[]. Round-tripping through JSON keeps
// the shape in one place (pkgrepo.Repository's tags) rather than hand-walking
// a nested map here and drifting from it.
func parseRepositories(raw interface{}) ([]pkgrepo.Repository, error) {
	if raw == nil {
		return nil, nil
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("software.repositories: %w", err)
	}
	var repos []pkgrepo.Repository
	if err := json.Unmarshal(blob, &repos); err != nil {
		return nil, fmt.Errorf("software.repositories: %w", err)
	}
	for i, r := range repos {
		if r.Name == "" {
			return nil, fmt.Errorf("software.repositories[%d]: name is required", i)
		}
		if !validSoftwareName(r.Name) {
			return nil, fmt.Errorf("software.repositories[%d]: invalid repository name %q", i, r.Name)
		}
	}
	return repos, nil
}

func parseExternal(raw interface{}) ([]externalPackage, error) {
	if raw == nil {
		return nil, nil
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("software.external: %w", err)
	}
	var wire []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		URL     string `json:"url"`
		Force   bool   `json:"force"`
	}
	if err := json.Unmarshal(blob, &wire); err != nil {
		return nil, fmt.Errorf("software.external: %w", err)
	}
	out := make([]externalPackage, 0, len(wire))
	for i, e := range wire {
		if e.Name == "" || e.Version == "" || e.URL == "" {
			return nil, fmt.Errorf("software.external[%d]: name, version and url are all required", i)
		}
		// Same agent-side regex the package lists get: a poisoned row must
		// not reach pkg(8) through this path either.
		if !validSoftwareName(e.Name) {
			return nil, fmt.Errorf("software.external[%d]: invalid package name %q", i, e.Name)
		}
		out = append(out, externalPackage{Name: e.Name, Version: e.Version, URL: e.URL, Force: e.Force})
	}
	return out, nil
}

// syncSoftwareSection runs the software pass for a SYNC. A SYNC with no
// software section has no policy attached: it removes the repository files a
// policy wrote (pkgrepo.Prune keeps only marked files, so an administrator's
// own repository stays) and does nothing else. In particular, no pkg command
// runs, so a device without a policy makes no catalog fetch on every SYNC, and
// no package is removed.
func syncSoftwareSection(ctx context.Context, sp *softwarePayload, configXMLPath string) SyncAPIResult {
	if sp != nil {
		return executeSyncSoftware(ctx, sp, configXMLPath)
	}
	result := SyncAPIResult{Success: true}
	pruneRepositories(nil, &result)
	return result
}

// pruneRepositories removes the managed repositories not named in keep and
// reports each removal, or the failure, in result. It returns whether any
// was removed and whether the prune succeeded.
func pruneRepositories(keep []string, result *SyncAPIResult) (removedAny, ok bool) {
	removed, err := pkgrepo.Prune(keep)
	if err != nil {
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Action: string(pkgmgr.ActionError),
			Status: "error", Error: err.Error(),
		})
		result.Errors = append(result.Errors, fmt.Sprintf("repository prune: %v", err))
		result.Success = false
		return false, false
	}
	for _, name := range removed {
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Name: name,
			Action: string(pkgmgr.ActionRepoRemoved), Status: "success",
		})
	}
	return len(removed) > 0, true
}

// executeSyncSoftware runs pkg(8) to reconcile the desired present/absent
// state. Returns a SyncAPIResult that joins the broader SYNC_API result —
// any non-success per-package action flips overall Success to false, same
// binary contract the snippet executors use.
//
// Execution order (six phases; the repository work brackets the original
// sequence rather than reordering it):
//
//  1. Foreign-duplicate scan. If a repo config we do not own already defines
//     a repository name this policy declares, fail BEFORE writing anything.
//     Scanning after writing would only notice the collision once the device
//     already carried two definitions — the state this feature exists to
//     prevent — and failing there would leave the box dirty.
//  2. Reconcile repository config: write/refresh our files, materialize
//     signature material, prune repositories the policy dropped.
//  3. `pkg update` once (fresh catalog → fewer false NOT_FOUND).
//  4. For each `absent` name: if installed, `pkg delete -y`. ALREADY_ABSENT
//     otherwise.
//  5. For each `present` name: if installed, ALREADY_PRESENT (no-op). Else
//     shadow-check, then `pkg install -y`.
//  6. For each `external` entry: a version that is not a pkg version, and
//     without the organization's opt-in a URL that is not https, is refused
//     (externalPermitted) before anything else.
//     If the declared name+version is installed and force is unset,
//     ALREADY_PRESENT with no download. Else `pkg add`.
//  7. OPNsense's plugin list follows the os-* packages of the pass
//     (syncPluginRegistry).
//
// Per-package failure types: INVALID_NAME (didn't pass the regex),
// NOT_FOUND (pkg's "no packages matching" message), ERROR (any other
// non-zero pkg exit).
func executeSyncSoftware(ctx context.Context, sp *softwarePayload, configXMLPath string) SyncAPIResult {
	log := logging.Named("SYNC_SOFTWARE")
	result := SyncAPIResult{Success: true}

	if sp == nil {
		return result
	}

	// Phases 1-2: repository configuration, before any pkg mutation.
	repoChanged, ok := reconcileRepositories(ctx, sp, &result)
	if !ok {
		// Refused or failed: the device is unchanged and the task fails with
		// a reason that names what to fix.
		return result
	}

	// Nothing left to install or remove: the repository reconcile above was
	// the whole job. Skip the catalog refresh — a policy that only ever
	// configured repositories, or one that has just been emptied, should not
	// pay for a `pkg update` on every sync.
	if len(sp.Present) == 0 && len(sp.Absent) == 0 && len(sp.External) == 0 {
		return result
	}

	// One catalog refresh per task. A failure here is recorded as a
	// "warning" result item, not an `errors` entry: pkg can still operate
	// against stale metadata, so Success stays true.
	// repoChanged is deliberately not used to force a refresh yet: pkgmgr.Update
	// runs `pkg update -q` unconditionally, and adding a forced variant is a
	// separate change with its own cost on a production catalog. Keeping the
	// signal here makes that a one-line follow-up rather than a re-derivation.
	_ = repoChanged
	if err := pkgmgr.Update(ctx); err != nil {
		msg := fmt.Sprintf("pkg update: %v", err)
		log.Warnw("pkg update failed; continuing against possibly-stale catalog", "err", err)
		result.Results = append(result.Results, SyncAPIItemResult{
			Type:   "software",
			Name:   "pkg_update",
			Action: "warning",
			Status: "warning",
			Error:  msg,
		})
	}

	// Process absent first so an obsolete plugin clears before we attempt
	// the upgrade that conflicts with it.
	for _, name := range dedupSorted(sp.Absent) {
		item := SyncAPIItemResult{Type: "SOFTWARE", Name: name}

		if !validSoftwareName(name) {
			item.Action = string(pkgmgr.ActionInvalidName)
			item.Status = "error"
			item.Error = "package name failed the agent-side regex; refusing to invoke pkg"
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: invalid name", name))
			result.Success = false
			continue
		}

		installed, err := pkgmgr.IsInstalled(ctx, name)
		if err != nil {
			item.Action = string(pkgmgr.ActionError)
			item.Status = "error"
			item.Error = err.Error()
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: pkg info: %v", name, err))
			result.Success = false
			continue
		}
		if !installed {
			item.Action = string(pkgmgr.ActionAlreadyAbsent)
			item.Status = "success"
			result.Results = append(result.Results, item)
			continue
		}

		out := pkgmgr.Delete(ctx, name)
		item.Action = string(out.Action)
		if out.Action == pkgmgr.ActionRemoved {
			item.Status = "success"
		} else {
			item.Status = "error"
			item.Error = out.ErrMsg
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: pkg delete: %s", name, out.ErrMsg))
			result.Success = false
		}
		result.Results = append(result.Results, item)
	}

	for _, name := range dedupSorted(sp.Present) {
		item := SyncAPIItemResult{Type: "SOFTWARE", Name: name}

		if !validSoftwareName(name) {
			item.Action = string(pkgmgr.ActionInvalidName)
			item.Status = "error"
			item.Error = "package name failed the agent-side regex; refusing to invoke pkg"
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: invalid name", name))
			result.Success = false
			continue
		}

		installed, err := pkgmgr.IsInstalled(ctx, name)
		if err != nil {
			item.Action = string(pkgmgr.ActionError)
			item.Status = "error"
			item.Error = err.Error()
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: pkg info: %v", name, err))
			result.Success = false
			continue
		}
		if installed {
			item.Action = string(pkgmgr.ActionAlreadyPresent)
			item.Status = "success"
			result.Results = append(result.Results, item)
			continue
		}

		// Shadow check, only for packages actually about to be installed.
		// A settled device — everything ALREADY_PRESENT — pays nothing, and
		// an already-installed package is governed by CONSERVATIVE_UPGRADE
		// rather than by this decision.
		//
		// Priority does not protect us here: pkg picks the highest version
		// regardless of repository priority, so two repositories offering the
		// same name means pkg would choose a winner the operator never did.
		// Refusing is the only honest answer.
		offering, err := pkgmgr.OfferedBy(ctx, name)
		if err != nil {
			// Could not establish that the install is unambiguous.
			// Unverifiable is not the same as safe.
			item.Action = string(pkgmgr.ActionError)
			item.Status = "error"
			item.Error = err.Error()
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: shadow check: %v", name, err))
			result.Success = false
			continue
		}
		if len(offering) > 1 {
			shadow := pkgmgr.ShadowError{Package: name, Repositories: offering}
			item.Action = string(pkgmgr.ActionShadowed)
			item.Status = "error"
			item.Error = shadow.Error()
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors, shadow.Error())
			result.Success = false
			continue
		}

		out := pkgmgr.Install(ctx, name)
		item.Action = string(out.Action)
		switch out.Action {
		case pkgmgr.ActionInstalled:
			item.Status = "success"
		case pkgmgr.ActionNotFound:
			item.Status = "error"
			item.Error = "no repository has this package"
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: not found in any repository", name))
			result.Success = false
		default:
			item.Status = "error"
			item.Error = out.ErrMsg
			result.Errors = append(result.Errors,
				fmt.Sprintf("software %s: pkg install: %s", name, out.ErrMsg))
			result.Success = false
		}
		result.Results = append(result.Results, item)
	}

	// Phase 6: external URL packages, after everything the catalog can serve.
	installExternal(ctx, sp, &result)

	syncPluginRegistry(ctx, configXMLPath, &result)

	return result
}

// reconcileRepositories runs phases 1 and 2. Returns (repoConfigChanged, ok);
// ok=false means the task must stop without touching packages.
func reconcileRepositories(
	ctx context.Context, sp *softwarePayload, result *SyncAPIResult,
) (bool, bool) {
	names := make([]string, 0, len(sp.Repositories))
	for _, r := range sp.Repositories {
		names = append(names, r.Name)
	}

	// Phase 1: refuse before writing, never after.
	conflicts, err := pkgrepo.ScanForeign(names)
	if err != nil {
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Action: string(pkgmgr.ActionError),
			Status: "error", Error: err.Error(),
		})
		result.Errors = append(result.Errors, fmt.Sprintf("repository scan: %v", err))
		result.Success = false
		return false, false
	}
	if len(conflicts) > 0 {
		for _, c := range conflicts {
			result.Results = append(result.Results, SyncAPIItemResult{
				Type: "REPOSITORY", Name: c.Repository,
				Action: string(pkgmgr.ActionRepoConflict),
				Status: "error", Error: c.Error(),
			})
			result.Errors = append(result.Errors, c.Error())
		}
		result.Success = false
		return false, false
	}

	// Phase 2: write, then drop repositories the policy no longer lists.
	written, err := pkgrepo.Apply(sp.Repositories, sp.AllowUnverified)
	if err != nil {
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Action: string(pkgmgr.ActionError),
			Status: "error", Error: err.Error(),
		})
		result.Errors = append(result.Errors, err.Error())
		result.Success = false
		return false, false
	}
	changed := pkgrepo.AnyChanged(written)

	removedAny, ok := pruneRepositories(names, result)
	if !ok {
		return changed, false
	}
	changed = changed || removedAny

	// Per entry, not one flag for the batch: a single new repository used to
	// make every sibling report as freshly configured.
	for _, r := range sp.Repositories {
		action := pkgmgr.ActionRepoUnchanged
		if written[r.Name] {
			action = pkgmgr.ActionRepoConfigured
		}
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Name: r.Name, Action: string(action), Status: "success",
		})
	}
	return changed, true
}

// installExternal runs phase 6. An entry externalPermitted refuses gets a
// refused item and fails the task, whatever is installed, and the others go on.
//
// `pkg add` records no repository origin, so the URL alone cannot answer
// "already satisfied"; the installed version is read by the package's exact
// name (pkgmgr.InstalledVersion, no pattern). A version that names a build is
// compared as it is, so a settled device downloads nothing. A version without
// a digit (latest) names no build: the archive is fetched and its own version
// read (NDAgent-go#262), and the add is skipped when that version is installed.
// Before any add the archive is read too, and one that holds another package,
// or another build than the version the entry names, is refused.
func installExternal(ctx context.Context, sp *softwarePayload, result *SyncAPIResult) {
	for _, e := range sp.External {
		item := SyncAPIItemResult{Type: "SOFTWARE", Name: e.Name}
		fail := func(action pkgmgr.SoftwareAction, msg string) {
			item.Action = string(action)
			item.Status = "error"
			item.Error = msg
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors, fmt.Sprintf("external %s from %s: %s", e.Name, e.URL, msg))
			result.Success = false
		}
		present := func() {
			item.Action = string(pkgmgr.ActionAlreadyPresent)
			item.Status = "success"
			result.Results = append(result.Results, item)
		}

		if err := externalPermitted(e, sp.AllowUnverified); err != nil {
			item.Action = "refused"
			item.Status = "error"
			item.Error = err.Error()
			result.Results = append(result.Results, item)
			result.Errors = append(result.Errors, err.Error())
			result.Success = false
			continue
		}

		namesBuild := strings.ContainsAny(e.Version, "0123456789")
		if !e.Force && namesBuild {
			installed, err := pkgmgr.InstalledVersion(ctx, e.Name)
			if err != nil {
				fail(pkgmgr.ActionError, fmt.Sprintf("the installed version could not be read: %v", err))
				continue
			}
			if installed == e.Version {
				present()
				continue
			}
		}

		archiveName, archiveVersion, err := readExternalArchive(ctx, e.URL)
		if err != nil {
			fail(pkgmgr.ActionError, fmt.Sprintf("the archive could not be read: %v", err))
			continue
		}
		if archiveName != e.Name {
			fail("refused", fmt.Sprintf("the archive holds the package %s, not %s; nothing was installed", archiveName, e.Name))
			continue
		}
		if namesBuild && archiveVersion != e.Version {
			fail("refused", fmt.Sprintf("the archive holds %s-%s, not the version %s the policy names; nothing was installed", archiveName, archiveVersion, e.Version))
			continue
		}
		if !e.Force && !namesBuild {
			installed, err := pkgmgr.InstalledVersion(ctx, e.Name)
			if err != nil {
				fail(pkgmgr.ActionError, fmt.Sprintf("the installed version could not be read: %v", err))
				continue
			}
			if installed == archiveVersion {
				present()
				continue
			}
		}

		out := pkgmgr.AddURL(ctx, e.URL, e.Force)
		if out.Action == pkgmgr.ActionInstalled {
			out = confirmExternalAdded(ctx, e, archiveVersion)
		}
		if out.Action == pkgmgr.ActionInstalled {
			item.Action = string(out.Action)
			item.Status = "success"
			result.Results = append(result.Results, item)
			continue
		}
		fail(out.Action, out.ErrMsg)
	}
}

// confirmExternalAdded checks, after a `pkg add` that succeeded, that the
// archive's version is the installed one (NDAgent-go#142). pkg 2.3.1 (OPNsense
// 26.1) answers an add over another installed version with "already
// installed", installs nothing and exits 0; -f would replace it but also skips
// pkg's ABI check, so the agent does not add it on its own.
func confirmExternalAdded(ctx context.Context, e externalPackage, version string) pkgmgr.MutateOutcome {
	installed, err := pkgmgr.InstalledVersion(ctx, e.Name)
	if err != nil {
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionError, ErrMsg: fmt.Sprintf("pkg add finished, but the installed version of %s could not be read: %v", e.Name, err)}
	}
	if installed == version {
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	}
	if e.Force {
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionError, ErrMsg: fmt.Sprintf("pkg add -f finished, but %s-%s is not installed (installed: %q)", e.Name, version, installed)}
	}
	return pkgmgr.MutateOutcome{Action: pkgmgr.ActionError, ErrMsg: fmt.Sprintf("pkg add finished, but %s-%s is not installed (installed: %q): pkg add left the installed version in place; set force to replace it", e.Name, version, installed)}
}

// readExternalArchive fetches an external package's archive and reads the
// name and version it holds. Overridable by tests.
var readExternalArchive = fetchAndReadArchive

// externalFetchTimeout bounds the download as pkg add's own is bounded.
const externalFetchTimeout = 900 * time.Second

// pkgURL reports whether pkg add reads s as a URL to download, by its own
// three prefixes (pkg 2.3.1 src/add.c is_url); it reads anything else as a
// path on the box.
func pkgURL(s string) bool {
	for _, prefix := range []string{"http://", "https://", "file://"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// externalTempDir holds the downloaded archive: /var/tmp, not /tmp, which
// OPNsense can mount as a memory disk.
var externalTempDir = "/var/tmp"

// fetchAndReadArchive downloads the archive with fetch(1) into a temporary
// directory it removes after the read, in the environment pkg gives its own
// downloads (pkg.conf's PKG_ENV: proxies, CA file, timeouts), so it goes the
// way `pkg add <url>` would. A path is read in place, as pkg reads it.
func fetchAndReadArchive(ctx context.Context, rawURL string) (string, string, error) {
	path := rawURL
	if pkgURL(rawURL) {
		fetchEnv, err := pkgmgr.FetchEnv(ctx)
		if err != nil {
			return "", "", err
		}
		dir, err := os.MkdirTemp(externalTempDir, "ndagent-external-")
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(dir)
		path = filepath.Join(dir, "archive.pkg")
		fctx, cancel := context.WithTimeout(ctx, externalFetchTimeout)
		defer cancel()
		cmd := exec.CommandContext(fctx, "/usr/bin/fetch", "-q", "-o", path, "--", rawURL)
		cmd.Env = append(DeviceExecEnv(), fetchEnv...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return "", "", fmt.Errorf("fetch: %s", strings.SplitN(msg, "\n", 2)[0])
			}
			return "", "", fmt.Errorf("fetch: %w", err)
		}
	}
	return pkgmgr.ArchiveNameVersion(ctx, path)
}

// externalPermitted is the agent's own check of an external package entry. Its
// version must be a pkg version (softwarePackageVersionPattern), since it is
// compared with the installed and the archive's versions as written. `pkg add`
// installs what it fetches with no repository signature over it, so without
// the organization's opt-in only an https URL is allowed. The prefix is
// matched as pkg matches it, case and all: pkg reads anything that does not
// start with a literal "https://" (or "http://", "file://") as a local path.
func externalPermitted(e externalPackage, allowUnverified bool) error {
	if len(e.Version) > softwarePackageVersionMaxLen || !softwarePackageVersionPattern.MatchString(e.Version) {
		return fmt.Errorf("external %s: %q is not a package version", e.Name, e.Version)
	}
	if strings.HasPrefix(e.URL, "-") {
		return fmt.Errorf("external %s: %q starts with \"-\", which pkg would read as an option", e.Name, e.URL)
	}
	if allowUnverified {
		return nil
	}
	parsed, err := url.Parse(e.URL)
	if err != nil || !strings.HasPrefix(e.URL, "https://") || parsed.Host == "" {
		return fmt.Errorf("external %s: %q is not an https URL, which this device's organization requires for packages installed outside a repository", e.Name, e.URL)
	}
	return nil
}

func validSoftwareName(name string) bool {
	if len(name) == 0 || len(name) > softwarePackageNameMaxLen {
		return false
	}
	return softwarePackageNamePattern.MatchString(name)
}

// dedupSorted preserves input order with case-sensitive dedup, then sorts
// alphabetically so identical desired states produce identical pkg call
// orders (helps log diffing between runs).
func dedupSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
