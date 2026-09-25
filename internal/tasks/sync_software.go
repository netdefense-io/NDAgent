package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

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

const softwarePackageNameMaxLen = 100

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
// payload. Returns (nil, nil) when the key is absent or doesn't contain
// anything actionable — that matches the "no software policy attached"
// case, where executeSyncSoftware is a no-op.
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
	// An absent `software` key still returns nil: that is a server which sent
	// no software section at all, and it must not be read as "prune".
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
//  6. For each `external` entry: if the declared name+version is installed
//     and force is unset, ALREADY_PRESENT with no download. Else `pkg add`.
//
// Per-package failure types: INVALID_NAME (didn't pass the regex),
// NOT_FOUND (pkg's "no packages matching" message), ERROR (any other
// non-zero pkg exit).
func executeSyncSoftware(ctx context.Context, sp *softwarePayload) SyncAPIResult {
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

	removed, err := pkgrepo.Prune(names)
	if err != nil {
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Action: string(pkgmgr.ActionError),
			Status: "error", Error: err.Error(),
		})
		result.Errors = append(result.Errors, fmt.Sprintf("repository prune: %v", err))
		result.Success = false
		return changed, false
	}
	// Removing a repository from the device is a change the operator should
	// see, not something that happens silently.
	for _, name := range removed {
		changed = true
		result.Results = append(result.Results, SyncAPIItemResult{
			Type: "REPOSITORY", Name: name,
			Action: string(pkgmgr.ActionRepoRemoved), Status: "success",
		})
	}

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

// installExternal runs phase 6.
//
// The declared name+version is the identity, because `pkg add` records no
// repository origin and the URL alone cannot answer "already satisfied".
// Checking first means a settled device performs no download at all.
func installExternal(ctx context.Context, sp *softwarePayload, result *SyncAPIResult) {
	for _, e := range sp.External {
		item := SyncAPIItemResult{Type: "SOFTWARE", Name: e.Name}

		if !e.Force {
			// pkg identifies an exact build as name-version.
			installed, err := pkgmgr.IsInstalled(ctx, e.Name+"-"+e.Version)
			if err != nil {
				item.Action = string(pkgmgr.ActionError)
				item.Status = "error"
				item.Error = err.Error()
				result.Results = append(result.Results, item)
				result.Errors = append(result.Errors,
					fmt.Sprintf("external %s: pkg info: %v", e.Name, err))
				result.Success = false
				continue
			}
			if installed {
				item.Action = string(pkgmgr.ActionAlreadyPresent)
				item.Status = "success"
				result.Results = append(result.Results, item)
				continue
			}
		}

		out := pkgmgr.AddURL(ctx, e.URL, e.Force)
		item.Action = string(out.Action)
		if out.Action == pkgmgr.ActionInstalled {
			item.Status = "success"
		} else {
			item.Status = "error"
			item.Error = out.ErrMsg
			result.Errors = append(result.Errors,
				fmt.Sprintf("external %s from %s: %s", e.Name, e.URL, out.ErrMsg))
			result.Success = false
		}
		result.Results = append(result.Results, item)
	}
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
