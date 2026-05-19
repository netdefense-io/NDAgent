package tasks

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
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

	if len(out.Present) == 0 && len(out.Absent) == 0 {
		return nil, nil
	}
	return out, nil
}

// executeSyncSoftware runs pkg(8) to reconcile the desired present/absent
// state. Returns a SyncAPIResult that joins the broader SYNC_API result —
// any non-success per-package action flips overall Success to false, same
// binary contract the snippet executors use.
//
// Execution order:
//
//  1. `pkg update -q` once (fresh catalog → fewer false NOT_FOUND).
//  2. For each `absent` name: if installed, `pkg delete -y`. ALREADY_ABSENT
//     otherwise.
//  3. For each `present` name: if installed, ALREADY_PRESENT (no-op). Else
//     `pkg install -y`.
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

	// One catalog refresh per task. A failure here doesn't poison every
	// per-package call — pkg can still operate against stale metadata —
	// but it's worth surfacing as a single ERROR so the operator sees it.
	if err := pkgmgr.Update(ctx); err != nil {
		log.Warnw("pkg update failed; continuing against possibly-stale catalog", "err", err)
		result.Errors = append(result.Errors, fmt.Sprintf("pkg update: %v", err))
		// Don't flip Success — a stale catalog is recoverable; only real
		// per-package failures should fail the whole task.
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

	return result
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
