package track

import (
	"fmt"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Plan is what a check says the next update would do, read for the questions a
// pin asks. A check lists base and kernel as packages of their own (the sets a
// reboot installs), next to the core package and the others.
type Plan struct {
	Upgrades   []opnapi.FirmwarePackageEntry
	Downgrades []opnapi.FirmwarePackageEntry
	News       []opnapi.FirmwarePackageEntry
	Removes    []opnapi.FirmwarePackageEntry
	Reinstalls []opnapi.FirmwarePackageEntry

	// Major is the series the mirror offers an upgrade to ("" when none), and
	// MajorSets the sets of that upgrade, which the check lists beside it. The
	// offer is these two and never the check's status: a package entry of any kind,
	// a same-version reinstall included, keeps the status at "update" while the
	// major is still offered. An offered major says nothing about the pin: a device
	// at its series' final build is offered one whatever it is pinned to, and the
	// minor steps ignore it.
	Major     string
	MajorSets []opnapi.FirmwareUpgradeSet
	// Crossing says the check ran against another ABI than the installed one.
	Crossing bool
}

// NewPlan reads a check result.
func NewPlan(st *opnapi.FirmwareUpgradeStatus) Plan {
	return Plan{
		Upgrades:   st.UpgradePackages,
		Downgrades: st.DowngradePackages,
		News:       st.NewPackages,
		Removes:    st.RemovePackages,
		Reinstalls: st.ReinstallPackages,
		Major:      strings.TrimSpace(st.UpgradeMajorVersion),
		MajorSets:  st.UpgradeSets,
		Crossing:   st.ABICrossing(),
	}
}

// fromOPNsense reports whether an entry comes from OPNsense's own repositories,
// the ones a pin holds. The others (the NetDefense one, a plugin repository)
// are not pinned and still upgrade, so they say nothing about the pin.
func fromOPNsense(e opnapi.FirmwarePackageEntry) bool {
	return e.Repository == "" || strings.HasPrefix(e.Repository, "OPNsense")
}

func (p Plan) of(list []opnapi.FirmwarePackageEntry) []opnapi.FirmwarePackageEntry {
	var out []opnapi.FirmwarePackageEntry
	for _, e := range list {
		if fromOPNsense(e) {
			out = append(out, e)
		}
	}
	return out
}

// ReinstallEntries is how many same-version reinstalls the check lists. A
// factory-installed core record makes the first check at a pin list one
// (OPNsense's GUI says "1 update available"); it is benign, and never holds a
// step or triggers a reinstall.
func (p Plan) ReinstallEntries() int { return len(p.Reinstalls) }

func isSet(name string) bool { return name == "base" || name == "kernel" }

// SetsPending reports whether base or kernel is in the plan, which a reboot
// installs. The sets of an offered major upgrade are not in the plan of a minor
// step: they are a reboot that nothing has queued.
func (p Plan) SetsPending() bool {
	for _, e := range p.of(p.Upgrades) {
		if isSet(e.Name) {
			return true
		}
	}
	return false
}

// PackagesPending reports whether the plan holds anything a run without a reboot
// can install: base and kernel wait for the reboot.
func (p Plan) PackagesPending() bool {
	for _, e := range p.of(p.Upgrades) {
		if !isSet(e.Name) {
			return true
		}
	}
	return len(p.of(p.News)) > 0 || len(p.of(p.Removes)) > 0
}

func entryVersion(e opnapi.FirmwarePackageEntry) string { return e.VersionString() }

func (p Plan) find(name string) (opnapi.FirmwarePackageEntry, bool) {
	for _, e := range p.of(p.Upgrades) {
		if e.Name == name {
			return e, true
		}
	}
	return opnapi.FirmwarePackageEntry{}, false
}

// Core is the entry for OPNsense's own package, whose version is the release.
func (p Plan) Core() (opnapi.FirmwarePackageEntry, bool) {
	for _, e := range p.of(p.Upgrades) {
		if opnapi.IsCorePackage(e.Name) {
			return e, true
		}
	}
	return opnapi.FirmwarePackageEntry{}, false
}

// anyOther reports whether the plan changes anything from OPNsense's
// repositories: an upgrade, a new package or a removal.
func (p Plan) anyOther() bool {
	return len(p.of(p.Upgrades)) > 0 || len(p.of(p.News)) > 0 || len(p.of(p.Removes)) > 0
}

// held is the verdict of a plan that a step refuses: the reason it is held for,
// and a sentence for the log.
type held struct {
	Reason string
	Why    string
}

// common refuses what no step accepts: a downgrade, a check that ran against
// another ABI. A major upgrade on offer is no longer one of them: the final build
// of a series is offered one whatever the pin says, so a device enrolled at it, or
// asked for a minor hotfix, has to be able to go on; the series upgrade is its own
// step (forMajor).
func (p Plan) common() *held {
	switch {
	case len(p.Downgrades) > 0:
		return &held{ReasonHeldDowngradeRisk, "the plan would downgrade " + p.Downgrades[0].Name}
	case p.Crossing:
		return &held{ReasonHeldUnexpectedPlan, "the check ran against another ABI than the installed one"}
	}
	return nil
}

// forEnroll judges the plan of a check made at the pin on the installed release:
// it must show nothing the pin was meant to prevent. Same-release hotfix
// upgrades are allowed (a release's directory takes hotfix revisions in place,
// so a device a few revisions behind sees them); anything beyond the installed
// x.y.z, a pending reboot, a new or a removed package holds.
func (p Plan) forEnroll(installed string) *held {
	if h := p.common(); h != nil {
		return h
	}
	ik, ok := ParseKey(installed)
	if !ok {
		return &held{ReasonHeldCheckFailed, "the installed release is not one the agent can compare"}
	}
	// The release is the core package, opnsense-update, base and kernel. Any of
	// them moving to a later x.y.z than the installed one is a plan beyond the
	// release; a hotfix revision of it, or a component catching up to it, is not.
	for _, e := range p.of(p.Upgrades) {
		if !opnapi.IsCorePackage(e.Name) && e.Name != "opnsense-update" && !isSet(e.Name) {
			continue
		}
		k, ok := ParseKey(entryVersion(e))
		if !ok || (k.Compare(ik) > 0 && !k.SameRelease(ik)) {
			return &held{ReasonHeldUnexpectedPlan, e.Name + " would move to " + entryVersion(e) + ", beyond the installed " + installed}
		}
	}
	if p.SetsPending() {
		return &held{ReasonHeldRebootPending, "base or kernel is pending, a reboot is queued"}
	}
	if len(p.of(p.News)) > 0 || len(p.of(p.Removes)) > 0 {
		return &held{ReasonHeldUnexpectedPlan, "the plan adds or removes packages"}
	}
	return nil
}

// advanceKind is what a check at the target's directory says about moving there.
type advanceKind int

const (
	// planLands: the plan installs the target (or a hotfix revision of its release).
	planLands advanceKind = iota
	// planNothingNewer: the directory offers nothing newer than the installed release.
	planNothingNewer
	// planBehindTarget: the directory offers a release, but not the target yet.
	planBehindTarget
	// planHeld: the plan is refused; see held.
	planHeld
)

// forAdvance judges the plan of a check made at the pin on the target's
// directory. needsCore says the installed release is below the target, so the
// plan has to carry the core package up to it. The core package, base and kernel
// are the release; the rest of the plan may add or remove packages, as an
// update does.
func (p Plan) forAdvance(installed, target string, needsCore bool) (advanceKind, *held, string) {
	if h := p.common(); h != nil {
		return planHeld, h, ""
	}

	base, hasBase := p.find("base")
	kernel, hasKernel := p.find("kernel")
	update, hasUpdate := p.find("opnsense-update")
	if hasBase != hasKernel || (hasBase && entryVersion(base) != entryVersion(kernel)) {
		return planHeld, &held{ReasonHeldUnexpectedPlan, "base and kernel are not planned together at one release"}, ""
	}
	if hasBase && hasUpdate && entryVersion(base) != StripHotfix(entryVersion(update)) {
		return planHeld, &held{ReasonHeldUnexpectedPlan, "base and kernel do not match the opnsense-update package the plan installs"}, ""
	}

	core, hasCore := p.Core()
	if !hasCore {
		switch {
		case needsCore:
			return planBehindTarget, nil, ""
		case p.anyOther():
			return planLands, nil, ""
		default:
			return planNothingNewer, nil, ""
		}
	}

	version := entryVersion(core)
	k, ok := ParseKey(version)
	tk, tok := ParseKey(target)
	ik, iok := ParseKey(installed)
	if !ok || !tok || !iok {
		return planHeld, &held{ReasonHeldUnexpectedPlan, "the plan names a release the agent cannot compare (" + version + ")"}, ""
	}
	switch {
	case k.Compare(ik) <= 0:
		return planHeld, &held{ReasonHeldUnexpectedPlan, "the plan's core package " + version + " is not above the installed " + installed}, ""
	case !k.SameRelease(tk):
		if k.Compare(tk) < 0 {
			return planBehindTarget, nil, ""
		}
		return planHeld, &held{ReasonHeldUnexpectedPlan, "the plan moves to " + version + ", beyond the target " + target}, ""
	case k.Compare(tk) < 0:
		return planBehindTarget, nil, ""
	}
	return planLands, nil, version
}

// majorKind is what a check says about the series upgrade a step was asked for.
type majorKind int

const (
	// majorOffered: the check offers the series, its three sets are as expected and
	// nothing else is pending: the request may be made.
	majorOffered majorKind = iota
	// majorNoOffer: the check offers no major at all. The device is below its
	// series' final build, which is what carries the offer, or the project has
	// closed the path; either way nothing is asked of OPNsense.
	majorNoOffer
	// majorHeld: the offer is not the one the step expects; see held.
	majorHeld
)

// majorSetNames are the three sets of a series upgrade.
var majorSetNames = []string{"packages", "kernel", "base"}

// forMajor judges the check made at the current pin against the series the step
// asked for. It reads the offer (upgrade_major_version and upgrade_sets) and the
// plan, and never the status: a same-version reinstall of the agent's own package,
// which the check lists after a hop on an ABI change, turns the status into
// "update" while the major is still offered.
//
//   - no major offered: majorNoOffer;
//   - another series offered, or the sets are not exactly packages, kernel and
//     base, each once, each with a size and each at the series: held_unexpected_plan;
//   - the check ran against another ABI: held_unexpected_plan;
//   - a downgrade: held_downgrade_risk;
//   - base or kernel in the plan (a minor reboot pending): held_reboot_pending;
//   - any other real change from OPNsense's repositories, an upgrade, a new or a
//     removed package (the minor step should have taken it: a race with a hotfix):
//     held_unexpected_plan.
//
// Same-version reinstall entries are counted and never held on.
func (p Plan) forMajor(major string) (majorKind, *held) {
	if p.Major == "" {
		return majorNoOffer, nil
	}
	if p.Major != major {
		return majorHeld, &held{ReasonHeldUnexpectedPlan, "the check offers " + p.Major + ", not " + major}
	}
	if why := p.setsProblem(major); why != "" {
		return majorHeld, &held{ReasonHeldUnexpectedPlan, why}
	}
	switch {
	case p.Crossing:
		return majorHeld, &held{ReasonHeldUnexpectedPlan, "the check ran against another ABI than the installed one"}
	case len(p.Downgrades) > 0:
		return majorHeld, &held{ReasonHeldDowngradeRisk, "the plan would downgrade " + p.Downgrades[0].Name}
	case p.SetsPending():
		return majorHeld, &held{ReasonHeldRebootPending, "base or kernel is in the plan, a reboot is queued"}
	case p.anyOther():
		return majorHeld, &held{ReasonHeldUnexpectedPlan, "the plan holds a change from OPNsense's repositories besides the series upgrade"}
	}
	return majorOffered, nil
}

// setsProblem says what is wrong with the sets of the offer, "" when they are the
// three the step expects.
func (p Plan) setsProblem(major string) string {
	if len(p.MajorSets) != len(majorSetNames) {
		return fmt.Sprintf("the offer lists %d sets, not packages, kernel and base", len(p.MajorSets))
	}
	seen := make(map[string]bool, len(majorSetNames))
	for _, s := range p.MajorSets {
		switch {
		case !contains(majorSetNames, s.Name) || seen[s.Name]:
			return fmt.Sprintf("the offer lists a set named %q that is not one of packages, kernel and base, or lists one twice", s.Name)
		case s.NewVersion != major:
			return fmt.Sprintf("the %s set brings %q, not %s", s.Name, s.NewVersion, major)
		case s.Size <= 0:
			return fmt.Sprintf("the %s set carries no size the agent can read", s.Name)
		}
		seen[s.Name] = true
	}
	return ""
}
