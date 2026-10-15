package track

import "regexp"

// The pin is OPNsense's own firmware flavour setting (system.firmware.flavour)
// set to `<series>/MINT/<dir>/latest`: the directory of one release on the
// OPNsense mirror. OPNsense replays it into the generated repository files at
// boot, at every core post-install and on a firmware reload, and it replaces
// everything after the ABI in their URLs, so a check, the GUI's Update and the
// auto-update cron all see that release's packages and nothing newer.

var flavourRE = regexp.MustCompile(`\A(` + SeriesPattern + `)/MINT/(` + VersionPattern + `)/latest\z`)

// Flavour is the setting that holds a device at the MINT directory dir of series.
func Flavour(series, dir string) string {
	return series + "/MINT/" + dir + "/latest"
}

// ParseFlavour reads a flavour of the shape the agent writes. Anything else (the
// default, a custom path, a directory outside its own series) is not a pin the
// agent could have written.
func ParseFlavour(flavour string) (series, dir string, ok bool) {
	m := flavourRE.FindStringSubmatch(flavour)
	if m == nil {
		return "", "", false
	}
	if s, _ := SeriesOf(m[2]); s != m[1] {
		return "", "", false
	}
	return m[1], m[2], true
}

// DirCovers reports whether the MINT directory dir holds the installed release:
// the directory of a release takes its hotfix revisions in place (26.7.3 holds
// 26.7.3_11), so it covers the release with any hotfix; a hotfix directory that
// exists after a series' final release (24.7.12_3) covers that revision only.
func DirCovers(dir, installed string) bool {
	return dir == installed || dir == StripHotfix(installed)
}

// DirCandidates are the directories that can hold the installed release, most
// specific first: its own name (a hotfix directory after a final release), then
// the release it is a revision of.
func DirCandidates(installed string) []string {
	if base := StripHotfix(installed); base != installed {
		return []string{installed, base}
	}
	return []string{installed}
}
