package track

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// RepoConfPath is the repository file OPNsense generates from the firmware
// settings; its url line is what pkg uses, so it is the device's own mirror.
const RepoConfPath = "/usr/local/etc/pkg/repos/OPNsense.conf"

// RepoBase is the device's own mirror as its generated repository file says it:
// where the release directories live, whatever flavour is set.
type RepoBase struct {
	// Base is the mirror up to the ABI: https://pkg.opnsense.org.
	Base string
	// ABI is pkg's expansion of ${ABI}: FreeBSD:15:amd64.
	ABI string
	// Series is the series directory the repository file points into: 26.7.
	Series string
	// Path is the url's path after the ABI, flavour included.
	Path string
}

var (
	repoURLRE = regexp.MustCompile(`(?m)^\s*url:\s*"([^"]+)"`)
	abiRE     = regexp.MustCompile(`\AFreeBSD:[0-9]{1,3}:[a-z0-9_]{1,16}\z`)
)

// ParseRepoConf reads the mirror out of the repository file's url line. The URL
// is `<base>/${ABI}/<series>/...`, optionally with pkg's `pkg+` scheme prefix
// (an SRV-resolved mirror); what pkg resolves by SRV is probed on the host the
// line names, which is the host a community mirror is.
func ParseRepoConf(conf, abi string) (RepoBase, error) {
	if !abiRE.MatchString(abi) {
		return RepoBase{}, fmt.Errorf("pkg's ABI %q is not one the agent recognizes", abi)
	}
	base, rest, err := splitRepoURL(conf)
	if err != nil {
		return RepoBase{}, err
	}
	series, _, _ := strings.Cut(rest, "/")
	if !ValidSeries(series) {
		return RepoBase{}, fmt.Errorf("the repository url does not name a series (%q)", series)
	}
	return RepoBase{Base: base, ABI: abi, Series: series, Path: rest}, nil
}

// RepoPath is what the repository file's url holds after the ABI: the path a
// firmware flavour replaces (`26.7/latest` by default, `26.7/MINT/26.7.3/latest`
// under a pin). OPNsense writes the file from the setting at boot, at every core
// post-install and on a firmware reload; a command that rewrites the file alone
// (`opnsense-update -sd`) leaves the setting and the file saying different things.
func RepoPath(conf string) (string, error) {
	_, rest, err := splitRepoURL(conf)
	return rest, err
}

func splitRepoURL(conf string) (base, rest string, err error) {
	m := repoURLRE.FindStringSubmatch(conf)
	if m == nil {
		return "", "", fmt.Errorf("the repository file has no url line")
	}
	raw := strings.TrimPrefix(m[1], "pkg+")
	base, rest, found := strings.Cut(raw, "/${ABI}/")
	if !found {
		return "", "", fmt.Errorf("the repository url has no ${ABI} to read the mirror from")
	}
	u, perr := url.Parse(base)
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("the repository url is not a plain http(s) mirror")
	}
	if strings.ContainsAny(base, " \t\r\n\"'`$\\;&|<>(){}[]*?!#") {
		return "", "", fmt.Errorf("the repository url holds characters the agent does not pass on")
	}
	return strings.TrimRight(base, "/"), strings.TrimRight(rest, "/"), nil
}

// FolderURL is the meta.conf of the release directory dir (or its aux part),
// which pkg fetches first and which answers 200 only when the directory is
// there. Probing it before a pin is written is what keeps a pin from pointing at
// a directory the mirror does not hold: pkg 2.8 deletes its local catalog after
// a 404, and every update fails until a check refetches it.
func (r RepoBase) FolderURL(dir string, aux bool) string {
	leaf := "latest"
	if aux {
		leaf = "aux"
	}
	return r.Base + "/" + r.ABI + "/" + r.Series + "/MINT/" + dir + "/" + leaf + "/meta.conf"
}

// ProbeResult is what asking the mirror for a directory answered.
type ProbeResult int

const (
	// ProbeFound: the mirror answered 200.
	ProbeFound ProbeResult = iota
	// ProbeMissing: the mirror answered, and the directory is not there (404).
	ProbeMissing
	// ProbeUnreachable: no answer to go on (DNS, TLS, a timeout, a 5xx, a 403).
	// Never taken for a missing directory.
	ProbeUnreachable
)

func (p ProbeResult) String() string {
	switch p {
	case ProbeFound:
		return "found"
	case ProbeMissing:
		return "missing"
	default:
		return "unreachable"
	}
}

// redactURL is the mirror URL as it may be logged: a path segment that looks
// like a subscription key is replaced.
var subscriptionSegmentRE = regexp.MustCompile(`/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(/|\z)`)

func redactURL(s string) string {
	return subscriptionSegmentRE.ReplaceAllString(s, "/<subscription>$1")
}
