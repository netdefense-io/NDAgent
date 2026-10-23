package track

import (
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

func TestJudgeMajorOffer(t *testing.T) {
	offer := func(tweak func(*opnapi.FirmwareUpgradeStatus)) *opnapi.FirmwareUpgradeStatus {
		s := statusOf()
		s.UpgradeMajorVersion = "26.7"
		s.UpgradeSets = offerSets("26.7")
		if tweak != nil {
			tweak(s)
		}
		return s
	}
	cases := []struct {
		name    string
		st      *opnapi.FirmwareUpgradeStatus
		series  string
		verdict MajorOfferVerdict
		target  string
	}{
		{"the supported upgrade with its three sets", offer(nil), "26.1", MajorOffered, "26.7"},
		{"no offer", statusOf(), "26.1", MajorNotOffered, ""},
		{"sets alone are no offer", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeMajorVersion = "" }), "26.1", MajorNotOffered, ""},
		{"a message alone is no offer", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.UpgradeMajorMessage = "This software release has reached its end of life."
			return s
		}(), "26.1", MajorNotOffered, ""},
		{"no offer on a series the hop table has no row from", statusOf(), "26.7", MajorNotOffered, ""},
		{"an offer from a series the hop table has no row from", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeMajorVersion = "27.1"
			s.UpgradeSets = offerSets("27.1")
		}), "26.7", MajorRefused, ""},
		{"an offer when the installed series cannot be read", offer(nil), "", MajorRefused, ""},
		{"an offer of another series than the hop's", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeMajorVersion = "26.9"
			s.UpgradeSets = offerSets("26.9")
		}), "26.1", MajorRefused, "26.7"},
		{"an offer without its sets", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets = nil }), "26.1", MajorRefused, "26.7"},
		{"an offer whose set carries no size", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[2].Size = -1 }), "26.1", MajorRefused, "26.7"},
		{"a check against another ABI", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.CheckABI, s.InstalledABI = "26.7", "26.1" }), "26.1", MajorRefused, "26.7"},
		{"an update pending besides the offer", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{entry("curl", "OPNsense", "8.21.0", "8.22.0")}
		}), "26.1", MajorRefused, "26.7"},
		{"an upgrade of the agent's own package beside the offer", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{entry("os-netdefense-dev", "NetDefense", "1.26_0", "1.27_0")}
		}), "26.1", MajorOffered, "26.7"},
	}
	for _, tc := range cases {
		verdict, target, why := JudgeMajorOffer(tc.st, tc.series)
		if verdict != tc.verdict || target != tc.target {
			t.Errorf("%s: verdict %v, target %q (%s), want %v, %q", tc.name, verdict, target, why, tc.verdict, tc.target)
			continue
		}
		if (verdict == MajorRefused) != (why != "") {
			t.Errorf("%s: verdict %v with why %q: a refusal, and only a refusal, says why", tc.name, verdict, why)
		}
	}
}

func TestUsableCheck(t *testing.T) {
	if err := UsableCheck(statusOf()); err != nil {
		t.Fatalf("a finished, clean check of the installed release: %v", err)
	}
	for name, tweak := range map[string]func(*opnapi.FirmwareUpgradeStatus){
		"no result":                   func(s *opnapi.FirmwareUpgradeStatus) { s.LastCheck = "" },
		"a check of another release":  func(s *opnapi.FirmwareUpgradeStatus) { s.ProductVersion, s.InstalledVersion = "26.1.10", "26.1.11" },
		"a check that failed":         func(s *opnapi.FirmwareUpgradeStatus) { s.Status = "error" },
		"no connection to the mirror": func(s *opnapi.FirmwareUpgradeStatus) { s.Connection = "unresolved" },
		"a repository that failed":    func(s *opnapi.FirmwareUpgradeStatus) { s.Repository = "error" },
	} {
		s := statusOf()
		tweak(s)
		if err := UsableCheck(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
