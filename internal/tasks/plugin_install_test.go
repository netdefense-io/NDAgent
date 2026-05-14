package tasks

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/pkg/version"
)

func TestAlreadyAtTargetVersion(t *testing.T) {
	cases := []struct {
		name             string
		runningVersion   string
		runningPackage   string
		target           string
		stubAvailable    string // empty → query stub returns no AvailableVersion
		wantAlready      bool
		wantMsgContains  string
	}{
		{
			name:            "explicit target matches running",
			runningVersion:  "1.2.3",
			runningPackage:  "os-netdefense-prod",
			target:          "1.2.3",
			wantAlready:     true,
			wantMsgContains: "Already at version 1.2.3",
		},
		{
			name:           "explicit target differs from running",
			runningVersion: "1.2.3",
			runningPackage: "os-netdefense-prod",
			target:         "1.2.4",
			wantAlready:    false,
		},
		{
			name:            "latest with stubbed-available equal to running",
			runningVersion:  "1.2.3",
			runningPackage:  "os-netdefense-prod",
			target:          "",
			stubAvailable:   "1.2.3",
			wantAlready:     true,
			wantMsgContains: "Already at latest version 1.2.3",
		},
		{
			name:           "latest with stubbed-available newer than running",
			runningVersion: "1.2.3",
			runningPackage: "os-netdefense-prod",
			target:         "",
			stubAvailable:  "1.2.4",
			wantAlready:    false,
		},
		{
			name:           "latest with package not in any repo (stub returns empty)",
			runningVersion: "1.2.3",
			runningPackage: "os-netdefense-prod",
			target:         "",
			stubAvailable:  "",
			wantAlready:    false,
		},
		{
			name:           "running version is dev placeholder — never short-circuit",
			runningVersion: "dev",
			runningPackage: "os-netdefense-prod",
			target:         "1.2.3",
			wantAlready:    false,
		},
		{
			name:           "running version is unknown placeholder — never short-circuit",
			runningVersion: "unknown",
			runningPackage: "os-netdefense-prod",
			target:         "1.2.3",
			wantAlready:    false,
		},
	}

	prevVersion := version.Version
	prevPackage := version.PackageName
	prevQuery := pkgmgrQueryForTest()
	t.Cleanup(func() {
		version.Version = prevVersion
		version.PackageName = prevPackage
		setPkgmgrQueryForTest(prevQuery)
	})

	log := zap.NewNop().Sugar()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version.Version = tc.runningVersion
			version.PackageName = tc.runningPackage
			setPkgmgrQueryForTest(func(_ context.Context, names []string) ([]pkgmgr.Status, error) {
				if len(names) != 1 || names[0] != tc.runningPackage {
					t.Fatalf("unexpected query names: %v", names)
				}
				return []pkgmgr.Status{{Name: tc.runningPackage, AvailableVersion: tc.stubAvailable}}, nil
			})

			gotAlready, gotMsg := alreadyAtTargetVersion(context.Background(), log, tc.target)
			if gotAlready != tc.wantAlready {
				t.Fatalf("alreadyAtTargetVersion() already=%v, want %v (msg=%q)", gotAlready, tc.wantAlready, gotMsg)
			}
			if tc.wantMsgContains != "" && !contains(gotMsg, tc.wantMsgContains) {
				t.Fatalf("message %q does not contain %q", gotMsg, tc.wantMsgContains)
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
