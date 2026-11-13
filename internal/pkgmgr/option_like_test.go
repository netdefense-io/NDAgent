package pkgmgr

import (
	"context"
	"strings"
	"testing"
)

// A package name or URL that starts with "-" would be read by pkg(8) as an
// option, so every entry that puts one on pkg's command line refuses it before
// anything runs.
func TestAnOptionLikeNameOrURLIsRefusedBeforePkgRuns(t *testing.T) {
	ctx := context.Background()
	for _, arg := range []string{"-f", "--yes", "-"} {
		if out := pkgInstallFreeBSD(ctx, arg); out.Action != ActionError || !strings.Contains(out.ErrMsg, "read by pkg as an option") {
			t.Errorf("install %q: %+v", arg, out)
		}
		if out := pkgRemoveFreeBSD(ctx, arg); out.Action != ActionError || !strings.Contains(out.ErrMsg, "read by pkg as an option") {
			t.Errorf("delete %q: %+v", arg, out)
		}
		if out := pkgAddURLFreeBSD(ctx, arg, false); out.Action != ActionError || !strings.Contains(out.ErrMsg, "read by pkg as an option") {
			t.Errorf("add %q: %+v", arg, out)
		}
		if _, err := pkgIsInstalledFreeBSD(ctx, arg); err == nil || !strings.Contains(err.Error(), "read by pkg as an option") {
			t.Errorf("info %q: %v", arg, err)
		}
		if _, err := installedVersion(ctx, arg); err == nil || !strings.Contains(err.Error(), "read by pkg as an option") {
			t.Errorf("query %q: %v", arg, err)
		}
		if _, err := availableVersion(ctx, arg); err == nil || !strings.Contains(err.Error(), "read by pkg as an option") {
			t.Errorf("rquery %q: %v", arg, err)
		}
		if _, err := pkgOfferedByFreeBSD(ctx, arg); err == nil || !strings.Contains(err.Error(), "read by pkg as an option") {
			t.Errorf("rquery %%R %q: %v", arg, err)
		}
	}
}
