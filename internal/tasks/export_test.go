package tasks

import (
	"context"

	"github.com/netdefense-io/ndagent/internal/pkgmgr"
)

// pkgmgrQueryForTest returns the current pkgmgr query indirection so a
// test can save/restore it. Lives in export_test.go so it doesn't ship
// in the production binary.
func pkgmgrQueryForTest() func(context.Context, []string) ([]pkgmgr.Status, error) {
	return pkgmgrQuery
}

// setPkgmgrQueryForTest swaps the pkgmgr query indirection used by the
// PLUGIN_INSTALL handler. Test-only.
func setPkgmgrQueryForTest(f func(context.Context, []string) ([]pkgmgr.Status, error)) {
	pkgmgrQuery = f
}
