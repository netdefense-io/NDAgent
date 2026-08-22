// Serialization and time-bounding for every pkg(8) invocation.
//
// Two problems this solves, both of which get worse once SoftwarePolicy
// sync starts configuring repositories and downloading external packages:
//
//  1. Concurrency. The agent dispatches every incoming command in its own
//     goroutine, so a SYNC_API task and a PLUGIN_INSTALL task can shell out
//     to pkg(8) at the same moment. pkg holds its own lock on the local
//     package database, but retries for only a few seconds (LOCK_WAIT=1,
//     LOCK_RETRIES=5, verified on OPNsense 26.1) — far less than an install
//     takes. The loser fails on a lock timeout, which reads to the operator
//     as a broken agent rather than as two tasks overlapping.
//
//  2. Unbounded runtime. Nothing on this path set a deadline, so a hung pkg
//     held its task open until the WebSocket connection tore down. A bounded
//     context turns that into an ordinary, reportable task failure.
//
// SCOPE, stated plainly: this mutex is IN-PROCESS ONLY. It does not protect
// against a second NDAgent process, an operator at the shell, or OPNsense's
// own firmware tooling running pkg concurrently. pkg's own database lock
// remains the only cross-process guard, and it is as short as described
// above. This narrows a real and likely race; it does not eliminate the
// class.
package pkgmgr

import (
	"sync"
	"time"
)

// Ceilings per operation kind. Installs and deletes get long budgets
// because a large package on a slow link legitimately takes minutes;
// fetching an external package by URL gets longer still, since its size and
// the server serving it are both outside our control.
const (
	updateTimeout = 120 * time.Second
	mutateTimeout = 600 * time.Second
	addURLTimeout = 900 * time.Second
)

// pkgMu serializes pkg(8) invocations within this process. Reads are
// included deliberately: `pkg info` consults the same local database that
// `pkg install` is writing, so letting them overlap would reintroduce the
// collision this exists to prevent.
//
// Held only for the duration of one invocation. Never hold it across two,
// and never call an exported wrapper from inside another — sync.Mutex is
// not reentrant and would deadlock.
var pkgMu sync.Mutex
