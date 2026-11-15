package core

import (
	"time"

	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// directPeerShutdownWait is how long a stopping agent gives its remote
// sessions to close toward their clients and have their ends recorded. A
// companion that does not end by itself is signalled after 5 s and killed 4 s
// later, so this covers the slowest one.
const directPeerShutdownWait = 10 * time.Second

// newDirectPeerManager builds the process's manager of direct-peer sessions
// on the record of session ids at ledgerPath. Nothing is started and nothing
// is written here: a device that is never sent a direct-peer task has no
// companion process and no record file.
func newDirectPeerManager(deviceUUID, ledgerPath string) *directpeer.Manager {
	ledger, err := directpeer.OpenLedger(ledgerPath, nil)
	if err != nil {
		// The record is usable: it refuses, for a while, every session that
		// could predate what was lost.
		logging.Named("lifecycle").Warnw("Remote sessions: the record of session ids was unusable", "error", err)
	}
	return directpeer.NewManager(directpeer.NewStarter(version.Version), ledger, deviceUUID)
}
