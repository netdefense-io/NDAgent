package tasks

import (
	"context"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// adminPrivPolicy is how the admin-equivalence catalog applies on this device:
// with opnapi.ElevateFloorDependentPrivsBelowFloor on, which it is, the
// floor-dependent IDs are administrator-equivalent on a release below the
// supported floor and on one that cannot be read. It reads the installed release
// (a local file) every time it is asked, because an update can change the answer.
func adminPrivPolicy(ctx context.Context, client *opnapi.Client) opnapi.PrivPolicy {
	return adminPrivPolicyWith(ctx, client, opnapi.ElevateFloorDependentPrivsBelowFloor)
}

func adminPrivPolicyWith(ctx context.Context, client *opnapi.Client, switchOn bool) opnapi.PrivPolicy {
	if !switchOn {
		return opnapi.PrivPolicy{}
	}
	release, err := client.InstalledRelease(ctx)
	return opnapi.PrivPolicyForRelease(release, err == nil)
}

// livePrivCatalog reads the privilege IDs the device itself defines, for the
// verdicts on its live rows: an ID outside it grants nothing there. It is nil
// when the catalog cannot be read, and every verdict then counts an ID the agent
// does not know as administrator-equivalent. A sync or a pull reads it once.
func livePrivCatalog(ctx context.Context, client *opnapi.Client) *opnapi.DevicePrivs {
	defined, err := client.DevicePrivs(ctx)
	if err != nil {
		logging.Named("ADMIN_POLICY").Warnw("Could not read the device's privilege catalog; a privilege ID that NetDefense does not know counts as administrator-equivalent on the live rows",
			"error", err)
		return nil
	}
	return defined
}
