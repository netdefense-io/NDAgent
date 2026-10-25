package track

import (
	"context"
	"fmt"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// readCatalog reads the catalog pkg cached, a few times: pkg writes it while an
// update or a check of someone else's runs.
func (e *Engine) readCatalog(ctx context.Context) (Catalog, error) {
	var cat Catalog
	err := e.retryFor(ctx, e.timing.APIWait, func() (err error) {
		cat, err = e.dev.Catalog(ctx)
		return err
	}, nil)
	return cat, err
}

// planAgrees says whether the plan of a check lists only versions the catalog
// holds. A check that was made against another catalog than the one just read (a
// check or an update of someone else's in between) does not.
func planAgrees(status *opnapi.FirmwareUpgradeStatus, cat Catalog) error {
	for _, list := range [][]opnapi.FirmwarePackageEntry{status.UpgradePackages, status.NewPackages} {
		for _, e := range list {
			if !fromOPNsense(e) || isSet(e.Name) || e.Name == "packages" {
				continue
			}
			if e.Repository == "" && !cat.Has(e.Name) {
				continue // an entry that names no repository and is not OPNsense's
			}
			if !cat.Offers(e.Name, e.VersionString()) {
				return fmt.Errorf("the plan installs %s %s, which the catalog does not hold", e.Name, e.VersionString())
			}
		}
	}
	return nil
}

// verifyRevision is the gate after the forced check: the catalog the check was
// made against has to be the revision the dispatch approved. It returns the reason
// to hold for, "" to go on. A dispatch with no revision for the task's series is
// not held to one.
func (e *Engine) verifyRevision(ctx context.Context, o *op, status *opnapi.FirmwareUpgradeStatus) string {
	want := o.wanted()
	if want == "" {
		return ""
	}
	cat, err := e.readCatalog(ctx)
	if err != nil {
		e.log.Warnw("Cannot read the catalog the check was made against", "error", describeErr(err))
		return ReasonHeldCheckFailed
	}
	if err := planAgrees(status, cat); err != nil {
		e.log.Warnw("The check does not agree with the catalog on the device", "error", err)
		return ReasonHeldCheckFailed
	}
	o.revision = cat.Fingerprint
	if cat.Fingerprint != want {
		e.log.Infow("The folder holds another revision than the one approved", "approved", want, "found", cat.Fingerprint)
		return ReasonHeldRevisionMismatch
	}
	return ""
}

// reverifyRevision is the same read right before the update is requested: a folder
// rewritten since the check is not applied.
func (e *Engine) reverifyRevision(ctx context.Context, o *op) string {
	want := o.wanted()
	if want == "" {
		return ""
	}
	cat, err := e.readCatalog(ctx)
	if err != nil {
		e.log.Warnw("Cannot read the catalog before the update", "error", describeErr(err))
		return ReasonHeldCheckFailed
	}
	if cat.Fingerprint != want {
		o.revision = cat.Fingerprint
		e.log.Infow("The folder was rewritten since the check; not updating", "approved", want, "found", cat.Fingerprint)
		return ReasonHeldRevisionMismatch
	}
	return ""
}

// recheckRevision is reverifyRevision at the last moment before a request: after
// every wait for OPNsense's lock, the holder of which is the likeliest thing to
// have refetched the catalog, and again before a request that is made a second
// time. It returns the answer of a task that must not go on, nil otherwise. A
// series upgrade is not held to a revision.
func (e *Engine) recheckRevision(ctx context.Context, o *op, meta *firmware.Meta, prev, next string) *Outcome {
	if o.kind != "" {
		return nil
	}
	reason := e.reverifyRevision(ctx, o)
	if reason == "" {
		return nil
	}
	if ctx.Err() != nil {
		return aborted()
	}
	return e.nothingStarted(ctx, o, meta, prev, next, reason)
}

// readAppliedRevision records the revision the catalog holds once the update has
// ended, which is the one it installed from: pkg may fetch the catalog again by
// itself in the moments between the last read and its own run. A catalog that
// cannot be read leaves the answer without a revision, and so without evidence.
func (e *Engine) readAppliedRevision(ctx context.Context, o *op) {
	if o.wanted() == "" {
		return
	}
	cat, err := e.readCatalog(ctx)
	if err != nil {
		e.log.Warnw("Cannot read the catalog after the update; the answer names no revision", "task_id", o.in.TaskID, "error", describeErr(err))
		o.revision = ""
		return
	}
	o.revision = cat.Fingerprint
	if cat.Fingerprint != o.wanted() {
		e.log.Warnw("The update installed from another revision than the one approved", "task_id", o.in.TaskID,
			"approved", o.wanted(), "installed_from", cat.Fingerprint)
	}
}
