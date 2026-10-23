package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// majorFrom is a 26.1 box at its series' final build, which is offered 26.7.
const majorFrom = "26.1.11_10"

// majorOfferStatus is a usable check of that box: the 26.7 upgrade on offer
// with its three sets, as the 26.1 to 26.7 offer measured them.
func majorOfferStatus(lastCheck string) *opnapi.FirmwareUpgradeStatus {
	return &opnapi.FirmwareUpgradeStatus{
		ProductVersion: majorFrom, ProductSeries: "26.1", Status: "upgrade",
		Connection: "ok", Repository: "ok", LastCheck: lastCheck,
		UpgradeMajorVersion: "26.7",
		UpgradeSets: []opnapi.FirmwareUpgradeSet{
			{Name: "packages", Size: 1142865408, CurrentVersion: "26.1.6_2", NewVersion: "26.7"},
			{Name: "kernel", Size: 33428352, CurrentVersion: "26.1.11", NewVersion: "26.7"},
			{Name: "base", Size: 98926556, CurrentVersion: "26.1.11", NewVersion: "26.7"},
		},
	}
}

// offerOf is the offer a check made by the task stands for.
func offerOf(st *opnapi.FirmwareUpgradeStatus) majorOffer {
	return majorOffer{checked: st, series: "26.1", target: "26.7", from: st.ProductVersion}
}

// majorClient is OPNsense for a series upgrade asked for outside a track. /status
// answers what the last check that ran left (before, until one runs); a check
// that runs leaves after with a last_check of its own, unless OPNsense drops it.
type majorClient struct {
	mu sync.Mutex

	before *opnapi.FirmwareUpgradeStatus
	after  *opnapi.FirmwareUpgradeStatus
	ran    int

	checkErr   error
	dropChecks bool          // the launcher drops every check
	busy       bool          // the backend never frees up after a check
	busyFor    time.Duration // the backend is busy this long after a check
	checkedAt  time.Time
	release    string

	// beforeRecheck runs, under the lock, at the second read of the check's
	// result (the first is the task finding it): what changes between the check
	// and the request.
	beforeRecheck func(c *majorClient)
	resultReads   int

	checks, posts int
	onReboot      func()
	// onPost runs when the series upgrade is requested.
	onPost func()
}

func newMajorClient(before, after *opnapi.FirmwareUpgradeStatus) *majorClient {
	return &majorClient{before: before, after: after, release: majorFrom}
}

func (c *majorClient) TriggerFirmwareCheck(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	c.checkedAt = time.Now()
	if c.checkErr != nil {
		return c.checkErr
	}
	if !c.dropChecks {
		c.ran++
	}
	return nil
}

func (c *majorClient) GetFirmwareRunning(context.Context) (*opnapi.FirmwareRunning, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checks > 0 && (c.busy || time.Since(c.checkedAt) < c.busyFor) {
		return &opnapi.FirmwareRunning{Status: "busy"}, nil
	}
	return &opnapi.FirmwareRunning{Status: "ready"}, nil
}

func (c *majorClient) GetFirmwareUpgradeStatus(context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ran == 0 || c.after == nil {
		st := *c.before
		return &st, nil
	}
	if c.resultReads++; c.resultReads == 2 && c.beforeRecheck != nil {
		c.beforeRecheck(c)
	}
	st := *c.after
	if st.LastCheck == "" {
		st.LastCheck = fmt.Sprintf("check %d", c.ran)
	}
	return &st, nil
}

func (c *majorClient) InstalledRelease(context.Context) (opnapi.ProductRelease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return opnapi.ProductRelease{Raw: c.release}, nil
}

func (c *majorClient) TriggerFirmwareUpdate(context.Context) (*opnapi.FirmwareUpdateResponse, error) {
	return nil, errors.New("a series upgrade asked for a point release")
}

func (c *majorClient) TriggerFirmwareUpgrade(context.Context) (*opnapi.FirmwareUpgradeResponse, error) {
	c.mu.Lock()
	c.posts++
	c.mu.Unlock()
	if c.onPost != nil {
		c.onPost()
	}
	return &opnapi.FirmwareUpgradeResponse{Status: "ok"}, nil
}

func (c *majorClient) GetFirmwareUpgradeProgress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	c.mu.Lock()
	posted := c.posts > 0
	c.mu.Unlock()
	if !posted {
		return &opnapi.FirmwareProgressStatus{Status: "done", Log: "the previous run\n***DONE***"}, nil
	}
	if c.onReboot != nil {
		c.onReboot()
	}
	return &opnapi.FirmwareProgressStatus{Status: "reboot", Log: upgradeRequestMarker + "\n***REBOOT***"}, nil
}

func (c *majorClient) postCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.posts
}

// runMajor runs a FIRMWARE_UPGRADE mode=major task against c, as the agent does,
// and ends it when the box goes down for the reboot.
func runMajor(t *testing.T, f *firmwareFixture, c *majorClient, extra map[string]interface{}) {
	t.Helper()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	payload := map[string]interface{}{"mode": "major"}
	for k, v := range extra {
		payload[k] = v
	}
	f.begin("140")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.onReboot = func() { time.AfterFunc(5*time.Millisecond, cancel) }
	cmd := network.Command{TaskID: "140", TaskType: "FIRMWARE_UPGRADE", Payload: payload}
	if err := HandleFirmwareUpgrade(ctx, firmwareWS(), cmd); err != nil {
		t.Fatalf("HandleFirmwareUpgrade: %v", err)
	}
}

// assertNotRequested: the task FAILED saying why, and POST /upgrade was never made.
func assertNotRequested(t *testing.T, f *firmwareFixture, c *majorClient, why string) {
	t.Helper()
	if n := c.postCount(); n != 0 {
		t.Fatalf("POST /upgrade made %d times, want none", n)
	}
	got := f.terminalResponses()
	if len(got) != 1 || got[0].success || !strings.Contains(got[0].message, "Nothing was applied") ||
		!strings.Contains(got[0].message, why) {
		t.Fatalf("terminal responses = %+v, want one FAILED saying %q", got, why)
	}
}

// assertNoUpdate: the task COMPLETED as a no-op, and POST /upgrade was never made.
func assertNoUpdate(t *testing.T, f *firmwareFixture, c *majorClient) {
	t.Helper()
	if n := c.postCount(); n != 0 {
		t.Fatalf("POST /upgrade made %d times, want none", n)
	}
	got := f.terminalResponses()
	if len(got) != 1 || !got[0].success {
		t.Fatalf("terminal responses = %+v, want one COMPLETED", got)
	}
	assertFirmwareJSON(t, got[0].message, map[string]interface{}{"no_update": true, "applied": false})
}

// The supported offer, from a check the task made, is requested once, and the
// progress message names both series.
func TestHandleMajor_AnOfferFromTheTasksOwnCheckIsRequested(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
	runMajor(t, f, c, nil)

	if n := c.postCount(); n != 1 {
		t.Fatalf("POST /upgrade made %d times, want 1", n)
	}
	if c.checks != 1 {
		t.Fatalf("%d checks, want the task's own", c.checks)
	}
	if !containsMessage(f.progressMessages(), "major upgrade from series 26.1 to 26.7") {
		t.Fatalf("IN_PROGRESS messages = %v", f.progressMessages())
	}
}

// check_first=false does not let a series upgrade run on the cached status:
// here the cached result still offers 26.7, and the task's own check, which
// offers nothing, decides.
func TestHandleMajor_ACachedOfferIsNotTrusted(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	none := majorOfferStatus("")
	none.UpgradeMajorVersion, none.UpgradeSets, none.Status = "", nil, "none"
	c := newMajorClient(majorOfferStatus("an older check"), none)
	runMajor(t, f, c, map[string]interface{}{"check_first": false})

	if c.checks != 1 {
		t.Fatalf("%d checks, want one made by the task although check_first was false", c.checks)
	}
	assertNoUpdate(t, f, c)
	assertFirmwareJSON(t, f.terminalResponses()[0].message, map[string]interface{}{"check_first_ignored": true})
}

// A partial offer (sets without a series, or a message alone) is no offer.
func TestHandleMajor_APartialOfferIsANoOp(t *testing.T) {
	for name, tweak := range map[string]func(*opnapi.FirmwareUpgradeStatus){
		"sets without a series": func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeMajorVersion = "" },
		"a message alone": func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeMajorVersion, s.UpgradeSets = "", nil
			s.UpgradeMajorMessage = "26.7 is available"
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireSlotFree(t)
			f := newFirmwareFixture(t)
			after := majorOfferStatus("")
			tweak(after)
			c := newMajorClient(majorOfferStatus("an older check"), after)
			runMajor(t, f, c, nil)
			assertNoUpdate(t, f, c)
		})
	}
}

// A check the task could not make, or whose result cannot be judged, stops the
// run with the reason, and nothing is requested.
func TestHandleMajor_AnUnusableCheckIsAFailureThatSaysWhy(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *majorClient)
		why   string
	}{
		{"the check cannot be requested", func(c *majorClient) { c.checkErr = errors.New("connection refused") },
			"the firmware check could not be requested"},
		{"OPNsense drops the check twice", func(c *majorClient) { c.dropChecks = true },
			"OPNsense did not run the firmware check"},
		{"the check never ends", func(c *majorClient) { c.busy = true },
			"the firmware check did not finish"},
		{"the check could not use the mirror", func(c *majorClient) { c.after.Connection = "unresolved" },
			"could not use the mirror"},
		{"the check describes another release", func(c *majorClient) {
			c.after.ProductVersion, c.after.InstalledVersion = "26.1.10", majorFrom
		}, "describes release 26.1.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireSlotFree(t)
			f := newFirmwareFixture(t)
			defer SetMajorCheckTimeoutForTest(50 * time.Millisecond)()
			c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
			tc.setup(c)
			runMajor(t, f, c, nil)
			assertNotRequested(t, f, c, tc.why)
		})
	}
}

// The check is waited for as long as a track's series upgrade waits for its own:
// a slow mirror must not fail the one and pass the other.
func TestHandleMajor_TheCheckIsWaitedForAsATracksSeriesUpgradeWaits(t *testing.T) {
	if majorCheckTimeoutVar != 3*time.Minute || majorCheckTimeoutVar != track.DefaultTiming().CheckTimeout {
		t.Errorf("a series upgrade waits %v for its check, want 3m0s, the firmware tracks' CheckTimeout", majorCheckTimeoutVar)
	}
	if firmwareCheckIdleDropVar != 20*time.Second || firmwareCheckIdleDropVar != track.DefaultTiming().CheckIdleDrop {
		t.Errorf("a series upgrade's check counts as dropped after %v idle, want 20s, the firmware tracks' CheckIdleDrop", firmwareCheckIdleDropVar)
	}

	requireSlotFree(t)
	f := newFirmwareFixture(t)
	defer SetFirmwareCheckTimeoutForTest(30 * time.Millisecond)()
	defer SetMajorCheckTimeoutForTest(5 * time.Second)()
	c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
	c.busyFor = 200 * time.Millisecond
	runMajor(t, f, c, nil)

	if n := c.postCount(); n != 1 {
		t.Fatalf("POST /upgrade made %d times after a check that outlasted the point-release bound, want 1 (terminals %+v)",
			n, f.terminalResponses())
	}
}

// Only the hop table's target, with its three sets and nothing else pending, is
// requested; anything else is refused with the reason.
func TestHandleMajor_AnOfferTheAgentDoesNotRunIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		release string
		tweak   func(*opnapi.FirmwareUpgradeStatus)
		why     string
	}{
		{"a series the hop table has no row from", "26.7.5", func(s *opnapi.FirmwareUpgradeStatus) {
			s.ProductVersion, s.ProductSeries, s.UpgradeMajorVersion = "26.7.5", "26.7", "27.1"
			for i := range s.UpgradeSets {
				s.UpgradeSets[i].NewVersion = "27.1"
			}
		}, "no series upgrade from \"26.7\""},
		{"another series than the hop's", majorFrom, func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeMajorVersion = "26.9"
		}, "the check offers 26.9, not 26.7"},
		{"two sets", majorFrom, func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets = s.UpgradeSets[:2] },
			"the offer lists 2 sets"},
		{"a set with no size", majorFrom, func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[1].Size = -1 },
			"carries no size"},
		{"a point release still pending", majorFrom, func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{{Name: "curl", Repository: "OPNsense", CurrentVersion: "8.21.0", NewVersionAlt: "8.22.0"}}
		}, "besides the series upgrade"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireSlotFree(t)
			f := newFirmwareFixture(t)
			after := majorOfferStatus("")
			tc.tweak(after)
			c := newMajorClient(majorOfferStatus("an older check"), after)
			c.release = tc.release
			runMajor(t, f, c, nil)
			assertNotRequested(t, f, c, tc.why)
		})
	}
}

// What changes between the check and the request stops the run: the status and
// the installed release are read again right before the POST.
func TestHandleMajor_TheOfferIsReadAgainRightBeforeTheRequest(t *testing.T) {
	cases := []struct {
		name   string
		change func(c *majorClient)
		why    string
	}{
		{"another check ran", func(c *majorClient) { c.ran++ }, "changed after this task's check"},
		{"the offer is gone", func(c *majorClient) {
			c.after = cloneStatus(c.after)
			c.after.UpgradeMajorVersion, c.after.UpgradeSets = "", nil
		}, "no longer offers the upgrade to 26.7"},
		{"the installed release moved", func(c *majorClient) { c.release = "26.1.11_11" },
			"changed from 26.1.11_10 to 26.1.11_11"},
	}
	for _, tc := range cases {
		for _, ignored := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, check_first ignored %v", tc.name, ignored), func(t *testing.T) {
				requireSlotFree(t)
				f := newFirmwareFixture(t)
				c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
				c.beforeRecheck = tc.change
				extra := map[string]interface{}{}
				if ignored {
					extra["check_first"] = false
				}
				runMajor(t, f, c, extra)
				if n := c.postCount(); n != 0 {
					t.Fatalf("POST /upgrade made %d times, want none", n)
				}
				got := f.terminalResponses()
				if len(got) != 1 || got[0].success || !strings.Contains(got[0].message, "was not started") ||
					!strings.Contains(got[0].message, tc.why) {
					t.Fatalf("terminal responses = %+v, want one FAILED saying %q", got, tc.why)
				}
				noted := strings.HasSuffix(got[0].message, " A series upgrade always checks first; check_first=false was ignored.")
				if noted != ignored {
					t.Errorf("the failure %q notes an ignored check_first: %v, want %v", got[0].message, noted, ignored)
				}
				// The row says so too, though nothing was requested: whoever settles a
				// row left behind says it.
				if m, found := f.meta("140"); !found || m.Triggered() || m.CheckFirstIgnored != ignored {
					t.Errorf("the record = %+v (found %v), want it untriggered with CheckFirstIgnored %v", m, found, ignored)
				}
			})
		}
	}
}

// A check whose release is not the installed one is refused, also when the
// status carries no product block to tell it by.
func TestHandleMajor_ACheckOfAnotherReleaseThanTheInstalledOneIsRefused(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
	c.release = "26.1.11_11"
	runMajor(t, f, c, nil)
	assertNotRequested(t, f, c, "describes release 26.1.11_10, not the installed 26.1.11_11")
}

// A preview names the target series and the reboots the run makes, and requests
// nothing.
func TestHandleMajor_ADryRunNamesTheTarget(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
	runMajor(t, f, c, map[string]interface{}{"dry_run": true})

	if n := c.postCount(); n != 0 {
		t.Fatalf("POST /upgrade made %d times by a dry run", n)
	}
	got := f.terminalResponses()
	if len(got) != 1 || !got[0].success {
		t.Fatalf("terminal responses = %+v", got)
	}
	assertFirmwareJSON(t, got[0].message, map[string]interface{}{
		"dry_run": true, "applied": false, "resolved_mode": "major",
		"from_version": majorFrom, "to_version": "26.7", "reboots_expected": float64(3),
	})
	if strings.Contains(got[0].message, "check_first_ignored") {
		t.Errorf("a dry run that honoured check_first notes it was ignored: %s", got[0].message)
	}
}

// check_first=false is not honoured by a series upgrade, and every result of one
// says so: the JSON of a dry run, the record the run's COMPLETED result is built
// from (by the handler, or by the reconciler after the reboots), and a failure.
func TestHandleMajor_AnIgnoredCheckFirstIsNoted(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		requireSlotFree(t)
		f := newFirmwareFixture(t)
		c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
		runMajor(t, f, c, map[string]interface{}{"dry_run": true, "check_first": false})
		got := f.terminalResponses()
		if len(got) != 1 || !got[0].success {
			t.Fatalf("terminal responses = %+v", got)
		}
		assertFirmwareJSON(t, got[0].message, map[string]interface{}{"dry_run": true, "check_first_ignored": true})
	})

	t.Run("the run", func(t *testing.T) {
		for _, ignored := range []bool{true, false} {
			requireSlotFree(t)
			f := newFirmwareFixture(t)
			c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
			var atThePost firmware.Meta
			c.onPost = func() { atThePost, _ = f.meta("140") }
			extra := map[string]interface{}{}
			if ignored {
				extra["check_first"] = false
			}
			runMajor(t, f, c, extra)
			if c.postCount() != 1 {
				t.Fatalf("check_first ignored %v: POST /upgrade made %d times", ignored, c.postCount())
			}
			if !atThePost.Triggered() || atThePost.CheckFirstIgnored != ignored {
				t.Errorf("check_first ignored %v: the record at the request is %+v", ignored, atThePost)
			}
		}
	})

	t.Run("a failure", func(t *testing.T) {
		for _, ignored := range []bool{true, false} {
			requireSlotFree(t)
			f := newFirmwareFixture(t)
			c := newMajorClient(majorOfferStatus("an older check"), majorOfferStatus(""))
			c.dropChecks = true
			extra := map[string]interface{}{}
			if ignored {
				extra["check_first"] = false
			}
			runMajor(t, f, c, extra)
			got := f.terminalResponses()
			if len(got) != 1 || got[0].success {
				t.Fatalf("terminal responses = %+v", got)
			}
			noted := strings.HasSuffix(got[0].message, "A series upgrade always checks first; check_first=false was ignored.")
			if noted != ignored {
				t.Errorf("check_first ignored %v: failure %q", ignored, got[0].message)
			}
		}
	})
}

func cloneStatus(st *opnapi.FirmwareUpgradeStatus) *opnapi.FirmwareUpgradeStatus {
	c := *st
	c.UpgradeSets = append([]opnapi.FirmwareUpgradeSet(nil), st.UpgradeSets...)
	return &c
}
