package tasks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// A renewal is written first and its services are reloaded after. Whatever
// happens between the two, a failed step, a write whose answer was lost or an
// agent that stopped, the reloads still run: in the same pass, or in the next
// one from the record kept on disk.

// renewalSetup puts the root and an old fw1 on the device, fw1 used by an
// OpenVPN instance, and returns the payload that renews fw1.
func renewalSetup(t *testing.T, f *fakeTrust, p trustPKI) (payload map[string]interface{}, consumers string) {
	t.Helper()
	old := p.root.issue(t, "fw1.example.net", true)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, root.refid)
	consumers = `<OPNsense><OpenVPN><Instances><Instance uuid="aaaaaaaa-0000-4000-8000-000000000001"><description>VPN</description><cert>` + cert.refid + `</cert></Instance></Instances></OpenVPN></OPNsense>`
	return trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), consumers
}

func pendingOnDisk(t *testing.T) trustPending {
	t.Helper()
	pending, err := loadTrustPending()
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

// A step that fails after the renewal (here the second read of the CAs, before
// an orphan CA is removed) does not take the reloads with it.
func TestExecuteSyncTrust_ReloadsWhenALaterStepFails(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	payload, consumers := renewalSetup(t, f, p)
	f.add(opnapi.TrustCA, uuidOrphanCA, "Old CA", p.inter.certPEM, "", "")
	f.searchesBeforeFailing[opnapi.TrustCA] = 1
	f.failSearch[opnapi.TrustCA] = fakeFailure{status: 500}

	out := runTrust(t, f, payload, false, f.configXML(t, consumers))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
		"trust_ca discover error",
		"trust_reload VPN openvpn configure success",
	)
	if !reflect.DeepEqual(*calls, []string{"openvpn configure"}) {
		t.Errorf("configctl calls = %q", *calls)
	}
	if !pendingOnDisk(t).empty() {
		t.Error("a renewal whose reloads ran is still waiting")
	}
}

// A write whose answer is an error may have landed. The object is read again,
// and a renewal that landed is reloaded; the next pass finds it in place and
// reloads nothing more. When it cannot be read either, it counts as renewed.
func TestExecuteSyncTrust_ReloadsARenewalWhoseAnswerWasLost(t *testing.T) {
	p := newTrustPKI(t)
	recordConfigctl(t)

	t.Run("the write landed", func(t *testing.T) {
		f := newFakeTrust(t)
		calls := recordConfigctl(t)
		payload, consumers := renewalSetup(t, f, p)
		f.failSet[uuidHostCert] = fakeFailure{status: 502}
		f.applyFailedSet = true

		out := runTrust(t, f, payload, false, f.configXML(t, consumers))
		assertItems(t, out.Result,
			"trust_ca Corp Root CA unchanged success",
			"trust_cert fw1 update error TRUST_IMPORT_FAILED",
			"trust_reload VPN openvpn configure success",
		)
		*calls = nil
		delete(f.failSet, uuidHostCert)
		out = runTrust(t, f, payload, false, f.configXML(t, consumers))
		assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 unchanged success")
		if len(*calls) != 0 {
			t.Errorf("configctl calls = %q", *calls)
		}
	})

	t.Run("the write did not land", func(t *testing.T) {
		f := newFakeTrust(t)
		calls := recordConfigctl(t)
		payload, consumers := renewalSetup(t, f, p)
		f.failSet[uuidHostCert] = fakeFailure{status: 502}

		out := runTrust(t, f, payload, false, f.configXML(t, consumers))
		assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 update error TRUST_IMPORT_FAILED")
		if len(*calls) != 0 {
			t.Errorf("configctl calls = %q", *calls)
		}
	})

	t.Run("the object cannot be read back", func(t *testing.T) {
		f := newFakeTrust(t)
		calls := recordConfigctl(t)
		payload, consumers := renewalSetup(t, f, p)
		f.failGet[uuidHostCert] = fakeFailure{status: 500}

		out := runTrust(t, f, payload, false, f.configXML(t, consumers))
		assertItems(t, out.Result,
			"trust_ca Corp Root CA unchanged success",
			"trust_cert fw1 update error TRUST_IMPORT_FAILED",
			"trust_reload VPN openvpn configure success",
		)
		if !reflect.DeepEqual(*calls, []string{"openvpn configure"}) {
			t.Errorf("configctl calls = %q", *calls)
		}
	})

	t.Run("the device stored something else", func(t *testing.T) {
		f := newFakeTrust(t)
		calls := recordConfigctl(t)
		payload, consumers := renewalSetup(t, f, p)
		f.storeOther[uuidHostCert] = p.root.issue(t, "fw1.example.net", true).certPEM

		out := runTrust(t, f, payload, false, f.configXML(t, consumers))
		assertItems(t, out.Result,
			"trust_ca Corp Root CA unchanged success",
			"trust_cert fw1 update error TRUST_IMPORT_FAILED",
			"trust_reload VPN openvpn configure success",
		)
		if !reflect.DeepEqual(*calls, []string{"openvpn configure"}) {
			t.Errorf("configctl calls = %q", *calls)
		}
	})
}

// A renewal whose reloads cannot be worked out waits on disk and is reloaded
// by the next pass, as is one an agent that stopped before its reloads left
// behind.
func TestExecuteSyncTrust_ARenewalWaitsForItsReloads(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	payload, consumers := renewalSetup(t, f, p)
	refid := f.find(opnapi.TrustCert, uuidHostCert).refid

	out := runTrust(t, f, payload, false, "/nonexistent/config.xml")
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
		"trust_reload fw1 reload warning TRUST_RELOAD_FAILED",
	)
	if got := pendingOnDisk(t); !reflect.DeepEqual(got.Certs, []renewedTrust{{RefID: refid, Name: "fw1"}}) || len(got.CAs) != 0 {
		t.Fatalf("pending = %+v", got)
	}

	out = runTrust(t, f, payload, false, f.configXML(t, consumers))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 unchanged success",
		"trust_reload VPN openvpn configure success",
	)
	if _, err := os.Stat(trustPendingPath); !os.IsNotExist(err) {
		t.Fatalf("the record outlived its reloads: %v", err)
	}

	*calls = nil
	out = runTrust(t, f, payload, false, f.configXML(t, consumers))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 unchanged success")
	if len(*calls) != 0 {
		t.Errorf("configctl calls = %q", *calls)
	}

	// An agent that stopped between a renewal and its reloads.
	if err := saveTrustPending(trustPending{Certs: []renewedTrust{{RefID: refid, Name: "fw1"}}}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(trustPendingPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending file: %v, %v", info, err)
	}
	out = runTrust(t, f, payload, false, f.configXML(t, consumers))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 unchanged success",
		"trust_reload VPN openvpn configure success",
	)
	if !pendingOnDisk(t).empty() {
		t.Error("a renewal whose reloads ran is still waiting")
	}

	// The record holds identifiers only.
	raw, _ := os.ReadFile(trustPendingPath)
	if strings.Contains(string(raw), "BEGIN") {
		t.Errorf("the record holds certificate text: %s", raw)
	}
}

// A CA the payload drops is judged on a fresh read of both stores once
// anything was written: OPNsense re-links certificates when one is written, so
// the reference count read before is stale.
func TestExecuteSyncTrust_ReadsTheStoresAgainBeforeRemovingACA(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	oldCA := f.add(opnapi.TrustCA, uuidOrphanCA, "Old CA", p.inter.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidWildcard, "fw-wildcard", p.inter.issue(t, "*.example.net", false).certPEM, "", oldCA.refid)
	g2 := newTestCA(t, "Corp Issuing CA G2", p.root, nil)
	renewed := g2.issue(t, "*.example.net", false)

	out := runTrust(t, f, trustPayload(caSnippet(uuidInterCA, "Corp Issuing CA G2", g2), certSnippet(uuidWildcard, "fw-wildcard", renewed)), false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Issuing CA G2 created success",
		"trust_cert fw-wildcard updated success",
		"trust_ca Old CA deleted success",
	)
	if got := f.searchCount(opnapi.TrustCA); got != 2 {
		t.Errorf("CA searches = %d, want the discovery and one more before the removal", got)
	}
}

// A write is read back by uuid, not by listing the whole store again. The
// certificates are listed once more after a CA write, which re-links them all.
func TestExecuteSyncTrust_ReadsBackByUUID(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	out := runTrust(t, f, p.payload(), false, writeConfigXML(t, ""))
	if !out.Result.Success {
		t.Fatalf("errors: %v", out.Result.Errors)
	}
	if ca, cert, gets := f.searchCount(opnapi.TrustCA), f.searchCount(opnapi.TrustCert), f.getCount(); ca != 1 || cert != 2 || gets != 4 {
		t.Errorf("%d CA searches, %d certificate searches, %d gets; want 1, 2 and one get per write", ca, cert, gets)
	}

	// A pass that writes no CA lists the certificates once, and the stores
	// again before the CAs it drops: the intermediate goes with the wildcard,
	// and the CAs are read once more after it.
	out = runTrust(t, f, trustPayload(certSnippet(uuidHostCert, "fw1", p.root.issue(t, "fw1.example.net", true))), false, writeConfigXML(t, ""))
	if ca, cert := f.searchCount(opnapi.TrustCA), f.searchCount(opnapi.TrustCert); ca != 4 || cert != 4 {
		t.Errorf("after a certificate-only pass: %d CA searches, %d certificate searches; want 4 and 4 (items %q)", ca, cert, itemsOf(out.Result))
	}
}

// A device with no trust store holds nothing to remove; one that is asked to
// write still reports the store it could not read.
func TestExecuteSyncTrust_NoTrustStore(t *testing.T) {
	p := newTrustPKI(t)
	recordConfigctl(t)
	managed := writeConfigXML(t, `<ca uuid="`+uuidOrphanCA+`"><refid>66f0aaaaaaaaa</refid></ca>`)

	f := newFakeTrust(t)
	f.failSearch[opnapi.TrustCA] = fakeFailure{status: 404}
	f.failSearch[opnapi.TrustCert] = fakeFailure{status: 404}
	out := runTrust(t, f, trustPayload(), false, managed)
	if len(out.Result.Results) != 0 || !out.Result.Success {
		t.Fatalf("result = %+v", out.Result)
	}

	out = runTrust(t, f, p.payload(), false, managed)
	assertItems(t, out.Result, "trust_ca discover error")
}

// Below the supported OPNsense floor, or on a release that cannot be read,
// nothing is written; what matches stays unchanged and removals still run.
func TestExecuteSyncTrust_OldOPNsenseTakesNoWrites(t *testing.T) {
	p := newTrustPKI(t)
	recordConfigctl(t)

	for _, tc := range []struct{ name, version, reason string }{
		{"below the floor", "25.7.3", "this device runs OPNsense 25.7.3"},
		{"unreadable", "", "the OPNsense release of this device could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTrust(t)
			useTrustRelease(t, tc.version)
			f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
			f.add(opnapi.TrustCert, uuidOrphanCert, "old", p.wildcard.certPEM, p.wildcard.keyPEM, "")

			out := runTrust(t, f, trustPayload(
				caSnippet(uuidRootCA, "Corp Root CA", p.root),
				caSnippet(uuidInterCA, "Corp Issuing CA", p.inter),
			), false, f.configXML(t, ""))
			assertItems(t, out.Result,
				"trust_ca Corp Root CA unchanged success",
				"trust_ca Corp Issuing CA blocked blocked TRUST_OPNSENSE_TOO_OLD",
				"trust_cert old deleted success",
			)
			msg := out.Result.Results[1].Error
			if !strings.Contains(msg, tc.reason) || !strings.Contains(msg, "26.1.11") {
				t.Errorf("refusal = %q", msg)
			}
			if got := f.writeLog(); !reflect.DeepEqual(got, []string{"del cert " + uuidOrphanCert}) {
				t.Fatalf("writes = %q", got)
			}
		})
	}
}

// The reloads run even when the task is cancelled (a dropped connection
// cancels every task): a reload cut off between a stop and its start would
// leave a service down.
func TestExecuteSyncTrust_ReloadsOutliveTheTask(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	_, consumers := renewalSetup(t, f, p)
	refid := f.find(opnapi.TrustCert, uuidHostCert).refid
	cfg := f.configXML(t, consumers)
	if err := saveTrustPending(trustPending{Certs: []renewedTrust{{RefID: refid, Name: "fw1"}}}); err != nil {
		t.Fatal(err)
	}
	var live []string
	prev := runConfigctlFunc
	runConfigctlFunc = func(ctx context.Context, args ...string) error {
		if ctx.Err() == nil {
			live = append(live, strings.Join(args, " "))
		}
		return nil
	}
	t.Cleanup(func() { runConfigctlFunc = prev })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := executeSyncTrust(ctx, f.client, parseAPITrustContent(trustPayload()), false, cfg)
	if !reflect.DeepEqual(live, []string{"openvpn configure"}) {
		t.Fatalf("configctl ran with a live context: %q; items %q", live, itemsOf(out.Result))
	}
	if !pendingOnDisk(t).empty() {
		t.Error("a renewal whose reloads ran is still waiting")
	}
}

// A unit that did not finish (its own time ran out) keeps its renewals for the
// next pass; one that failed outright reports the failure and lets them go.
func TestExecuteSyncTrust_AnUnfinishedReloadWaits(t *testing.T) {
	p := newTrustPKI(t)
	for _, tc := range []struct {
		name string
		err  error
		kept bool
	}{
		{"out of time", fmt.Errorf("configctl openvpn configure did not finish: %w", context.DeadlineExceeded), true},
		{"failed", errors.New("configctl openvpn configure exited 1"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTrust(t)
			payload, consumers := renewalSetup(t, f, p)
			prev := runConfigctlFunc
			runConfigctlFunc = func(context.Context, ...string) error { return tc.err }
			t.Cleanup(func() { runConfigctlFunc = prev })

			out := runTrust(t, f, payload, false, f.configXML(t, consumers))
			assertItems(t, out.Result,
				"trust_ca Corp Root CA unchanged success",
				"trust_cert fw1 updated success",
				"trust_reload VPN openvpn configure warning TRUST_RELOAD_FAILED",
			)
			if got := !pendingOnDisk(t).empty(); got != tc.kept {
				t.Errorf("kept = %v, want %v", got, tc.kept)
			}
		})
	}
}

// A web GUI restart a renewal asked for stays recorded, and is asked for again
// by every pass, until the restart has started.
func TestExecuteSyncTrust_AWebGUIRestartWaitsUntilItStarted(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	payload, _ := renewalSetup(t, f, p)
	gui := `<system><webgui><ssl-certref>` + f.find(opnapi.TrustCert, uuidHostCert).refid + `</ssl-certref></webgui></system>`

	out := runTrust(t, f, payload, false, f.configXML(t, gui))
	if !out.RestartWebGUI || !pendingOnDisk(t).WebGUI {
		t.Fatalf("RestartWebGUI = %v, pending = %+v", out.RestartWebGUI, pendingOnDisk(t))
	}

	// The agent stopped before the restart started: the next pass asks again.
	out = runTrust(t, f, payload, false, f.configXML(t, gui))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 unchanged success")
	if !out.RestartWebGUI {
		t.Fatal("a restart that never started was not asked for again")
	}

	clearPendingWebGUIRestart()
	if pendingOnDisk(t).WebGUI {
		t.Fatal("the started restart is still recorded")
	}
	out = runTrust(t, f, payload, false, f.configXML(t, gui))
	if out.RestartWebGUI {
		t.Fatal("a started restart was asked for again")
	}
}

// A write that changed only the name or the issuer is no renewal, even when
// the object cannot be read back.
func TestExecuteSyncTrust_ARenameIsNotARenewal(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidHostCert, "fw1", p.host.certPEM, p.host.keyPEM, root.refid)
	f.failGet[uuidHostCert] = fakeFailure{status: 500}
	consumers := `<OPNsense><OpenVPN><Instances><Instance uuid="aaaaaaaa-0000-4000-8000-000000000001"><description>VPN</description><cert>` + cert.refid + `</cert></Instance></Instances></OpenVPN></OPNsense>`

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1 renamed", p.host)), false, f.configXML(t, consumers))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 renamed update error TRUST_IMPORT_FAILED")
	if len(*calls) != 0 || !pendingOnDisk(t).empty() {
		t.Errorf("configctl calls %q, pending %+v", *calls, pendingOnDisk(t))
	}
}

// A CA chain that leaves the payload leaves in one pass: the intermediate goes
// before the root that issued it, and the root is judged on the stores as they
// are once the intermediate is gone.
func TestExecuteSyncTrust_RemovesACAChainInOnePass(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCA, uuidInterCA, "Corp Issuing CA", p.inter.certPEM, "", root.refid)

	out := runTrust(t, f, trustPayload(), false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Issuing CA deleted success",
		"trust_ca Corp Root CA deleted success",
	)
}

// A renewal recorded mid-pass keeps a web GUI restart that is still owed.
func TestAddRenewed_KeepsAnOwedWebGUIRestart(t *testing.T) {
	usePendingFile(t)
	r := &trustRun{webGUIOwed: true}
	r.addRenewed(opnapi.TrustCert, renewedTrust{RefID: "66f0aaaaaaaa1", Name: "fw1"})
	if got := pendingOnDisk(t); !got.WebGUI || len(got.Certs) != 1 {
		t.Fatalf("pending = %+v", got)
	}
}
