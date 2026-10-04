package network

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/telemetry"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// A restart restores the heavy snapshot the previous process saved, and the
// first heartbeat of the first connection carries it with its original
// stamps, so the broker's copy does not lose services, the update reading and
// the certificates while the new process collects them again.
func TestFirstHeartbeatAfterARestartCarriesTheRestoredSnapshot(t *testing.T) {
	dir := t.TempDir()
	versionFile := filepath.Join(dir, "core")
	if err := os.WriteFile(versionFile, []byte(`{"product_series":"26.7","product_version":"26.7"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opnapi.SetVersionFileForTest(versionFile))

	stamp := float64(time.Now().Add(-10 * time.Minute).Unix())
	saved, err := json.Marshal(map[string]any{"v": 1, "heavy": telemetry.HeavySnapshot{
		Services: &telemetry.ServicesBlock{
			Items: []opnapi.ServiceEntry{{Name: "unbound", Description: "DNS", Running: true}},
			AsOf:  stamp,
		},
		Updates: &telemetry.UpdatesBlock{
			FirmwareStatus: &opnapi.FirmwareStatus{
				Status: "update", LastCheck: "Sun Oct  4 03:02:47 UTC 2026", UpgradeCount: 86,
				Connection: "ok", Repository: "ok", OPNsenseVersion: "26.7", OPNsenseLatest: "26.7.5",
				OPNsensePackage: "opnsense", LastCheckUnix: 1791082967,
			},
			AsOf: stamp,
		},
		Certs:       &telemetry.CertsBlock{Items: []opnapi.CertEntry{{Description: "Web GUI", DaysLeft: 92}}, AsOf: stamp},
		CollectedAt: stamp,
	}})
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "heavy.json")
	if err := os.WriteFile(cache, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	// What NewLifecycleManager does at start; the collector's loop is not
	// needed for the first frame.
	heavy := telemetry.NewHeavyCollector(nil, cache)
	heavy.Restore()

	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	w.SetHeavyProvider(heavy.Snapshot)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	var first HeartbeatMessage
	if err := json.Unmarshal(b.HeartbeatFrames()[0], &first); err != nil {
		t.Fatalf("decode the first heartbeat: %v", err)
	}
	if first.Sequence != 1 || first.Telemetry == nil || first.Telemetry.Heavy == nil {
		t.Fatalf("the first heartbeat carries no heavy block: %s", b.HeartbeatFrames()[0])
	}
	got := first.Telemetry.Heavy
	if got.Services == nil || got.Certs == nil || got.Updates == nil || got.Updates.FirmwareStatus == nil {
		t.Fatalf("the first heartbeat's heavy block is incomplete: %s", b.HeartbeatFrames()[0])
	}
	if got.Services.AsOf != stamp || got.Certs.AsOf != stamp || got.Updates.AsOf != stamp || got.CollectedAt != stamp {
		t.Fatalf("restored blocks were restamped: %s", b.HeartbeatFrames()[0])
	}
	u := got.Updates
	if u.OPNsenseVersion != "26.7" || u.OPNsenseLatest != "26.7.5" || u.OPNsensePackage != "opnsense" || u.LastCheckUnix != 1791082967 {
		t.Fatalf("update reading = %+v", u.FirmwareStatus)
	}
}

// The facts of a connect carry the installed release from the version file
// even when the heavy-telemetry cache is empty, as it is in a new process: the
// broker's copy no longer loses it for the first minute after every start.
func TestConnectFactsCarryTheReleaseBeforeAnyHeavyTelemetry(t *testing.T) {
	dir := t.TempDir()
	versionFile := filepath.Join(dir, "core")
	if err := os.WriteFile(versionFile, []byte(`{"product_series":"25.7","product_version":"25.7.11_9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opnapi.SetVersionFileForTest(versionFile))

	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	w.SetHeavyProvider(func() *telemetry.HeavySnapshot { return nil })
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	var auth AuthMessage
	if err := json.Unmarshal(b.AuthFrames()[0], &auth); err != nil {
		t.Fatalf("decode the authentication message: %v", err)
	}
	if auth.Facts == nil || auth.Facts.OPNsense == nil ||
		auth.Facts.OPNsense.Version != "25.7.11_9" || auth.Facts.OPNsense.Series != "25.7" {
		t.Fatalf("the connect's facts = %s, want opnsense 25.7.11_9 from the version file", b.AuthFrames()[0])
	}
}
