package telemetry

import (
	"encoding/json"
	"testing"
)

func TestCollectPopulatesBaseFields(t *testing.T) {
	snap := Collect()

	if snap.CollectedAt == 0 {
		t.Error("CollectedAt should be set")
	}
	if snap.CPUCount == 0 {
		t.Error("CPUCount should be > 0 on any host")
	}
	// Uptime and load come from host/load gopsutil probes. On darwin/freebsd
	// they should always succeed; if a future port loses support we want a
	// loud test failure, not a silent zero on the wire.
	if snap.UptimeSec == 0 {
		t.Error("UptimeSec should be > 0; gopsutil host.Info() probe failed")
	}
	if snap.Load1 == 0 && snap.Load5 == 0 && snap.Load15 == 0 {
		t.Error("load averages all zero; gopsutil load.Avg() probe failed")
	}
	if snap.MemTotalKB == 0 {
		t.Error("MemTotalKB should be > 0; gopsutil mem.VirtualMemory() probe failed")
	}
}

func TestCollectSerializesToWireShape(t *testing.T) {
	snap := Collect()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Spot-check that the JSON keys downstream services depend on are
	// present. NDBroker / NDManager read these names; renaming any of
	// them is a wire break.
	for _, key := range []string{
		`"uptime_sec"`,
		`"load1"`,
		`"mem_used_pct"`,
		`"swap_used_pct"`,
		`"disks"`,
		`"cpu_count"`,
		`"collected_at"`,
	} {
		if !contains(b, key) {
			t.Errorf("snapshot JSON missing %s: %s", key, string(b))
		}
	}
}

func TestRound1(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{0, 0},
		{1.0, 1.0},
		{1.04, 1.0},
		{1.05, 1.1},
		{99.99, 100.0},
	}
	for _, c := range cases {
		if got := round1(c.in); got != c.want {
			t.Errorf("round1(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func contains(haystack []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		if string(haystack[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}
