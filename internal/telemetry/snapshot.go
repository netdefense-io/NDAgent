// Package telemetry collects a per-heartbeat snapshot of the OPNsense host's
// instantaneous OS-level health for the NetDefense dashboard. No history is
// kept here — the snapshot is shipped on every heartbeat (60s) and stored
// transiently by NDBroker. Heavier OPNsense-specific probes (service states,
// pkg updates, certificate expiries) will land in a follow-up.
package telemetry

import (
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// Snapshot is the wire shape embedded in HeartbeatMessage.Telemetry. Field
// names match the dashboard contract; absent values stay zero-valued so the
// dashboard can distinguish "0% used" from "not collected".
//
// Heavy fields (pending_updates, cert_expiry, services) are intentionally
// not present yet — adding them is an additive wire change.
type Snapshot struct {
	UptimeSec    uint64         `json:"uptime_sec"`
	Load1        float64        `json:"load1"`
	Load5        float64        `json:"load5"`
	Load15       float64        `json:"load15"`
	CPUCount     int            `json:"cpu_count"`
	MemUsedPct   float64        `json:"mem_used_pct"`
	MemTotalKB   uint64         `json:"mem_total_kb"`
	SwapUsedPct  float64        `json:"swap_used_pct"`
	SwapTotalKB  uint64         `json:"swap_total_kb"`
	Disks        []DiskUsage    `json:"disks"`
	Hostname     string         `json:"hostname,omitempty"`
	OSPlatform   string         `json:"os_platform,omitempty"`
	OSVersion    string         `json:"os_version,omitempty"`
	CollectedAt  float64        `json:"collected_at"`
	CollectionMs int64          `json:"collection_ms"`
	// Heavy holds OPNsense-API-derived fields refreshed every 15 min by
	// HeavyCollector. Absent until the collector's first refresh succeeds
	// and on agents where the OPNsense API client wasn't configured (no
	// SYNC creds). Older brokers ignore the unknown field.
	Heavy        *HeavySnapshot `json:"heavy,omitempty"`
}

// DiskUsage is one mountpoint slice of the snapshot. We report mountpoints
// the dashboard cares about for a firewall (/, /var, /tmp, /var/log) plus
// anything else over a usage threshold. KB units stay int-sized; percentages
// are floats with one decimal place worth of resolution.
type DiskUsage struct {
	Mountpoint string  `json:"mountpoint"`
	UsedPct    float64 `json:"used_pct"`
	TotalKB    uint64  `json:"total_kb"`
	UsedKB     uint64  `json:"used_kb"`
}

// mountpointAllowlist is the firewall-relevant set we always include even
// if usage is low. Anything outside this set is included only if used_pct
// crosses noisyMountpointPctThreshold — keeps the wire frame compact on
// devices with dozens of mounts (ZFS snapshots, nullfs jails, etc.).
var mountpointAllowlist = map[string]bool{
	"/":         true,
	"/var":      true,
	"/tmp":      true,
	"/var/log":  true,
	"/usr":      true,
	"/usr/home": true,
}

const noisyMountpointPctThreshold = 75.0

// Collect builds a fresh Snapshot. Every gopsutil call is best-effort: if a
// probe fails (which happens on some FreeBSD configurations for swap), the
// affected field stays zero-valued and the rest of the snapshot still ships.
// No error is returned — a partial snapshot is strictly better than no
// telemetry at all for the dashboard use case.
func Collect() Snapshot {
	start := time.Now()
	snap := Snapshot{
		CPUCount:    runtime.NumCPU(),
		CollectedAt: float64(start.Unix()),
	}

	if info, err := host.Info(); err == nil {
		snap.UptimeSec = info.Uptime
		snap.Hostname = info.Hostname
		snap.OSPlatform = info.Platform
		snap.OSVersion = info.PlatformVersion
	}

	if l, err := load.Avg(); err == nil {
		snap.Load1 = round1(l.Load1)
		snap.Load5 = round1(l.Load5)
		snap.Load15 = round1(l.Load15)
	}

	if v, err := mem.VirtualMemory(); err == nil {
		snap.MemTotalKB = v.Total / 1024
		snap.MemUsedPct = round1(v.UsedPercent)
	}

	if s, err := mem.SwapMemory(); err == nil {
		snap.SwapTotalKB = s.Total / 1024
		snap.SwapUsedPct = round1(s.UsedPercent)
	}

	snap.Disks = collectDisks()
	snap.CollectionMs = time.Since(start).Milliseconds()
	return snap
}

func collectDisks() []DiskUsage {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	out := make([]DiskUsage, 0, len(parts))
	for _, p := range parts {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		// Skip pseudo-filesystems with zero capacity (devfs, fdescfs).
		if usage.Total == 0 {
			continue
		}
		used := round1(usage.UsedPercent)
		if !mountpointAllowlist[p.Mountpoint] && used < noisyMountpointPctThreshold {
			continue
		}
		out = append(out, DiskUsage{
			Mountpoint: p.Mountpoint,
			UsedPct:    used,
			TotalKB:    usage.Total / 1024,
			UsedKB:     usage.Used / 1024,
		})
	}
	return out
}

func round1(f float64) float64 {
	// One decimal place is enough for percentages on a dashboard; keeps
	// the JSON frame compact and stops floating-point noise from
	// invalidating cache comparisons.
	return float64(int64(f*10+0.5)) / 10
}
