package firmware

import (
	"testing"
	"time"
)

func TestDeadline(t *testing.T) {
	expires := t0.Add(15 * time.Minute)
	if got, want := Deadline(expires), expires.Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("Deadline = %v, want the expiry plus five minutes (%v)", got, want)
	}
}

func TestUptime_IsMonotonicAndGrows(t *testing.T) {
	first := Uptime()
	time.Sleep(5 * time.Millisecond)
	if second := Uptime(); second <= first {
		t.Fatalf("Uptime went from %v to %v", first, second)
	}
}

// The task lifetimes are NDManager's (run_service.py) and the grace is this
// package's own: the values are spelled out literally.
func TestTaskLifetimes(t *testing.T) {
	if MinorTTL != 15*time.Minute || MajorTTL != 60*time.Minute {
		t.Fatalf("TTLs = %v / %v, want 15m / 60m", MinorTTL, MajorTTL)
	}
	if Grace != 5*time.Minute {
		t.Fatalf("Grace = %v, want 5m", Grace)
	}
	if TTL("minor") != MinorTTL || TTL("major") != MajorTTL {
		t.Fatalf("TTL(mode) does not match the constants")
	}
}
