package network

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter_DeltaSeconds(t *testing.T) {
	got := parseRetryAfter("12")
	if got != 12*time.Second {
		t.Errorf("parseRetryAfter(\"12\") = %v, want 12s", got)
	}
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	// HTTP-date 30 seconds in the future. Allow ±2s tolerance for the
	// time.Until() resolution.
	future := time.Now().UTC().Add(30 * time.Second)
	header := future.Format(http.TimeFormat)

	got := parseRetryAfter(header)
	if got < 28*time.Second || got > 31*time.Second {
		t.Errorf("parseRetryAfter(<+30s>) = %v, want ~30s", got)
	}
}

func TestParseRetryAfter_PastDateReturnsZero(t *testing.T) {
	past := time.Now().UTC().Add(-30 * time.Second).Format(http.TimeFormat)
	if got := parseRetryAfter(past); got != 0 {
		t.Errorf("parseRetryAfter(<past>) = %v, want 0", got)
	}
}

func TestParseRetryAfter_EmptyAndGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "not a number", "-5"} {
		if got := parseRetryAfter(in); got != 0 {
			t.Errorf("parseRetryAfter(%q) = %v, want 0", in, got)
		}
	}
}

func TestRegistrationStartError_IsTransient(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusTooManyRequests, true},
		{500, true},
		{502, true},
		{503, true},
		{599, true},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{418, false},
	}
	for _, tc := range cases {
		err := &RegistrationStartError{StatusCode: tc.status}
		if got := err.IsTransient(); got != tc.want {
			t.Errorf("status %d: IsTransient = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestNextStartBackoff_FirstFailureIsAtLeastInitial(t *testing.T) {
	// First call: prev=0, no Retry-After → 10s + 0–5s jitter, never below 10s.
	for i := 0; i < 50; i++ {
		got := nextStartBackoff(0, 0, 60*time.Second)
		if got < 10*time.Second {
			t.Fatalf("first backoff = %v, want >= 10s", got)
		}
		if got > 15*time.Second {
			t.Fatalf("first backoff = %v, want <= 15s", got)
		}
	}
}

func TestNextStartBackoff_DoublesUntilCap(t *testing.T) {
	max := 60 * time.Second
	prev := 10 * time.Second

	// 10 → ~20-25 → ~40-45 → cap (60). The +jitter means we always
	// undershoot or hit the cap; never exceed it.
	prev = nextStartBackoff(prev, 0, max)
	if prev < 20*time.Second || prev > 25*time.Second {
		t.Errorf("after 10s: %v, want 20-25s", prev)
	}
	prev = nextStartBackoff(prev, 0, max)
	if prev < 40*time.Second || prev > max {
		t.Errorf("after second double: %v, want 40s-60s", prev)
	}
	prev = nextStartBackoff(prev, 0, max)
	if prev != max {
		t.Errorf("after third double: %v, want exactly %v (capped)", prev, max)
	}
	// And remains capped.
	prev = nextStartBackoff(prev, 0, max)
	if prev != max {
		t.Errorf("at cap: %v, want %v", prev, max)
	}
}

func TestNextStartBackoff_RetryAfterFloorWins(t *testing.T) {
	// Server says "wait 30s" but local doubling would give us only ~10-15s.
	// Honor the server's hint.
	got := nextStartBackoff(0, 30*time.Second, 60*time.Second)
	if got != 30*time.Second {
		t.Errorf("got %v, want 30s (Retry-After should win when larger)", got)
	}
}

func TestNextStartBackoff_RetryAfterIgnoredWhenSmaller(t *testing.T) {
	// Server says "wait 1s" but we've been failing — local backoff is
	// already 30s and growing. Don't shorten our sleep on the server's say-so.
	got := nextStartBackoff(30*time.Second, 1*time.Second, 60*time.Second)
	if got < 60*time.Second {
		// 30 doubles to 60 + jitter, capped at 60.
		t.Errorf("got %v, want at least the local computation", got)
	}
}

func TestNextStartBackoff_RetryAfterCanExceedMax(t *testing.T) {
	// Edge case: Retry-After is so large it exceeds our local cap. The
	// server knows its limiter window better than we do; honor it even
	// past the cap. (Cap is for "never grow past this on our own", not
	// "never sleep more than this".)
	got := nextStartBackoff(10*time.Second, 5*time.Minute, 60*time.Second)
	if got != 5*time.Minute {
		t.Errorf("got %v, want 5m (Retry-After must win past cap)", got)
	}
}
