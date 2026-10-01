package tasks

import (
	"context"
	"testing"
)

// TestAdminPrivPolicy_SwitchOffNeverLooksAtTheRelease pins the cost of the seam
// with the switch off: no release lookup at all, and the catalog as reviewed.
func TestAdminPrivPolicy_SwitchOffNeverLooksAtTheRelease(t *testing.T) {
	srv := &versionServer{version: "25.7.11_9"}
	client := srv.client(t)

	if got := adminPrivPolicyWith(context.Background(), client, false); got.FloorDependentElevated {
		t.Error("switch off: the floor-dependent IDs must stay ordinary")
	}
	if calls := srv.callCount(); calls != 0 {
		t.Errorf("release read %d times with the switch off, want 0", calls)
	}
}

// The build runs with the switch on: what the gates use follows the release the
// device reports, a release that cannot be read counts as below the floor, and
// the lookup is one release read.
func TestAdminPrivPolicy_TheBuildFollowsTheInstalledRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		fail    bool
		want    bool
	}{
		{"below the floor in the same series", "26.1.10", false, true},
		{"the first release of the series", "26.1", false, true},
		{"an older series", "25.7.11_9", false, true},
		{"at the floor", "26.1.11", false, false},
		{"above the floor", "26.1.12_2", false, false},
		{"the next series", "26.7.4", false, false},
		{"unreadable", "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &versionServer{version: tt.version, fail: tt.fail}
			client := srv.client(t)

			if got := adminPrivPolicy(context.Background(), client); got.FloorDependentElevated != tt.want {
				t.Errorf("FloorDependentElevated = %v, want %v", got.FloorDependentElevated, tt.want)
			}
			if calls := srv.callCount(); calls != 1 {
				t.Errorf("release read %d times, want 1", calls)
			}
		})
	}
}

func TestAdminPrivPolicy_SwitchOnFollowsTheInstalledRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		fail    bool
		want    bool
	}{
		{"a release below the floor", "25.7.11_9", false, true},
		{"a release at or above the floor", "26.7.5", false, false},
		{"a release that cannot be read", "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &versionServer{version: tt.version, fail: tt.fail}
			client := srv.client(t)

			got := adminPrivPolicyWith(context.Background(), client, true)
			if got.FloorDependentElevated != tt.want {
				t.Errorf("FloorDependentElevated = %v, want %v", got.FloorDependentElevated, tt.want)
			}
		})
	}
}
