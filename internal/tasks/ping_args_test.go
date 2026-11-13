package tasks

import (
	"reflect"
	"testing"
)

// The target follows "--", so ping never reads it as an option.
func TestPingArgs_TheTargetFollowsTheEndOfTheOptions(t *testing.T) {
	if got, want := pingArgs(4, "-f"), []string{"-c", "4", "--", "-f"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pingArgs = %q, want %q", got, want)
	}
}
