package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
)

func TestMaybeClearRebindTokenInConfig(t *testing.T) {
	cases := []struct {
		name           string
		token          string
		stub           func(context.Context) error
		wantInvoked    bool
		wantTokenAfter string
	}{
		{
			name:           "no token in config — helper not invoked",
			token:          "",
			stub:           func(context.Context) error { t.Fatal("helper should not be called when token is empty"); return nil },
			wantTokenAfter: "",
		},
		{
			name:           "token present + helper succeeds — token cleared in-process",
			token:          "fake-token",
			stub:           func(context.Context) error { return nil },
			wantInvoked:    true,
			wantTokenAfter: "",
		},
		{
			name:           "token present + helper fails — token preserved in-process so next run can retry",
			token:          "fake-token",
			stub:           func(context.Context) error { return errors.New("helper missing") },
			wantInvoked:    true,
			wantTokenAfter: "fake-token",
		},
	}

	prev := clearRebindTokenInConfigFunc
	t.Cleanup(func() { clearRebindTokenInConfigFunc = prev })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			clearRebindTokenInConfigFunc = func(ctx context.Context) error {
				invoked = true
				return tc.stub(ctx)
			}
			l := &LifecycleManager{cfg: &config.Config{BootstrapToken: tc.token}}
			l.maybeClearRebindTokenInConfig(context.Background())
			if invoked != tc.wantInvoked {
				t.Fatalf("helper invoked=%v, want %v", invoked, tc.wantInvoked)
			}
			if l.cfg.BootstrapToken != tc.wantTokenAfter {
				t.Fatalf("token after=%q, want %q", l.cfg.BootstrapToken, tc.wantTokenAfter)
			}
		})
	}
}

// The helper writes config.xml, so it runs as every such script does
// (tasks.RunPHPConfigHelper, under the lifecycle's context), never with
// exec.CommandContext, whose cancellation would SIGKILL it mid-save.
func TestClearRebindTokenInConfigDefault_RunsTheHelperAsAConfigWriter(t *testing.T) {
	script := filepath.Join(t.TempDir(), "clear_rebind_token.php")
	if err := os.WriteFile(script, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	prevScript, prevRun := rebindTokenScript, runPHPConfigHelper
	t.Cleanup(func() { rebindTokenScript, runPHPConfigHelper = prevScript, prevRun })
	rebindTokenScript = script

	type call struct {
		ctx    context.Context
		script string
		args   []string
	}
	var calls []call
	failure := errors.New("clear_rebind_token.php exited 22: failed config lock unavailable")
	runPHPConfigHelper = func(ctx context.Context, script string, args ...string) (string, error) {
		calls = append(calls, call{ctx, script, args})
		return "failed", failure
	}

	ctx := context.WithValue(context.Background(), struct{}{}, "lifecycle")
	err := clearRebindTokenInConfigDefault(ctx)
	if !errors.Is(err, failure) {
		t.Fatalf("error %v, want the helper's", err)
	}
	if len(calls) != 1 || calls[0].ctx != ctx || calls[0].script != script || !reflect.DeepEqual(calls[0].args, []string{"--json"}) {
		t.Fatalf("calls %+v", calls)
	}

	calls = nil
	rebindTokenScript = filepath.Join(t.TempDir(), "missing.php")
	if err := clearRebindTokenInConfigDefault(ctx); err == nil || len(calls) != 0 {
		t.Fatalf("a plugin without the helper: error %v, calls %d", err, len(calls))
	}
}
