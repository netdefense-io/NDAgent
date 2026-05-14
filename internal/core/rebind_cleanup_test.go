package core

import (
	"context"
	"errors"
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
