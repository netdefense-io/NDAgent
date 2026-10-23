package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
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

// The run that sends the rebind token clears it from config.xml too: the
// registration start zeroes the in-memory copy it shares with the lifecycle,
// and the cleanup used to read that copy and skip the helper until the next
// agent start.
func TestTheRebindTokenIsClearedInTheRunThatUsedIt(t *testing.T) {
	const token = "rebind-token-0123456789"
	var sent network.StartRegistrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		BootstrapToken: token,
		DeviceUUID:     "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:          "00000000-0000-4000-8000-000000000000",
		ServerURIStart: srv.URL + "/v1/DeviceRegistrationStart",
		DevicePrivKey:  base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}
	st, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The keypair was rotated for this token already: the rotation writes the
	// device's own key file, which a test cannot.
	sum := sha256.Sum256([]byte(token))
	if err := st.SetLastRebindTokenHash(hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}

	prev := clearRebindTokenInConfigFunc
	t.Cleanup(func() { clearRebindTokenInConfigFunc = prev })
	cleared := 0
	clearRebindTokenInConfigFunc = func(context.Context) error {
		cleared++
		return nil
	}

	l := &LifecycleManager{cfg: cfg, state: st, registrationClient: network.NewRegistrationClient(cfg)}
	if err := l.maybeRotateForRebindToken(); err != nil {
		t.Fatalf("rebind-token check: %v", err)
	}
	if err := l.registrationClient.StartRegistration(context.Background()); err != nil {
		t.Fatalf("StartRegistration: %v", err)
	}
	if sent.BootstrapToken != token {
		t.Fatalf("the registration start carried bootstrap token %q, want the one in the conf", sent.BootstrapToken)
	}
	if cfg.BootstrapToken != "" {
		t.Fatal("the registration start left the in-memory token, so this test shows nothing")
	}

	l.maybeClearRebindTokenInConfig(context.Background())
	if cleared != 1 {
		t.Fatalf("the helper ran %d times after the device was enabled, want once", cleared)
	}
	l.maybeClearRebindTokenInConfig(context.Background())
	if cleared != 1 {
		t.Fatalf("the helper ran again (%d times) once the token was cleared", cleared)
	}
}

// A helper that fails is tried again by the next lifecycle round of the run.
func TestARebindTokenTheHelperCouldNotClearIsTriedAgain(t *testing.T) {
	prev := clearRebindTokenInConfigFunc
	t.Cleanup(func() { clearRebindTokenInConfigFunc = prev })
	calls := 0
	clearRebindTokenInConfigFunc = func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("config lock held")
		}
		return nil
	}

	// What the lifecycle holds once the registration start sent the token.
	l := &LifecycleManager{cfg: &config.Config{}, rebindTokenInConf: true}
	l.maybeClearRebindTokenInConfig(context.Background())
	l.maybeClearRebindTokenInConfig(context.Background())
	l.maybeClearRebindTokenInConfig(context.Background())
	if calls != 2 {
		t.Fatalf("the helper ran %d times, want twice: the failure, then the success", calls)
	}
}
