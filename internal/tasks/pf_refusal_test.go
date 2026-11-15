package tasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every test of the package reads pf's files from a directory that does not
// exist, unless it points them elsewhere: the host's /tmp says nothing about
// the fake device. The files the tests write are the test user's.
func init() {
	dir := filepath.Join(os.TempDir(), "ndagent-tasks-test-no-pf-files")
	pfLoadErrorPath = filepath.Join(dir, "rules.debug.error")
	pfRulesBannerPath = filepath.Join(dir, "rules.error")
	pfFileOwnerOK = func(uid uint32) bool { return uid == uint32(os.Getuid()) }
}

// usePfFiles points pf's files at a temporary directory for the rest of the
// test.
func usePfFiles(t *testing.T) (loadError, banner string) {
	t.Helper()
	dir := t.TempDir()
	prevLoad, prevBanner := pfLoadErrorPath, pfRulesBannerPath
	pfLoadErrorPath = filepath.Join(dir, "rules.debug.error")
	pfRulesBannerPath = filepath.Join(dir, "rules.error")
	t.Cleanup(func() { pfLoadErrorPath, pfRulesBannerPath = prevLoad, prevBanner })
	return pfLoadErrorPath, pfRulesBannerPath
}

func writeAt(t *testing.T, path, content string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// Measured on OPNsense 26.7.8 (e2e-a) for a rule with tag 123.
const (
	pfLoadErrorOutput = "/tmp/rules.debug:108: syntax error\npfctl: Syntax error in config file: pf rules not loaded\n"
	pfBannerText      = "There were error(s) loading the rules: /tmp/rules.debug:108: syntax error - The line in question reads [108]: pass in quick on vtnet0 inet from {192.0.2.10} to {any} keep state tag 123 label \"ec45fab7-c72c-4c25-a628-5b4df64b3469\" # pf-refusal probe 305\n"
)

func TestPfRulesetRefused(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		loadError   *string
		banner      *string
		bannerAt    time.Time
		wantRefused bool
		wantMessage string
	}{
		{name: "no files: the last load succeeded"},
		{
			// The state after a good load: OPNsense keeps the banner until it
			// is dismissed.
			name:     "a banner left from an earlier refusal",
			banner:   ptr(pfBannerText),
			bannerAt: now.Add(-time.Hour),
		},
		{
			name:      "an empty load error: a load is under way",
			loadError: ptr(""),
		},
		{
			name:        "refused, with the banner of the same load",
			loadError:   ptr(pfLoadErrorOutput),
			banner:      ptr(pfBannerText),
			bannerAt:    now.Add(time.Second),
			wantRefused: true,
			wantMessage: strings.TrimSpace(pfBannerText),
		},
		{
			name:        "refused, with a banner stamped the same instant",
			loadError:   ptr(pfLoadErrorOutput),
			banner:      ptr(pfBannerText),
			bannerAt:    now,
			wantRefused: true,
			wantMessage: strings.TrimSpace(pfBannerText),
		},
		{
			name:        "refused, with only a banner from an earlier load",
			loadError:   ptr(pfLoadErrorOutput),
			banner:      ptr("URL port aliases types not supported [x]"),
			bannerAt:    now.Add(-time.Hour),
			wantRefused: true,
			wantMessage: "/tmp/rules.debug:108: syntax error",
		},
		{
			name:        "refused, without a banner",
			loadError:   ptr("\n  /tmp/rules.debug:9: no such table\n"),
			wantRefused: true,
			wantMessage: "/tmp/rules.debug:9: no such table",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loadError, banner := usePfFiles(t)
			if tc.loadError != nil {
				writeAt(t, loadError, *tc.loadError, now)
			}
			if tc.banner != nil {
				writeAt(t, banner, *tc.banner, tc.bannerAt)
			}
			refused, message, err := pfRulesetRefused()
			if err != nil {
				t.Fatal(err)
			}
			if refused != tc.wantRefused || message != tc.wantMessage {
				t.Errorf("got refused=%v message %q; want %v %q", refused, message, tc.wantRefused, tc.wantMessage)
			}
		})
	}
}

func TestPfRulesetRefused_AnUnreadableLoadErrorSaysNothing(t *testing.T) {
	loadError, _ := usePfFiles(t)
	if err := os.Mkdir(loadError, 0o700); err != nil {
		t.Fatal(err)
	}
	refused, _, err := pfRulesetRefused()
	if refused || err == nil {
		t.Errorf("got refused=%v err=%v; want not refused, with an error", refused, err)
	}
}

// /tmp is anybody's: a file the agent could be pointed through to another
// file, or one root did not write, is not read.
func TestPfRulesetRefused_ReadsOnlyRootsOwnFile(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	writeAt(t, secret, "a secret line\n", time.Now())
	cases := map[string]func(t *testing.T, loadError string){
		"a symbolic link": func(t *testing.T, loadError string) {
			if err := os.Symlink(secret, loadError); err != nil {
				t.Fatal(err)
			}
		},
		"a hard link": func(t *testing.T, loadError string) {
			if err := os.Link(secret, loadError); err != nil {
				t.Fatal(err)
			}
		},
		"another owner's file": func(t *testing.T, loadError string) {
			writeAt(t, loadError, pfLoadErrorOutput, time.Now())
			prev := pfFileOwnerOK
			pfFileOwnerOK = func(uint32) bool { return false }
			t.Cleanup(func() { pfFileOwnerOK = prev })
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			loadError, _ := usePfFiles(t)
			plant(t, loadError)
			refused, message, err := pfRulesetRefused()
			if refused || err == nil || strings.Contains(message, "secret") {
				t.Errorf("got refused=%v message %q err=%v; want not refused, with an error", refused, message, err)
			}
		})
	}
}

// The banner is read with the same care: a banner that cannot be trusted
// leaves pf's own line.
func TestPfRulesetRefused_AnUntrustedBannerIsNotRead(t *testing.T) {
	loadError, banner := usePfFiles(t)
	secret := filepath.Join(t.TempDir(), "secret")
	writeAt(t, secret, "a secret line\n", time.Now().Add(time.Second))
	writeAt(t, loadError, pfLoadErrorOutput, time.Now())
	if err := os.Symlink(secret, banner); err != nil {
		t.Fatal(err)
	}
	refused, message, err := pfRulesetRefused()
	if err != nil || !refused || message != "/tmp/rules.debug:108: syntax error" {
		t.Errorf("got refused=%v message %q err=%v", refused, message, err)
	}
}

func TestPfRulesetRefused_TheMessageIsBounded(t *testing.T) {
	loadError, _ := usePfFiles(t)
	writeAt(t, loadError, "bad\x1b[31m line "+strings.Repeat("é", pfFileReadMax), time.Now())
	refused, message, err := pfRulesetRefused()
	if err != nil || !refused {
		t.Fatalf("refused=%v err=%v", refused, err)
	}
	if len(message) > pfMessageMax || !strings.HasSuffix(message, "...") || strings.ContainsRune(message, 0x1b) {
		t.Errorf("message (%d bytes) = %q", len(message), message)
	}
	if !strings.HasPrefix(message, "bad [31m line é") {
		t.Errorf("message = %q", message)
	}
}

// A refused ruleset fails the SYNC with pf's message and stays owed, so a
// SYNC with nothing new fails again instead of reporting success on a
// firewall that runs its previous rules; once pf takes the ruleset the owed
// apply clears.
func TestExecuteSyncAPI_ARefusedRulesetFailsTheSyncAndStaysOwed(t *testing.T) {
	useApplyRecord(t)
	loadError, banner := usePfFiles(t)
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	refuse := true
	device.onRuleApply = func() {
		if refuse {
			writeAt(t, loadError, pfLoadErrorOutput, time.Now())
			writeAt(t, banner, pfBannerText, time.Now())
			return
		}
		_ = os.Remove(loadError)
	}
	rules := []APIRulePayload{desiredRule(t, "r", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","tag":"123"}`)}

	assertRefused := func(name string, result SyncAPIResult) {
		t.Helper()
		if result.Success {
			t.Fatalf("%s: the SYNC succeeded with the ruleset refused", name)
		}
		item := applyItemOf(result.Results, "rule_apply")
		if item == nil || item.Status != "error" || item.Code != codeRulesetRefused || !strings.Contains(item.Error, "tag 123") {
			t.Errorf("%s: rule_apply item = %+v", name, item)
		}
		assertErrorHasMatchingResultItem(t, "Rule apply", result.Errors, result.Results)
		if !recordOwes(t)[applyFirewallRules] {
			t.Errorf("%s: the refused apply is not owed: %v", name, recordOwes(t))
		}
	}

	assertRefused("the write", executeSyncAPI(syncCtx(), device.client, nil, rules))
	assertRefused("nothing new", executeSyncAPI(syncCtx(), device.client, nil, rules))

	refuse = false
	healed := executeSyncAPI(syncCtx(), device.client, nil, rules)
	if !healed.Success {
		t.Fatalf("pf took the ruleset and the SYNC failed: %v", healed.Errors)
	}
	if item := applyItemOf(healed.Results, "rule_apply"); item == nil || item.Status != "success" || item.Code != codeApplyOwed {
		t.Errorf("rule_apply item = %+v, want a success with code %s", item, codeApplyOwed)
	}
	if recordOwes(t)[applyFirewallRules] {
		t.Errorf("the apply is still owed after pf took the ruleset")
	}
	// The banner stays until somebody dismisses it, and says nothing.
	if _, err := os.Stat(banner); err != nil {
		t.Fatal(err)
	}
	after := executeSyncAPI(syncCtx(), device.client, nil, rules)
	if !after.Success || applyItemOf(after.Results, "rule_apply") != nil {
		t.Errorf("a SYNC with nothing new after the heal: success=%v results %+v", after.Success, after.Results)
	}
}

func ptr(s string) *string { return &s }
