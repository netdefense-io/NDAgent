package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// -----------------------------------------------------------------
// Strict parsing
// -----------------------------------------------------------------

func TestParseAuthServerContent_StrictUnknownKeyRejected(t *testing.T) {
	content := `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
	"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
	"ldap_basedn":"dc=example,dc=com","ldap_authcn":"","ldap_attr_user":"sAMAccountName",
	"a_future_field_this_agent_does_not_know_about":"x"}`

	if _, err := parseAuthServerContent(content); err == nil {
		t.Fatal("expected a strict-decode error for an unrecognized key, got nil")
	}
}

func TestParseAuthServerContent_UnrecognizedTypeRejected(t *testing.T) {
	// A future v1.1 RADIUS server type must fail closed on this (older)
	// agent, not half-apply as if it were LDAP.
	content := `{"name":"Corp RADIUS","type":"radius","host":"radius.example.com","ldap_port":"636",
	"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
	"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`

	_, err := parseAuthServerContent(content)
	if err == nil {
		t.Fatal("expected an error for type != \"ldap\", got nil")
	}
	if !strings.Contains(err.Error(), "radius") {
		t.Errorf("error = %v, want it to name the unrecognized type", err)
	}
}

// TestParseAuthServerContent_TrailingDataRejected mirrors the AUTH_ORDER
// case: trailing bytes after a complete, otherwise-valid JSON value must
// fail closed rather than decode successfully with the trailing data
// silently discarded.
func TestParseAuthServerContent_TrailingDataRejected(t *testing.T) {
	content := `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
	"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
	"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"} trailing-garbage`

	if _, err := parseAuthServerContent(content); err == nil {
		t.Fatal("expected an error for trailing data after the JSON value, got nil")
	}
}

func TestParseAuthServerContent_ValidLDAPAccepted(t *testing.T) {
	content := `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
	"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
	"ldap_basedn":"dc=example,dc=com","ldap_authcn":"cn=svc,dc=example,dc=com",
	"ldap_attr_user":"sAMAccountName","ldap_binddn":"cn=svc,dc=example,dc=com",
	"ldap_bindpw":"s3cr3t","caseInSensitiveUsernames":true,
	"ldap_read_properties":true,"ldap_sync_memberof_constraint":false,
	"ldap_sync_memberof":true,"ldap_attr_memberof":"memberOf",
	"ldap_sync_memberof_groups":"eng-external","ldap_sync_default_groups":"",
	"ldap_sync_create_local_users":false,"nd_allow_cleartext_ldap":false}`

	server, err := parseAuthServerContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server.Name != "Corp AD" || server.Type != "ldap" {
		t.Fatalf("unexpected decode: %+v", server)
	}

	fields, err := server.helperFields()
	if err != nil {
		t.Fatalf("helperFields: %v", err)
	}
	if _, present := fields["name"]; present {
		t.Error("helperFields must never include \"name\"")
	}
	if _, present := fields["type"]; present {
		t.Error("helperFields must never include \"type\" -- the helper hardcodes it")
	}
	// Booleans must stay JSON booleans, not stringified -- the PHP helper
	// does (bool)$fields[$key] for these, and a bare "false" string is
	// truthy under that cast.
	if v, ok := fields["nd_allow_cleartext_ldap"].(bool); !ok || v != false {
		t.Errorf("nd_allow_cleartext_ldap = %#v, want JSON bool false", fields["nd_allow_cleartext_ldap"])
	}
	if v, ok := fields["ldap_sync_memberof"].(bool); !ok || v != true {
		t.Errorf("ldap_sync_memberof = %#v, want JSON bool true", fields["ldap_sync_memberof"])
	}
	if fields["ldap_bindpw"] != "s3cr3t" {
		t.Errorf("ldap_bindpw = %v, want the resolved secret passthrough", fields["ldap_bindpw"])
	}
}

func TestParseAuthOrderContent_UnrecognizedFacilityRejected(t *testing.T) {
	content := `{"facilities":{"openvpn":{"order":["Local Database"]}}}`
	if _, err := parseAuthOrderContent(content); err == nil {
		t.Fatal("expected an error for a facility outside the v1 allow-list, got nil")
	}
}

func TestParseAuthOrderContent_UnknownKeyInsideFacilityRejected(t *testing.T) {
	content := `{"facilities":{"webadmin":{"order":["Local Database"],"extra":true}}}`
	if _, err := parseAuthOrderContent(content); err == nil {
		t.Fatal("expected an error for an unrecognized key inside webadmin, got nil")
	}
}

// TestParseAuthOrderContent_TrailingDataRejected is a fail-closed
// regression: json.Decoder.Decode on its own silently accepts and ignores
// trailing data after a complete value, which is not the strict,
// fail-closed parsing AUTH content requires.
func TestParseAuthOrderContent_TrailingDataRejected(t *testing.T) {
	content := `{"facilities":{"webadmin":{"order":["Local Database"]}}} trailing-garbage`
	if _, err := parseAuthOrderContent(content); err == nil {
		t.Fatal("expected an error for trailing data after the JSON value, got nil")
	}
}

// TestParseAuthOrderContent_NullFacilityBodyRejected: a JSON `null`
// facility body decodes without error into the zero value (same
// observable shape as an omitted `order` key), which would otherwise
// silently produce an empty order and round-trip as `"order":null` to the
// helper.
func TestParseAuthOrderContent_NullFacilityBodyRejected(t *testing.T) {
	content := `{"facilities":{"webadmin":null}}`
	if _, err := parseAuthOrderContent(content); err == nil {
		t.Fatal("expected an error for a null facility body, got nil")
	}
}

// TestParseAuthOrderContent_NullOrderRejected mirrors the above for a
// present-but-null `order` key specifically.
func TestParseAuthOrderContent_NullOrderRejected(t *testing.T) {
	content := `{"facilities":{"webadmin":{"order":null}}}`
	if _, err := parseAuthOrderContent(content); err == nil {
		t.Fatal("expected an error for a null order, got nil")
	}
}

func TestParseAuthOrderContent_ValidWebadminAccepted(t *testing.T) {
	content := `{"facilities":{"webadmin":{"order":["Local Database","Corp AD"]}}}`
	facilities, err := parseAuthOrderContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	order, ok := facilities[authFacilityWebadmin]
	if !ok || len(order) != 2 || order[0] != "Local Database" || order[1] != "Corp AD" {
		t.Fatalf("facilities = %+v, want webadmin: [Local Database, Corp AD]", facilities)
	}
}

// -----------------------------------------------------------------
// parseAPIAuthContent / authFamilyShouldRun
// -----------------------------------------------------------------

func TestParseAPIAuthContent_NoSnippets(t *testing.T) {
	out := parseAPIAuthContent(map[string]interface{}{})
	if out.HasContent {
		t.Error("HasContent = true, want false for a payload with no snippets key")
	}
	if out.Err != nil {
		t.Errorf("Err = %v, want nil", out.Err)
	}
}

func TestParseAPIAuthContent_IgnoresOtherConfigTypes(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "GROUP", "content": `{"name":"eng"}`},
		},
	}
	out := parseAPIAuthContent(payload)
	if out.HasContent {
		t.Error("HasContent = true, want false when no AUTH_SERVER/AUTH_ORDER snippet is present")
	}
}

// TestParseAPIAuthContent_OneBadSnippetFailsTheWholeFamily is the revert
// guard for AUTH's deliberate departure from the "drop just the offending
// element" pattern every other family uses: a single unparseable
// AUTH_SERVER snippet must turn the WHOLE AUTH family into a no-op for
// this pass (Err set), not just skip that one element while applying a
// second, valid AUTH_SERVER snippet in the same payload.
func TestParseAPIAuthContent_OneBadSnippetFailsTheWholeFamily(t *testing.T) {
	goodContent := `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
	"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
	"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`
	badContent := `{"name":"Bad Server","type":"radius","host":"x"}`

	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "AUTH_SERVER", "content": goodContent},
			map[string]interface{}{"config_type": "AUTH_SERVER", "content": badContent},
		},
	}
	out := parseAPIAuthContent(payload)
	if !out.HasContent {
		t.Fatal("HasContent = false, want true")
	}
	if out.Err == nil {
		t.Fatal("Err = nil, want the bad snippet's parse error to be surfaced")
	}
	if len(out.Servers) != 1 {
		t.Fatalf("Servers = %d, want exactly the one good server parsed (the caller must ignore this partial result on Err != nil)", len(out.Servers))
	}
}

// TestParseAPIAuthContent_ConflictingFacilityDuplicateFailsClosed pins
// "two snippets that define the same facility for one device
// are a build conflict": NDManager's own build-time check
// (AUTH_ORDER_FACILITY_CONFLICT) is meant to catch this before dispatch,
// but Go must fail closed on its own if a conflict ever reaches it anyway,
// rather than silently taking an arbitrary last-wins order onto the
// device.
func TestParseAPIAuthContent_ConflictingFacilityDuplicateFailsClosed(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "AUTH_ORDER", "content": `{"facilities":{"webadmin":{"order":["Local Database","Corp AD"]}}}`},
			map[string]interface{}{"config_type": "AUTH_ORDER", "content": `{"facilities":{"webadmin":{"order":["Local Database","HQ-LDAP"]}}}`},
		},
	}
	out := parseAPIAuthContent(payload)
	if out.Err == nil {
		t.Fatal("Err = nil, want a conflicting duplicate facility definition to fail the whole family")
	}
}

// TestParseAPIAuthContent_IdenticalFacilityDuplicateDeduplicates covers the
// legitimate companion case: "the same snippet reached
// twice is deduplicated" -- two AUTH_ORDER snippets defining the SAME
// facility with the byte-identical order are not a conflict.
func TestParseAPIAuthContent_IdenticalFacilityDuplicateDeduplicates(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "AUTH_ORDER", "content": `{"facilities":{"webadmin":{"order":["Local Database","Corp AD"]}}}`},
			map[string]interface{}{"config_type": "AUTH_ORDER", "content": `{"facilities":{"webadmin":{"order":["Local Database","Corp AD"]}}}`},
		},
	}
	out := parseAPIAuthContent(payload)
	if out.Err != nil {
		t.Errorf("Err = %v, want nil for an identical duplicate (the same snippet reached twice)", out.Err)
	}
	if fmt.Sprint(out.Facilities["webadmin"]) != fmt.Sprint([]string{"Local Database", "Corp AD"}) {
		t.Errorf("Facilities[webadmin] = %v, want [Local Database Corp AD]", out.Facilities["webadmin"])
	}
}

func TestAuthFamilyShouldRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")

	// No file at all: fails CLOSED (assume markers exist) -- this gates a
	// live security decision (the reserved-name exclusion recompute and
	// the blanket-deferral trigger), not a diagnostic, so an unreadable
	// config.xml must not silently skip the family.
	if !authFamilyShouldRun(false, path) {
		t.Error("no content, unreadable config.xml: want true (fail closed)")
	}

	if err := os.WriteFile(path, []byte("<opnsense><system></system></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if authFamilyShouldRun(false, path) {
		t.Error("no content, no markers: want false")
	}
	if !authFamilyShouldRun(true, path) {
		t.Error("content present: want true regardless of markers")
	}

	if err := os.WriteFile(path, []byte("<opnsense><system><authserver><netdefense_owner>u</netdefense_owner></authserver></system></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !authFamilyShouldRun(false, path) {
		t.Error("no content but a live marker: want true")
	}
}

// -----------------------------------------------------------------
// authDeferralInfo / filterDeferredGroupMembers
// -----------------------------------------------------------------

func TestAuthDeferralInfo_IsDeferred(t *testing.T) {
	inactive := authDeferralInfo{}
	if inactive.isDeferred("anything") {
		t.Error("inactive deferral must never defer anything (zero value == no-op)")
	}

	blanket := authDeferralInfo{Active: true, Blanket: true}
	if !blanket.isDeferred("anyone") {
		t.Error("blanket deferral must defer every name")
	}

	scoped := authDeferralInfo{Active: true, StaleNames: map[string]bool{"corp-admins": true}}
	if !scoped.isDeferred("Corp-Admins") {
		t.Error("stale-name matching must be case-insensitive")
	}
	if scoped.isDeferred("someone-else") {
		t.Error("a name not in StaleNames must not be deferred")
	}
}

func TestFilterDeferredGroupMembers(t *testing.T) {
	auth := authDeferralInfo{Active: true, StaleNames: map[string]bool{"root": true, "newbadmin": true}}
	live := map[string]bool{"root": true} // root was ALREADY a member before this sync

	payload := opnapi.APIGroupPayload{
		Name:    "eng",
		Members: []string{"root", "newbadmin", "alice"},
	}
	kept, deferred := filterDeferredGroupMembers(payload, live, auth)

	// root is stale-named but already live -- never withheld.
	// newbadmin is stale AND new -- withheld.
	// alice is new but not stale -- kept.
	wantKept := []string{"root", "alice"}
	wantDeferred := []string{"newbadmin"}
	if strings.Join(kept, ",") != strings.Join(wantKept, ",") {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if strings.Join(deferred, ",") != strings.Join(wantDeferred, ",") {
		t.Errorf("deferred = %v, want %v", deferred, wantDeferred)
	}
}

// -----------------------------------------------------------------
// runAuthServersHelperFunc indirection / executeSyncAuth
// -----------------------------------------------------------------

// withFakeAuthHelper swaps runAuthServersHelperFunc for the duration of
// the test and restores it afterward -- every test using this must run
// serially (no t.Parallel()), since the swap is a package-level var.
func withFakeAuthHelper(t *testing.T, fn func(requestJSON []byte) ([]byte, int, error)) {
	t.Helper()
	orig := runAuthServersHelperFunc
	runAuthServersHelperFunc = fn
	t.Cleanup(func() { runAuthServersHelperFunc = orig })
}

func TestExecuteSyncAuth_NoContentNoMarkers_NoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) {
		called = true
		return nil, 0, nil
	})

	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, authParseOutcome{}, nil, nil)
	if !out.Result.Success {
		t.Errorf("expected success, got errors: %v", out.Result.Errors)
	}
	if out.Deferral.Active {
		t.Error("no content, no markers: deferral must not be active")
	}
	if called {
		t.Error("the helper must never be invoked when the family does not run")
	}
}

func TestExecuteSyncAuth_ParseFailure_BlanketDeferWhenMarkersExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense><system><authserver><netdefense_owner>device-1</netdefense_owner></authserver></system></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) {
		called = true
		return nil, 0, nil
	})

	parsed := authParseOutcome{HasContent: true, Err: errors.New("unrecognized auth server type")}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a parse failure must fail the AUTH family (task FAILS)")
	}
	if len(out.Result.Errors) != 1 || !strings.Contains(out.Result.Errors[0], "AUTH_CONTENT_UNSUPPORTED") {
		t.Errorf("errors = %v, want one naming AUTH_CONTENT_UNSUPPORTED", out.Result.Errors)
	}
	if !out.Deferral.Active || !out.Deferral.Blanket {
		t.Errorf("deferral = %+v, want Active+Blanket (markers exist, AUTH did not complete)", out.Deferral)
	}
	if called {
		t.Error("the helper must never be invoked when Go's own strict parse already failed")
	}
}

func TestExecuteSyncAuth_ParseFailure_NoDeferWhenNoMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return nil, 0, nil })

	parsed := authParseOutcome{HasContent: true, Err: errors.New("bad")}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a parse failure must still fail the AUTH family regardless of markers")
	}
	if out.Deferral.Blanket {
		t.Error("no managed markers exist yet -- there is nothing to shadow, so blanket deferral must not fire")
	}
}

func TestExecuteSyncAuth_HelperFault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense><system><authserver><netdefense_owner>device-1</netdefense_owner></authserver></system></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) {
		return nil, -1, errors.New("exec: \"php\": executable file not found in $PATH")
	})

	parsed := authParseOutcome{HasContent: true}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a helper exec fault must fail the AUTH family")
	}
	if !out.Deferral.Blanket {
		t.Error("a helper fault with markers present must blanket-defer")
	}
}

func TestExecuteSyncAuth_HelperProtocolFault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	faultBody, _ := json.Marshal(map[string]interface{}{
		"contract": 1,
		"error":    map[string]string{"code": "AUTH_LOCK_TIMEOUT"},
	})
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return faultBody, 2, nil })

	parsed := authParseOutcome{HasContent: true}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a non-zero exit must fail the AUTH family")
	}
	if len(out.Result.Errors) != 1 || !strings.Contains(out.Result.Errors[0], "AUTH_LOCK_TIMEOUT") {
		t.Errorf("errors = %v, want the helper's own fault code surfaced", out.Result.Errors)
	}
}

// TestExecuteSyncAuth_HelperConsumerScanFailedFault pins CONSUMER_SCAN_FAILED
// (added in PR #90's round-1/2 passes: "a failure of the curated scan
// fails the family with CONSUMER_SCAN_FAILED") specifically, rather than
// relying only on the generic AUTH_LOCK_TIMEOUT case above to exercise this
// code path. Go has no fixed allow-list of helper fault codes — any code the
// helper's top-level catch reports (auth_servers.php's own KNOWN_FAULT_CODES)
// must surface verbatim, and this is the one this family's sync-mode
// consumer pre-flight can actually produce on its own.
func TestExecuteSyncAuth_HelperConsumerScanFailedFault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}
	faultBody, _ := json.Marshal(map[string]interface{}{
		"contract": 1,
		"error":    map[string]string{"code": "CONSUMER_SCAN_FAILED"},
	})
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return faultBody, 2, nil })

	parsed := authParseOutcome{HasContent: true}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a CONSUMER_SCAN_FAILED protocol fault must fail the AUTH family")
	}
	if len(out.Result.Errors) != 1 || !strings.Contains(out.Result.Errors[0], "CONSUMER_SCAN_FAILED") {
		t.Errorf("errors = %v, want CONSUMER_SCAN_FAILED surfaced verbatim", out.Result.Errors)
	}
}

// TestExecuteSyncAuth_HelperResponseMissingRequestedServerFaults is the
// coverage half of validateAuthHelperResponse: an exit-0 response that
// simply omits a result for a server this pass actually requested (a
// truncated response, or a helper bug) must never be silently mapped as
// success for the servers that DID come back -- it must fault the whole
// family instead.
func TestExecuteSyncAuth_HelperResponseMissingRequestedServerFaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	// Response covers zero of the one requested server.
	resp := authHelperSyncResponse{Contract: 1}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	parsed := authParseOutcome{
		HasContent: true,
		Servers: []authServerContent{
			mustParseAuthServer(t, `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
			"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
			"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`),
		},
	}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)
	if out.Result.Success {
		t.Error("expected failure: the response has no result for the one requested server")
	}
}

// TestExecuteSyncAuth_HelperResponseWrongContractFaults covers the other
// validateAuthHelperResponse check: a contract-version mismatch on an
// exit-0 response must fault, not be silently trusted.
func TestExecuteSyncAuth_HelperResponseWrongContractFaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	resp := authHelperSyncResponse{Contract: 99}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	parsed := authParseOutcome{HasContent: true}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)
	if out.Result.Success {
		t.Error("expected failure: the response's contract version does not match")
	}
}

// TestExecuteSyncAuth_HelperResponseTopLevelErrorFaults: an exit-0
// response that ALSO carries a populated top-level `error` must fault
// rather than be mapped as a normal success/mixed result.
func TestExecuteSyncAuth_HelperResponseTopLevelErrorFaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	resp := authHelperSyncResponse{Contract: 1, Error: &authHelperErrorBody{Code: "AUTH_UNEXPECTED"}}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	parsed := authParseOutcome{HasContent: true}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)
	if out.Result.Success {
		t.Error("expected failure: the response carries a populated top-level error on a 'handled' exit")
	}
}

// TestExecuteSyncAuth_MissingExclusionCodeFaultsAndDoesNotFailOpen is the
// major-finding regression: a "handled" (exit 0) response that omits
// exclusion.code (the zero value, indistinguishable on the wire from an
// explicit "no stale names") must never be silently trusted. Before the
// fix, mapAuthResponseToResult/authDeferralInfo read a nil StaleNames as
// "nothing is stale" and the stale-exclusion deferral quietly turned itself off, on a
// device that already carries managed markers -- exactly the fail-OPEN
// this validation function otherwise refuses for every other
// missing/malformed field.
func TestExecuteSyncAuth_MissingExclusionCodeFaultsAndDoesNotFailOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense><system><authserver><netdefense_owner>device-1</netdefense_owner></authserver></system></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}

	// exclusion is entirely omitted -- decodes to the zero value, Code=="".
	resp := authHelperSyncResponse{
		Contract: 1,
		Servers: []authHelperServerResult{
			{Name: "Corp AD", Action: "created", Code: "OK"},
		},
	}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	parsed := authParseOutcome{
		HasContent: true,
		Servers: []authServerContent{
			mustParseAuthServer(t, `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
			"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
			"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`),
		},
	}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Error("a response missing exclusion.code must fault the family, not be trusted as success")
	}
	// Markers exist on the device (netdefense_owner above), so the fault
	// must blanket-defer -- the fail-open bug would instead have reported
	// Deferral.Active but with an empty StaleNames map, deferring nothing.
	if !out.Deferral.Blanket {
		t.Errorf("deferral = %+v, want Blanket (no exclusion data to trust)", out.Deferral)
	}
}

func TestExecuteSyncAuth_SuccessMapsResultsAndStaleNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := authHelperSyncResponse{
		Contract: 1,
		Release:  "26.7",
		Servers: []authHelperServerResult{
			{Name: "Corp AD", Action: "created", Code: "OK"},
			{Name: "Collides", Action: "blocked", Code: "NAME_COLLISION_UNMANAGED"},
		},
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {Action: "written", Code: "OK"},
		},
		Exclusion:     authHelperExclusion{StaleNames: []string{"NewAdmin"}, Code: "AUTH_EXCLUSION_STALE"},
		ConfigWritten: true,
	}
	respJSON, _ := json.Marshal(resp)

	var capturedRequest authHelperRequest
	withFakeAuthHelper(t, func(requestJSON []byte) ([]byte, int, error) {
		if err := json.Unmarshal(requestJSON, &capturedRequest); err != nil {
			t.Fatalf("could not decode the request this test itself built: %v", err)
		}
		return respJSON, 0, nil
	})

	parsed := authParseOutcome{
		HasContent: true,
		Servers: []authServerContent{
			mustParseAuthServer(t, `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
			"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
			"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`),
		},
		Facilities: map[string][]string{"webadmin": {"Local Database"}},
	}
	users := []opnapi.APIUserPayload{{Name: "svc-monitor"}}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-42", true, path, parsed, users, nil)

	if capturedRequest.Contract != authHelperContractVersion || capturedRequest.Mode != "sync" {
		t.Errorf("request = %+v, want contract=%d mode=sync", capturedRequest, authHelperContractVersion)
	}
	if capturedRequest.DeviceUUID != "device-1" || capturedRequest.TaskID != "task-42" {
		t.Errorf("request identity fields = %+v", capturedRequest)
	}
	if !capturedRequest.RejectDangerous {
		t.Error("reject_dangerous was not threaded through to the request")
	}
	if len(capturedRequest.Servers) != 1 || capturedRequest.Servers[0].Name != "Corp AD" {
		t.Errorf("request.Servers = %+v", capturedRequest.Servers)
	}
	if _, present := capturedRequest.Servers[0].Fields["name"]; present {
		t.Error("request fields must never carry \"name\"")
	}
	found := false
	for _, n := range capturedRequest.ReservedNamesDesired {
		if n == "svc-monitor" {
			found = true
		}
	}
	if !found {
		t.Errorf("reserved_names_desired = %v, want it to include the desired USER svc-monitor", capturedRequest.ReservedNamesDesired)
	}

	if out.Result.Success {
		t.Error("a blocked server result must fail the task")
	}
	var sawCreated, sawBlocked, sawFacility bool
	for _, r := range out.Result.Results {
		switch {
		case r.Type == "auth_server" && r.Name == "Corp AD" && r.Status == "success":
			sawCreated = true
		case r.Type == "auth_server" && r.Name == "Collides" && r.Status == "blocked":
			sawBlocked = true
		case r.Type == "auth_facility" && r.Name == "webadmin" && r.Status == "success":
			sawFacility = true
		}
	}
	if !sawCreated || !sawBlocked || !sawFacility {
		t.Errorf("results = %+v, missing an expected mapped item", out.Result.Results)
	}

	if !out.Deferral.Active || out.Deferral.Blanket {
		t.Errorf("deferral = %+v, want Active (normal case), not Blanket", out.Deferral)
	}
	if !out.Deferral.isDeferred("newadmin") {
		t.Error("stale_names from the response must be consulted case-insensitively by the deferral")
	}
}

// TestMapAuthResponseToResult_EnrichesBlockedMessages is the major-finding
// regression: a blocked outcome's message must name the detail required
// (consumers, the reject-gate opt-out, the sub-code, the version floor)
// instead of a bare "auth server X: CODE", and
// local-server risks / shadowable-user warnings must reach the task
// response as named result items, not just a log line.
func TestMapAuthResponseToResult_EnrichesBlockedMessages(t *testing.T) {
	resp := authHelperSyncResponse{
		Contract: 1,
		Release:  "26.1.5",
		Servers: []authHelperServerResult{
			{Name: "Corp AD", Action: "blocked", Code: "AUTH_REJECTED_DANGEROUS"},
			{Name: "Legacy AD", Action: "blocked", Code: "CONSUMER_REFERENCED", Consumers: []string{"OpenVPN/instance1/authmode"}},
		},
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {
				Action:     "refused",
				Code:       "AUTH_ORDER_UNRESOLVED",
				Before:     []string{"Local Database"},
				Unresolved: []string{"Typo AD"},
				Available:  []string{"Corp AD", "Local Database", "hand-made-ldap"},
				LocalServers: []authHelperLocalServer{
					{Name: "hand-made-ldap", Risks: []string{"cleartext"}},
				},
			},
		},
		Warnings: []authHelperWarning{{Code: "PRIVILEGED_LOCAL_USERS_SHADOWABLE", Count: 2}},
	}

	result := mapAuthResponseToResult(resp, true)
	if result.Success {
		t.Fatal("expected failure with two blocked servers and a refused facility")
	}

	var authRejected, consumerRef, unresolved bool
	for _, e := range result.Errors {
		if strings.Contains(e, "Corp AD") && strings.Contains(e, "reject_dangerous_snippets=false") {
			authRejected = true
		}
		if strings.Contains(e, "Legacy AD") && strings.Contains(e, "OpenVPN/instance1/authmode") {
			consumerRef = true
		}
		if strings.Contains(e, "webadmin") && strings.Contains(e, "Typo AD") && strings.Contains(e, "Local Database") &&
			strings.Contains(e, "hand-made-ldap") {
			unresolved = true
		}
	}
	if !authRejected {
		t.Errorf("errors = %v, want one naming Corp AD and the reject_dangerous_snippets opt-out", result.Errors)
	}
	if !consumerRef {
		t.Errorf("errors = %v, want one naming Legacy AD and its consumer XPath", result.Errors)
	}
	if !unresolved {
		t.Errorf("errors = %v, want one naming the unresolved entry, the helper's reported resolution set (available), and the kept order", result.Errors)
	}

	var sawLocalServerWarning, sawShadowableWarning bool
	for _, r := range result.Results {
		if r.Type == "auth_local_server" && r.Name == "hand-made-ldap" && r.Status == "warning" && strings.Contains(r.Error, "cleartext") {
			sawLocalServerWarning = true
		}
		if r.Type == "auth_warning" && r.Name == "PRIVILEGED_LOCAL_USERS_SHADOWABLE" && r.Status == "warning" {
			sawShadowableWarning = true
		}
	}
	if !sawLocalServerWarning {
		t.Errorf("results = %+v, want a warning item for the hand-made local server naming its risks", result.Results)
	}
	if !sawShadowableWarning {
		t.Errorf("results = %+v, want a warning item for PRIVILEGED_LOCAL_USERS_SHADOWABLE", result.Results)
	}
	// Neither warning item may count toward failure -- only the two
	// blocked servers and the refused facility should.
	if len(result.Errors) != 3 {
		t.Errorf("errors = %v, want exactly 3 (warnings must never be counted)", result.Errors)
	}
}

// TestMapAuthResponseToResult_LocalServerRisksPopulateStructuredField pins
// the ORDER_NAMES_LOCAL_SERVER risk list against SyncAPIItemResult.Risks
// -- a consumer must never have to rfind() "; risks: " out of Error to
// learn what is wrong with a hand-made server named in a written order.
func TestMapAuthResponseToResult_LocalServerRisksPopulateStructuredField(t *testing.T) {
	resp := authHelperSyncResponse{
		Contract: 1,
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {
				Action: "written",
				Code:   "OK",
				LocalServers: []authHelperLocalServer{
					{Name: "hand-made-ldap", Risks: []string{"cleartext", "unscoped_sync"}},
				},
			},
		},
	}
	result := mapAuthResponseToResult(resp, false)

	var found bool
	for _, r := range result.Results {
		if r.Type != "auth_local_server" || r.Name != "hand-made-ldap" {
			continue
		}
		found = true
		if fmt.Sprint(r.Risks) != fmt.Sprint([]string{"cleartext", "unscoped_sync"}) {
			t.Errorf("Risks = %v, want [cleartext unscoped_sync]", r.Risks)
		}
	}
	if !found {
		t.Fatal("results missing the auth_local_server item for hand-made-ldap")
	}
}

// TestAuthFacilityBlockedMessage_AvailableAndBeforeAreDistinctFacts pins
// the round-3 `available` wire field against `Before`: `Before`
// is the facility's kept, unchanged order value, while `Available` is the
// resolution set an unresolved entry was checked against ("the server
// names that do exist") -- the two are never the same list here on
// purpose, so a regression that conflates them (e.g. dropping one field's
// rendering, or swapping which slice feeds which phrase) is caught.
func TestAuthFacilityBlockedMessage_AvailableAndBeforeAreDistinctFacts(t *testing.T) {
	f := authHelperFacilityResult{
		Action:     "refused",
		Code:       "AUTH_ORDER_UNRESOLVED",
		Before:     []string{"Local Database", "Corp AD"},
		Unresolved: []string{"Typo AD"},
		Available:  []string{"Local Database", "Corp AD", "hand-made-ldap"},
	}
	msg := authFacilityBlockedMessage("webadmin", f, "26.7")

	if !strings.Contains(msg, "Typo AD") {
		t.Errorf("message = %q, want the unresolved entry named", msg)
	}
	if !strings.Contains(msg, "server names that do exist") || !strings.Contains(msg, "hand-made-ldap") {
		t.Errorf("message = %q, want the available/resolution set named, including the hand-made server", msg)
	}
	if !strings.Contains(msg, "kept its current order") {
		t.Errorf("message = %q, want the kept order named separately from the resolution set", msg)
	}
}

// TestAuthFacilityBlockedMessage_OmittedAvailableIsSkipped guards the
// backward-compat case: an older helper predating PR #90's round-3 pass
// never sends `available` at all, which decodes to a nil slice. The
// message must degrade gracefully (no "server names that do exist:"
// clause with nothing after it) rather than panic or render an empty list.
func TestAuthFacilityBlockedMessage_OmittedAvailableIsSkipped(t *testing.T) {
	f := authHelperFacilityResult{
		Action:     "refused",
		Code:       "AUTH_ORDER_UNRESOLVED",
		Before:     []string{"Local Database"},
		Unresolved: []string{"Typo AD"},
	}
	msg := authFacilityBlockedMessage("webadmin", f, "26.7")
	if strings.Contains(msg, "server names that do exist") {
		t.Errorf("message = %q, want no resolution-set clause when the helper omitted `available`", msg)
	}
}

// TestAuthFacilityBlockedMessage_RejectedDangerousGetsOptOut pins the
// facility-level mirror of authServerBlockedMessage's own
// AUTH_REJECTED_DANGEROUS wording: a refused facility write under the
// gate must also tell the operator how to opt out, not just name the
// bare code (the reject_dangerous_snippets=false SYNC recovery push
// needs this instruction to be actionable).
func TestAuthFacilityBlockedMessage_RejectedDangerousGetsOptOut(t *testing.T) {
	f := authHelperFacilityResult{Action: "refused", Code: "AUTH_REJECTED_DANGEROUS"}
	msg := authFacilityBlockedMessage("webadmin", f, "26.7")
	if !strings.Contains(msg, "reject_dangerous_snippets=false") {
		t.Errorf("message = %q, want the reject_dangerous_snippets opt-out named", msg)
	}
}

// TestAuthFacilityBlockedMessage_InvalidCodesGetDetail is the facility
// equivalent of TestAuthServerBlockedMessage_InvalidSubcodesGetDetail: a
// table over every authFacilityInvalidDetail code, each of which the
// switch in authFacilityBlockedMessage does not otherwise special-case
// (unresolved entries/available/before/the floor/the gate).
func TestAuthFacilityBlockedMessage_InvalidCodesGetDetail(t *testing.T) {
	for code, detail := range authFacilityInvalidDetail {
		t.Run(code, func(t *testing.T) {
			f := authHelperFacilityResult{Action: "refused", Code: code}
			msg := authFacilityBlockedMessage("webadmin", f, "26.7")
			if !strings.Contains(msg, code) {
				t.Errorf("message = %q, want the bare code named", msg)
			}
			if !strings.Contains(msg, detail) {
				t.Errorf("message = %q, want the detail clause %q", msg, detail)
			}
		})
	}
}

// TestSyncAPIItemResult_AuthJSONShape pins the wire shape of the four
// additive fields (Code/Before/After/Available): present with their exact
// documented key names when set, and entirely ABSENT from the marshaled
// JSON (not merely null/empty) when unset -- the "omitempty" half of the
// additive-fields contract, so a non-AUTH item or an older consumer sees
// no shape change.
func TestSyncAPIItemResult_AuthJSONShape(t *testing.T) {
	full := SyncAPIItemResult{
		Type: "auth_facility", Name: "webadmin", Action: "refused", Status: "blocked",
		Code: "AUTH_ORDER_UNRESOLVED", Error: "auth order \"webadmin\": AUTH_ORDER_UNRESOLVED",
		Before: []string{"Local Database"}, After: []string{"Local Database", "Corp AD"},
		Available: []string{"Local Database", "Corp AD"},
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, key := range []string{"code", "before", "after", "available"} {
		if _, ok := m[key]; !ok {
			t.Errorf("marshaled JSON %s is missing key %q, want it present when the field is set", b, key)
		}
	}

	empty := SyncAPIItemResult{Type: "auth_server", Name: "Corp AD", Action: "created", Status: "success"}
	b2, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var m2 map[string]interface{}
	if err := json.Unmarshal(b2, &m2); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, key := range []string{"code", "before", "after", "available", "error"} {
		if _, ok := m2[key]; ok {
			t.Errorf("marshaled JSON %s has key %q, want it omitted (omitempty) when the field is unset", b2, key)
		}
	}
}

// TestMapAuthResponseToResult_PopulatesCodeOnEveryItem pins that every AUTH
// result item -- the auth_server item, the auth_facility item, the
// auth_local_server warning and the generic auth_warning -- carries a
// structured Code a consumer can key on, not just a free-text Error a
// caller would have to parse.
func TestMapAuthResponseToResult_PopulatesCodeOnEveryItem(t *testing.T) {
	resp := authHelperSyncResponse{
		Contract: 1,
		Release:  "26.7",
		Servers: []authHelperServerResult{
			{Name: "Corp AD", Action: "created", Code: "OK"},
			{Name: "Collides", Action: "blocked", Code: "NAME_COLLISION_UNMANAGED"},
		},
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {
				Action:     "refused",
				Code:       "AUTH_ORDER_UNRESOLVED",
				Before:     []string{"Local Database"},
				Unresolved: []string{"Typo AD"},
				LocalServers: []authHelperLocalServer{
					{Name: "hand-made-ldap", Risks: []string{"cleartext"}},
				},
			},
		},
		Warnings: []authHelperWarning{{Code: "PRIVILEGED_LOCAL_USERS_SHADOWABLE", Count: 2}},
	}

	result := mapAuthResponseToResult(resp, false)

	wantCode := map[string]string{
		"auth_server:Corp AD":                            "OK",
		"auth_server:Collides":                           "NAME_COLLISION_UNMANAGED",
		"auth_facility:webadmin":                         "AUTH_ORDER_UNRESOLVED",
		"auth_local_server:hand-made-ldap":               "ORDER_NAMES_LOCAL_SERVER",
		"auth_warning:PRIVILEGED_LOCAL_USERS_SHADOWABLE": "PRIVILEGED_LOCAL_USERS_SHADOWABLE",
	}
	seen := map[string]bool{}
	for _, r := range result.Results {
		key := r.Type + ":" + r.Name
		if want, ok := wantCode[key]; ok {
			seen[key] = true
			if r.Code != want {
				t.Errorf("result %s: Code = %q, want %q", key, r.Code, want)
			}
		}
	}
	for key := range wantCode {
		if !seen[key] {
			t.Errorf("results = %+v, missing expected item %s", result.Results, key)
		}
	}
}

// TestMapAuthResponseToResult_FacilityBeforeAfterAlwaysSet_AvailableOnlyOnRefusal
// pins "Result: before, after and action ... plus available (the
// resolution set) on refusals" literally: Before/After travel on the
// auth_facility item whether the outcome is a clean write/unchanged or a
// refusal, but Available is populated ONLY on a refusal, never on success
// -- so a caller cannot mistake a clean outcome that merely happens to
// resolve everything for a refusal.
func TestMapAuthResponseToResult_FacilityBeforeAfterAlwaysSet_AvailableOnlyOnRefusal(t *testing.T) {
	resp := authHelperSyncResponse{
		Contract: 1,
		Release:  "26.7",
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {
				Action:    "written",
				Code:      "OK",
				Before:    []string{"Local Database"},
				After:     []string{"Local Database", "Corp AD"},
				Available: []string{"Local Database", "Corp AD"}, // must be dropped on success
			},
		},
	}
	result := mapAuthResponseToResult(resp, false)
	if len(result.Results) != 1 {
		t.Fatalf("results = %+v, want exactly one auth_facility item", result.Results)
	}
	item := result.Results[0]
	if item.Status != "success" {
		t.Fatalf("item.Status = %q, want success", item.Status)
	}
	if len(item.Before) != 1 || item.Before[0] != "Local Database" {
		t.Errorf("item.Before = %v, want [\"Local Database\"] even on success", item.Before)
	}
	if len(item.After) != 2 || item.After[1] != "Corp AD" {
		t.Errorf("item.After = %v, want the written order even on success", item.After)
	}
	if len(item.Available) != 0 {
		t.Errorf("item.Available = %v, want empty on a successful (non-refused) facility write", item.Available)
	}

	respRefused := authHelperSyncResponse{
		Contract: 1,
		Facilities: map[string]authHelperFacilityResult{
			"webadmin": {
				Action:     "refused",
				Code:       "AUTH_ORDER_UNRESOLVED",
				Before:     []string{"Local Database"},
				Unresolved: []string{"Typo AD"},
				Available:  []string{"Local Database", "Corp AD"},
			},
		},
	}
	refusedResult := mapAuthResponseToResult(respRefused, false)
	refusedItem := refusedResult.Results[0]
	if refusedItem.Status != "blocked" {
		t.Fatalf("refusedItem.Status = %q, want blocked", refusedItem.Status)
	}
	if len(refusedItem.Available) != 2 {
		t.Errorf("refusedItem.Available = %v, want the resolution set populated on a refusal", refusedItem.Available)
	}
}

// TestAuthServerBlockedMessage_ConsumerReferencedWebadminRemedy pins the
// qualified remedy for removing a server from login: when the webadmin
// facility itself is one of the CONSUMER_REFERENCED consumers, the message
// must say to remove the server from the login order first (an AUTH_ORDER
// policy without it, OR a change made directly on the device — the
// hand-edited-order case has no policy to rewrite), not merely list the
// consumer. When reject_dangerous_snippets is on, NetDefense cannot rewrite
// that order itself, so the message must also point at CONNECT (at
// remote_access_policy=full) or a local edit — omitted when the gate is
// off, since NetDefense CAN rewrite the order in that case. An ordinary
// curated consumer (an OpenVPN instance's authmode, an XPath-ish label,
// never the bare facility name) must NOT trigger any of this.
func TestAuthServerBlockedMessage_ConsumerReferencedWebadminRemedy(t *testing.T) {
	withWebadmin := authHelperServerResult{
		Name: "Corp AD", Action: "retained", Code: "CONSUMER_REFERENCED",
		Consumers: []string{"webadmin"},
	}
	msg := authServerBlockedMessage(withWebadmin, "26.7", false)
	if !strings.Contains(msg, "webadmin") || !strings.Contains(msg, "remove this server from the") {
		t.Errorf("message = %q, want the webadmin-specific remove-from-order remedy", msg)
	}
	if strings.Contains(msg, "CONNECT") {
		t.Errorf("message = %q, want no CONNECT/local-edit qualifier when reject_dangerous_snippets is off", msg)
	}

	msgGated := authServerBlockedMessage(withWebadmin, "26.7", true)
	if !strings.Contains(msgGated, "CONNECT") || !strings.Contains(msgGated, "remote_access_policy=full") {
		t.Errorf("message = %q, want the CONNECT/local-edit qualifier when reject_dangerous_snippets is on", msgGated)
	}

	withoutWebadmin := authHelperServerResult{
		Name: "Legacy AD", Action: "retained", Code: "CONSUMER_REFERENCED",
		Consumers: []string{"OPNsense/OpenVPN/Instances/Instance[0]/authmode"},
	}
	msg2 := authServerBlockedMessage(withoutWebadmin, "26.7", true)
	if strings.Contains(msg2, "remove this server from the") || strings.Contains(msg2, "CONNECT") {
		t.Errorf("message = %q, want no webadmin-specific remedy when webadmin is not among the consumers", msg2)
	}
	if !strings.Contains(msg2, "OPNsense/OpenVPN/Instances/Instance[0]/authmode") {
		t.Errorf("message = %q, want the XPath-ish consumer label named", msg2)
	}
}

// TestAuthServerBlockedMessage_CreateActivatesLoginPathNamesConsumers pins
// the dangling-token create check's CREATE_ACTIVATES_LOGIN_PATH message: the blocking login-order
// entries now travel structurally in Consumers (PR #90 round 5), and Go
// must render them by name instead of leaving the operator to go read the
// device log for the helper's own "warnings" free text.
func TestAuthServerBlockedMessage_CreateActivatesLoginPathNamesConsumers(t *testing.T) {
	s := authHelperServerResult{
		Name: "Ghost", Action: "rejected", Code: "CREATE_ACTIVATES_LOGIN_PATH",
		Consumers: []string{"webadmin"},
	}
	msg := authServerBlockedMessage(s, "26.7", false)
	if !strings.Contains(msg, "webadmin") {
		t.Errorf("message = %q, want the blocking consumer named", msg)
	}
}

// TestAuthServerBlockedMessage_InvalidSubcodesGetDetail is a table test
// over every AuthServerAlgo::AUTH_SERVER_INVALID_* sub-code (PR #90 round
// 4) plus the pre-round-4 generic fallback: each must render its own
// human-readable detail clause (authServerInvalidSubcodeDetail), and an
// unrecognized code must degrade to just the bare code with no detail
// clause appended (rather than panicking on a missing map entry).
func TestAuthServerBlockedMessage_InvalidSubcodesGetDetail(t *testing.T) {
	for code, detail := range authServerInvalidSubcodeDetail {
		t.Run(code, func(t *testing.T) {
			msg := authServerBlockedMessage(authHelperServerResult{Name: "Corp AD", Action: "blocked", Code: code}, "26.7", false)
			if !strings.Contains(msg, code) {
				t.Errorf("message = %q, want the bare code named", msg)
			}
			if !strings.Contains(msg, detail) {
				t.Errorf("message = %q, want the detail clause %q", msg, detail)
			}
		})
	}

	msg := authServerBlockedMessage(authHelperServerResult{Name: "Corp AD", Action: "blocked", Code: "SOME_FUTURE_CODE"}, "26.7", false)
	if !strings.Contains(msg, "SOME_FUTURE_CODE") {
		t.Errorf("message = %q, want the bare unrecognized code still named", msg)
	}
	for _, detail := range authServerInvalidSubcodeDetail {
		if strings.Contains(msg, detail) {
			t.Errorf("message = %q, want no detail clause from the sub-code table for an unrecognized code", msg)
		}
	}
}

// TestExecuteSyncAuth_FaultItemCarriesCode pins the family-level "auth"
// result item's Code -- the same code that prefixes its Error string --
// so a caller can key on Code even for a whole-family fault (a strict-
// parse failure, a helper fault, etc.), not only for a per-server or
// per-facility outcome.
func TestExecuteSyncAuth_FaultItemCarriesCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600); err != nil {
		t.Fatal(err)
	}

	parsed := authParseOutcome{HasContent: true, Err: fmt.Errorf("some parse error")}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	if out.Result.Success {
		t.Fatal("a parse failure must fail the family")
	}
	if len(out.Result.Results) != 1 {
		t.Fatalf("results = %+v, want exactly one family-level item", out.Result.Results)
	}
	if out.Result.Results[0].Code != "AUTH_CONTENT_UNSUPPORTED" {
		t.Errorf("item.Code = %q, want AUTH_CONTENT_UNSUPPORTED", out.Result.Results[0].Code)
	}
	if out.Result.Results[0].Type != "auth" {
		t.Errorf("item.Type = %q, want \"auth\"", out.Result.Results[0].Type)
	}
}

// TestExecuteSyncAuth_NoSecretInResultsOrErrors is the revert guard for
// "Go never embeds helper output in errors": a
// resolved ldap_bindpw must never appear anywhere in the mapped
// SyncAPIResult, which is exactly what reaches the task response an
// operator or an org:ro caller can read back.
func TestExecuteSyncAuth_NoSecretInResultsOrErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	const canary = "CANARY-SECRET-VALUE-zzz9"
	resp := authHelperSyncResponse{
		Contract: 1,
		Servers: []authHelperServerResult{
			{Name: "Corp AD", Action: "blocked", Code: "AUTH_REJECTED_DANGEROUS"},
		},
		Exclusion: authHelperExclusion{Code: "OK"},
	}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	parsed := authParseOutcome{
		HasContent: true,
		Servers: []authServerContent{
			mustParseAuthServer(t, `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
			"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
			"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName","ldap_binddn":"cn=svc",
			"ldap_bindpw":"`+canary+`"}`),
		},
	}
	out := executeSyncAuth(context.Background(), nil, "device-1", "task-1", true, path, parsed, nil, nil)

	dump, _ := json.Marshal(out.Result)
	if strings.Contains(string(dump), canary) {
		t.Fatalf("the canary secret leaked into the mapped SyncAPIResult: %s", dump)
	}
}

func mustParseAuthServer(t *testing.T, content string) authServerContent {
	t.Helper()
	s, err := parseAuthServerContent(content)
	if err != nil {
		t.Fatalf("parseAuthServerContent: %v", err)
	}
	return s
}

// -----------------------------------------------------------------
// computeReservedNamesDesired
// -----------------------------------------------------------------

func TestComputeReservedNamesDesired_NilClient(t *testing.T) {
	users := []opnapi.APIUserPayload{{Name: "svc-monitor"}}
	groups := []opnapi.APIGroupPayload{
		{Name: "eng", Members: []string{"alice"}},
		{Name: "eng-external", Members: nil, ExternalMembers: true},
	}
	got, complete := computeReservedNamesDesired(context.Background(), nil, users, groups)
	if !complete {
		t.Fatal("a nil client (test isolation seam) must report complete==true, not force the caller to refuse to start the helper")
	}
	want := map[string]bool{"svc-monitor": true, "alice": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected name %q in reserved set", n)
		}
	}
}

func TestComputeReservedNamesDesired_MergesLiveManaged(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "u1", "name": "live-managed-user", "descr": "svc [nd-template:base]", "uid": "2001"},
			},
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "g1", "name": "live-managed-group", "description": "svc [nd-template:base]", "gid": "3001", "member": "2001"},
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	got, complete := computeReservedNamesDesired(context.Background(), client, nil, nil)
	if !complete {
		t.Fatal("a successful live listing must report complete==true")
	}
	found := false
	for _, n := range got {
		if n == "live-managed-user" {
			found = true
		}
	}
	if !found {
		t.Errorf("got %v, want it to include the live managed user (from FilterManagedUsers)", got)
	}
}

// TestComputeReservedNamesDesired_IncompleteOnLiveUserListFailure is the
// major-finding regression: a real client whose live-user listing fails
// must report complete==false so the caller refuses to launch the helper
// against a possibly-partial exclusion, rather than silently continuing
// with the payload-only subset.
func TestComputeReservedNamesDesired_IncompleteOnLiveUserListFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	_, complete := computeReservedNamesDesired(context.Background(), client, nil, nil)
	if complete {
		t.Fatal("expected complete==false when the live user listing fails")
	}
}

// TestComputeReservedNamesDesired_IncompleteOnLiveGroupListFailure mirrors
// the above for the group-listing call.
func TestComputeReservedNamesDesired_IncompleteOnLiveGroupListFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	_, complete := computeReservedNamesDesired(context.Background(), client, nil, nil)
	if complete {
		t.Fatal("expected complete==false when the live group listing fails")
	}
}

// TestComputeReservedNamesDesired_SkipsExternalLiveGroupMembers reproduces
// the bug where a live, already-managed GROUP that this pass's payload
// declares external_members:true had its directory-synced live members
// (memberOf sync populates OPNsense's own `member` field, same as any
// other group) folded into the reserved-name exclusion anyway, because
// ConvertGroupToAPI (reading the LIVE group back) has no way to know a
// group is external — that flag exists only in payload content, never as
// a marker on the device. Without the cross-reference against the
// payload's ExternalMembers flag, this directory account (alice) would
// become permanently excluded from every managed LDAP server the moment
// she is added to eng-ext by the directory itself.
func TestComputeReservedNamesDesired_SkipsExternalLiveGroupMembers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "u1", "name": "alice", "descr": "", "uid": "2009", "scope": "automation"},
			},
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				// A live, already-managed group (carries the template
				// tag) whose member list was populated by LDAP memberOf
				// sync, not by NDAgent — exactly what an external group
				// looks like on the wire; there is no separate marker.
				{"uuid": "g1", "name": "eng-ext", "description": "[nd-template:ad]", "gid": "3009", "member": "2009"},
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groups := []opnapi.APIGroupPayload{
		{Name: "eng-ext", ExternalMembers: true},
	}

	got, complete := computeReservedNamesDesired(context.Background(), client, nil, groups)
	if !complete {
		t.Fatal("expected complete==true for a successful live listing")
	}
	for _, n := range got {
		if n == "alice" {
			t.Fatalf("got %v, want it to EXCLUDE alice — she is a directory-synced member of a live external group, not a NetDefense-managed identity", got)
		}
	}
}

// -----------------------------------------------------------------
// runAuthServerDecommission
// -----------------------------------------------------------------

func TestRunAuthServerDecommission_EmptyUUIDRejected(t *testing.T) {
	if err := runAuthServerDecommission("", ""); err == nil {
		t.Fatal("expected an error for an empty device_uuid")
	}
}

func TestRunAuthServerDecommission_PostConditionNotClean(t *testing.T) {
	resp := authHelperDecommissionResponse{Contract: 1, PostConditionClean: false}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	err := runAuthServerDecommission("device-1", "")
	if err == nil {
		t.Fatal("expected an error when post_condition_clean is false")
	}
}

func TestRunAuthServerDecommission_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	var captured authHelperRequest
	resp := authHelperDecommissionResponse{Contract: 1, PostConditionClean: true, DeletedServers: []string{"Corp AD"}}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func(requestJSON []byte) ([]byte, int, error) {
		_ = json.Unmarshal(requestJSON, &captured)
		return respJSON, 0, nil
	})

	if err := runAuthServerDecommission("device-1", path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.Mode != "decommission" || captured.DeviceUUID != "device-1" {
		t.Errorf("request = %+v, want mode=decommission device_uuid=device-1", captured)
	}
}

// TestRunAuthServerDecommission_LeftoverMarkerFailsEvenWhenHelperReportsClean
// is the major-finding regression for decommission's post-condition: the helper's
// own PostConditionClean is trusted, but this device-independent Go-side
// rescan of config.xml must ALSO catch a marker the helper's check missed
// (e.g. a facility marker it failed to parse) rather than letting the
// decommission step report success while a marker naming this device's
// uuid is still on disk.
func TestRunAuthServerDecommission_LeftoverMarkerFailsEvenWhenHelperReportsClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense><authserver><netdefense_owner>device-1</netdefense_owner></authserver></opnsense>"), 0o600) //nolint:errcheck

	resp := authHelperDecommissionResponse{Contract: 1, PostConditionClean: true}
	respJSON, _ := json.Marshal(resp)
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) { return respJSON, 0, nil })

	if err := runAuthServerDecommission("device-1", path); err == nil {
		t.Fatal("expected an error: a <netdefense_owner> naming this device's uuid is still in config.xml")
	}
}

// -----------------------------------------------------------------
// Process safety, against a REAL OS process (not the fake seam) --
// runHelperSubprocess is the shared, binary-agnostic implementation
// runAuthServersHelperDefault applies to php/auth_servers.php, so these
// tests exercise the actual mechanism (independent context, SIGTERM-only
// cancellation, deliberately no WaitDelay, stdin-only input, exit-code
// capture) with a plain shell script rather than depending on `php` or
// the plugin's helper being present on the machine running `go test`.
// -----------------------------------------------------------------

func TestRunHelperSubprocess_NormalExitCapturesOutputAndExitCode(t *testing.T) {
	stdout, exitCode, err := runHelperSubprocess("/bin/sh", []string{"-c", `cat; exit 7`}, []byte("hello-stdin"), time.Second, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 7 {
		t.Errorf("exitCode = %d, want 7", exitCode)
	}
	if string(stdout) != "hello-stdin" {
		t.Errorf("stdout = %q, want the request echoed back (proves stdin, not argv, carries the request)", stdout)
	}
}

// TestRunHelperSubprocess_SIGTERMOnlyNeverKillsAfterCeiling is the revert
// guard for the helper's most safety-critical claim, and for the WaitDelay trap
// documented on authHelperCeiling: past the ceiling, the process is asked
// to terminate (SIGTERM) -- confirmed here by a trap handler that writes
// its own marker the instant it's caught -- and is then left to exit on
// its own schedule, NEVER forcibly killed by this code. A process that
// traps and ignores SIGTERM, then keeps running past the ceiling and
// finishes normally on its own, must be let it finish: the overall call
// must NOT return early at the ceiling, and the process's own normal exit
// (code 0) must be what's reported -- not a signal-killed result. Before
// the WaitDelay trap was found and fixed, a nonzero WaitDelay here made
// Go's own runtime SIGKILL this same process shortly after the ceiling,
// which this test also failed against.
func TestRunHelperSubprocess_SIGTERMOnlyNeverKillsAfterCeiling(t *testing.T) {
	dir := t.TempDir()
	signaled := filepath.Join(dir, "signaled")
	survived := filepath.Join(dir, "survived")
	// Traps SIGTERM (proving delivery, not just absence of a crash),
	// ignores it, then keeps running well past the ceiling before exiting
	// normally.
	script := fmt.Sprintf(`trap 'touch %s' TERM; sleep 0.3; touch %s`, signaled, survived)

	ceiling := 50 * time.Millisecond
	start := time.Now()
	_, exitCode, err := runHelperSubprocess("/bin/sh", []string{"-c", script}, nil, ceiling, time.Minute)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v (the process should have exited normally, not been killed)", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (a clean exit, not a signal-terminated one)", exitCode)
	}
	// The call must NOT return early at the ceiling (~50ms) -- it has to
	// keep waiting for the process's real exit, well past it.
	if elapsed < 250*time.Millisecond {
		t.Errorf("runHelperSubprocess returned after %v, want it to block until the script's real exit (~300ms), not cut off at the ceiling", elapsed)
	}
	if _, statErr := os.Stat(signaled); statErr != nil {
		t.Error("the SIGTERM was never delivered around the ceiling (trap never fired)")
	}
	if _, statErr := os.Stat(survived); statErr != nil {
		t.Error("the process never reached its own normal exit -- it was killed instead of merely signaled")
	}
}

// TestRunHelperSubprocess_AbandonsWithoutKillingPastGrace is the major-
// finding regression: a process that ignores SIGTERM and keeps running
// past ceiling+grace must make runHelperSubprocess RETURN (with
// errAuthHelperAbandoned) rather than block forever -- and the process
// itself must still never be killed. Before this fix there was no grace
// window at all: the call blocked on cmd.Wait() for as long as the
// process legitimately (or not) kept running, which -- now that the SYNC
// FIFO serializes every SYNC through one worker -- would stall every
// later SYNC behind a single stuck helper indefinitely.
func TestRunHelperSubprocess_AbandonsWithoutKillingPastGrace(t *testing.T) {
	dir := t.TempDir()
	signaled := filepath.Join(dir, "signaled")
	stillRunning := filepath.Join(dir, "still-running")
	// Traps and ignores SIGTERM, then sleeps far longer than the test's
	// ceiling+grace window (touching a marker partway through, well past
	// where the test asserts abandonment, to prove it wasn't killed).
	script := fmt.Sprintf(`trap 'touch %s' TERM; sleep 0.3; touch %s`, signaled, stillRunning)

	ceiling := 50 * time.Millisecond
	grace := 100 * time.Millisecond
	start := time.Now()
	_, exitCode, err := runHelperSubprocess("/bin/sh", []string{"-c", script}, nil, ceiling, grace)
	elapsed := time.Since(start)

	if !errors.Is(err, errAuthHelperAbandoned) {
		t.Fatalf("err = %v, want errAuthHelperAbandoned", err)
	}
	if exitCode != -1 {
		t.Errorf("exitCode = %d, want -1 (no terminal status -- the process is still running)", exitCode)
	}
	// Must return at roughly ceiling+grace (150ms), not wait for the
	// process's real ~300ms exit.
	if elapsed > 280*time.Millisecond {
		t.Errorf("runHelperSubprocess took %v, want it to give up around ceiling+grace (~150ms)", elapsed)
	}

	// Give the still-untouched, still-running process time to actually
	// finish on its own and prove it was never killed. A shell blocked in
	// a foreground `sleep` typically defers running a caught trap until
	// that sleep returns, so `signaled` may only appear around the same
	// time as `stillRunning` (~300ms in) — check both only here, not
	// right after abandonment.
	deadline := time.After(2 * time.Second)
	for {
		if _, statErr := os.Stat(stillRunning); statErr == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the process never reached its own normal exit -- it was killed despite the abandon-without-kill contract")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, statErr := os.Stat(signaled); statErr != nil {
		t.Error("SIGTERM was never delivered at the ceiling")
	}
}

// TestExecuteSyncAuth_AlreadyCancelledContextRefusesToStartHelper replaces
// an earlier (incorrect) test that asserted the opposite: that an
// already-cancelled ctx still caused a NEW helper invocation. "The
// helper is not tied to task/WebSocket cancellation" is about a
// helper ALREADY RUNNING being left to finish safely (which is still true
// and unaffected by this fix -- runAuthServersHelperFunc's signature
// carries no context parameter at all, so nothing here could abort an
// in-flight subprocess even if it wanted to). It is not a licence to START
// a brand-new config mutation against a context that is already dead --
// see the major-finding fix in executeSyncAuth's ctx.Err() check.
func TestExecuteSyncAuth_AlreadyCancelledContextRefusesToStartHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense></opnsense>"), 0o600) //nolint:errcheck

	called := false
	respJSON, _ := json.Marshal(authHelperSyncResponse{Contract: 1})
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) {
		called = true
		return respJSON, 0, nil
	})

	parsed := authParseOutcome{
		HasContent: true,
		Servers: []authServerContent{
			mustParseAuthServer(t, `{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_port":"636",
			"ldap_urltype":"SSL - Encrypted","ldap_protver":"3","ldap_scope":"subtree",
			"ldap_basedn":"","ldap_authcn":"","ldap_attr_user":"sAMAccountName"}`),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before executeSyncAuth is even called

	out := executeSyncAuth(ctx, nil, "device-1", "task-1", true, path, parsed, nil, nil)
	if called {
		t.Fatal("the helper was invoked against an already-cancelled context -- must refuse to start a new mutation instead")
	}
	if out.Result.Success {
		t.Error("expected the family to fail (AUTH_RESERVED_SET_UNAVAILABLE), got success")
	}
	found := false
	for _, e := range out.Result.Errors {
		if strings.Contains(e, "AUTH_RESERVED_SET_UNAVAILABLE") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors = %v, want AUTH_RESERVED_SET_UNAVAILABLE", out.Result.Errors)
	}
	// config.xml carries no markers, so there is nothing to blanket-defer.
	if out.Deferral.Active {
		t.Errorf("expected no deferral (no pre-existing markers), got %+v", out.Deferral)
	}
}

// TestExecuteSyncAuth_IncompleteReservedSetRefusesToStartHelper is the
// executeSyncAuth-level half of the major finding: a live-listing failure
// inside computeReservedNamesDesired must stop the family before the
// helper is ever invoked, with a blanket deferral when managed markers
// already exist on the device (there is no exclusion data to trust).
func TestExecuteSyncAuth_IncompleteReservedSetRefusesToStartHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte("<opnsense><netdefense_owner>device-1</netdefense_owner></opnsense>"), 0o600) //nolint:errcheck

	called := false
	respJSON, _ := json.Marshal(authHelperSyncResponse{Contract: 1})
	withFakeAuthHelper(t, func([]byte) ([]byte, int, error) {
		called = true
		return respJSON, 0, nil
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	parsed := authParseOutcome{HasContent: true}

	out := executeSyncAuth(context.Background(), client, "device-1", "task-1", true, path, parsed, nil, nil)
	if called {
		t.Fatal("the helper was invoked against an incomplete reserved-name set")
	}
	if out.Result.Success {
		t.Error("expected failure, got success")
	}
	if !out.Deferral.Active || !out.Deferral.Blanket {
		t.Errorf("expected an active blanket deferral (markers exist, AUTH did not complete), got %+v", out.Deferral)
	}
}
