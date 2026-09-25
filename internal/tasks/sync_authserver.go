// Copyright (C) 2026 NetDefense
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.

package tasks

// AUTH_SERVER / AUTH_ORDER: the Go side of the NDAgent contract for LDAP/AD
// directory integration. The PHP helper implementing the OPNsense-side
// algorithm ships in `plugin/.../AuthServerHelper.php` and
// `plugin/.../auth_servers.php` (PR #5, feature/auth-server-helper-pr5).
// This file is the strict-parsing gate, the helper invocation with
// its process-safety rules, and the response mapping back into the
// same SyncAPIItemResult shape every other SYNC_API family reports.
//
// AUTH_SERVER has no OPNsense REST API at all — the legacy
// system_authservers.php page writes system/authserver[] via write_config(),
// with no MVC model and no reload. This is the one deliberate, documented
// exception to NDAgent otherwise managing OPNsense exclusively through its
// REST/MVC API (aliases, rules, users, groups, VPN, Unbound, Zabbix all go
// through internal/opnapi's HTTP client). AUTH_SERVER/AUTH_ORDER instead
// shell out to a PHP helper that edits config.xml directly, because there
// is no REST surface to call. Do not follow this pattern for anything that
// DOES have a REST/MVC model — see CLAUDE.md's "Firewall rules/aliases:
// MVC API only" rule, which this does not relax.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

const (
	// authServerHelperScript is the PHP entry point shipped in the plugin
	// package (PR #5). phpInterpreter (decommission.go) is reused as-is.
	authServerHelperScript = "/usr/local/opnsense/scripts/OPNsense/NetDefense/auth_servers.php"

	// authFacilityWebadmin is the only facility v1 defines.
	authFacilityWebadmin = "webadmin"

	// authHelperContractVersion pins the wire contract version.
	authHelperContractVersion = 1

	// authHelperCeiling implements the helper's process-safety rule. The helper
	// is NOT tied to task/WebSocket cancellation — it is started against a
	// fresh, independent context bounded only by this ceiling, never the
	// task's own ctx — and receives SIGTERM only after that ceiling, never
	// the os/exec default (Process.Kill). The helper deliberately ignores
	// SIGTERM/SIGINT while it holds the OPNsense config lock and only
	// exits once it has safely unlocked; escalating to SIGKILL would
	// reintroduce the kill-during-save() config.xml truncation the whole
	// design exists to prevent.
	//
	// Deliberately no WaitDelay. A tempting-looking `cmd.WaitDelay` field
	// exists on exec.Cmd, and internal/pathfinder/exec.go's runCommand
	// uses it as a pure "bound how long Wait() blocks on I/O" backstop —
	// but that reading of WaitDelay is INCOMPLETE, and a genuine trap: per
	// os/exec's watchCtx, once the context is done, a NONZERO WaitDelay
	// does not merely bound an I/O wait — after WaitDelay elapses AND
	// Cancel has been called, Go's OWN runtime sends the process a REAL
	// kill (Process.Kill, i.e. SIGKILL) if it still has not exited,
	// regardless of what Cancel did. That is exactly the case a helper
	// legitimately in the middle of holding the OPNsense config lock past
	// the ceiling would hit — Go itself would SIGKILL it, truncating
	// config.xml, the one thing this whole mechanism exists to prevent.
	// Confirmed by reproducing it directly: a WaitDelay paired with a
	// SIGTERM-only Cancel still ends the process (`err == "signal:
	// killed"`) shortly after WaitDelay elapses, even though the script
	// traps and ignores SIGTERM. With WaitDelay left at its zero value,
	// watchCtx calls Cancel and returns — no kill timer is armed at all,
	// and Wait() blocks for as long as the process legitimately takes to
	// exit on its own. The tradeoff (a leaked descriptor to an unexpected
	// grandchild could block this goroutine indefinitely) is accepted:
	// auth_servers.php is a straight-line synchronous script that forks
	// nothing of its own, so that failure mode does not apply here the way
	// it does for the interactive exec stream runCommand guards against.
	authHelperCeiling = 5 * time.Minute

	// authHelperAbandonGrace bounds how much LONGER runHelperSubprocess
	// will wait for the child to exit on its own after cmd.Cancel has
	// already sent SIGTERM at the ceiling. Never killing the process (see
	// authHelperCeiling's doc comment) does not mean waiting for it
	// forever: because the SYNC FIFO (internal/network/dispatcher.go) now
	// runs every SYNC's handler synchronously on one worker, an
	// indefinite cmd.Run()/cmd.Wait() here would stall every later SYNC
	// behind this one — eventually filling the queue and answering every
	// new SYNC with SYNC_QUEUE_FULL — and stalls the auth family inside
	// decommission the same way. Past ceiling+authHelperAbandonGrace,
	// runHelperSubprocess stops waiting and returns errAuthHelperAbandoned
	// (mapped to AUTH_HELPER_TIMEOUT with the usual blanket deferral when
	// markers exist) — but the process itself is left completely alone to
	// finish whatever save() it may legitimately still be in the middle
	// of; a later helper invocation simply serializes behind it on the
	// PHP-side lock (AUTH_LOCK_TIMEOUT, 30s). The grace window is sized
	// generously relative to a single allow-list-diff-and-save — which
	// the design assumes is fast — while still bounding the worst case to
	// a fixed number rather than "forever".
	authHelperAbandonGrace = 60 * time.Second

	// authHelperMaxResponseBytes is NDAgent's OWN defensive cap on the
	// helper's stdout, capped at 1 MB. auth_servers.php does NOT itself enforce a matching
	// stdout truncation today (only MAX_REQUEST_BYTES, its stdin cap) —
	// its "symmetry with the 1 MB stdout cap" comment is aspirational, not
	// an actual limit on the PHP side — so this is not "on top of" a
	// helper-side cap the way the old comment claimed; it is the only
	// stdout bound that exists at all right now. A truncated response
	// simply fails JSON parsing downstream (never causing cmd.Run() to
	// error), which is reported as a generic helper fault, never as the
	// raw bytes themselves.
	authHelperMaxResponseBytes = 1024 * 1024
)

// errAuthHelperAbandoned is runHelperSubprocess's sentinel for "gave up
// waiting after ceiling+authHelperAbandonGrace" — checked with errors.Is
// so callers can map it to a distinct, actionable code (AUTH_HELPER_TIMEOUT)
// instead of the generic AUTH_HELPER_FAULT.
var errAuthHelperAbandoned = errors.New("auth helper subprocess abandoned: still running past ceiling+grace, never killed")

// -----------------------------------------------------------------
// Strict parsing
// -----------------------------------------------------------------

// authServerContent is one AUTH_SERVER snippet's content, decoded with an
// exhaustive, strict field set (DisallowUnknownFields): a future key this
// agent version does not know about yet fails the WHOLE content closed
// rather than silently dropping just that key. name/type are handled
// separately from the rest — type is fixed "ldap" in v1, and the helper
// hardcodes it on create, so neither is ever part of the
// `fields` map sent on the wire (helperFields below).
type authServerContent struct {
	Name                       string `json:"name"`
	Type                       string `json:"type"`
	Host                       string `json:"host"`
	LdapPort                   string `json:"ldap_port"`
	LdapUrltype                string `json:"ldap_urltype"`
	LdapProtver                string `json:"ldap_protver"`
	LdapScope                  string `json:"ldap_scope"`
	LdapBasedn                 string `json:"ldap_basedn"`
	LdapAuthcn                 string `json:"ldap_authcn"`
	LdapExtendedQuery          string `json:"ldap_extended_query"`
	LdapAttrUser               string `json:"ldap_attr_user"`
	LdapBinddn                 string `json:"ldap_binddn"`
	LdapBindpw                 string `json:"ldap_bindpw"`
	CaseInSensitiveUsernames   bool   `json:"caseInSensitiveUsernames"`
	LdapReadProperties         bool   `json:"ldap_read_properties"`
	LdapSyncMemberofConstraint bool   `json:"ldap_sync_memberof_constraint"`
	LdapSyncMemberof           bool   `json:"ldap_sync_memberof"`
	LdapAttrMemberof           string `json:"ldap_attr_memberof"`
	LdapSyncMemberofGroups     string `json:"ldap_sync_memberof_groups"`
	LdapSyncDefaultGroups      string `json:"ldap_sync_default_groups"`
	LdapSyncCreateLocalUsers   bool   `json:"ldap_sync_create_local_users"`
	NdAllowCleartextLdap       bool   `json:"nd_allow_cleartext_ldap"`
}

// helperFields renders the wire `fields` map for one server: every key
// above except name/type, with original JSON types preserved (a bool stays
// a JSON bool, never stringified to "0"/"1") — AuthServerHelper.php's own
// field application does `(bool)$fields[$key]` for the boolean keys, and a
// bare non-"" string like "false" is truthy under PHP's cast, so sending a
// native boolean is the only unambiguous wire form.
func (c authServerContent) helperFields() (map[string]interface{}, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	delete(m, "name")
	delete(m, "type")
	return m, nil
}

// parseAuthServerContent strictly decodes one AUTH_SERVER snippet's content
// string. NDManager/NDDataModels already validated field shapes (regexes,
// length limits, the RFC 4515 parser, etc.) before this content ever
// reached the device — this decode's job is narrower: reject any key this
// agent version does not recognize, and reject any `type` other than
// "ldap" (RADIUS ships in v1.1 and old agents must fail closed on it,
// not half-apply it).

// rejectTrailingJSON requires that dec has nothing left to decode after
// the value it just read — `json.Decoder.Decode` on its own happily
// accepts and silently ignores trailing data after a complete JSON value
// (`{...}garbage` decodes with err==nil), which is not the fail-closed
// behavior strict parsing is supposed to give AUTH content. Called
// immediately after every top-level Decode call in this file.
func rejectTrailingJSON(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("strict decode failed: unexpected trailing data after the JSON value")
		}
		return fmt.Errorf("strict decode failed: %w", err)
	}
	return nil
}

func parseAuthServerContent(jsonContent string) (authServerContent, error) {
	dec := json.NewDecoder(strings.NewReader(jsonContent))
	dec.DisallowUnknownFields()
	var c authServerContent
	if err := dec.Decode(&c); err != nil {
		return authServerContent{}, fmt.Errorf("strict decode failed: %w", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		return authServerContent{}, err
	}
	if c.Name == "" {
		return authServerContent{}, fmt.Errorf("missing required field: name")
	}
	if c.Type != "ldap" {
		return authServerContent{}, fmt.Errorf("unrecognized auth server type %q (this agent only recognizes \"ldap\")", c.Type)
	}
	return c, nil
}

// authOrderWebadminContent is the only facility body v1 defines.
type authOrderWebadminContent struct {
	Order []string `json:"order"`
}

// parseAuthOrderContent strictly decodes one AUTH_ORDER snippet's content
// into a facility-name -> order-list map. Any facility key outside the v1
// allow-list, or any unrecognized key inside a known facility's own object,
// fails closed the same way an unknown AUTH_SERVER key does — an agent that
// does not know a facility must fail closed rather than half-apply it.
func parseAuthOrderContent(jsonContent string) (map[string][]string, error) {
	var top struct {
		Facilities map[string]json.RawMessage `json:"facilities"`
	}
	dec := json.NewDecoder(strings.NewReader(jsonContent))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("strict decode failed: %w", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		return nil, err
	}
	if len(top.Facilities) == 0 {
		return nil, fmt.Errorf("facilities must have at least one key")
	}

	out := make(map[string][]string, len(top.Facilities))
	for fname, raw := range top.Facilities {
		if fname != authFacilityWebadmin {
			return nil, fmt.Errorf("unrecognized facility %q", fname)
		}
		var wa authOrderWebadminContent
		fdec := json.NewDecoder(bytes.NewReader(raw))
		fdec.DisallowUnknownFields()
		if err := fdec.Decode(&wa); err != nil {
			return nil, fmt.Errorf("facility %q: strict decode failed: %w", fname, err)
		}
		// A JSON `null` facility body decodes without error into the zero
		// value (Order == nil) — same observable shape as an omitted
		// `order` key entirely. Rejecting both here, rather than only at
		// NDManager/the PHP helper, means Go never silently treats
		// "facilities":{"webadmin":null} as a valid, empty order (which
		// would otherwise round-trip as `"order":null` on the wire to the
		// helper).
		if len(wa.Order) == 0 {
			return nil, fmt.Errorf("facility %q: order must have at least one entry (got none or null)", fname)
		}
		out[fname] = wa.Order
	}
	return out, nil
}

// authParseOutcome is what parseAPIAuthContent found in the payload this
// pass. HasContent is set as soon as ANY AUTH_SERVER/AUTH_ORDER snippet is
// seen, even one that later fails to parse — it drives the "when does
// the family run" decision (authFamilyShouldRun) independently of Err.
//
// A single unparseable snippet turns the WHOLE family into a no-op for this
// pass (Err is set to the first failure and parsing of the rest still
// continues so HasContent/counts stay accurate, but Servers/Facilities from
// a failed pass are never handed to the helper) — unlike every other
// SYNC_API family, which drops just the offending element. This is
// deliberate: a future key, facility or type an old agent doesn't
// recognize yet fails closed for AUTH specifically, without aborting the
// rest of the SYNC the way a whole-payload parse failure would for every
// other family.
type authParseOutcome struct {
	HasContent bool
	Servers    []authServerContent
	Facilities map[string][]string
	Err        error
}

// parseAPIAuthContent extracts AUTH_SERVER/AUTH_ORDER snippets from the
// SYNC_API payload. See authParseOutcome for the no-abort-on-error contract
// — callers must NOT treat a non-nil Err the way every other parseAPIX
// function in sync_api.go is treated (an immediate whole-task failure).
func parseAPIAuthContent(payload map[string]interface{}) authParseOutcome {
	out := authParseOutcome{Facilities: make(map[string][]string)}

	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return out
	}
	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		out.Err = fmt.Errorf("snippets must be an array")
		return out
	}

	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			continue // malformed snippet shape is caught by the other families' parsers
		}

		configType, _ := snippetMap["config_type"].(string)
		switch configType {
		case "AUTH_SERVER":
			out.HasContent = true
			content, _ := snippetMap["content"].(string)
			if content == "" {
				if out.Err == nil {
					out.Err = fmt.Errorf("%s: missing content", snippetLabel("auth_server", snippetMap, idx))
				}
				continue
			}
			server, err := parseAuthServerContent(content)
			if err != nil {
				if out.Err == nil {
					out.Err = fmt.Errorf("%s: %v", snippetLabel("auth_server", snippetMap, idx), err)
				}
				continue
			}
			out.Servers = append(out.Servers, server)

		case "AUTH_ORDER":
			out.HasContent = true
			content, _ := snippetMap["content"].(string)
			if content == "" {
				if out.Err == nil {
					out.Err = fmt.Errorf("%s: missing content", snippetLabel("auth_order", snippetMap, idx))
				}
				continue
			}
			facilities, err := parseAuthOrderContent(content)
			if err != nil {
				if out.Err == nil {
					out.Err = fmt.Errorf("%s: %v", snippetLabel("auth_order", snippetMap, idx), err)
				}
				continue
			}
			for fname, order := range facilities {
				// "Two snippets that define the same facility
				// for one device are a build conflict." NDManager's own
				// build-time check (AUTH_ORDER_FACILITY_CONFLICT) is meant
				// to catch this before dispatch, but Go must not trust
				// that unconditionally and silently take an arbitrary
				// last-wins order if a build-time bug (or an older
				// NDManager without the check) ever lets a conflict
				// through — that would write a login order to the device
				// that a build-time check should have refused. The same
				// snippet reached twice (sync_service.py's own dedupe)
				// legitimately produces two identical entries here, and
				// that case is not an error.
				if existing, ok := out.Facilities[fname]; ok {
					if slices.Equal(existing, order) {
						continue
					}
					if out.Err == nil {
						out.Err = fmt.Errorf("%s: facility %q is defined more than once with different orders",
							snippetLabel("auth_order", snippetMap, idx), fname)
					}
					continue
				}
				out.Facilities[fname] = order
			}
		}
	}
	return out
}

// authFamilyShouldRun implements "when the family runs": the
// payload carries AUTH content, OR a raw substring scan of config.xml finds
// an existing marker. The second half is what lets facility "absent means
// untouched" and server sweep-on-detach work even after every AUTH
// snippet has been removed from every template — that decision lives in
// device state, not in this pass's payload.
func authFamilyShouldRun(hasContent bool, configXMLPath string) bool {
	return hasContent || configXMLHasAuthMarkers(configXMLPath)
}

// configXMLHasAuthMarkers is a cheap raw scan — never a full XML parse —
// for either ownership marker AuthServerHelper.php writes
// (<netdefense_owner>, <netdefense_authmode_owner>).
//
// Deliberately FAIL-CLOSED (assume markers exist) on a read error, unlike
// checkRuleInterfaces's fail-open convention for its own diagnostic-only
// read: this result gates two live security decisions, not a diagnostic —
// authFamilyShouldRun (whether the AUTH family, and so the reserved-name
// exclusion recompute, runs at all) and executeSyncAuth's markersExist
// (whether an incomplete/faulted AUTH pass blanket-defers every new
// USER/GROUP-member this sync). Returning false on an unreadable
// config.xml would silently skip BOTH: a device whose config.xml briefly
// can't be read would let users/groups create new privileged identities
// with no exclusion recomputed and no blanket deferral to catch it. Failing
// closed instead just means the family runs (and PHP's own read will
// legitimately fault if the file really is unreadable, which correctly
// produces the blanket deferral through the normal fault() path).
func configXMLHasAuthMarkers(configXMLPath string) bool {
	data, err := os.ReadFile(configXMLPath)
	if err != nil {
		logging.Named("SYNC_API").Warnw("AUTH: could not scan config.xml for existing markers; assuming markers exist (fail closed on this security gate)",
			"path", configXMLPath, "error", err)
		return true
	}
	return bytes.Contains(data, []byte("netdefense_owner")) || bytes.Contains(data, []byte("netdefense_authmode_owner"))
}

// -----------------------------------------------------------------
// Wire contract types
// -----------------------------------------------------------------

type authHelperServerRequest struct {
	Name   string                 `json:"name"`
	Fields map[string]interface{} `json:"fields"`
}

type authHelperFacilityRequest struct {
	Order []string `json:"order"`
}

type authHelperRequest struct {
	Contract             int                                  `json:"contract"`
	Mode                 string                               `json:"mode"`
	DeviceUUID           string                               `json:"device_uuid"`
	TaskID               string                               `json:"task_id,omitempty"`
	RejectDangerous      bool                                 `json:"reject_dangerous"`
	ReservedNamesDesired []string                             `json:"reserved_names_desired,omitempty"`
	Servers              []authHelperServerRequest            `json:"servers,omitempty"`
	Facilities           map[string]authHelperFacilityRequest `json:"facilities,omitempty"`
}

type authHelperServerResult struct {
	Name          string   `json:"name"`
	Action        string   `json:"action"`
	Code          string   `json:"code"`
	ChangedFields []string `json:"changed_fields"`
	Consumers     []string `json:"consumers"`
	Warnings      []string `json:"warnings"`
}

type authHelperLocalServer struct {
	Name  string   `json:"name"`
	Risks []string `json:"risks"`
}

type authHelperFacilityResult struct {
	Action       string                  `json:"action"`
	Before       []string                `json:"before"`
	After        []string                `json:"after"`
	Code         string                  `json:"code"`
	Unresolved   []string                `json:"unresolved"`
	LocalServers []authHelperLocalServer `json:"local_servers"`
	// Available lists the server names that do exist: Local Database plus every local
	// server plus every server this save actually applied — the
	// resolution set a refused AUTH_ORDER_UNRESOLVED/NOT_APPLIED/
	// NAMES_REMOVED_SERVER entry was checked against. `Before` (the
	// kept, unchanged order) is a different fact and is reported
	// separately; do not conflate the two.
	Available []string `json:"available"`
}

type authHelperExclusion struct {
	StaleNames []string `json:"stale_names"`
	Code       string   `json:"code"`
}

type authHelperWarning struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

type authHelperErrorBody struct {
	Code string `json:"code"`
}

// authHelperSyncResponse is the `mode: "sync"` response shape.
type authHelperSyncResponse struct {
	Contract      int                                 `json:"contract"`
	Release       string                              `json:"release"`
	Servers       []authHelperServerResult            `json:"servers"`
	Facilities    map[string]authHelperFacilityResult `json:"facilities"`
	Exclusion     authHelperExclusion                 `json:"exclusion"`
	Warnings      []authHelperWarning                 `json:"warnings"`
	ConfigWritten bool                                `json:"config_written"`
	Error         *authHelperErrorBody                `json:"error,omitempty"`
}

// authHelperDecommissionResponse is the `mode: "decommission"` response
// shape.
type authHelperDecommissionResponse struct {
	Contract           int                  `json:"contract"`
	DeletedServers     []string             `json:"deleted_servers"`
	Facilities         map[string]string    `json:"facilities"`
	PostConditionClean bool                 `json:"post_condition_clean"`
	ConfigWritten      bool                 `json:"config_written"`
	Error              *authHelperErrorBody `json:"error,omitempty"`
}

// -----------------------------------------------------------------
// Helper invocation
// -----------------------------------------------------------------

// runAuthServersHelperFunc is the indirection point for tests — production
// wiring is runAuthServersHelperDefault. Returns the helper's raw stdout
// bytes and its exit code; the caller decides how to interpret them (sync
// vs. decommission mode parse differently). Never returns the child's
// stdout/stderr text embedded in the returned error — "the
// helper never echoes values" applies to Go's own error paths too, not
// only the PHP helper's.
var runAuthServersHelperFunc = runAuthServersHelperDefault

func runAuthServersHelperDefault(requestJSON []byte) (stdout []byte, exitCode int, err error) {
	if _, statErr := os.Stat(authServerHelperScript); statErr != nil {
		return nil, -1, fmt.Errorf("auth_servers.php not present at %s: %w", authServerHelperScript, statErr)
	}

	args := []string{
		"-d", "display_errors=0",
		"-d", "log_errors=0",
		"-d", "zend.exception_ignore_args=1",
		authServerHelperScript, "--json",
	}
	return runHelperSubprocess(phpInterpreter, args, requestJSON, authHelperCeiling, authHelperAbandonGrace)
}

// runHelperSubprocess implements the helper's process-safety rules against an
// arbitrary binary/args/ceiling/grace, so the mechanism (independent
// context, SIGTERM-only cancellation, output capping, stdin-only input, no
// stdio embedded in errors, bounded-but-never-killed abandonment) can be
// exercised directly against a real OS process in tests without depending
// on `php`/auth_servers.php being present on the test host, and without a
// real test having to wait out the full production grace window.
// runAuthServersHelperDefault is this function applied to the production
// binary/script/timing.
func runHelperSubprocess(binary string, args []string, requestJSON []byte, ceiling, grace time.Duration) (stdout []byte, exitCode int, err error) {
	// Deliberately NOT the task's own context: the helper can hold
	// the OPNsense config lock across a single save() and must run to
	// completion even if the task is cancelled or the WebSocket drops
	// mid-sync. This is a fresh, independent ceiling — "not tied to
	// cancellation" does not mean "unbounded".
	ctx, cancel := context.WithTimeout(context.Background(), ceiling)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = util.DeviceExecEnv()
	cmd.Stdin = bytes.NewReader(requestJSON)

	// SIGTERM only, never the os/exec default (Process.Kill on ctx-done).
	// WaitDelay is deliberately left unset (zero) — see authHelperCeiling's
	// doc comment for why a nonzero WaitDelay here would let Go's own
	// runtime SIGKILL the process out from under a legitimate in-progress
	// save().
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}

	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{limit: authHelperMaxResponseBytes, buf: &out}
	// Discarded outright: the script's own -d flags already suppress
	// display_errors/log_errors, and "the helper never echoes values"
	// applies to a stray warning that slips through despite those flags
	// too — never logged, never embedded in an error.
	cmd.Stderr = io.Discard

	if startErr := cmd.Start(); startErr != nil {
		// The process never even started (binary missing, fork/exec
		// failure, etc.) — startErr's own text here is a process-lifecycle
		// description (a path, a permission error), never the child's
		// stdio, so wrapping it is safe.
		return nil, -1, fmt.Errorf("helper subprocess did not start: %w", startErr)
	}

	// Never block the caller (the SYNC FIFO's single worker, or the
	// decommission sequence) indefinitely on Wait(), even though the
	// process itself is never killed. Once ceiling has elapsed, cmd.Cancel
	// has already sent SIGTERM; authHelperAbandonGrace is how much LONGER
	// we wait for it to actually exit on its own before giving up on
	// THIS call and reporting errAuthHelperAbandoned — the process keeps
	// running untouched, and a later helper invocation simply serializes
	// behind it on the PHP-side config lock.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	select {
	case waitErr := <-waitDone:
		// Deliberately keyed off cmd.ProcessState, NOT waitErr. Another
		// os/exec subtlety: once the ceiling fires and Cancel succeeds,
		// Cmd.Wait() reports ctx.Err() (context.DeadlineExceeded) as the
		// returned error — even if the process, having merely been asked
		// (SIGTERM) rather than forced, goes on to exit cleanly on its own
		// right afterward. Treating that as "the helper did not complete"
		// would discard a perfectly good, successful response purely
		// because it happened to finish around the same moment the
		// ceiling fired. cmd.ProcessState is set from the real wait4()
		// result regardless of that later error substitution, so it —
		// not waitErr — is the source of truth for whether the process
		// actually produced a terminal exit status.
		if cmd.ProcessState != nil {
			return out.Bytes(), cmd.ProcessState.ExitCode(), nil
		}
		return nil, -1, fmt.Errorf("helper subprocess did not complete: %w", waitErr)

	case <-time.After(ceiling + grace):
		// Deliberately return nil stdout, not out.Bytes(): the internal
		// stdout-copying goroutine os/exec started alongside the process
		// may still be writing into `out` after we return (Wait() has not
		// returned, so nothing guarantees that copy has finished) — this
		// avoids handing the caller a half-written buffer, not a data
		// race (nothing else ever reads `out` again in this function).
		return nil, -1, fmt.Errorf("%w (ceiling %s + grace %s)", errAuthHelperAbandoned, ceiling, grace)
	}
}

// limitedWriter caps how many bytes Go will buffer from the helper's
// stdout at authHelperMaxResponseBytes — see that constant's own doc
// comment for why this is NOT "on top of" a matching helper-side cap: no
// such cap exists on the PHP side today, so this is the only stdout bound
// that exists at all. Bytes past the limit are silently dropped (never
// causing cmd.Run() to error); a truncated response simply fails JSON
// parsing downstream, which is reported as a generic helper fault, never
// as the raw bytes themselves.
type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		l.buf.Write(p[:remaining])
		return len(p), nil
	}
	l.buf.Write(p)
	return len(p), nil
}

// authHelperFaultCode extracts {"error":{"code":"..."}} from a
// protocol-fault response, defensively — an unparseable or missing body
// maps to a generic code rather than including anything from the payload.
func authHelperFaultCode(stdout []byte) string {
	var body struct {
		Error *authHelperErrorBody `json:"error"`
	}
	if err := json.Unmarshal(stdout, &body); err != nil || body.Error == nil || body.Error.Code == "" {
		return "AUTH_HELPER_FAULT"
	}
	return body.Error.Code
}

// -----------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------

// authFamilyOutcome is executeSyncAuth's return: the usual SyncAPIResult
// plumbing for the task response, plus the deferral state the
// stale-exclusion deferral needs to hand to executeSyncUsersGroups, which
// runs immediately afterward in the same SYNC (the executor order).
type authFamilyOutcome struct {
	Result   SyncAPIResult
	Deferral authDeferralInfo
}

// executeSyncAuth runs the AUTH_SERVER/AUTH_ORDER family. See
// authParseOutcome for the strict-parsing gate, runAuthServersHelperFunc
// for the process-safety rules and authDeferralInfo for what this hands
// off to executeSyncUsersGroups.
//
// client is used ONLY to read the current desired/live users'/groups' names
// for the reserved-name exclusion (computeReservedNamesDesired) — the
// AUTH family itself never touches OPNsense through the REST API, only
// through the PHP helper and config.xml. A nil client (no API
// credentials configured — HandleSyncAPI already refuses SYNC_API entirely
// in that case) is never actually passed here in production; the nil check
// inside computeReservedNamesDesired exists for tests exercising this
// function in isolation.
func executeSyncAuth(
	ctx context.Context,
	client *opnapi.Client,
	deviceUUID string,
	taskID string,
	rejectDangerous bool,
	configXMLPath string,
	parsed authParseOutcome,
	users []opnapi.APIUserPayload,
	groups []opnapi.APIGroupPayload,
) authFamilyOutcome {
	log := logging.Named("SYNC_API")

	if !authFamilyShouldRun(parsed.HasContent, configXMLPath) {
		return authFamilyOutcome{Result: SyncAPIResult{Success: true}}
	}
	markersExist := configXMLHasAuthMarkers(configXMLPath)

	fault := func(code, detail string) authFamilyOutcome {
		msg := fmt.Sprintf("%s: %s", code, detail)
		return authFamilyOutcome{
			Result: SyncAPIResult{
				Success: false,
				Results: []SyncAPIItemResult{{Type: "auth", Action: "unsupported", Status: "blocked", Code: code, Error: msg}},
				Errors:  []string{msg},
			},
			// The AUTH step did not complete while managed markers
			// may already exist on the device — with no exclusion data at
			// all to consult, every name new this pass is treated as
			// stale rather than risking a directory account winning the
			// race against an exclusion that never got recomputed.
			Deferral: authDeferralInfo{Active: markersExist, Blanket: markersExist},
		}
	}

	if parsed.Err != nil {
		log.Warnw("AUTH: content this agent cannot parse; AUTH family is a no-op this pass", "error", parsed.Err)
		return fault("AUTH_CONTENT_UNSUPPORTED", parsed.Err.Error())
	}

	// The reserved-name set must never fail open into a helper run: starting
	// a NEW config mutation (create/update/facility-write) against a
	// possibly-incomplete exclusion is worse than not running this pass at
	// all, because the helper composes whatever we send it and an
	// exclusion, once written, only ever grows — a name silently missing
	// from THIS pass because the ctx was already cancelled or a live
	// listing call failed is not caught later; it is just never excluded.
	// "The helper is not tied to task/WebSocket cancellation"
	// is about a helper ALREADY RUNNING finishing safely, never a licence
	// to start a brand-new one against a context that is already dead —
	// see TestExecuteSyncAuth_AlreadyCancelledContextRefusesToStartHelper.
	if ctx.Err() != nil {
		log.Warnw("AUTH: task context already cancelled; refusing to start a new helper run against a possibly-stale reserved-name set", "error", ctx.Err())
		return fault("AUTH_RESERVED_SET_UNAVAILABLE", "task context was already cancelled before the reserved-name exclusion could be recomputed")
	}

	reservedNames, reservedSetComplete := computeReservedNamesDesired(ctx, client, users, groups)
	if !reservedSetComplete {
		log.Errorw("AUTH: could not list live users/groups; refusing to start a new helper run against an incomplete reserved-name set")
		return fault("AUTH_RESERVED_SET_UNAVAILABLE", "could not list live OPNsense users/groups to recompute the reserved-name exclusion")
	}

	req := authHelperRequest{
		Contract:             authHelperContractVersion,
		Mode:                 "sync",
		DeviceUUID:           deviceUUID,
		TaskID:               taskID,
		RejectDangerous:      rejectDangerous,
		ReservedNamesDesired: reservedNames,
		Facilities:           make(map[string]authHelperFacilityRequest, len(parsed.Facilities)),
	}
	for _, srv := range parsed.Servers {
		fields, err := srv.helperFields()
		if err != nil {
			// A round-trip failure of our own already-strictly-decoded
			// struct is a Go-side bug, not bad input — fail this element
			// closed rather than panic or silently omit it.
			return fault("AUTH_HELPER_FAULT", "could not build the helper request for server "+srv.Name)
		}
		req.Servers = append(req.Servers, authHelperServerRequest{Name: srv.Name, Fields: fields})
	}
	for fname, order := range parsed.Facilities {
		req.Facilities[fname] = authHelperFacilityRequest{Order: order}
	}

	requestJSON, err := json.Marshal(req)
	if err != nil {
		return fault("AUTH_HELPER_FAULT", "could not build the helper request")
	}

	stdout, exitCode, runErr := runAuthServersHelperFunc(requestJSON)
	if runErr != nil {
		if errors.Is(runErr, errAuthHelperAbandoned) {
			// The helper is still running, untouched — we simply stopped
			// waiting for it. Distinct code from AUTH_HELPER_FAULT so this
			// is diagnosable as "still in progress, not dead", but the
			// same blanket-deferral treatment applies: there is no
			// exclusion data from this pass to trust either way.
			log.Errorw("AUTH: helper abandoned after ceiling+grace; leaving it running undisturbed", "error", runErr)
			return fault("AUTH_HELPER_TIMEOUT", runErr.Error())
		}
		log.Errorw("AUTH: helper did not run", "error", runErr)
		return fault("AUTH_HELPER_FAULT", "the auth_servers.php helper did not run")
	}
	if exitCode != 0 {
		code := authHelperFaultCode(stdout)
		log.Errorw("AUTH: helper protocol fault", "exit_code", exitCode, "code", code)
		return fault(code, "the auth_servers.php helper reported a protocol-level fault")
	}

	var resp authHelperSyncResponse
	if err := json.Unmarshal(stdout, &resp); err != nil {
		log.Errorw("AUTH: helper returned unparseable JSON on a 'handled' exit", "error", err)
		return fault("AUTH_HELPER_FAULT", "the helper's response could not be parsed")
	}
	if validationErr := validateAuthHelperResponse(req, resp); validationErr != nil {
		log.Errorw("AUTH: helper response failed validation on a 'handled' exit", "error", validationErr)
		return fault("AUTH_HELPER_FAULT", validationErr.Error())
	}

	return authFamilyOutcome{
		Result:   mapAuthResponseToResult(resp, rejectDangerous),
		Deferral: authDeferralInfo{Active: true, StaleNames: lowercaseSet(resp.Exclusion.StaleNames)},
	}
}

// validateAuthHelperResponse checks the shape of a "handled" (exit 0)
// helper response before it is trusted at all: a wrong contract version,
// a populated top-level error, or a missing/duplicate result for a
// requested server or facility all indicate the helper did not actually
// process this request the way exit 0 claims (a protocol mismatch, an
// internal bug, or truncated output that still happened to parse as
// valid JSON) — none of these should ever be silently mapped as success
// for whatever names DID come back.
func validateAuthHelperResponse(req authHelperRequest, resp authHelperSyncResponse) error {
	if resp.Contract != authHelperContractVersion {
		return fmt.Errorf("helper response contract %d != expected %d", resp.Contract, authHelperContractVersion)
	}
	if resp.Error != nil {
		return fmt.Errorf("helper reported an error on a 'handled' exit: %s", resp.Error.Code)
	}

	gotServers := make(map[string]int, len(resp.Servers))
	for _, s := range resp.Servers {
		gotServers[s.Name]++
	}
	for _, want := range req.Servers {
		switch gotServers[want.Name] {
		case 1:
			// exactly one result -- fine.
		case 0:
			return fmt.Errorf("helper response has no result for requested server %q", want.Name)
		default:
			return fmt.Errorf("helper response has %d results for requested server %q, want exactly 1", gotServers[want.Name], want.Name)
		}
	}

	for fname := range req.Facilities {
		if _, ok := resp.Facilities[fname]; !ok {
			return fmt.Errorf("helper response has no result for requested facility %q", fname)
		}
	}

	// A "handled" response with no exclusion.code is a protocol mismatch,
	// not "nothing was stale": an omitted/empty code decodes to a
	// zero-value authHelperExclusion, which mapAuthResponseToResult would
	// otherwise treat as authDeferralInfo{Active: true, StaleNames: {}} --
	// silently turning the stale-exclusion deferral off (fail OPEN) instead of triggering
	// the blanket deferral this validation function otherwise fails
	// closed into for every other missing/malformed field.
	if resp.Exclusion.Code == "" {
		return fmt.Errorf("helper response is missing exclusion.code")
	}
	return nil
}

// mapAuthResponseToResult turns a successfully-parsed helper response into
// the same SyncAPIItemResult shape every other SYNC_API family reports.
// Any server/facility outcome other than the clean-success set below feeds
// the task's errors (the reject-dangerous gate, order-consistency
// failures, name collisions, the dangling-token create check's refusal,
// etc. all surface this way: a policy-driven refusal FAILS the SYNC with
// an actionable reason, while every other family still applies).
// Local-server risk warnings and the shadowable-users count are logged
// only, never failures.
func mapAuthResponseToResult(resp authHelperSyncResponse, rejectDangerous bool) SyncAPIResult {
	log := logging.Named("SYNC_API")
	var results []SyncAPIItemResult
	var errs []string

	okServerActions := map[string]bool{"created": true, "updated": true, "unchanged": true, "deleted": true}
	for _, s := range resp.Servers {
		status := "success"
		if !okServerActions[s.Action] {
			status = "blocked"
		}
		item := SyncAPIItemResult{Type: "auth_server", Name: s.Name, Action: s.Action, Status: status, Code: s.Code}
		if status == "blocked" {
			item.Error = authServerBlockedMessage(s, resp.Release, rejectDangerous)
			errs = append(errs, item.Error)
		}
		results = append(results, item)
		for _, w := range s.Warnings {
			log.Warnw("AUTH: server warning", "name", s.Name, "warning", w)
		}
	}

	okFacilityActions := map[string]bool{"written": true, "unchanged": true}
	for fname, f := range resp.Facilities {
		status := "success"
		if !okFacilityActions[f.Action] {
			status = "blocked"
		}
		// Before/After travel on every auth_facility item, success or
		// blocked alike. Available is the resolution set an unresolved
		// entry was checked against -- reported only on a refusal, never on success,
		// so a caller keying on "Available present" cannot mistake a
		// clean write for a refusal that merely happened to resolve
		// everything.
		item := SyncAPIItemResult{
			Type: "auth_facility", Name: fname, Action: f.Action, Status: status, Code: f.Code,
			Before: f.Before, After: f.After,
		}
		if status == "blocked" {
			item.Available = f.Available
			item.Error = authFacilityBlockedMessage(fname, f, resp.Release)
			errs = append(errs, item.Error)
		}
		results = append(results, item)

		// Local-server risks are never a failure: NetDefense never
		// modifies a hand-made server, and none of the managed-server
		// guardrails apply to it — but they must still
		// reach the task response as a named warning, not just a log
		// line an operator would need device-log access to ever see.
		for _, local := range f.LocalServers {
			log.Warnw("AUTH: order names a hand-made server", "facility", fname, "server", local.Name, "risks", local.Risks)
			results = append(results, SyncAPIItemResult{
				Type:   "auth_local_server",
				Name:   local.Name,
				Action: "warning",
				Status: "warning",
				Code:   "ORDER_NAMES_LOCAL_SERVER",
				// Risks travels structurally too (SyncAPIItemResult.Risks)
				// so a consumer never has to rfind() "; risks: " out of
				// Error — the free-text form stays for a human reading
				// the log/task summary.
				Risks: local.Risks,
				Error: fmt.Sprintf("ORDER_NAMES_LOCAL_SERVER: facility %q names %q, a server NetDefense did not create; risks: %s",
					fname, local.Name, strings.Join(local.Risks, ", ")),
			})
		}
	}

	if resp.Exclusion.Code != "" && resp.Exclusion.Code != "OK" {
		log.Warnw("AUTH: reserved-name exclusion has coverage gaps this pass",
			"code", resp.Exclusion.Code, "stale_names", resp.Exclusion.StaleNames)
	}
	for _, w := range resp.Warnings {
		log.Warnw("AUTH: helper warning", "code", w.Code, "count", w.Count)
		// PRIVILEGED_LOCAL_USERS_SHADOWABLE and friends: informational
		// only (never a failure — NetDefense makes no guardrail claim
		// about local users/servers it did not create), but still named
		// in the task response rather than log-only.
		results = append(results, SyncAPIItemResult{
			Type:   "auth_warning",
			Name:   w.Code,
			Action: "warning",
			Status: "warning",
			Code:   w.Code,
			Error:  fmt.Sprintf("%s: count=%d", w.Code, w.Count),
		})
	}

	return SyncAPIResult{Success: len(errs) == 0, Results: results, Errors: errs}
}

// authServerInvalidSubcodeDetail maps every AuthServerAlgo::AUTH_SERVER_
// INVALID_* sub-code (PR #90 round 4, AuthServerAlgo.php's
// AUTH_SERVER_INVALID_CODES catalogue — validateServerName/
// validateServerFieldsShape/validateServerFieldsRequired) to a
// human-readable detail clause, plus the pre-round-4 generic fallback
// AUTH_SERVER_INVALID a helper predating that round (or an unexpected
// exception the helper's own allow-list check declines to surface
// verbatim) still reports. Grouped by rule CATEGORY, matching the PHP
// side's own stated granularity — not one entry per exact sub-reason.
var authServerInvalidSubcodeDetail = map[string]string{
	"AUTH_SERVER_INVALID":                  "one of this server's fields failed device-side validation",
	"AUTH_SERVER_INVALID_NAME":             "the server name is empty, too long, contains a disallowed character, has leading/trailing space, or is reserved (\"Local Database\"/\"Local API\")",
	"AUTH_SERVER_INVALID_UNKNOWN_FIELD":    "the request contained a field this agent/helper version does not recognize",
	"AUTH_SERVER_INVALID_FIELD_TYPE":       "a field had the wrong JSON type or an out-of-range value (e.g. ldap_port outside 1-65535)",
	"AUTH_SERVER_INVALID_CONTROL_CHARS":    "a field contained control characters",
	"AUTH_SERVER_INVALID_HOST":             "host is empty, too long, or contains a character outside [A-Za-z0-9.:-]",
	"AUTH_SERVER_INVALID_BASEDN":           "ldap_basedn is missing or exceeds the length limit",
	"AUTH_SERVER_INVALID_AUTHCN":           "ldap_authcn is missing or exceeds the length limit",
	"AUTH_SERVER_INVALID_ATTR_USER":        "ldap_attr_user does not match ^[A-Za-z][A-Za-z0-9-]*$",
	"AUTH_SERVER_INVALID_URLTYPE":          "ldap_urltype is not one of StartTLS/SSL - Encrypted/TCP - Standard, or TCP - Standard was set without nd_allow_cleartext_ldap acknowledged",
	"AUTH_SERVER_INVALID_PROTOCOL":         "ldap_protver must be \"3\" and ldap_scope must be \"one\" or \"subtree\"",
	"AUTH_SERVER_INVALID_EXTENDED_QUERY":   "ldap_extended_query does not parse as exactly one RFC 4515 filter item",
	"AUTH_SERVER_INVALID_BIND_PAIR":        "ldap_binddn and ldap_bindpw must both be set or both be empty (no anonymous-bind mismatch)",
	"AUTH_SERVER_INVALID_GROUPS":           "an invalid, too-long, or protected group name in ldap_sync_memberof_groups/ldap_sync_default_groups; memberOf sync enabled without Read properties (ldap_read_properties) or without Limit groups (ldap_sync_memberof_groups); or create_local_users enabled without memberOf sync or a non-empty default-group list",
	"AUTH_SERVER_INVALID_CASE_INSENSITIVE": "caseInSensitiveUsernames is only allowed when ldap_attr_user is one of sAMAccountName/uid/cn/mail/userPrincipalName",
	// The following are not AUTH_SERVER_INVALID_* sub-codes (they are
	// full outcome codes handled by the switch in authServerBlockedMessage
	// below), but share the same one-line-detail rendering, so they live
	// in the same map rather than a second one.
	"NAME_COLLISION_UNMANAGED": "a server with this exact name already exists on the device and NetDefense did not create it — rename the snippet or remove the hand-made server",
	"GROUP_NAME_AMBIGUOUS":     "a Limit or default group name matches a live group NetDefense does not manage (case-insensitive) — OPNsense would link that other group instead",
	"AUTH_EXCLUSION_TOO_LONG":  "the composed reserved-name exclusion exceeds the 16384-character cap; the names it could not fit are reported stale (USER_DEFERRED_EXCLUSION_STALE) until it shrinks",
}

// authServerBlockedMessage builds an actionable message for a server
// outcome outside the clean-success set — naming consumers (the
// CONSUMER_REFERENCED remedy), the reject-gate opt-out
// (dangerousSnippetRejectionMessage-style wording), and the
// per-rule AUTH_SERVER_INVALID_* sub-code detail (authServerInvalidSubcodeDetail
// above) where the code indicates them, plus the helper's own reported
// release (Go never runs a second version parser) for a floor
// rejection. rejectDangerous is this pass's own gate setting (not derived
// from s.Code), needed for the CONSUMER_REFERENCED/webadmin remedy below,
// which must qualify its instruction differently depending on whether
// NetDefense could even attempt the rewrite it is suggesting.
func authServerBlockedMessage(s authHelperServerResult, release string, rejectDangerous bool) string {
	msg := fmt.Sprintf("auth server %q: %s", s.Name, s.Code)
	switch {
	case s.Code == "AUTH_REJECTED_DANGEROUS":
		msg += "; rejected by local policy reject_dangerous_snippets: set reject_dangerous_snippets=false in the agent's local configuration to allow"
	case s.Code == "AUTH_VERSION_UNSUPPORTED":
		msg += fmt.Sprintf("; this device reports OPNsense release %q, below the 26.1.6 floor AUTH_SERVER mutations require", release)
	case s.Code == "CONSUMER_REFERENCED":
		if len(s.Consumers) > 0 {
			msg += fmt.Sprintf("; still referenced by: %s", strings.Join(s.Consumers, ", "))
		}
		// The qualified remedy: detaching the SERVER is blocked while
		// the webadmin order still names it, and the fix is to rewrite
		// the order policy first, not to detach the server. Consumers is
		// keyed by an XPath-ish label for every curated consumer EXCEPT
		// a facility, which is keyed by its plain facility name
		// (readLiveFacilityTokens()/AuthServerHelper.php) -- so this is
		// an exact-match check against the one v1 facility name, not a
		// substring/XPath match. This also covers a policy-less hand
		// edit of `authmode`: there is no policy to name, so the
		// remedy still says to remove the server from the order, whether
		// that order is a policy or a hand edit.
		if consumersNameFacility(s.Consumers, authFacilityWebadmin) {
			msg += fmt.Sprintf("; remove this server from the %q login order first (an AUTH_ORDER policy without it, or a change made directly on the device), then retry", authFacilityWebadmin)
			if rejectDangerous {
				msg += "; reject_dangerous_snippets is on, so NetDefense cannot rewrite the order itself — use CONNECT at remote_access_policy=full, or a local edit"
			}
		}
	case s.Code == "CREATE_ACTIVATES_LOGIN_PATH":
		if len(s.Consumers) > 0 {
			msg += fmt.Sprintf("; creating this server would activate a dangling login-order entry: %s", strings.Join(s.Consumers, ", "))
		}
		msg += "; retry once every order naming it is written or unchanged in the same save"
	default:
		if detail, ok := authServerInvalidSubcodeDetail[s.Code]; ok {
			msg += "; " + detail
		}
	}
	if len(s.ChangedFields) > 0 {
		msg += fmt.Sprintf("; changed fields: %s", strings.Join(s.ChangedFields, ", "))
	}
	return msg
}

// consumersNameFacility reports whether consumers (a CONSUMER_REFERENCED
// result's list of curated-consumer labels) includes the given facility
// name exactly -- the facility's own consumer-list key, distinct from
// every other curated consumer's XPath-ish label (see the doc comment
// on the CONSUMER_REFERENCED case above).
func consumersNameFacility(consumers []string, facility string) bool {
	for _, c := range consumers {
		if c == facility {
			return true
		}
	}
	return false
}

// authFacilityInvalidDetail is authFacilityBlockedMessage's equivalent of
// authServerInvalidSubcodeDetail above: a one-line detail clause for a
// facility fault code that the switch in authFacilityBlockedMessage does
// not already special-case with its own clause (unresolved entries,
// available, before, or the version floor).
var authFacilityInvalidDetail = map[string]string{
	"AUTH_ORDER_TOO_LONG":           "the order has more than 8 entries",
	"AUTH_ORDER_ENTRY_INVALID":      "an entry contains a comma, a control character, or is empty",
	"AUTH_ORDER_DUPLICATE_ENTRY":    "the same entry name (case-insensitive) appears more than once",
	"LOCAL_DATABASE_RULE_VIOLATION": "\"Local Database\" is missing or not first",
	"LOCAL_DATABASE_SHADOWED":       "a live server is literally named \"Local Database\", which OPNsense would use instead of the built-in local connector",
}

// authFacilityBlockedMessage mirrors authServerBlockedMessage for a
// facility outcome — naming the unresolved entries, the resolution set
// they were checked against, and the device's current (kept) order for
// AUTH_ORDER_UNRESOLVED/NOT_APPLIED/NAMES_REMOVED_SERVER, the
// reject-gate opt-out for AUTH_REJECTED_DANGEROUS (mirroring
// authServerBlockedMessage's own wording), and a one-line detail for any
// other fault code (authFacilityInvalidDetail above).
// `Available` is the helper's own reported resolution set ("the server
// names that do exist", checkRuleInterfaces-style wording) —
// use it for that, rather than `Before` (the device's kept order value,
// a distinct fact reported separately below). An older helper that
// predates the `available` field (round-3 PR #90) simply omits the key,
// which decodes to a nil slice here and is skipped.
func authFacilityBlockedMessage(fname string, f authHelperFacilityResult, release string) string {
	msg := fmt.Sprintf("auth order %q: %s", fname, f.Code)
	if len(f.Unresolved) > 0 {
		msg += fmt.Sprintf("; unresolved entries: %s", strings.Join(f.Unresolved, ", "))
	}
	if len(f.Available) > 0 {
		msg += fmt.Sprintf("; server names that do exist: %s", strings.Join(f.Available, ", "))
	}
	if len(f.Before) > 0 {
		msg += fmt.Sprintf("; facility kept its current order: %s", strings.Join(f.Before, ", "))
	}
	switch f.Code {
	case "AUTH_VERSION_UNSUPPORTED":
		msg += fmt.Sprintf("; this device reports OPNsense release %q, below the 26.1.6 floor AUTH_SERVER mutations require", release)
	case "AUTH_REJECTED_DANGEROUS":
		msg += "; rejected by local policy reject_dangerous_snippets: set reject_dangerous_snippets=false in the agent's local configuration to allow"
	default:
		if detail, ok := authFacilityInvalidDetail[f.Code]; ok {
			msg += "; " + detail
		}
	}
	return msg
}

func lowercaseSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToLower(n)] = true
	}
	return out
}

// computeReservedNamesDesired supplies the payload/live half of the
// reserved-name set that only NDAgent can see: every desired USER name and
// every member of every desired member-managed GROUP (a GROUP declared
// external_members:true in this pass's payload never carries members, so
// it contributes nothing here), unioned with the same for whatever is
// ALREADY live and managed — EXCLUDING the live members of any already-
// managed group this pass's payload marks external (directory-owned
// membership must never be composed into the exclusion; see the
// externalGroupNames comment inside this function for why the live half
// cannot tell external apart from member-managed on its own). The helper's
// own buildReservedNames() adds the static names (root, netdefense-agent,
// netdefense-readonly) and every live scope=system user on top of this,
// belt-and-braces (AuthServerHelper.php) — but that belt-and-braces only
// covers the STATIC names and scope=system users, never a NetDefense-
// managed automation user or member-managed GROUP member, which is exactly
// what `complete==false` protects: the caller (executeSyncAuth) refuses to
// start a new helper run at all rather than launch one against a set this
// function knows is incomplete: fail CLOSED, not
// open — a partial exclusion, once composed, never grows back on its own).
//
// complete is false only when a live listing call actually failed with a
// real (non-nil) client — a nil client is a test-only isolation seam
// (production always has API credentials by the time SYNC_API runs at
// all) and is reported complete, matching every existing nil-client test.
func computeReservedNamesDesired(ctx context.Context, client *opnapi.Client, users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload) (names []string, complete bool) {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}

	// externalGroupNames is built from THIS PASS's payload — it is the
	// only place "this group is external" is known at all. A live
	// OPNsense group carries no marker or tag recording external_members;
	// ConvertGroupToAPI (used below on the live side) always reports
	// ExternalMembers==false because there is nothing in the raw OPNsense
	// data to set it from. Without this cross-reference, the live loop
	// below would add every member of a live, already-managed external
	// group — directory accounts memberOf sync placed there included —
	// straight into the reserved-name exclusion, permanently locking those
	// same directory accounts out of every managed LDAP server (an
	// exclusion can only ever grow a name, never un-exclude it once
	// composed). See computeReservedNamesDesired's own tests for the
	// reproduction.
	externalGroupNames := make(map[string]bool, len(groups))
	for _, g := range groups {
		if g.ExternalMembers {
			externalGroupNames[g.Name] = true
			continue
		}
		for _, m := range g.Members {
			add(m)
		}
	}

	for _, u := range users {
		add(u.Name)
	}

	if client == nil {
		return out, true
	}

	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		logging.Named("SYNC_API").Warnw("AUTH: could not list live users for the reserved-name set; the caller must refuse to start a new helper run against this incomplete result", "error", err)
		return out, false
	}
	for _, mu := range opnapi.FilterManagedUsers(allUsers) {
		if name, ok := mu["name"].(string); ok {
			add(name)
		}
	}

	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		logging.Named("SYNC_API").Warnw("AUTH: could not list live groups for the reserved-name set; the caller must refuse to start a new helper run against this incomplete result", "error", err)
		return out, false
	}
	for _, mg := range opnapi.FilterManagedGroups(allGroups) {
		name, _ := mg["name"].(string)
		if externalGroupNames[name] {
			// This live, already-managed group is declared
			// external_members:true in this pass's payload — its
			// members are directory-owned (memberOf sync), never
			// NetDefense's to reserve. A live managed group that is
			// NOT in this pass's payload at all (about to be
			// orphan-deleted) falls through to the member-managed
			// branch below, which is the conservative (over-inclusive,
			// never under-inclusive) default absent payload evidence
			// either way.
			continue
		}
		api := opnapi.ConvertGroupToAPI(mg, allUsers)
		for _, m := range api.Members {
			add(m)
		}
	}

	return out, true
}

// -----------------------------------------------------------------
// Stale-exclusion deferral (consumed by executeSyncUsersGroups)
// -----------------------------------------------------------------

// authDeferralInfo carries the AUTH family's outcome into
// executeSyncUsersGroups, which runs immediately afterward in the same
// SYNC. The zero value defers nothing, so every call site that has
// nothing to do with AUTH (decommission's empty-desired-state reconcile,
// every existing test) passes authDeferralInfo{} unchanged.
type authDeferralInfo struct {
	// Active is false when AUTH never needed to run at all (no content, no
	// markers) — no deferral applies.
	Active bool
	// Blanket means the AUTH step did not complete for any reason (a
	// helper fault, AUTH_CONTENT_UNSUPPORTED) while the device already
	// carries managed AUTH markers: every name new this pass is treated as
	// stale, because there is no exclusion data at all to consult.
	Blanket bool
	// StaleNames is the normal case: the helper's own
	// exclusion.stale_names, lowercased.
	StaleNames map[string]bool
}

func (a authDeferralInfo) isDeferred(name string) bool {
	if !a.Active {
		return false
	}
	if a.Blanket {
		return true
	}
	return a.StaleNames[strings.ToLower(name)]
}

// authCodeUserDeferredExclusionStale is the structured Code for a
// "group_member"/"user" deferral item (sync_api.go). Every other AUTH
// result item carries a Code a consumer can key on together with Status,
// never on free-text parsing of Error — this is the one
// deferral shares with them, since until now it existed only inside
// authDeferredMessage's free text.
const authCodeUserDeferredExclusionStale = "USER_DEFERRED_EXCLUSION_STALE"

// authDeferredMessage explains a USER_DEFERRED_EXCLUSION_STALE outcome:
// this identity is a reserved/managed name that no managed AUTH_SERVER's
// exclusion currently covers, so creating it (or adding it to a
// member-managed GROUP) waits for a later pass — make-before-break, never
// the reverse.
func authDeferredMessage(kind, name string) string {
	return fmt.Sprintf(
		"deferred by AUTH exclusion staleness (%s): %s %q is not yet covered by every managed AUTH_SERVER's reserved-name exclusion; it will apply on a later sync once AUTH_SERVER coverage catches up",
		authCodeUserDeferredExclusionStale, kind, name,
	)
}

// filterDeferredGroupMembers splits a GROUP payload's desired Members into
// the safe-to-send subset and the ones to withhold this pass: a member is
// withheld only if it is NEW (not already in liveMembers, the group's
// member set from BEFORE this sync started) AND currently stale-excluded.
// An already-live member is never withheld, whatever the exclusion says —
// deferral is about preventing a NEW privileged identity from landing
// ahead of its exclusion, not about revoking one that was already there.
func filterDeferredGroupMembers(payload opnapi.APIGroupPayload, liveMembers map[string]bool, auth authDeferralInfo) (kept, deferred []string) {
	for _, m := range payload.Members {
		if !liveMembers[m] && auth.isDeferred(m) {
			deferred = append(deferred, m)
			continue
		}
		kept = append(kept, m)
	}
	return kept, deferred
}

// -----------------------------------------------------------------
// Decommission
// -----------------------------------------------------------------

// runAuthServerDecommission drives the helper's "decommission" mode: delete
// every server this device owns and reset every facility marker this
// device wrote, ignoring the reject_dangerous gate and the OPNsense-release
// floor (both exempt for decommission). Intentionally NOT gated on an
// OPNsense API client — auth servers have no REST API at all, so this
// family runs identically with or without one, unlike every other
// decommission family in decommission.go.
func runAuthServerDecommission(deviceUUID, configXMLPath string) error {
	if deviceUUID == "" {
		return fmt.Errorf("empty device_uuid")
	}

	req := authHelperRequest{
		Contract:   authHelperContractVersion,
		Mode:       "decommission",
		DeviceUUID: deviceUUID,
	}
	requestJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("build decommission request: %w", err)
	}

	stdout, exitCode, err := runAuthServersHelperFunc(requestJSON)
	if err != nil {
		return fmt.Errorf("auth_servers.php decommission: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("auth_servers.php decommission fault: %s", authHelperFaultCode(stdout))
	}

	var resp authHelperDecommissionResponse
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return fmt.Errorf("auth_servers.php decommission: response could not be parsed")
	}
	if !resp.PostConditionClean {
		return fmt.Errorf("auth_servers.php decommission: a marker naming this device still remains")
	}

	// Decommission's post-condition is "no marker naming THIS device's uuid
	// remains". The helper's own
	// PostConditionClean is ALSO a raw walk of the whole config document
	// (AuthServerHelper::rawScanForDeviceMarkers) rather than relying on
	// classifyLiveServers()'/facilityOwnerMarkerElement()'s assumptions
	// about where a marker node lives — an earlier round of this file's
	// own reasoning assumed otherwise and was stale. This Go-side rescan
	// stays anyway, as a second, independently-implemented check across
	// the language boundary (a bug in one scanner's tag/prefix matching
	// need not be a bug in the other's) — belt-and-braces, not a
	// substitute for the helper's own check. Fails open (logs a WARN,
	// does not block) on a read error, since decommission already
	// tolerates a step failing and retries with backoff; this is
	// verification, not the primary mechanism.
	if configXMLMarkerRemains(configXMLPath, deviceUUID) {
		return fmt.Errorf("auth_servers.php decommission: a marker naming this device's uuid still remains in config.xml (found by NDAgent's own rescan, independent of the helper's post_condition_clean)")
	}
	return nil
}

// configXMLMarkerRemains does a best-effort raw scan of config.xml for
// either ownership marker naming deviceUUID: a server marker
// (`<netdefense_owner>UUID</netdefense_owner>`) or a facility marker
// (`<netdefense_authmode_owner>UUID:...</netdefense_authmode_owner>`
// — the value is `<uuid>:<sha256>`, so the uuid is always the prefix up to
// the colon). Fails open (returns false, logs a WARN) on a read error —
// this is a defense-in-depth verification on top of the helper's own
// PostConditionClean, not the primary safety mechanism, and decommission's
// own retry-with-backoff already tolerates a step that cannot complete.
func configXMLMarkerRemains(configXMLPath, deviceUUID string) bool {
	if deviceUUID == "" {
		return false
	}
	data, err := os.ReadFile(configXMLPath)
	if err != nil {
		logging.Named("SYNC_API").Warnw("AUTH decommission: could not rescan config.xml for leftover markers",
			"path", configXMLPath, "error", err)
		return false
	}
	ownerTag := []byte("<netdefense_owner>" + deviceUUID + "</netdefense_owner>")
	authmodeTag := []byte("<netdefense_authmode_owner>" + deviceUUID + ":")
	return bytes.Contains(data, ownerTag) || bytes.Contains(data, authmodeTag)
}
