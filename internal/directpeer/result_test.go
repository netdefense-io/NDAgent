package directpeer

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const vectorConnectID = "eff97f3e3ad593d08e250b5a5e492449"

// vectorResponses reads the four responses of the shared vector as the JSON
// values they are.
func vectorResponses(t *testing.T) map[string]map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(contractVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Responses map[string]map[string]interface{} `json:"responses"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Responses) != 4 {
		t.Fatalf("the vector has %d responses, want 4", len(v.Responses))
	}
	return v.Responses
}

// asJSON is what a result is once signed: status, message and the object
// that passes the last check, through JSON.
func asJSON(t *testing.T, r Result) map[string]interface{} {
	t.Helper()
	clean, ok := CleanResult(r.Status, r.Connect)
	if !ok {
		t.Fatalf("CleanResult refuses the result %+v", r)
	}
	raw, err := json.Marshal(map[string]interface{}{"status": r.Status, "message": r.Message, ResultKey: clean})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheResultsAreTheVectors(t *testing.T) {
	want := vectorResponses(t)
	got := map[string]Result{
		"listening": ListeningResult(vectorConnectID),
		"session_end": SessionEndResult(vectorConnectID, SessionEnd{
			Reason: EndClientClosed, Duration: 1832*time.Second + 900*time.Millisecond,
			Paired: true, PairedAfter: 4*time.Second + 999*time.Millisecond, Path: PathDirect,
		}),
		"failed": FailedResult(vectorConnectID, FailUnsealFailed),
		"closed": ClosedResult(vectorConnectID, true),
	}
	for name, result := range got {
		if !reflect.DeepEqual(asJSON(t, result), want[name]) {
			gotJSON, _ := json.Marshal(asJSON(t, result))
			wantJSON, _ := json.Marshal(want[name])
			t.Errorf("%s:\n got  %s\n want %s", name, gotJSON, wantJSON)
		}
	}
}

// The texts other modules show, spelled out: a table changed to match its
// test would agree with it.
func TestTheMessagesAreTheContracts(t *testing.T) {
	ends := map[string]string{
		"client_closed":    "Remote session ended: the client closed the session",
		"client_timeout":   "Remote session ended: the client stopped responding",
		"no_client":        "Remote session ended: no client connected in time",
		"idle_timeout":     "Remote session ended: idle for too long",
		"max_duration":     "Remote session ended: the maximum session time was reached",
		"closed":           "Remote session ended: closed on request",
		"agent_shutdown":   "Remote session ended: the agent stopped",
		"companion_exited": "Remote session ended: the session process stopped unexpectedly",
		"error":            "Remote session ended: an error ended the session",
	}
	if len(ends) != len(EndReasons) {
		t.Fatalf("%d end messages for %d reasons", len(ends), len(EndReasons))
	}
	for _, reason := range EndReasons {
		r := SessionEndResult(vectorConnectID, SessionEnd{Reason: reason})
		if r.Message != ends[reason] || r.Status != "COMPLETED" || r.Connect["reason"] != reason {
			t.Errorf("%s: %+v", reason, r)
		}
		if _, ok := CleanResult(r.Status, r.Connect); !ok {
			t.Errorf("%s: CleanResult refuses it", reason)
		}
	}

	if got := ListeningResult(vectorConnectID).Message; got != "Remote session ready" {
		t.Errorf("listening message %q", got)
	}
	if got := ClosedResult(vectorConnectID, true).Message; got != "Remote session closed" {
		t.Errorf("closed message %q", got)
	}
	if got := ClosedResult(vectorConnectID, false).Message; got != "No such remote session" {
		t.Errorf("closed, not found, message %q", got)
	}
	if got := FailedResult(vectorConnectID, FailUnsupportedAction).Message; got != "Remote session refused: the request is not one this agent can read" {
		t.Errorf("unsupported_action message %q", got)
	}

	for _, reason := range FailureReasons {
		r := FailedResult(vectorConnectID, reason)
		if r.Status != "FAILED" || r.Connect["reason"] != reason || !strings.HasPrefix(r.Message, "Remote session refused: ") ||
			len(r.Message) <= len("Remote session refused: ") {
			t.Errorf("%s: %+v", reason, r)
		}
		for _, word := range []string{"ndagent-connect", "tailscale", "tailcat", "derp", "DERP", "NDBroker", "NDManager", "PathFinder", "wireguard", "WireGuard"} {
			if strings.Contains(r.Message, word) {
				t.Errorf("%s: the message names %q: %s", reason, word, r.Message)
			}
		}
		if _, ok := CleanResult(r.Status, r.Connect); !ok {
			t.Errorf("%s: CleanResult refuses it", reason)
		}
	}
}

func TestAnUnknownReasonIsReportedAsTheGeneralOne(t *testing.T) {
	end := SessionEndResult(vectorConnectID, SessionEnd{Reason: "stdin_closed"})
	if end.Connect["reason"] != "error" || end.Message != "Remote session ended: an error ended the session" {
		t.Errorf("end: %+v", end)
	}
	failed := FailedResult(vectorConnectID, "bad_config")
	if failed.Connect["reason"] != "internal" || failed.Message != "Remote session refused: an internal error on the device" {
		t.Errorf("failed: %+v", failed)
	}
}

func TestASessionEndSaysWhetherAClientConnected(t *testing.T) {
	none := SessionEndResult(vectorConnectID, SessionEnd{Reason: EndNoClient, Duration: 300 * time.Second, Path: PathDirect})
	if _, has := none.Connect["paired_after_seconds"]; has || none.Connect["path"] != "none" || none.Connect["duration_seconds"] != 300 {
		t.Errorf("no client: %+v", none.Connect)
	}
	// A client connected and the companion never named a path.
	unnamed := SessionEndResult(vectorConnectID, SessionEnd{Reason: EndClientClosed, Paired: true})
	if unnamed.Connect["path"] != "relayed" || unnamed.Connect["paired_after_seconds"] != 0 {
		t.Errorf("unnamed path: %+v", unnamed.Connect)
	}
	negative := SessionEndResult(vectorConnectID, SessionEnd{Reason: EndError, Duration: -time.Minute, Paired: true, PairedAfter: -time.Second})
	if negative.Connect["duration_seconds"] != 0 || negative.Connect["paired_after_seconds"] != 0 {
		t.Errorf("negative times: %+v", negative.Connect)
	}
	for _, r := range []Result{none, unnamed, negative} {
		if _, ok := CleanResult(r.Status, r.Connect); !ok {
			t.Errorf("CleanResult refuses %+v", r.Connect)
		}
	}
}

func TestCleanResultKeepsOnlyWhatTheContractNames(t *testing.T) {
	good := func() map[string]interface{} {
		return map[string]interface{}{
			"event": "session-end", "connect_id": vectorConnectID, "protocol": float64(1), "reason": "client_closed",
			"duration_seconds": float64(1832), "paired_after_seconds": float64(4), "path": "direct",
		}
	}
	clean, ok := CleanResult("COMPLETED", good())
	if !ok {
		t.Fatal("the vector's session-end, as read back from JSON, is refused")
	}
	if clean["protocol"] != 1 || clean["duration_seconds"] != 1832 || clean["paired_after_seconds"] != 4 {
		t.Errorf("numbers read back: %#v", clean)
	}

	extra := good()
	extra["seed"] = "b2bb"
	extra["detail"] = "dial tcp 10.0.0.1:443"
	clean, ok = CleanResult("COMPLETED", extra)
	if !ok || len(clean) != 7 {
		t.Fatalf("extra keys: ok %v, %#v", ok, clean)
	}
	if _, has := clean["seed"]; has {
		t.Error("an extra key was kept")
	}

	refused := map[string]struct {
		status string
		change func(m map[string]interface{})
	}{
		"a session-end as FAILED":           {"FAILED", nil},
		"an in-progress status":             {"IN_PROGRESS", nil},
		"no event":                          {"COMPLETED", func(m map[string]interface{}) { delete(m, "event") }},
		"an unknown event":                  {"COMPLETED", func(m map[string]interface{}) { m["event"] = "ready" }},
		"no session id":                     {"COMPLETED", func(m map[string]interface{}) { delete(m, "connect_id") }},
		"a session id in upper case":        {"COMPLETED", func(m map[string]interface{}) { m["connect_id"] = strings.ToUpper(vectorConnectID) }},
		"a short session id":                {"COMPLETED", func(m map[string]interface{}) { m["connect_id"] = vectorConnectID[:31] }},
		"a session id that is not hex":      {"COMPLETED", func(m map[string]interface{}) { m["connect_id"] = vectorConnectID[:31] + "g" }},
		"no protocol":                       {"COMPLETED", func(m map[string]interface{}) { delete(m, "protocol") }},
		"protocol 0":                        {"COMPLETED", func(m map[string]interface{}) { m["protocol"] = 0 }},
		"protocol as text":                  {"COMPLETED", func(m map[string]interface{}) { m["protocol"] = "1" }},
		"protocol 1.5":                      {"COMPLETED", func(m map[string]interface{}) { m["protocol"] = 1.5 }},
		"protocol beyond 65535":             {"COMPLETED", func(m map[string]interface{}) { m["protocol"] = 65536 }},
		"a reason of the companion":         {"COMPLETED", func(m map[string]interface{}) { m["reason"] = "peer_closed" }},
		"a failure reason":                  {"COMPLETED", func(m map[string]interface{}) { m["reason"] = "unseal_failed" }},
		"no reason":                         {"COMPLETED", func(m map[string]interface{}) { delete(m, "reason") }},
		"no duration":                       {"COMPLETED", func(m map[string]interface{}) { delete(m, "duration_seconds") }},
		"a negative duration":               {"COMPLETED", func(m map[string]interface{}) { m["duration_seconds"] = -1 }},
		"an unknown path":                   {"COMPLETED", func(m map[string]interface{}) { m["path"] = "derp" }},
		"no path":                           {"COMPLETED", func(m map[string]interface{}) { delete(m, "path") }},
		"paired, on no path":                {"COMPLETED", func(m map[string]interface{}) { m["path"] = "none" }},
		"a path, never paired":              {"COMPLETED", func(m map[string]interface{}) { delete(m, "paired_after_seconds") }},
		"paired after a fraction":           {"COMPLETED", func(m map[string]interface{}) { m["paired_after_seconds"] = 0.5 }},
		"a failed event as COMPLETED":       {"COMPLETED", func(m map[string]interface{}) { m["event"] = "failed"; m["reason"] = "unseal_failed" }},
		"a failed event with an end reason": {"FAILED", func(m map[string]interface{}) { m["event"] = "failed" }},
		"a closed event without found":      {"COMPLETED", func(m map[string]interface{}) { m["event"] = "closed" }},
		"a closed event, found as text":     {"COMPLETED", func(m map[string]interface{}) { m["event"] = "closed"; m["found"] = "true" }},
		"a closed event as FAILED":          {"FAILED", func(m map[string]interface{}) { m["event"] = "closed"; m["found"] = true }},
		"a listening event as FAILED":       {"FAILED", func(m map[string]interface{}) { m["event"] = "listening" }},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			m := good()
			if c.change != nil {
				c.change(m)
			}
			if clean, ok := CleanResult(c.status, m); ok {
				t.Fatalf("accepted: %#v", clean)
			}
		})
	}

	for name, v := range map[string]interface{}{
		"nil": nil, "text": "listening", "a list": []interface{}{}, "a typed map": map[string]string{"event": "listening"},
	} {
		if _, ok := CleanResult("COMPLETED", v); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestResultEvent(t *testing.T) {
	if got := ResultEvent(ListeningResult(vectorConnectID).Data()); got != "listening" {
		t.Errorf("got %q", got)
	}
	for _, data := range []map[string]interface{}{nil, {}, {"connect": "x"}, {"connect": map[string]interface{}{"event": 1}}} {
		if got := ResultEvent(data); got != "" {
			t.Errorf("%v: got %q", data, got)
		}
	}
}

func TestValidConnectID(t *testing.T) {
	if !ValidConnectID(vectorConnectID) {
		t.Error("the vector's id is refused")
	}
	for _, id := range []string{"", vectorConnectID + "0", vectorConnectID[:31], strings.ToUpper(vectorConnectID), vectorConnectID[:31] + " ", "../../../../etc/passwd0000000000"} {
		if ValidConnectID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}
