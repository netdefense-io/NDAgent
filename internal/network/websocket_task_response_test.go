package network

import (
	"reflect"
	"testing"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// TestBuildTaskResponseInner_CarriesErrors asserts that data["errors"]
// reaches the signed envelope's payload, exactly like results and
// validation_errors already do.
func TestBuildTaskResponseInner_CarriesErrors(t *testing.T) {
	log := logging.Named("test")

	data := map[string]interface{}{
		"results": []map[string]interface{}{
			{"type": "alias", "name": "Console_PKI", "action": "updated", "status": "success"},
			{"type": "group", "name": "NDAdmins", "action": "updated", "status": "success"},
		},
		"validation_errors": []string{},
		"errors":            []string{"Alias reconfigure: timeout"},
	}

	inner := buildTaskResponseInner("FAILED", "Aliases ~1; Groups ~1 (1 errors)", data, log)

	got, ok := inner["errors"]
	if !ok {
		t.Fatalf("buildTaskResponseInner dropped data[\"errors\"] — got keys %v", keysOf(inner))
	}
	want := data["errors"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inner[\"errors\"] = %#v, want %#v", got, want)
	}

	// results/validation_errors/status/message must still be carried through.
	if _, ok := inner["results"]; !ok {
		t.Error("inner[\"results\"] missing")
	}
	if _, ok := inner["validation_errors"]; !ok {
		t.Error("inner[\"validation_errors\"] missing")
	}
	if inner["status"] != "FAILED" || inner["message"] != "Aliases ~1; Groups ~1 (1 errors)" {
		t.Errorf("status/message not carried through: %#v", inner)
	}
}

// TestBuildTaskResponseInner_NoErrorsKeyWhenAbsent asserts a clean
// COMPLETED response never grows a spurious "errors" key.
func TestBuildTaskResponseInner_NoErrorsKeyWhenAbsent(t *testing.T) {
	log := logging.Named("test")

	data := map[string]interface{}{
		"results": []map[string]interface{}{
			{"type": "alias", "name": "Console_PKI", "action": "updated", "status": "success"},
		},
	}

	inner := buildTaskResponseInner("COMPLETED", "Aliases ~1", data, log)

	if _, ok := inner["errors"]; ok {
		t.Errorf("inner[\"errors\"] present with no source data[\"errors\"]: %#v", inner)
	}
}

// TestBuildTaskResponseInner_NilData covers the non-SYNC task shape (e.g.
// PING/RESTART), which calls SendTaskResponse with a nil data map.
func TestBuildTaskResponseInner_NilData(t *testing.T) {
	log := logging.Named("test")

	inner := buildTaskResponseInner("COMPLETED", "pong", nil, log)

	want := map[string]interface{}{"status": "COMPLETED", "message": "pong"}
	if !reflect.DeepEqual(inner, want) {
		t.Errorf("buildTaskResponseInner(nil data) = %#v, want %#v", inner, want)
	}
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
