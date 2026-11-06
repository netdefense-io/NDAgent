//go:build integration
// +build integration

package opnapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Reads and writes the settings model only. It never calls reconfigure or
// starts a service: a reconfigure contacts CrowdSec's servers.
func TestIntegration_CrowdsecSettingsRoundTrip(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	original, err := client.GetCrowdsecGeneral(ctx)
	if err != nil {
		if IsNotFound(err) {
			t.Skip("os-crowdsec is not installed on this device")
		}
		t.Fatalf("GetCrowdsecGeneral() error = %v", err)
	}
	for _, key := range []string{"agent_enabled", "lapi_enabled", "firewall_bouncer_enabled", "lapi_manual_configuration", "rules_enabled", "rules_log", "rules_tag", "enroll_key", "crowdsec_firewall_verbose"} {
		if _, ok := original[key]; !ok {
			t.Errorf("the settings model has no %q", key)
		}
	}

	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer restoreCancel()
		if err := client.SetCrowdsecGeneral(restoreCtx, map[string]string{"rules_tag": original["rules_tag"]}); err != nil {
			t.Errorf("restoring rules_tag failed: %v", err)
		}
	})

	if err := client.SetCrowdsecGeneral(ctx, map[string]string{"rules_tag": "ndintegration"}); err != nil {
		t.Fatalf("SetCrowdsecGeneral() error = %v", err)
	}
	after, err := client.GetCrowdsecGeneral(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after["rules_tag"] != "ndintegration" {
		t.Errorf("rules_tag = %q after a partial set", after["rules_tag"])
	}
	for key, value := range original {
		if key != "rules_tag" && after[key] != value {
			t.Errorf("a partial set changed %q", key)
		}
	}

	err = client.SetCrowdsecGeneral(ctx, map[string]string{"rules_tag": "not a valid tag"})
	var verr *CrowdsecValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("an invalid tag must come back as a validation error, got %v", err)
	}
	if _, ok := verr.Fields["rules_tag"]; !ok {
		t.Errorf("validation fields = %v", verr.Fields)
	}

	status, err := client.CrowdsecServiceStatus(ctx)
	if err != nil {
		t.Fatalf("CrowdsecServiceStatus() error = %v", err)
	}
	switch status {
	case "running", "stopped", "disabled":
	default:
		t.Errorf("unexpected service status %q", status)
	}
}
