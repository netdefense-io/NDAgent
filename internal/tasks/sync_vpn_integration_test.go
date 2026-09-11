//go:build integration
// +build integration

package tasks

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// integrationClient builds an OPNsense client from the same environment
// variables ./internal/opnapi/'s integration suite uses.
func integrationClient(t *testing.T) *opnapi.Client {
	t.Helper()

	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	apiURL := os.Getenv("OPNSENSE_API_URL")

	if apiKey == "" || apiSecret == "" || apiURL == "" {
		t.Skip("OPNSENSE_API_KEY, OPNSENSE_API_SECRET, and OPNSENSE_API_URL must be set")
	}

	return opnapi.NewClient(apiURL, apiKey, apiSecret, true)
}

// Integration test for the WireGuard master-switch fix (Community #9).
//
// Run against the lab OPNsense with:
//
//	go test -tags=integration -run TestIntegration_SyncVPN ./internal/tasks/
//
// Required environment variables (same as ./internal/opnapi/):
//
//	OPNSENSE_API_KEY, OPNSENSE_API_SECRET, OPNSENSE_API_URL
//
// The device must already carry at least one NDAgent-managed WireGuard
// network (an `nd-vpn__` server); the test reconstructs its desired state
// from the device and re-syncs it, so it converges back to what was there.
// It deliberately mutates the master switch and restores it on cleanup.

// vpnNetworkFromDevice rebuilds a VPNNetwork from the managed WireGuard
// state currently on the device, so the re-sync is a no-op update rather
// than a new network. Returns false when the device carries no managed
// network to exercise.
func vpnNetworkFromDevice(ctx context.Context, t *testing.T, client *opnapi.Client) (VPNNetwork, bool) {
	t.Helper()

	servers, err := client.SearchServers(ctx, opnapi.NDAgentWireGuardPrefix)
	if err != nil {
		t.Fatalf("SearchServers() error = %v", err)
	}
	managed := opnapi.FilterManagedWireGuardServers(servers)
	if len(managed) == 0 {
		return VPNNetwork{}, false
	}

	server := managed[0]
	serverName, _ := server["name"].(string)
	serverUUID, _ := server["uuid"].(string)
	networkName := strings.TrimPrefix(serverName, opnapi.NDAgentWireGuardPrefix)

	port := 0
	if p, ok := server["port"].(string); ok {
		port, _ = strconv.Atoi(p)
	}

	privKey, _ := server["privkey"].(string)
	tunnelAddress, _ := server["tunneladdress"].(string)

	network := VPNNetwork{
		NetworkName: networkName,
		Interface: VPNInterface{
			PrivateKey: privKey,
			Address:    tunnelAddress,
			ListenPort: port,
		},
	}

	clients, err := client.SearchClients(ctx, opnapi.NDAgentWireGuardPrefix)
	if err != nil {
		t.Fatalf("SearchClients() error = %v", err)
	}
	for _, c := range opnapi.FilterManagedWireGuardClients(clients) {
		if servers, _ := c["servers"].(string); !strings.Contains(servers, serverUUID) {
			continue
		}
		name, _ := c["name"].(string)
		peerName := strings.TrimPrefix(name, opnapi.BuildClientName(networkName, ""))
		pubKey, _ := c["pubkey"].(string)
		tunnel, _ := c["tunneladdress"].(string)

		var allowedIPs []string
		for _, part := range strings.Split(tunnel, ",") {
			if p := strings.TrimSpace(part); p != "" {
				allowedIPs = append(allowedIPs, p)
			}
		}

		network.Peers = append(network.Peers, VPNPeer{
			PeerName:   peerName,
			PublicKey:  pubKey,
			AllowedIPs: allowedIPs,
		})
	}

	return network, true
}

func hasWireGuardInterfaceGroup(ctx context.Context, t *testing.T, client *opnapi.Client) bool {
	t.Helper()

	interfaces, err := client.GetInterfaceList(ctx)
	if err != nil {
		t.Fatalf("GetInterfaceList() error = %v", err)
	}
	for _, iface := range interfaces {
		if iface == wireGuardInterfaceGroup {
			return true
		}
	}
	return false
}

// TestIntegration_SyncVPNEnablesMasterSwitch is the on-device reproduction
// of Community #9: with the WireGuard plugin disabled, the `wireguard`
// interface group does not exist and a rule targeting it is rejected. One
// VPN sync must turn the plugin on, bring the interface up, and make the
// group appear — so a first-time setup converges in a single pass.
func TestIntegration_SyncVPNEnablesMasterSwitch(t *testing.T) {
	client := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	network, ok := vpnNetworkFromDevice(ctx, t, client)
	if !ok {
		t.Skip("device carries no NDAgent-managed WireGuard network to exercise")
	}
	networks := []VPNNetwork{network}

	original, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() error = %v", err)
	}
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer restoreCancel()
		if err := client.SetWireGuardGeneral(restoreCtx, original); err != nil {
			t.Errorf("failed to restore WireGuard master switch to %q: %v", original.Enabled, err)
		}
		if err := client.ReconfigureWireGuard(restoreCtx); err != nil {
			t.Errorf("failed to reconfigure WireGuard during restore: %v", err)
		}
	})

	// Reproduce the reported device state: master switch off.
	if err := client.SetWireGuardGeneral(ctx, opnapi.WireGuardGeneral{Enabled: "0"}); err != nil {
		t.Fatalf("failed to disable WireGuard for the repro: %v", err)
	}
	if err := client.ReconfigureWireGuard(ctx); err != nil {
		t.Fatalf("failed to reconfigure WireGuard for the repro: %v", err)
	}
	if hasWireGuardInterfaceGroup(ctx, t, client) {
		t.Fatal("precondition failed: the wireguard interface group is still present with the plugin disabled")
	}
	t.Log("repro state reached: WireGuard disabled, no wireguard interface group")

	// One sync must converge.
	result := executeSyncVPN(ctx, client, networks)
	if !result.Success {
		t.Fatalf("VPN sync failed: %v", result.Errors)
	}

	general, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() after sync error = %v", err)
	}
	if general.Enabled != "1" {
		t.Errorf("master switch after sync = %q, want \"1\"", general.Enabled)
	}
	if !hasWireGuardInterfaceGroup(ctx, t, client) {
		t.Error("the wireguard interface group is still missing after a VPN sync")
	}
	t.Log("after one sync: master switch on, wireguard interface group present")

	// A second sync must be a clean no-op and must not disturb the switch.
	if result := executeSyncVPN(ctx, client, networks); !result.Success {
		t.Fatalf("second VPN sync failed: %v", result.Errors)
	}
	general, err = client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() after second sync error = %v", err)
	}
	if general.Enabled != "1" {
		t.Errorf("master switch after second sync = %q, want \"1\"", general.Enabled)
	}
	if !hasWireGuardInterfaceGroup(ctx, t, client) {
		t.Error("the wireguard interface group went missing after the second sync")
	}
}

// TestIntegration_SyncVPNLeavesEnabledDeviceUndisturbed pins that a device
// whose plugin is already on is not rewritten: the executor reads the
// master switch and elides the redundant write (no config revision cut).
func TestIntegration_SyncVPNLeavesEnabledDeviceUndisturbed(t *testing.T) {
	client := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	network, ok := vpnNetworkFromDevice(ctx, t, client)
	if !ok {
		t.Skip("device carries no NDAgent-managed WireGuard network to exercise")
	}

	original, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() error = %v", err)
	}
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer restoreCancel()
		if err := client.SetWireGuardGeneral(restoreCtx, original); err != nil {
			t.Errorf("failed to restore WireGuard master switch: %v", err)
		}
	})

	if err := client.SetWireGuardGeneral(ctx, opnapi.WireGuardGeneral{Enabled: "1"}); err != nil {
		t.Fatalf("failed to enable WireGuard for the test: %v", err)
	}
	if err := client.ReconfigureWireGuard(ctx); err != nil {
		t.Fatalf("failed to reconfigure WireGuard: %v", err)
	}

	if result := executeSyncVPN(ctx, client, []VPNNetwork{network}); !result.Success {
		t.Fatalf("VPN sync failed: %v", result.Errors)
	}

	general, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() after sync error = %v", err)
	}
	if general.Enabled != "1" {
		t.Errorf("master switch after sync = %q, want it left on", general.Enabled)
	}
	if !hasWireGuardInterfaceGroup(ctx, t, client) {
		t.Error("the wireguard interface group is missing on an already-enabled device")
	}
}

// TestIntegration_CheckRuleInterfacesNamesMissingGroup exercises the
// pre-flight against the real device in both states: with the plugin off
// the `wireguard` group is missing and a rule targeting it must produce a
// message naming the rule and the group; with it on, the same rule passes.
func TestIntegration_CheckRuleInterfacesNamesMissingGroup(t *testing.T) {
	client := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	original, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		t.Fatalf("GetWireGuardGeneral() error = %v", err)
	}
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer restoreCancel()
		if err := client.SetWireGuardGeneral(restoreCtx, original); err != nil {
			t.Errorf("failed to restore WireGuard master switch: %v", err)
		}
		if err := client.ReconfigureWireGuard(restoreCtx); err != nil {
			t.Errorf("failed to reconfigure WireGuard during restore: %v", err)
		}
	})

	rules := []APIRulePayload{{
		UUID:        opnapi.NDAgentUUIDPrefix + "-preflight-probe",
		Description: "Allow VPN clients to LAN",
		Interface:   wireGuardInterfaceGroup,
	}}

	// Plugin off — the group does not exist, the pre-flight must say so.
	if err := client.SetWireGuardGeneral(ctx, opnapi.WireGuardGeneral{Enabled: "0"}); err != nil {
		t.Fatalf("failed to disable WireGuard: %v", err)
	}
	if err := client.ReconfigureWireGuard(ctx); err != nil {
		t.Fatalf("failed to reconfigure WireGuard: %v", err)
	}

	errs := checkRuleInterfaces(ctx, client, rules)
	if len(errs) != 1 {
		t.Fatalf("expected 1 validation error with WireGuard disabled, got %d: %+v", len(errs), errs)
	}
	if errs[0].ErrorCode != "INTERFACE_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want INTERFACE_NOT_FOUND", errs[0].ErrorCode)
	}
	for _, want := range []string{"Allow VPN clients to LAN", wireGuardInterfaceGroup} {
		if !strings.Contains(errs[0].Message, want) {
			t.Errorf("message %q missing %q", errs[0].Message, want)
		}
	}
	t.Logf("pre-flight message with WireGuard disabled: %s", errs[0].Message)

	// Plugin on — the group exists and the same rule must pass.
	if err := client.SetWireGuardGeneral(ctx, opnapi.WireGuardGeneral{Enabled: "1"}); err != nil {
		t.Fatalf("failed to enable WireGuard: %v", err)
	}
	if err := client.ReconfigureWireGuard(ctx); err != nil {
		t.Fatalf("failed to reconfigure WireGuard: %v", err)
	}

	if errs := checkRuleInterfaces(ctx, client, rules); len(errs) != 0 {
		t.Errorf("expected no validation errors with WireGuard enabled, got %+v", errs)
	}
}
