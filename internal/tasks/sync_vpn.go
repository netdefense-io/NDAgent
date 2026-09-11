package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// VPNNetwork represents a single VPN network configuration from the sync payload.
type VPNNetwork struct {
	NetworkName string       `json:"network_name"`
	Interface   VPNInterface `json:"interface"`
	Peers       []VPNPeer    `json:"peers"`
}

// VPNInterface represents the WireGuard interface (server) configuration.
type VPNInterface struct {
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	MTU        *int   `json:"mtu,omitempty"`
}

// VPNPeer represents a single WireGuard peer (client) configuration.
type VPNPeer struct {
	PeerName            string   `json:"peer_name"`
	PublicKey           string   `json:"public_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	EndpointHost        *string  `json:"endpoint_host"`
	EndpointPort        *int     `json:"endpoint_port"`
	PresharedKey        *string  `json:"preshared_key"`
	PersistentKeepalive *int     `json:"persistent_keepalive"`
}

// parseVPNNetworks extracts vpn_networks from the sync payload.
// Returns an empty slice if the field is absent.
func parseVPNNetworks(payload map[string]interface{}) ([]VPNNetwork, error) {
	raw, ok := payload["vpn_networks"]
	if !ok {
		return []VPNNetwork{}, nil
	}

	// Re-marshal and unmarshal to leverage JSON struct tags
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vpn_networks: %w", err)
	}

	var networks []VPNNetwork
	if err := json.Unmarshal(jsonBytes, &networks); err != nil {
		return nil, fmt.Errorf("failed to parse vpn_networks: %w", err)
	}

	return networks, nil
}

// executeSyncVPN performs declarative sync of WireGuard VPN networks.
// It follows the same idempotent pattern as alias/rule sync:
// search for existing managed resources, create/update desired state, delete orphans.
func executeSyncVPN(ctx context.Context, client *opnapi.Client, networks []VPNNetwork) SyncAPIResult {
	log := logging.Named("SYNC_VPN")

	result := SyncAPIResult{
		Success: true,
		Message: "VPN sync completed",
	}

	// Phase 1: Discovery — find all managed WireGuard resources
	log.Info("Phase 1: Discovering existing managed WireGuard resources")

	allServers, err := client.SearchServers(ctx, opnapi.NDAgentWireGuardPrefix)
	if err != nil {
		if opnapi.IsNotFound(err) {
			// os-wireguard plugin isn't installed on this device. Treat
			// the whole VPN sync as a silent no-op — same behavior the
			// Zabbix executor has when os-zabbix-agent is absent.
			log.Debug("WireGuard plugin not installed on this device; skipping VPN sync")
			return SyncAPIResult{
				Success: true,
				Message: "No changes applied",
			}
		}
		result.Success = false
		result.Message = fmt.Sprintf("Failed to search WireGuard servers: %v", err)
		result.Errors = append(result.Errors, result.Message)
		return result
	}
	managedServers := opnapi.FilterManagedWireGuardServers(allServers)

	allClients, err := client.SearchClients(ctx, opnapi.NDAgentWireGuardPrefix)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to search WireGuard clients: %v", err)
		result.Errors = append(result.Errors, result.Message)
		return result
	}
	managedClients := opnapi.FilterManagedWireGuardClients(allClients)

	// Build name→UUID maps from current state
	currentServerUUIDs := make(map[string]string) // name → UUID
	for _, s := range managedServers {
		name, _ := s["name"].(string)
		uuid, _ := s["uuid"].(string)
		if name != "" && uuid != "" {
			currentServerUUIDs[name] = uuid
		}
	}

	currentClientUUIDs := make(map[string]string)
	for _, c := range managedClients {
		name, _ := c["name"].(string)
		uuid, _ := c["uuid"].(string)
		if name != "" && uuid != "" {
			currentClientUUIDs[name] = uuid
		}
	}

	log.Infow("Discovery complete",
		"managed_servers", len(currentServerUUIDs),
		"managed_clients", len(currentClientUUIDs),
	)

	// Phase 1.5: Enable the WireGuard master switch when this device is
	// meant to carry VPN configuration.
	//
	// NetDefense config is authoritative: if a WireGuard network is being
	// synced to this device, WireGuard is turned on — every sync, no local
	// state tracking, no first-time-only guard, no attempt to detect an
	// operator's intent. Disabling the plugin by hand on the box is not a
	// supported way to leave a VPN; the supported way is to remove the
	// device from the network in NetDefense, which empties `networks` here
	// and takes the enable with it.
	//
	// Without this, a device whose master switch is off materializes the
	// wg_server/wg_client objects and reconfigures, but the plugin creates
	// no wgN interface — so OPNsense's `wireguard` interface group never
	// appears and any rule targeting it is rejected with
	// `Option [wireguard] not in list.`
	// Gated on a network that will actually be realized, not merely on one
	// being present in the payload. Deriving the public key is the only way
	// a network can fail before any API call, so a payload whose every
	// network is malformed must not flip the master switch on and then fail
	// — that would leave the plugin enabled with nothing behind it.
	if anyRealizableNetwork(networks) {
		if err := ensureWireGuardEnabled(ctx, client); err != nil {
			// Record and carry on rather than returning. The orphan sweep in
			// Phases 4 and 5 is the teardown half of this executor and does
			// not depend on the master switch; skipping it would strand
			// managed servers and clients on the device because an unrelated
			// call failed. Same rule as checkRuleInterfaces: a check that
			// coexists with an orphan sweep must not abort before it.
			//
			// The task still fails — errMsg lands in result.Errors — so this
			// is never silent.
			errMsg := fmt.Sprintf("Failed to enable WireGuard: %v", err)
			log.Errorw(errMsg)
			result.Errors = append(result.Errors, errMsg)
			result.Success = false
		}
	}

	// Track desired names for orphan detection
	desiredServerNames := make(map[string]bool)
	desiredClientNames := make(map[string]bool)

	// Track server name→UUID for client creation (need server UUID for linking)
	serverNameToUUID := make(map[string]string)

	// Phase 2: Create/Update Servers (before clients — dependency order)
	log.Info("Phase 2: Creating/updating WireGuard servers")

	for _, network := range networks {
		serverName := opnapi.BuildServerName(network.NetworkName)
		desiredServerNames[serverName] = true

		// Derive public key from private key
		pubKey, err := opnapi.DeriveWireGuardPublicKey(network.Interface.PrivateKey)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to derive public key for %s: %v", serverName, err)
			log.Errorw(errMsg)
			result.Errors = append(result.Errors, errMsg)
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "wg_server",
				Name:   serverName,
				Action: "create_or_update",
				Status: "error",
				Error:  errMsg,
			})
			result.Success = false
			continue
		}

		mtu := ""
		if network.Interface.MTU != nil {
			mtu = fmt.Sprintf("%d", *network.Interface.MTU)
		}

		server := opnapi.WireGuardServer{
			Enabled:       "1",
			Name:          serverName,
			PubKey:        pubKey,
			PrivKey:       network.Interface.PrivateKey,
			Port:          fmt.Sprintf("%d", network.Interface.ListenPort),
			TunnelAddress: network.Interface.Address,
			MTU:           mtu,
			DNS:           "",
			DisableRoutes: "0",
			Gateway:       "",
		}

		if existingUUID, exists := currentServerUUIDs[serverName]; exists {
			// Update existing server
			if err := client.SetServer(ctx, existingUUID, server); err != nil {
				errMsg := fmt.Sprintf("Failed to update server %s: %v", serverName, err)
				log.Errorw(errMsg)
				result.Errors = append(result.Errors, errMsg)
				result.Results = append(result.Results, SyncAPIItemResult{
					Type:   "wg_server",
					UUID:   existingUUID,
					Name:   serverName,
					Action: "update",
					Status: "error",
					Error:  errMsg,
				})
				result.Success = false
				continue
			}
			serverNameToUUID[serverName] = existingUUID
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "wg_server",
				UUID:   existingUUID,
				Name:   serverName,
				Action: "update",
				Status: "ok",
			})
			log.Infow("Updated WireGuard server", "name", serverName, "uuid", existingUUID)
		} else {
			// Create new server
			uuid, err := client.AddServer(ctx, server)
			if err != nil {
				errMsg := fmt.Sprintf("Failed to create server %s: %v", serverName, err)
				log.Errorw(errMsg)
				result.Errors = append(result.Errors, errMsg)
				result.Results = append(result.Results, SyncAPIItemResult{
					Type:   "wg_server",
					Name:   serverName,
					Action: "create",
					Status: "error",
					Error:  errMsg,
				})
				result.Success = false
				continue
			}
			serverNameToUUID[serverName] = uuid
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "wg_server",
				UUID:   uuid,
				Name:   serverName,
				Action: "create",
				Status: "ok",
			})
			log.Infow("Created WireGuard server", "name", serverName, "uuid", uuid)
		}
	}

	// Phase 3: Create/Update Clients
	log.Info("Phase 3: Creating/updating WireGuard clients")

	for _, network := range networks {
		serverName := opnapi.BuildServerName(network.NetworkName)
		serverUUID, ok := serverNameToUUID[serverName]
		if !ok {
			// Server creation failed earlier — skip its clients
			log.Warnw("Skipping clients for network with failed server", "network", network.NetworkName)
			continue
		}

		for _, peer := range network.Peers {
			clientName := opnapi.BuildClientName(network.NetworkName, peer.PeerName)
			desiredClientNames[clientName] = true

			wgClient := opnapi.WireGuardClient{
				Enabled:       "1",
				Name:          clientName,
				PubKey:        peer.PublicKey,
				PSK:           stringFromPtr(peer.PresharedKey),
				TunnelAddress: strings.Join(peer.AllowedIPs, ","),
				ServerAddress: stringFromPtr(peer.EndpointHost),
				ServerPort:    intPtrToString(peer.EndpointPort),
				KeepAlive:     intPtrToString(peer.PersistentKeepalive),
				Servers:       serverUUID,
			}

			if existingUUID, exists := currentClientUUIDs[clientName]; exists {
				// Update existing client
				if err := client.SetClient(ctx, existingUUID, wgClient); err != nil {
					errMsg := fmt.Sprintf("Failed to update client %s: %v", clientName, err)
					log.Errorw(errMsg)
					result.Errors = append(result.Errors, errMsg)
					result.Results = append(result.Results, SyncAPIItemResult{
						Type:   "wg_client",
						UUID:   existingUUID,
						Name:   clientName,
						Action: "update",
						Status: "error",
						Error:  errMsg,
					})
					result.Success = false
					continue
				}
				result.Results = append(result.Results, SyncAPIItemResult{
					Type:   "wg_client",
					UUID:   existingUUID,
					Name:   clientName,
					Action: "update",
					Status: "ok",
				})
				log.Infow("Updated WireGuard client", "name", clientName, "uuid", existingUUID)
			} else {
				// Create new client
				uuid, err := client.AddClient(ctx, wgClient)
				if err != nil {
					errMsg := fmt.Sprintf("Failed to create client %s: %v", clientName, err)
					log.Errorw(errMsg)
					result.Errors = append(result.Errors, errMsg)
					result.Results = append(result.Results, SyncAPIItemResult{
						Type:   "wg_client",
						Name:   clientName,
						Action: "create",
						Status: "error",
						Error:  errMsg,
					})
					result.Success = false
					continue
				}
				result.Results = append(result.Results, SyncAPIItemResult{
					Type:   "wg_client",
					UUID:   uuid,
					Name:   clientName,
					Action: "create",
					Status: "ok",
				})
				log.Infow("Created WireGuard client", "name", clientName, "uuid", uuid)
			}
		}
	}

	// Phase 4: Delete Orphan Clients (before servers — dependency order)
	log.Info("Phase 4: Deleting orphan WireGuard clients")

	for name, uuid := range currentClientUUIDs {
		if desiredClientNames[name] {
			continue
		}
		if err := client.DeleteClient(ctx, uuid); err != nil {
			errMsg := fmt.Sprintf("Failed to delete orphan client %s: %v", name, err)
			log.Errorw(errMsg)
			result.Errors = append(result.Errors, errMsg)
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "wg_client",
				UUID:   uuid,
				Name:   name,
				Action: "delete",
				Status: "error",
				Error:  errMsg,
			})
			result.Success = false
			continue
		}
		result.Results = append(result.Results, SyncAPIItemResult{
			Type:   "wg_client",
			UUID:   uuid,
			Name:   name,
			Action: "delete",
			Status: "ok",
		})
		log.Infow("Deleted orphan WireGuard client", "name", name, "uuid", uuid)
	}

	// Phase 5: Delete Orphan Servers
	log.Info("Phase 5: Deleting orphan WireGuard servers")

	for name, uuid := range currentServerUUIDs {
		if desiredServerNames[name] {
			continue
		}
		if err := client.DeleteServer(ctx, uuid); err != nil {
			errMsg := fmt.Sprintf("Failed to delete orphan server %s: %v", name, err)
			log.Errorw(errMsg)
			result.Errors = append(result.Errors, errMsg)
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "wg_server",
				UUID:   uuid,
				Name:   name,
				Action: "delete",
				Status: "error",
				Error:  errMsg,
			})
			result.Success = false
			continue
		}
		result.Results = append(result.Results, SyncAPIItemResult{
			Type:   "wg_server",
			UUID:   uuid,
			Name:   name,
			Action: "delete",
			Status: "ok",
		})
		log.Infow("Deleted orphan WireGuard server", "name", name, "uuid", uuid)
	}

	// Phase 6: Reconfigure WireGuard service
	log.Info("Phase 6: Applying WireGuard configuration")

	if err := client.ReconfigureWireGuard(ctx); err != nil {
		errMsg := fmt.Sprintf("Failed to reconfigure WireGuard: %v", err)
		log.Errorw(errMsg)
		result.Errors = append(result.Errors, errMsg)
		result.Success = false
		result.Message = errMsg
		return result
	}

	log.Info("VPN sync completed successfully")

	return result
}

// anyRealizableNetwork reports whether at least one desired network can
// actually be materialized, i.e. its private key yields a public key.
//
// This is the guard on the master-switch enable. Turning the plugin on for a
// payload that then fails every network leaves the device enabled with no
// instance — worse than where it started, and not something the operator's
// "if config is synced, enable it" rule asks for: nothing is being synced if
// nothing is realizable.
func anyRealizableNetwork(networks []VPNNetwork) bool {
	for _, network := range networks {
		if _, err := opnapi.DeriveWireGuardPublicKey(network.Interface.PrivateKey); err == nil {
			return true
		}
	}
	return false
}

// ensureWireGuardEnabled turns the os-wireguard master switch on.
//
// The end state is unconditional — this function either leaves the switch
// on or returns an error. The read is a write-elision only: `general/set`
// writes config.xml and cuts a config revision, so re-writing "1" over "1"
// on every sync would churn the device's config history for nothing. It is
// NOT intent preservation: an "0" read is always corrected to "1".
//
// No reconfigure here — Phase 6 does one at the end of the VPN sync, after
// the servers and clients exist, which is the point at which the plugin can
// actually bring the interface up.
func ensureWireGuardEnabled(ctx context.Context, client *opnapi.Client) error {
	log := logging.Named("SYNC_VPN")

	general, err := client.GetWireGuardGeneral(ctx)
	if err != nil {
		return fmt.Errorf("failed to read WireGuard general settings: %w", err)
	}

	if general.Enabled == "1" {
		log.Debug("WireGuard master switch already enabled")
		return nil
	}

	log.Infow("Enabling WireGuard master switch (device is receiving VPN configuration)",
		"previous_enabled", general.Enabled,
	)

	general.Enabled = "1"
	if err := client.SetWireGuardGeneral(ctx, general); err != nil {
		return fmt.Errorf("failed to write WireGuard general settings: %w", err)
	}

	return nil
}

// stringFromPtr returns the string value or empty string if nil.
func stringFromPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// intPtrToString converts an *int to a string, returning empty string if nil.
func intPtrToString(i *int) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%d", *i)
}
