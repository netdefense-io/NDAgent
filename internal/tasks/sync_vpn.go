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
