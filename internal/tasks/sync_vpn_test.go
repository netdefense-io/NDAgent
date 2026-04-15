package tasks

import (
	"encoding/json"
	"testing"
)

func TestParseVPNNetworks(t *testing.T) {
	payload := map[string]interface{}{
		"vpn_networks": []interface{}{
			map[string]interface{}{
				"network_name": "site-to-site",
				"interface": map[string]interface{}{
					"private_key":  "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=",
					"address":      "10.200.0.1/24",
					"listen_port":  float64(51820),
					"mtu":          float64(1420),
				},
				"peers": []interface{}{
					map[string]interface{}{
						"peer_name":            "branch-01",
						"public_key":           "Lx6kMwst3bkLLqbCtMdHikKJvduS7HsXU/e+Z84JHWI=",
						"allowed_ips":          []interface{}{"10.200.0.2/32", "192.168.1.0/24"},
						"endpoint_host":        "vpn.example.com",
						"endpoint_port":        float64(51820),
						"preshared_key":        "psk-base64==",
						"persistent_keepalive": float64(25),
					},
				},
			},
		},
	}

	networks, err := parseVPNNetworks(payload)
	if err != nil {
		t.Fatalf("parseVPNNetworks() error = %v", err)
	}

	if len(networks) != 1 {
		t.Fatalf("len(networks) = %d, want 1", len(networks))
	}

	net := networks[0]
	if net.NetworkName != "site-to-site" {
		t.Errorf("NetworkName = %s, want site-to-site", net.NetworkName)
	}
	if net.Interface.PrivateKey != "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=" {
		t.Errorf("PrivateKey = %s, want YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=", net.Interface.PrivateKey)
	}
	if net.Interface.Address != "10.200.0.1/24" {
		t.Errorf("Address = %s, want 10.200.0.1/24", net.Interface.Address)
	}
	if net.Interface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", net.Interface.ListenPort)
	}
	if net.Interface.MTU == nil || *net.Interface.MTU != 1420 {
		t.Errorf("MTU = %v, want 1420", net.Interface.MTU)
	}

	if len(net.Peers) != 1 {
		t.Fatalf("len(peers) = %d, want 1", len(net.Peers))
	}

	peer := net.Peers[0]
	if peer.PeerName != "branch-01" {
		t.Errorf("PeerName = %s, want branch-01", peer.PeerName)
	}
	if peer.PublicKey != "Lx6kMwst3bkLLqbCtMdHikKJvduS7HsXU/e+Z84JHWI=" {
		t.Errorf("PublicKey = %s, want Lx6kMwst3bkLLqbCtMdHikKJvduS7HsXU/e+Z84JHWI=", peer.PublicKey)
	}
	if len(peer.AllowedIPs) != 2 {
		t.Fatalf("len(AllowedIPs) = %d, want 2", len(peer.AllowedIPs))
	}
	if peer.AllowedIPs[0] != "10.200.0.2/32" || peer.AllowedIPs[1] != "192.168.1.0/24" {
		t.Errorf("AllowedIPs = %v, want [10.200.0.2/32 192.168.1.0/24]", peer.AllowedIPs)
	}
	if peer.EndpointHost == nil || *peer.EndpointHost != "vpn.example.com" {
		t.Errorf("EndpointHost = %v, want vpn.example.com", peer.EndpointHost)
	}
	if peer.EndpointPort == nil || *peer.EndpointPort != 51820 {
		t.Errorf("EndpointPort = %v, want 51820", peer.EndpointPort)
	}
	if peer.PresharedKey == nil || *peer.PresharedKey != "psk-base64==" {
		t.Errorf("PresharedKey = %v, want psk-base64==", peer.PresharedKey)
	}
	if peer.PersistentKeepalive == nil || *peer.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %v, want 25", peer.PersistentKeepalive)
	}
}

func TestParseVPNNetworksEmpty(t *testing.T) {
	payload := map[string]interface{}{
		"vpn_networks": []interface{}{},
	}

	networks, err := parseVPNNetworks(payload)
	if err != nil {
		t.Fatalf("parseVPNNetworks() error = %v", err)
	}
	if len(networks) != 0 {
		t.Errorf("len(networks) = %d, want 0", len(networks))
	}
}

func TestParseVPNNetworksAbsent(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{},
	}

	networks, err := parseVPNNetworks(payload)
	if err != nil {
		t.Fatalf("parseVPNNetworks() error = %v", err)
	}
	if len(networks) != 0 {
		t.Errorf("len(networks) = %d, want 0", len(networks))
	}
}

func TestParseVPNNetworksNullOptionals(t *testing.T) {
	// Simulate JSON with null optional fields
	raw := `[{
		"network_name": "minimal",
		"interface": {
			"private_key": "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=",
			"address": "10.200.0.1/24",
			"listen_port": 51820
		},
		"peers": [{
			"peer_name": "peer1",
			"public_key": "Lx6kMwst3bkLLqbCtMdHikKJvduS7HsXU/e+Z84JHWI=",
			"allowed_ips": ["10.200.0.2/32"],
			"endpoint_host": null,
			"endpoint_port": null,
			"preshared_key": null,
			"persistent_keepalive": null
		}]
	}]`

	var rawNetworks interface{}
	json.Unmarshal([]byte(raw), &rawNetworks)

	payload := map[string]interface{}{
		"vpn_networks": rawNetworks,
	}

	networks, err := parseVPNNetworks(payload)
	if err != nil {
		t.Fatalf("parseVPNNetworks() error = %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("len(networks) = %d, want 1", len(networks))
	}

	peer := networks[0].Peers[0]
	if peer.EndpointHost != nil {
		t.Errorf("EndpointHost = %v, want nil", peer.EndpointHost)
	}
	if peer.EndpointPort != nil {
		t.Errorf("EndpointPort = %v, want nil", peer.EndpointPort)
	}
	if peer.PresharedKey != nil {
		t.Errorf("PresharedKey = %v, want nil", peer.PresharedKey)
	}
	if peer.PersistentKeepalive != nil {
		t.Errorf("PersistentKeepalive = %v, want nil", peer.PersistentKeepalive)
	}
	if networks[0].Interface.MTU != nil {
		t.Errorf("MTU = %v, want nil", networks[0].Interface.MTU)
	}
}

func TestParseVPNNetworksMultiple(t *testing.T) {
	payload := map[string]interface{}{
		"vpn_networks": []interface{}{
			map[string]interface{}{
				"network_name": "net1",
				"interface": map[string]interface{}{
					"private_key":  "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=",
					"address":      "10.200.0.1/24",
					"listen_port":  float64(51820),
				},
				"peers": []interface{}{},
			},
			map[string]interface{}{
				"network_name": "net2",
				"interface": map[string]interface{}{
					"private_key":  "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms=",
					"address":      "10.201.0.1/24",
					"listen_port":  float64(51821),
				},
				"peers": []interface{}{},
			},
		},
	}

	networks, err := parseVPNNetworks(payload)
	if err != nil {
		t.Fatalf("parseVPNNetworks() error = %v", err)
	}
	if len(networks) != 2 {
		t.Fatalf("len(networks) = %d, want 2", len(networks))
	}
	if networks[0].NetworkName != "net1" {
		t.Errorf("networks[0].NetworkName = %s, want net1", networks[0].NetworkName)
	}
	if networks[1].NetworkName != "net2" {
		t.Errorf("networks[1].NetworkName = %s, want net2", networks[1].NetworkName)
	}
}

func TestStringFromPtr(t *testing.T) {
	s := "hello"
	if got := stringFromPtr(&s); got != "hello" {
		t.Errorf("stringFromPtr(&hello) = %s, want hello", got)
	}
	if got := stringFromPtr(nil); got != "" {
		t.Errorf("stringFromPtr(nil) = %s, want empty", got)
	}
}

func TestIntPtrToString(t *testing.T) {
	i := 25
	if got := intPtrToString(&i); got != "25" {
		t.Errorf("intPtrToString(&25) = %s, want 25", got)
	}
	if got := intPtrToString(nil); got != "" {
		t.Errorf("intPtrToString(nil) = %s, want empty", got)
	}
}
