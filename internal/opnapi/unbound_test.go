package opnapi

import (
	"testing"
)

func TestFilterManagedHostOverrides(t *testing.T) {
	overrides := []map[string]interface{}{
		{"uuid": "221f3268-1111-0000-0000-000000000001", "hostname": "managed1", "domain": "local"},
		{"uuid": "other-uuid-1234", "hostname": "unmanaged1", "domain": "local"},
		{"uuid": "221f3268-2222-0000-0000-000000000002", "hostname": "managed2", "domain": "local"},
		{"uuid": "another-uuid-5678", "hostname": "unmanaged2", "domain": "local"},
	}

	managed := FilterManagedHostOverrides(overrides)

	if len(managed) != 2 {
		t.Errorf("Expected 2 managed overrides, got %d", len(managed))
	}

	// Verify correct ones are filtered
	for _, m := range managed {
		uuid := m["uuid"].(string)
		if uuid != "221f3268-1111-0000-0000-000000000001" && uuid != "221f3268-2222-0000-0000-000000000002" {
			t.Errorf("Unexpected UUID in managed overrides: %s", uuid)
		}
	}
}

func TestFilterManagedForwards(t *testing.T) {
	forwards := []map[string]interface{}{
		{"uuid": "221f3268-1111-0000-0000-000000000001", "domain": "internal.local"},
		{"uuid": "other-uuid-1234", "domain": "external.com"},
		{"uuid": "221f3268-2222-0000-0000-000000000002", "domain": "corp.local"},
	}

	managed := FilterManagedForwards(forwards)

	if len(managed) != 2 {
		t.Errorf("Expected 2 managed forwards, got %d", len(managed))
	}
}

func TestFilterManagedHostAliases(t *testing.T) {
	aliases := []map[string]interface{}{
		{"uuid": "221f3268-1111-0000-0000-000000000001", "hostname": "alias1"},
		{"uuid": "other-uuid", "hostname": "alias2"},
	}

	managed := FilterManagedHostAliases(aliases)

	if len(managed) != 1 {
		t.Errorf("Expected 1 managed alias, got %d", len(managed))
	}
}

func TestFilterManagedACLs(t *testing.T) {
	acls := []map[string]interface{}{
		{"uuid": "221f3268-1111-0000-0000-000000000001", "name": "acl1"},
		{"uuid": "other-uuid", "name": "acl2"},
		{"uuid": "221f3268-2222-0000-0000-000000000002", "name": "acl3"},
	}

	managed := FilterManagedACLs(acls)

	if len(managed) != 2 {
		t.Errorf("Expected 2 managed ACLs, got %d", len(managed))
	}
}

func TestConvertToOPNHostOverride(t *testing.T) {
	payload := APIHostOverridePayload{
		UUID:        "221f3268-1111-0000-0000-000000000001",
		Enabled:     true,
		Hostname:    "server1",
		Domain:      "local",
		RR:          "A",
		Server:      "192.168.1.10",
		Description: "Test server",
		Templates:   []string{"dns-template"},
	}

	override := ConvertToOPNHostOverride(payload)

	if override.Enabled != "1" {
		t.Errorf("Expected Enabled=1, got %s", override.Enabled)
	}
	if override.Hostname != "server1" {
		t.Errorf("Expected Hostname=server1, got %s", override.Hostname)
	}
	if override.Domain != "local" {
		t.Errorf("Expected Domain=local, got %s", override.Domain)
	}
	if override.RR != "A" {
		t.Errorf("Expected RR=A, got %s", override.RR)
	}
	if override.Server != "192.168.1.10" {
		t.Errorf("Expected Server=192.168.1.10, got %s", override.Server)
	}
	if !IsManagedByDescription(override.Description) {
		t.Error("Expected description to contain template tag")
	}
}

func TestConvertToOPNHostOverrideDisabled(t *testing.T) {
	payload := APIHostOverridePayload{
		UUID:     "221f3268-1111-0000-0000-000000000001",
		Enabled:  false,
		Hostname: "server1",
		Domain:   "local",
	}

	override := ConvertToOPNHostOverride(payload)

	if override.Enabled != "0" {
		t.Errorf("Expected Enabled=0, got %s", override.Enabled)
	}
}

func TestConvertToOPNDomainForward(t *testing.T) {
	payload := APIDomainForwardPayload{
		UUID:               "221f3268-1111-0000-0000-000000000001",
		Enabled:            true,
		Type:               "forward",
		Domain:             "internal.corp",
		Server:             "10.0.0.1",
		Port:               "5353",
		ForwardTCPUpstream: true,
		ForwardFirst:       false,
		Description:        "Internal DNS",
		Templates:          []string{"fwd-template"},
	}

	forward := ConvertToOPNDomainForward(payload)

	if forward.Enabled != "1" {
		t.Errorf("Expected Enabled=1, got %s", forward.Enabled)
	}
	if forward.Type != "forward" {
		t.Errorf("Expected Type=forward, got %s", forward.Type)
	}
	if forward.Domain != "internal.corp" {
		t.Errorf("Expected Domain=internal.corp, got %s", forward.Domain)
	}
	if forward.Server != "10.0.0.1" {
		t.Errorf("Expected Server=10.0.0.1, got %s", forward.Server)
	}
	if forward.Port != "5353" {
		t.Errorf("Expected Port=5353, got %s", forward.Port)
	}
	if forward.ForwardTCPUpstream != "1" {
		t.Errorf("Expected ForwardTCPUpstream=1, got %s", forward.ForwardTCPUpstream)
	}
	if forward.ForwardFirst != "0" {
		t.Errorf("Expected ForwardFirst=0, got %s", forward.ForwardFirst)
	}
}

func TestConvertToOPNHostAlias(t *testing.T) {
	payload := APIHostAliasPayload{
		UUID:           "221f3268-1111-0000-0000-000000000001",
		Enabled:        true,
		ParentHostname: "server1",
		ParentDomain:   "local",
		Hostname:       "www",
		Domain:         "local",
		Description:    "Web alias",
		Templates:      []string{"alias-template"},
	}

	parentUUID := "221f3268-parent-uuid"
	alias := ConvertToOPNHostAlias(payload, parentUUID)

	if alias.Enabled != "1" {
		t.Errorf("Expected Enabled=1, got %s", alias.Enabled)
	}
	if alias.Host != parentUUID {
		t.Errorf("Expected Host=%s, got %s", parentUUID, alias.Host)
	}
	if alias.Hostname != "www" {
		t.Errorf("Expected Hostname=www, got %s", alias.Hostname)
	}
	if alias.Domain != "local" {
		t.Errorf("Expected Domain=local, got %s", alias.Domain)
	}
}

func TestConvertToOPNACL(t *testing.T) {
	payload := APIUnboundACLPayload{
		UUID:        "221f3268-1111-0000-0000-000000000001",
		Enabled:     true,
		Name:        "lan-clients",
		Action:      "allow",
		Networks:    []string{"192.168.1.0/24", "10.0.0.0/8"},
		Description: "LAN access",
		Templates:   []string{"acl-template"},
	}

	acl := ConvertToOPNACL(payload)

	if acl.Enabled != "1" {
		t.Errorf("Expected Enabled=1, got %s", acl.Enabled)
	}
	if acl.Name != "lan-clients" {
		t.Errorf("Expected Name=lan-clients, got %s", acl.Name)
	}
	if acl.Action != "allow" {
		t.Errorf("Expected Action=allow, got %s", acl.Action)
	}
	if acl.Networks != "192.168.1.0/24,10.0.0.0/8" {
		t.Errorf("Expected Networks=192.168.1.0/24,10.0.0.0/8, got %s", acl.Networks)
	}
}

func TestConvertHostOverrideToAPI(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":        "221f3268-1111-0000-0000-000000000001",
		"enabled":     "1",
		"hostname":    "server1",
		"domain":      "local",
		"rr":          "A",
		"server":      "192.168.1.10",
		"mxprio":      "",
		"mx":          "",
		"ttl":         "3600",
		"txtdata":     "",
		"description": "Test server [nd-template:dns-template]",
	}

	payload := ConvertHostOverrideToAPI(raw)

	if payload.UUID != "221f3268-1111-0000-0000-000000000001" {
		t.Errorf("Expected UUID, got %s", payload.UUID)
	}
	if !payload.Enabled {
		t.Error("Expected Enabled=true")
	}
	if payload.Hostname != "server1" {
		t.Errorf("Expected Hostname=server1, got %s", payload.Hostname)
	}
	if payload.Domain != "local" {
		t.Errorf("Expected Domain=local, got %s", payload.Domain)
	}
	if payload.TTL != "3600" {
		t.Errorf("Expected TTL=3600, got %s", payload.TTL)
	}
	if payload.Description != "Test server" {
		t.Errorf("Expected Description='Test server', got %s", payload.Description)
	}
	if len(payload.Templates) != 1 || payload.Templates[0] != "dns-template" {
		t.Errorf("Expected Templates=[dns-template], got %v", payload.Templates)
	}
}

func TestConvertDomainForwardToAPI(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":                 "221f3268-1111-0000-0000-000000000001",
		"enabled":              "1",
		"type":                 "dot",
		"domain":               "secure.com",
		"server":               "1.1.1.1",
		"port":                 "853",
		"verify":               "1",
		"forward_tcp_upstream": "1",
		"forward_first":        "0",
		"description":          "Secure DNS [nd-template:dot-template]",
	}

	payload := ConvertDomainForwardToAPI(raw)

	if !payload.Enabled {
		t.Error("Expected Enabled=true")
	}
	if payload.Type != "dot" {
		t.Errorf("Expected Type=dot, got %s", payload.Type)
	}
	if !payload.ForwardTCPUpstream {
		t.Error("Expected ForwardTCPUpstream=true")
	}
	if payload.ForwardFirst {
		t.Error("Expected ForwardFirst=false")
	}
}

func TestConvertHostAliasToAPI(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":        "221f3268-alias-uuid",
		"enabled":     "1",
		"host":        "221f3268-parent-uuid",
		"hostname":    "www",
		"domain":      "local",
		"description": "Web alias [nd-template:alias-template]",
	}

	hostOverrides := []map[string]interface{}{
		{
			"uuid":     "221f3268-parent-uuid",
			"hostname": "server1",
			"domain":   "local",
		},
	}

	payload := ConvertHostAliasToAPI(raw, hostOverrides)

	if payload.UUID != "221f3268-alias-uuid" {
		t.Errorf("Expected UUID, got %s", payload.UUID)
	}
	if payload.ParentHostname != "server1" {
		t.Errorf("Expected ParentHostname=server1, got %s", payload.ParentHostname)
	}
	if payload.ParentDomain != "local" {
		t.Errorf("Expected ParentDomain=local, got %s", payload.ParentDomain)
	}
	if payload.Hostname != "www" {
		t.Errorf("Expected Hostname=www, got %s", payload.Hostname)
	}
}

func TestConvertACLToAPI(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":        "221f3268-1111-0000-0000-000000000001",
		"enabled":     "1",
		"name":        "lan-clients",
		"action":      "allow",
		"networks":    "192.168.1.0/24,10.0.0.0/8",
		"description": "LAN access [nd-template:acl-template]",
	}

	payload := ConvertACLToAPI(raw)

	if payload.UUID != "221f3268-1111-0000-0000-000000000001" {
		t.Errorf("Expected UUID, got %s", payload.UUID)
	}
	if !payload.Enabled {
		t.Error("Expected Enabled=true")
	}
	if payload.Name != "lan-clients" {
		t.Errorf("Expected Name=lan-clients, got %s", payload.Name)
	}
	if payload.Action != "allow" {
		t.Errorf("Expected Action=allow, got %s", payload.Action)
	}
	if len(payload.Networks) != 2 {
		t.Errorf("Expected 2 networks, got %d", len(payload.Networks))
	}
	if payload.Networks[0] != "192.168.1.0/24" {
		t.Errorf("Expected first network=192.168.1.0/24, got %s", payload.Networks[0])
	}
}

func TestBuildHostOverrideUUIDLookup(t *testing.T) {
	overrides := []map[string]interface{}{
		{"uuid": "uuid-1", "hostname": "server1", "domain": "local"},
		{"uuid": "uuid-2", "hostname": "server2", "domain": "corp"},
		{"uuid": "uuid-3", "hostname": "www", "domain": "local"},
	}

	lookup := BuildHostOverrideUUIDLookup(overrides)

	if lookup["server1.local"] != "uuid-1" {
		t.Errorf("Expected server1.local -> uuid-1, got %s", lookup["server1.local"])
	}
	if lookup["server2.corp"] != "uuid-2" {
		t.Errorf("Expected server2.corp -> uuid-2, got %s", lookup["server2.corp"])
	}
	if lookup["www.local"] != "uuid-3" {
		t.Errorf("Expected www.local -> uuid-3, got %s", lookup["www.local"])
	}
}

func TestConvertHostOverrideToAPIMXRecord(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":        "221f3268-mx-uuid",
		"enabled":     "1",
		"hostname":    "",
		"domain":      "example.com",
		"rr":          "MX",
		"server":      "",
		"mxprio":      "10",
		"mx":          "mail.example.com",
		"description": "MX record",
	}

	payload := ConvertHostOverrideToAPI(raw)

	if payload.RR != "MX" {
		t.Errorf("Expected RR=MX, got %s", payload.RR)
	}
	if payload.MXPrio != "10" {
		t.Errorf("Expected MXPrio=10, got %s", payload.MXPrio)
	}
	if payload.MX != "mail.example.com" {
		t.Errorf("Expected MX=mail.example.com, got %s", payload.MX)
	}
}

func TestConvertHostOverrideToAPITXTRecord(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":        "221f3268-txt-uuid",
		"enabled":     "1",
		"hostname":    "_dmarc",
		"domain":      "example.com",
		"rr":          "TXT",
		"server":      "",
		"txtdata":     "v=DMARC1; p=none",
		"description": "DMARC record",
	}

	payload := ConvertHostOverrideToAPI(raw)

	if payload.RR != "TXT" {
		t.Errorf("Expected RR=TXT, got %s", payload.RR)
	}
	if payload.TXTData != "v=DMARC1; p=none" {
		t.Errorf("Expected TXTData='v=DMARC1; p=none', got %s", payload.TXTData)
	}
}
