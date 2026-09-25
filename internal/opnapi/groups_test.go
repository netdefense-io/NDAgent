package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConvertAPIToGroup_ExternalMembersNeverSendsMember is the revert guard:
// for an external GROUP (external_members:
// true), the directory owns membership, and NDAgent must never send the
// `member` field at all — OPNsense confirms an omitted `member` key leaves
// OPNsense's existing members untouched, which is exactly what an external
// group needs. This holds even if Members is non-empty (defense-in-depth;
// NDManager's schema is the primary enforcement that Members stays empty
// for an external group).
func TestConvertAPIToGroup_ExternalMembersNeverSendsMember(t *testing.T) {
	payload := APIGroupPayload{
		Name:            "eng-external",
		Description:     "Engineering (directory-managed)",
		Priv:            []string{"page-status-interfaces"},
		Members:         []string{"alice", "bob"}, // should never reach the wire
		SourceNetworks:  "10.0.0.0/8",
		ExternalMembers: true,
	}
	uidLookup := map[string]string{"alice": "1001", "bob": "1002"}

	group := ConvertAPIToGroup(payload, nil, uidLookup)

	if group.Member != "" {
		t.Errorf("Member = %q, want empty for an external group", group.Member)
	}
	if group.Priv != "page-status-interfaces" {
		t.Errorf("Priv = %q, want the resolved priv CSV", group.Priv)
	}
	if group.SourceNetworks != "10.0.0.0/8" {
		t.Errorf("SourceNetworks = %q, want the passthrough value", group.SourceNetworks)
	}

	// The wire encoding itself must omit "member" entirely (omitempty),
	// not merely set it to "" -- the OPNsense endpoint's own semantics
	// treat an explicit empty member list differently in principle
	// from an absent key, and an external group must always look like the
	// latter.
	b, err := json.Marshal(GroupWrapper{Group: group})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	groupRaw, _ := raw["group"].(map[string]interface{})
	if _, present := groupRaw["member"]; present {
		t.Errorf("wire JSON = %s, want no \"member\" key at all for an external group", b)
	}
}

// TestConvertAPIToGroup_MemberManagedResolvesMembers is the non-external
// control: an ordinary (member-managed) GROUP still resolves Members to
// UIDs exactly as before.
func TestConvertAPIToGroup_MemberManagedResolvesMembers(t *testing.T) {
	payload := APIGroupPayload{
		Name:    "eng",
		Members: []string{"alice", "bob"},
	}
	uidLookup := map[string]string{"alice": "1001", "bob": "1002"}

	group := ConvertAPIToGroup(payload, nil, uidLookup)

	if group.Member != "1001,1002" {
		t.Errorf("Member = %q, want \"1001,1002\"", group.Member)
	}
}

// TestGroupWire_PrivAndSourceNetworksAlwaysSent is the revert guard: priv
// and source_networks must be present on the
// wire even when empty, so a template-driven revoke (removing every priv,
// or clearing source_networks) actually reaches the device instead of
// being silently omitted by `omitempty` and leaving the stale value in
// place (an explicit "" is OPNsense's own "clear this field" signal).
// Member stays omitempty deliberately -- see the external-group test above.
func TestGroupWire_PrivAndSourceNetworksAlwaysSent(t *testing.T) {
	group := Group{Name: "eng", Description: "Engineering"}

	b, err := json.Marshal(GroupWrapper{Group: group})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	groupRaw, _ := raw["group"].(map[string]interface{})

	for _, key := range []string{"priv", "source_networks"} {
		val, present := groupRaw[key]
		if !present {
			t.Errorf("wire JSON = %s, want %q present even when empty", b, key)
			continue
		}
		if val != "" {
			t.Errorf("wire JSON %q = %v, want \"\"", key, val)
		}
	}
	if _, present := groupRaw["member"]; present {
		t.Errorf("wire JSON = %s, want no \"member\" key when Member is unset", b)
	}
}

// TestGetGroupRawMemberByName_ReturnsRawArtifact proves the search
// endpoint's raw string is what surfaces the empty-token artifact --
// unlike /auth/group/get, whose option-dict shape can never reveal it (see
// GetGroupRawMemberByName's doc comment).
func TestGetGroupRawMemberByName_ReturnsRawArtifact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := SearchResponse{
			Rows: []map[string]interface{}{
				// The exact byte shape confirmed live on the lab:
				// a leading comma left by a directory revoke->restore cycle.
				{"uuid": "g1", "name": "eng-external", "member": ",2004"},
				{"uuid": "g2", "name": "eng-external-decoy", "member": "9999"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", "secret", true)

	member, found, err := client.GetGroupRawMemberByName(context.Background(), "eng-external")
	if err != nil {
		t.Fatalf("GetGroupRawMemberByName() error = %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if member != ",2004" {
		t.Errorf("member = %q, want the raw, unsanitized \",2004\"", member)
	}
}

// TestGetGroupRawMemberByName_NotFound covers the fail-open input a caller
// needs: a group that no longer exists (e.g. deleted out from under this
// sync) reports found=false without an error, so the caller can fall back
// to the plain update path.
func TestGetGroupRawMemberByName_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SearchResponse{})
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", "secret", true)

	_, found, err := client.GetGroupRawMemberByName(context.Background(), "gone")
	if err != nil {
		t.Fatalf("GetGroupRawMemberByName() error = %v", err)
	}
	if found {
		t.Error("found = true, want false for a group that no longer exists")
	}
}

// TestRepairGroupMember_SendsExplicitSanitizedMember is the wire-level
// proof that RepairGroupMember (unlike SetGroup/ConvertAPIToGroup for an
// external group) sends member EVEN WHEN the sanitized value is empty --
// necessary because Group.Member's `omitempty` would otherwise silently
// drop exactly the repair value that matters.
func TestRepairGroupMember_SendsExplicitSanitizedMember(t *testing.T) {
	var gotBody map[string]interface{}
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(SetGroupResponse{Result: "saved"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", "secret", true)

	group := Group{Name: "eng-external", Description: "desc", Priv: "page-status-interfaces", SourceNetworks: "10.0.0.0/8"}
	if err := client.RepairGroupMember(context.Background(), "g1", group, "2004"); err != nil {
		t.Fatalf("RepairGroupMember() error = %v", err)
	}

	if gotPath != "/auth/group/set/g1" {
		t.Errorf("path = %q, want /auth/group/set/g1", gotPath)
	}
	groupRaw, _ := gotBody["group"].(map[string]interface{})
	memberVal, present := groupRaw["member"]
	if !present {
		t.Fatalf("body = %+v, want an explicit \"member\" key", gotBody)
	}
	if memberVal != "2004" {
		t.Errorf("member = %v, want \"2004\"", memberVal)
	}
	if groupRaw["priv"] != "page-status-interfaces" {
		t.Errorf("priv = %v, want the caller's group.Priv carried through unchanged", groupRaw["priv"])
	}
	if groupRaw["source_networks"] != "10.0.0.0/8" {
		t.Errorf("source_networks = %v, want the caller's group.SourceNetworks carried through unchanged", groupRaw["source_networks"])
	}
}

// TestRepairGroupMember_CanSendExplicitEmptyMember covers the all-artifact
// case (e.g. a stored "," with no real member at all): the repair must
// still send "member":"" explicitly, not omit the key -- an omitted key
// would leave the poisoned value in place.
func TestRepairGroupMember_CanSendExplicitEmptyMember(t *testing.T) {
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(SetGroupResponse{Result: "saved"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", "secret", true)

	if err := client.RepairGroupMember(context.Background(), "g1", Group{Name: "eng-external"}, ""); err != nil {
		t.Fatalf("RepairGroupMember() error = %v", err)
	}

	groupRaw, _ := gotBody["group"].(map[string]interface{})
	memberVal, present := groupRaw["member"]
	if !present {
		t.Fatalf("body = %+v, want an explicit \"member\" key even when the sanitized value is empty", gotBody)
	}
	if memberVal != "" {
		t.Errorf("member = %v, want \"\"", memberVal)
	}
}
