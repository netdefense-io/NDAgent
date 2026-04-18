//go:build integration
// +build integration

package opnapi

import (
	"context"
	"os"
	"testing"
	"time"
)

// Integration tests for the OPNsense API client.
// Run with: go test -tags=integration ./internal/opnapi/
//
// Required environment variables:
//   OPNSENSE_API_KEY    - API key for OPNsense
//   OPNSENSE_API_SECRET - API secret for OPNsense
//   OPNSENSE_API_URL    - API URL (e.g. https://opnsense.example.com/api)

func getTestClient(t *testing.T) *Client {
	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	apiURL := os.Getenv("OPNSENSE_API_URL")

	if apiKey == "" || apiSecret == "" || apiURL == "" {
		t.Skip("OPNSENSE_API_KEY, OPNSENSE_API_SECRET, and OPNSENSE_API_URL must be set")
	}

	return NewClient(apiURL, apiKey, apiSecret, true)
}

func TestIntegration_Ping(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	t.Log("Ping successful - API credentials are valid")
}

func TestIntegration_ListManagedAliases(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allAliases, err := client.ListAllAliases(ctx)
	if err != nil {
		t.Fatalf("ListAllAliases() error = %v", err)
	}

	managedAliases := FilterManagedAliases(allAliases)

	t.Logf("Found %d total aliases, %d managed", len(allAliases), len(managedAliases))
	for _, alias := range managedAliases {
		t.Logf("  - %s: %s", alias["uuid"], alias["name"])
	}
}

func TestIntegration_ListManagedRules(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allRules, err := client.ListAllRules(ctx)
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}

	managedRules := FilterManagedRules(allRules)

	t.Logf("Found %d total rules, %d managed", len(allRules), len(managedRules))
	for _, rule := range managedRules {
		t.Logf("  - %s: %s", rule["uuid"], rule["description"])
	}
}

func TestIntegration_CreateAndDeleteAlias(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test UUID with NDAgent prefix (must be valid hex only)
	testUUID := "221f3268-aaaa-4abc-9001-000000000001"

	// Create test alias
	alias := Alias{
		Enabled:     "1",
		Name:        "ND_IntegrationTest",
		Type:        "host",
		Content:     "test.example.com",
		Description: "Integration test alias [nd-template:test]",
	}

	t.Log("Creating test alias...")
	err := client.SetAlias(ctx, testUUID, alias)
	if err != nil {
		t.Fatalf("SetAlias() error = %v", err)
	}
	t.Log("Alias created successfully")

	// Verify it exists (search by name since searchPhrase searches in name/description, not UUID)
	aliases, err := client.SearchAliases(ctx, "ND_IntegrationTest")
	if err != nil {
		t.Fatalf("SearchAliases() error = %v", err)
	}
	if len(aliases) != 1 {
		t.Errorf("Expected 1 alias, got %d", len(aliases))
	} else {
		t.Logf("Found alias: uuid=%s, name=%s", aliases[0]["uuid"], aliases[0]["name"])
	}

	// Delete the alias
	t.Log("Deleting test alias...")
	err = client.DeleteAlias(ctx, testUUID)
	if err != nil {
		t.Fatalf("DeleteAlias() error = %v", err)
	}
	t.Log("Alias deleted successfully")

	// Verify it's gone (search by name)
	aliases, err = client.SearchAliases(ctx, "ND_IntegrationTest")
	if err != nil {
		t.Fatalf("SearchAliases() error = %v", err)
	}
	if len(aliases) != 0 {
		t.Errorf("Expected 0 aliases after delete, got %d", len(aliases))
	}
	t.Log("Alias cleanup verified")
}

func TestIntegration_CreateAndDeleteRule(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test UUID with NDAgent prefix (must be valid hex only)
	testUUID := "221f3268-bbbb-4abc-9002-000000000001"

	// Create test rule with description marker for searchability
	rule := Rule{
		Enabled:         "1",
		Sequence:        "999",
		Action:          "pass",
		Interface:       "lan",
		Direction:       "in",
		IPProtocol:      "inet",
		Protocol:        "TCP",
		SourceNet:       "any",
		DestinationNet:  "any",
		DestinationPort: "8888",
		Description:     "Integration test rule [nd-template:integration-test]",
	}

	t.Log("Creating test rule...")
	err := client.SetRule(ctx, testUUID, rule)
	if err != nil {
		t.Fatalf("SetRule() error = %v", err)
	}
	t.Log("Rule created successfully")

	// Verify it exists using list all + filter
	allRules, err := client.ListAllRules(ctx)
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}
	managedRules := FilterManagedRules(allRules)

	found := false
	for _, r := range managedRules {
		if r["uuid"] == testUUID {
			found = true
			t.Logf("Found rule: uuid=%s, description=%s", r["uuid"], r["description"])
			break
		}
	}
	if !found {
		t.Errorf("Created rule %s not found in managed rules", testUUID)
	}

	// Delete the rule
	t.Log("Deleting test rule...")
	err = client.DeleteRule(ctx, testUUID)
	if err != nil {
		t.Fatalf("DeleteRule() error = %v", err)
	}
	t.Log("Rule deleted successfully")

	// Verify it's gone
	allRules, err = client.ListAllRules(ctx)
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}
	managedRules = FilterManagedRules(allRules)
	for _, r := range managedRules {
		if r["uuid"] == testUUID {
			t.Errorf("Rule %s still exists after delete", testUUID)
		}
	}
	t.Log("Rule cleanup verified")
}

func TestIntegration_GetInterfaceList(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	interfaces, err := client.GetInterfaceList(ctx)
	if err != nil {
		t.Fatalf("GetInterfaceList() error = %v", err)
	}

	t.Logf("Found %d interfaces: %v", len(interfaces), interfaces)

	// Should have at least lan and wan
	if len(interfaces) < 2 {
		t.Errorf("Expected at least 2 interfaces, got %d", len(interfaces))
	}
}

func TestIntegration_GetAliasByName(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First create a test alias
	testUUID := "221f3268-cccc-4abc-9001-000000000001"
	alias := Alias{
		Enabled:     "1",
		Name:        "ND_TestPullAlias",
		Type:        "host",
		Content:     "test.example.com",
		Description: "Test alias for PULL_API [nd-template:test]",
	}

	t.Log("Creating test alias...")
	err := client.SetAlias(ctx, testUUID, alias)
	if err != nil {
		t.Fatalf("SetAlias() error = %v", err)
	}
	defer func() {
		// Cleanup
		_ = client.DeleteAlias(ctx, testUUID)
	}()

	// Now try to find it by name
	t.Log("Searching alias by name...")
	found, err := client.GetAliasByName(ctx, "ND_TestPullAlias")
	if err != nil {
		t.Fatalf("GetAliasByName() error = %v", err)
	}
	if found == nil {
		t.Fatal("GetAliasByName() returned nil, expected alias")
	}

	t.Logf("Found alias: uuid=%s, name=%s", found["uuid"], found["name"])

	// Search for non-existent alias
	notFound, err := client.GetAliasByName(ctx, "NonExistentAlias12345")
	if err != nil {
		t.Fatalf("GetAliasByName() error for non-existent = %v", err)
	}
	if notFound != nil {
		t.Error("GetAliasByName() should return nil for non-existent alias")
	}
	t.Log("Non-existent alias correctly returned nil")
}

func TestIntegration_GetRuleByDescription(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First create a test rule
	testUUID := "221f3268-dddd-4abc-9002-000000000001"
	rule := Rule{
		Enabled:         "1",
		Sequence:        "999",
		Action:          "pass",
		Interface:       "lan",
		Direction:       "in",
		IPProtocol:      "inet",
		Protocol:        "TCP",
		SourceNet:       "any",
		DestinationNet:  "any",
		DestinationPort: "9999",
		Description:     "Test rule for PULL_API [nd-template:test]",
	}

	t.Log("Creating test rule...")
	err := client.SetRule(ctx, testUUID, rule)
	if err != nil {
		t.Fatalf("SetRule() error = %v", err)
	}
	defer func() {
		// Cleanup
		_ = client.DeleteRule(ctx, testUUID)
	}()

	// Now try to find it by description
	t.Log("Searching rule by description...")
	found, err := client.GetRuleByDescription(ctx, "Test rule for PULL_API [nd-template:test]")
	if err != nil {
		t.Fatalf("GetRuleByDescription() error = %v", err)
	}
	if found == nil {
		t.Fatal("GetRuleByDescription() returned nil, expected rule")
	}

	t.Logf("Found rule: uuid=%s, description=%s", found["uuid"], found["description"])

	// Search for non-existent rule
	notFound, err := client.GetRuleByDescription(ctx, "NonExistentRule12345")
	if err != nil {
		t.Fatalf("GetRuleByDescription() error for non-existent = %v", err)
	}
	if notFound != nil {
		t.Error("GetRuleByDescription() should return nil for non-existent rule")
	}
	t.Log("Non-existent rule correctly returned nil")
}

func TestIntegration_ReconfigureAndApply(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// These should succeed even with no pending changes
	t.Log("Testing ReconfigureAliases...")
	err := client.ReconfigureAliases(ctx)
	if err != nil {
		t.Fatalf("ReconfigureAliases() error = %v", err)
	}
	t.Log("ReconfigureAliases successful")

	t.Log("Testing ApplyRules...")
	err = client.ApplyRules(ctx)
	if err != nil {
		t.Fatalf("ApplyRules() error = %v", err)
	}
	t.Log("ApplyRules successful")
}

func TestIntegration_FindAliasUsage(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First list all rules to see what fields are available
	allRules, err := client.ListAllRules(ctx)
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}

	t.Logf("Found %d rules total", len(allRules))
	for _, rule := range allRules {
		uuid, _ := rule["uuid"].(string)
		desc, _ := rule["description"].(string)
		sourceNet, _ := rule["source_net"].(string)
		destNet, _ := rule["destination_net"].(string)
		t.Logf("  Rule %s: desc=%q source_net=%q dest_net=%q", uuid, desc, sourceNet, destNet)
	}

	// Now test FindAliasUsage
	refs, err := client.FindAliasUsage(ctx, "Console_PKI")
	if err != nil {
		t.Fatalf("FindAliasUsage() error = %v", err)
	}

	t.Logf("FindAliasUsage('Console_PKI') returned %d references:", len(refs))
	for _, ref := range refs {
		t.Logf("  - %s", ref)
	}
}

// ===== User and Group Integration Tests =====

func TestIntegration_ListUsers(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers() error = %v", err)
	}

	managedUsers := FilterManagedUsers(allUsers)

	t.Logf("Found %d total users, %d managed", len(allUsers), len(managedUsers))
	for _, user := range allUsers {
		t.Logf("  - %s: %s (uid=%s, scope=%s)", user["uuid"], user["name"], user["uid"], user["scope"])
	}
}

func TestIntegration_ListGroups(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		t.Fatalf("ListAllGroups() error = %v", err)
	}

	managedGroups := FilterManagedGroups(allGroups)

	t.Logf("Found %d total groups, %d managed", len(allGroups), len(managedGroups))
	for _, group := range allGroups {
		t.Logf("  - %s: %s (gid=%s)", group["uuid"], group["name"], group["gid"])
	}
}

func TestIntegration_CreateAndDeleteGroup(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create test group
	group := Group{
		Name:        "nd_integration_test_group",
		Description: "Integration test group " + "[nd-template:integration-test]",
		Priv:        "page-system-login-logout",
	}

	t.Log("Creating test group...")
	newUUID, err := client.AddGroup(ctx, group)
	if err != nil {
		t.Fatalf("AddGroup() error = %v", err)
	}
	t.Logf("Group created with UUID: %s", newUUID)

	// Verify it exists
	groups, err := client.SearchGroups(ctx, "nd_integration_test_group")
	if err != nil {
		t.Fatalf("SearchGroups() error = %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("Expected 1 group, got %d", len(groups))
	} else {
		t.Logf("Found group: uuid=%s, name=%s, gid=%s", groups[0]["uuid"], groups[0]["name"], groups[0]["gid"])
	}

	// Test update
	group.Description = "Updated description " + "[nd-template:integration-test]"
	err = client.SetGroup(ctx, newUUID, group)
	if err != nil {
		t.Fatalf("SetGroup() error = %v", err)
	}
	t.Log("Group updated successfully")

	// Delete the group
	t.Log("Deleting test group...")
	err = client.DeleteGroup(ctx, newUUID)
	if err != nil {
		t.Fatalf("DeleteGroup() error = %v", err)
	}
	t.Log("Group deleted successfully")

	// Verify it's gone
	groups, err = client.SearchGroups(ctx, "nd_integration_test_group")
	if err != nil {
		t.Fatalf("SearchGroups() error = %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("Expected 0 groups after delete, got %d", len(groups))
	}
	t.Log("Group cleanup verified")
}

func TestIntegration_CreateAndDeleteUser(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create test user with password
	user := User{
		Name:     "nd_integration_test_user",
		Password: "TestPassword123!Secure",
		Disabled: "0",
		Scope:    "user",
		Descr:    "Integration test user " + "[nd-template:integration-test]",
	}

	t.Log("Creating test user...")
	newUUID, err := client.AddUser(ctx, user)
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}
	t.Logf("User created with UUID: %s", newUUID)

	// Verify it exists
	users, err := client.SearchUsers(ctx, "nd_integration_test_user")
	if err != nil {
		t.Fatalf("SearchUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	} else {
		t.Logf("Found user: uuid=%s, name=%s, uid=%s", users[0]["uuid"], users[0]["name"], users[0]["uid"])
	}

	// Test update (without changing password)
	user.Descr = "Updated description " + "[nd-template:integration-test]"
	user.Password = "" // Don't update password
	err = client.SetUser(ctx, newUUID, user)
	if err != nil {
		t.Fatalf("SetUser() error = %v", err)
	}
	t.Log("User updated successfully")

	// Delete the user
	t.Log("Deleting test user...")
	err = client.DeleteUser(ctx, newUUID)
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	t.Log("User deleted successfully")

	// Verify it's gone
	users, err = client.SearchUsers(ctx, "nd_integration_test_user")
	if err != nil {
		t.Fatalf("SearchUsers() error = %v", err)
	}
	if len(users) != 0 {
		t.Errorf("Expected 0 users after delete, got %d", len(users))
	}
	t.Log("User cleanup verified")
}

func TestIntegration_UserWithGroupMembership(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// First create a test group
	group := Group{
		Name:        "nd_test_membership_group",
		Description: "Test group for membership " + "[nd-template:integration-test]",
	}

	t.Log("Creating test group...")
	groupUUID, err := client.AddGroup(ctx, group)
	if err != nil {
		t.Fatalf("AddGroup() error = %v", err)
	}
	t.Logf("Group created with UUID: %s", groupUUID)
	defer func() {
		_ = client.DeleteGroup(ctx, groupUUID)
	}()

	// Get the GID for the new group
	allGroups, _ := client.ListAllGroups(ctx)
	gidLookup := BuildGIDLookup(allGroups)
	groupGID := gidLookup["nd_test_membership_group"]
	t.Logf("Group GID: %s", groupGID)

	// Create a user in that group
	user := User{
		Name:             "nd_test_membership_user",
		Password:         "TestPassword123!Secure",
		Disabled:         "0",
		Scope:            "user",
		Descr:            "Test user with group " + "[nd-template:integration-test]",
		GroupMemberships: groupGID,
	}

	t.Log("Creating test user with group membership...")
	userUUID, err := client.AddUser(ctx, user)
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}
	t.Logf("User created with UUID: %s", userUUID)
	defer func() {
		_ = client.DeleteUser(ctx, userUUID)
	}()

	// Verify the user has the group membership
	users, err := client.SearchUsers(ctx, "nd_test_membership_user")
	if err != nil {
		t.Fatalf("SearchUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("Expected 1 user, got %d", len(users))
	}

	userGroupMemberships, _ := users[0]["group_memberships"].(string)
	t.Logf("User group_memberships: %s", userGroupMemberships)

	if userGroupMemberships != groupGID {
		t.Errorf("Expected group_memberships=%s, got %s", groupGID, userGroupMemberships)
	}

	t.Log("User group membership verified")
}

func TestIntegration_GetUserByName(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create test user
	user := User{
		Name:     "nd_test_getbyname",
		Password: "TestPassword123!Secure",
		Disabled: "0",
		Scope:    "user",
		Descr:    "Test user for GetByName " + "[nd-template:integration-test]",
	}

	t.Log("Creating test user...")
	userUUID, err := client.AddUser(ctx, user)
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}
	defer func() {
		_ = client.DeleteUser(ctx, userUUID)
	}()

	// Find by name
	found, err := client.GetUserByName(ctx, "nd_test_getbyname")
	if err != nil {
		t.Fatalf("GetUserByName() error = %v", err)
	}
	if found == nil {
		t.Fatal("GetUserByName() returned nil, expected user")
	}

	t.Logf("Found user: uuid=%s, name=%s", found["uuid"], found["name"])

	// Search for non-existent user
	notFound, err := client.GetUserByName(ctx, "NonExistentUser12345")
	if err != nil {
		t.Fatalf("GetUserByName() error for non-existent = %v", err)
	}
	if notFound != nil {
		t.Error("GetUserByName() should return nil for non-existent user")
	}
	t.Log("Non-existent user correctly returned nil")
}

func TestIntegration_GetGroupByName(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create test group
	group := Group{
		Name:        "nd_test_getbyname_group",
		Description: "Test group for GetByName " + "[nd-template:integration-test]",
	}

	t.Log("Creating test group...")
	groupUUID, err := client.AddGroup(ctx, group)
	if err != nil {
		t.Fatalf("AddGroup() error = %v", err)
	}
	defer func() {
		_ = client.DeleteGroup(ctx, groupUUID)
	}()

	// Find by name
	found, err := client.GetGroupByName(ctx, "nd_test_getbyname_group")
	if err != nil {
		t.Fatalf("GetGroupByName() error = %v", err)
	}
	if found == nil {
		t.Fatal("GetGroupByName() returned nil, expected group")
	}

	t.Logf("Found group: uuid=%s, name=%s", found["uuid"], found["name"])

	// Search for non-existent group
	notFound, err := client.GetGroupByName(ctx, "NonExistentGroup12345")
	if err != nil {
		t.Fatalf("GetGroupByName() error for non-existent = %v", err)
	}
	if notFound != nil {
		t.Error("GetGroupByName() should return nil for non-existent group")
	}
	t.Log("Non-existent group correctly returned nil")
}

func TestIntegration_ConvertUserToAPI(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get all groups for the lookup
	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		t.Fatalf("ListAllGroups() error = %v", err)
	}

	// Get a user to convert
	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers() error = %v", err)
	}

	if len(allUsers) == 0 {
		t.Skip("No users to test conversion")
	}

	// Convert first non-root user
	for _, user := range allUsers {
		name, _ := user["name"].(string)
		if name == "root" {
			continue
		}

		payload := ConvertUserToAPI(user, allGroups)
		t.Logf("Converted user: name=%s, scope=%s, groups=%v", payload.Name, payload.Scope, payload.Groups)
		break
	}
}

func TestIntegration_ConvertGroupToAPI(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get all users for the lookup
	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers() error = %v", err)
	}

	// Get a group to convert
	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		t.Fatalf("ListAllGroups() error = %v", err)
	}

	if len(allGroups) == 0 {
		t.Skip("No groups to test conversion")
	}

	// Convert first non-admins group
	for _, group := range allGroups {
		name, _ := group["name"].(string)
		if name == "admins" {
			continue
		}

		payload := ConvertGroupToAPI(group, allUsers)
		t.Logf("Converted group: name=%s, members=%v, priv=%v", payload.Name, payload.Members, payload.Priv)
		break
	}
}

// ===== Unbound DNS Integration Tests =====

func TestIntegration_ListHostOverrides(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allOverrides, err := client.ListAllHostOverrides(ctx)
	if err != nil {
		t.Fatalf("ListAllHostOverrides() error = %v", err)
	}

	managedOverrides := FilterManagedHostOverrides(allOverrides)

	t.Logf("Found %d total host overrides, %d managed", len(allOverrides), len(managedOverrides))
	for _, override := range allOverrides {
		t.Logf("  - %s: %s.%s (%s)", override["uuid"], override["hostname"], override["domain"], override["rr"])
	}
}

func TestIntegration_ListForwards(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allForwards, err := client.ListAllForwards(ctx)
	if err != nil {
		t.Fatalf("ListAllForwards() error = %v", err)
	}

	managedForwards := FilterManagedForwards(allForwards)

	t.Logf("Found %d total domain forwards, %d managed", len(allForwards), len(managedForwards))
	for _, forward := range allForwards {
		t.Logf("  - %s: %s -> %s (%s)", forward["uuid"], forward["domain"], forward["server"], forward["type"])
	}
}

func TestIntegration_ListHostAliases(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allAliases, err := client.ListAllHostAliases(ctx)
	if err != nil {
		t.Fatalf("ListAllHostAliases() error = %v", err)
	}

	managedAliases := FilterManagedHostAliases(allAliases)

	t.Logf("Found %d total host aliases, %d managed", len(allAliases), len(managedAliases))
	for _, alias := range allAliases {
		t.Logf("  - %s: %s.%s -> host %s", alias["uuid"], alias["hostname"], alias["domain"], alias["host"])
	}
}

func TestIntegration_ListACLs(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allACLs, err := client.ListAllACLs(ctx)
	if err != nil {
		t.Fatalf("ListAllACLs() error = %v", err)
	}

	managedACLs := FilterManagedACLs(allACLs)

	t.Logf("Found %d total ACLs, %d managed", len(allACLs), len(managedACLs))
	for _, acl := range allACLs {
		t.Logf("  - %s: %s (%s)", acl["uuid"], acl["name"], acl["action"])
	}
}

func TestIntegration_CreateAndDeleteHostOverride(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test UUID with NDAgent prefix. OPNsense validates the UUID as strict
	// RFC-4122 hex; mnemonic segments (e.g. "ho01") contain non-hex chars and
	// get rejected with {"result":"failed"}.
	testUUID := "221f3268-0ff0-4abc-9001-000000000001"

	// Create test host override
	override := HostOverride{
		Enabled:     "1",
		Hostname:    "nd-integration-test",
		Domain:      "local",
		RR:          "A",
		Server:      "192.168.1.100",
		Description: "Integration test host override [nd-template:test]",
	}

	t.Log("Creating test host override...")
	err := client.SetHostOverride(ctx, testUUID, override)
	if err != nil {
		t.Fatalf("SetHostOverride() error = %v", err)
	}
	t.Log("Host override created successfully")

	// Verify it exists
	found, err := client.GetHostOverrideByName(ctx, "nd-integration-test", "local")
	if err != nil {
		t.Fatalf("GetHostOverrideByName() error = %v", err)
	}
	if found == nil {
		t.Error("Expected to find created host override")
	} else {
		t.Logf("Found host override: uuid=%s, hostname=%s", found["uuid"], found["hostname"])
	}

	// Delete the host override
	t.Log("Deleting test host override...")
	err = client.DeleteHostOverride(ctx, testUUID)
	if err != nil {
		t.Fatalf("DeleteHostOverride() error = %v", err)
	}
	t.Log("Host override deleted successfully")

	// Verify it's gone
	found, err = client.GetHostOverrideByName(ctx, "nd-integration-test", "local")
	if err != nil {
		t.Fatalf("GetHostOverrideByName() error = %v", err)
	}
	if found != nil {
		t.Error("Host override should be deleted")
	}
	t.Log("Host override cleanup verified")
}

func TestIntegration_CreateAndDeleteDomainForward(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test UUID with NDAgent prefix (strict hex — see hostOverride test for why).
	testUUID := "221f3268-0f01-4abc-9001-000000000001"

	// Create test domain forward
	forward := DomainForward{
		Enabled:     "1",
		Type:        "forward",
		Domain:      "nd-integration-test.local",
		Server:      "10.0.0.1",
		Description: "Integration test domain forward [nd-template:test]",
	}

	t.Log("Creating test domain forward...")
	err := client.SetForward(ctx, testUUID, forward)
	if err != nil {
		t.Fatalf("SetForward() error = %v", err)
	}
	t.Log("Domain forward created successfully")

	// Verify it exists
	found, err := client.GetForwardByDomain(ctx, "nd-integration-test.local")
	if err != nil {
		t.Fatalf("GetForwardByDomain() error = %v", err)
	}
	if found == nil {
		t.Error("Expected to find created domain forward")
	} else {
		t.Logf("Found domain forward: uuid=%s, domain=%s", found["uuid"], found["domain"])
	}

	// Delete the domain forward
	t.Log("Deleting test domain forward...")
	err = client.DeleteForward(ctx, testUUID)
	if err != nil {
		t.Fatalf("DeleteForward() error = %v", err)
	}
	t.Log("Domain forward deleted successfully")

	// Verify it's gone
	found, err = client.GetForwardByDomain(ctx, "nd-integration-test.local")
	if err != nil {
		t.Fatalf("GetForwardByDomain() error = %v", err)
	}
	if found != nil {
		t.Error("Domain forward should be deleted")
	}
	t.Log("Domain forward cleanup verified")
}

func TestIntegration_CreateAndDeleteHostAlias(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// First create a parent host override (strict-hex UUID).
	parentUUID := "221f3268-0ff0-4abc-9001-000000000002"
	parentOverride := HostOverride{
		Enabled:     "1",
		Hostname:    "nd-integration-parent",
		Domain:      "local",
		RR:          "A",
		Server:      "192.168.1.101",
		Description: "Parent host for alias test [nd-template:test]",
	}

	t.Log("Creating parent host override...")
	err := client.SetHostOverride(ctx, parentUUID, parentOverride)
	if err != nil {
		t.Fatalf("SetHostOverride() error = %v", err)
	}
	defer func() {
		_ = client.DeleteHostOverride(ctx, parentUUID)
	}()

	// Create test host alias (strict-hex UUID).
	aliasUUID := "221f3268-0a1a-4abc-9001-000000000001"
	alias := HostAlias{
		Enabled:     "1",
		Host:        parentUUID,
		Hostname:    "nd-integration-alias",
		Domain:      "local",
		Description: "Integration test host alias [nd-template:test]",
	}

	t.Log("Creating test host alias...")
	err = client.SetHostAlias(ctx, aliasUUID, alias)
	if err != nil {
		t.Fatalf("SetHostAlias() error = %v", err)
	}
	t.Log("Host alias created successfully")

	// Verify it exists
	found, err := client.GetHostAliasByName(ctx, "nd-integration-alias", "local")
	if err != nil {
		t.Fatalf("GetHostAliasByName() error = %v", err)
	}
	if found == nil {
		t.Error("Expected to find created host alias")
	} else {
		t.Logf("Found host alias: uuid=%s, hostname=%s, host=%s", found["uuid"], found["hostname"], found["host"])
	}

	// Delete the host alias
	t.Log("Deleting test host alias...")
	err = client.DeleteHostAlias(ctx, aliasUUID)
	if err != nil {
		t.Fatalf("DeleteHostAlias() error = %v", err)
	}
	t.Log("Host alias deleted successfully")

	// Verify it's gone
	found, err = client.GetHostAliasByName(ctx, "nd-integration-alias", "local")
	if err != nil {
		t.Fatalf("GetHostAliasByName() error = %v", err)
	}
	if found != nil {
		t.Error("Host alias should be deleted")
	}
	t.Log("Host alias cleanup verified")
}

func TestIntegration_CreateAndDeleteACL(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test UUID with NDAgent prefix
	testUUID := "221f3268-ac01-4abc-9001-000000000001"

	// Create test ACL
	acl := UnboundACL{
		Enabled:     "1",
		Name:        "nd_integration_test_acl",
		Action:      "allow",
		Networks:    "192.168.100.0/24",
		Description: "Integration test ACL [nd-template:test]",
	}

	t.Log("Creating test ACL...")
	err := client.SetACL(ctx, testUUID, acl)
	if err != nil {
		t.Fatalf("SetACL() error = %v", err)
	}
	t.Log("ACL created successfully")

	// Verify it exists
	found, err := client.GetACLByName(ctx, "nd_integration_test_acl")
	if err != nil {
		t.Fatalf("GetACLByName() error = %v", err)
	}
	if found == nil {
		t.Error("Expected to find created ACL")
	} else {
		t.Logf("Found ACL: uuid=%s, name=%s, action=%s", found["uuid"], found["name"], found["action"])
	}

	// Delete the ACL
	t.Log("Deleting test ACL...")
	err = client.DeleteACL(ctx, testUUID)
	if err != nil {
		t.Fatalf("DeleteACL() error = %v", err)
	}
	t.Log("ACL deleted successfully")

	// Verify it's gone
	found, err = client.GetACLByName(ctx, "nd_integration_test_acl")
	if err != nil {
		t.Fatalf("GetACLByName() error = %v", err)
	}
	if found != nil {
		t.Error("ACL should be deleted")
	}
	t.Log("ACL cleanup verified")
}

func TestIntegration_ReconfigureUnbound(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("Testing ReconfigureUnbound...")
	err := client.ReconfigureUnbound(ctx)
	if err != nil {
		t.Fatalf("ReconfigureUnbound() error = %v", err)
	}
	t.Log("ReconfigureUnbound successful")
}

func TestIntegration_ConvertHostOverrideToAPI(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	allOverrides, err := client.ListAllHostOverrides(ctx)
	if err != nil {
		t.Fatalf("ListAllHostOverrides() error = %v", err)
	}

	if len(allOverrides) == 0 {
		t.Skip("No host overrides to test conversion")
	}

	payload := ConvertHostOverrideToAPI(allOverrides[0])
	t.Logf("Converted host override: hostname=%s, domain=%s, rr=%s, server=%s",
		payload.Hostname, payload.Domain, payload.RR, payload.Server)
}

func TestIntegration_ConvertHostAliasToAPI(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	allAliases, err := client.ListAllHostAliases(ctx)
	if err != nil {
		t.Fatalf("ListAllHostAliases() error = %v", err)
	}

	if len(allAliases) == 0 {
		t.Skip("No host aliases to test conversion")
	}

	allOverrides, err := client.ListAllHostOverrides(ctx)
	if err != nil {
		t.Fatalf("ListAllHostOverrides() error = %v", err)
	}

	payload := ConvertHostAliasToAPI(allAliases[0], allOverrides)
	t.Logf("Converted host alias: hostname=%s, domain=%s, parent=%s.%s",
		payload.Hostname, payload.Domain, payload.ParentHostname, payload.ParentDomain)
}
