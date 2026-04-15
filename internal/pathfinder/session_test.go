package pathfinder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"root", "root"},
		{"admin", "admin"},
		{"user_name", "user_name"},
		{"user-name", "user-name"},
		{"user123", "user123"},
		{"../../../etc/passwd", "etcpasswd"},
		{"user;rm -rf /", "userrm-rf"},
		{"user\x00name", "username"},
		{"user/name", "username"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeUsername(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeUsername(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsValidSessionID(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"f6737f4c3759186bf3a7a2a34295e8f8", true},
		{"ABCDEF0123456789abcdef0123456789", true},
		{"f6737f4c3759186bf3a7a2a34295e8f", false},  // Too short
		{"f6737f4c3759186bf3a7a2a34295e8f88", false}, // Too long
		{"g6737f4c3759186bf3a7a2a34295e8f8", false},  // Invalid char 'g'
		{"f6737f4c3759186bf3a7a2a34295e8f!", false},  // Invalid char '!'
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isValidSessionID(tt.input)
			if result != tt.valid {
				t.Errorf("isValidSessionID(%q) = %v, want %v", tt.input, result, tt.valid)
			}
		})
	}
}

func TestGenerateRandomHex(t *testing.T) {
	hex1, err := generateRandomHex(16)
	if err != nil {
		t.Fatalf("generateRandomHex failed: %v", err)
	}

	if len(hex1) != 32 {
		t.Errorf("Expected 32 char hex, got %d", len(hex1))
	}

	// Verify it's valid hex
	if !isValidSessionID(hex1) {
		t.Errorf("Generated hex is not valid session ID format: %s", hex1)
	}

	// Generate another and verify they're different
	hex2, err := generateRandomHex(16)
	if err != nil {
		t.Fatalf("generateRandomHex failed: %v", err)
	}

	if hex1 == hex2 {
		t.Error("Two generated hex strings should be different")
	}
}

func TestGenerateRandomString(t *testing.T) {
	str1, err := generateRandomString(22)
	if err != nil {
		t.Fatalf("generateRandomString failed: %v", err)
	}

	if len(str1) != 22 {
		t.Errorf("Expected 22 char string, got %d", len(str1))
	}

	// Verify it only contains alphanumeric characters
	for _, c := range str1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			t.Errorf("Invalid character in random string: %c", c)
		}
	}

	// Generate another and verify they're different
	str2, err := generateRandomString(22)
	if err != nil {
		t.Fatalf("generateRandomString failed: %v", err)
	}

	if str1 == str2 {
		t.Error("Two generated strings should be different")
	}
}

func TestSerializePHPSession(t *testing.T) {
	sm := NewSessionManager("root", "/tmp")

	session := &Session{
		ID:        "f6737f4c3759186bf3a7a2a34295e8f8",
		CSRFToken: "abcdefghijklmnopqrstuv",
		CSRFKey:   "ABCDEFGHIJKLMNOPQRSTUV",
		Username:  "root",
		FilePath:  "/tmp/sess_f6737f4c3759186bf3a7a2a34295e8f8",
		CreatedAt: time.Unix(1700000000, 0),
	}

	data := sm.serializePHPSession(session)
	result := string(data)

	// Check that all required fields are present
	expectedParts := []string{
		`$PHALCON/CSRF$|s:22:"abcdefghijklmnopqrstuv"`,
		`$PHALCON/CSRF/KEY$|s:22:"ABCDEFGHIJKLMNOPQRSTUV"`,
		`Username|s:4:"root"`,
		`last_access|i:1700000000`,
		`protocol|s:5:"https"`,
	}

	for _, part := range expectedParts {
		if !strings.Contains(result, part) {
			t.Errorf("Session data missing expected part: %s\nGot: %s", part, result)
		}
	}
}

func TestSessionManagerCreateAndDestroy(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm := NewSessionManager("testuser", tmpDir)

	// Create a session
	session, err := sm.CreateSession()
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Verify session properties
	if len(session.ID) != 32 {
		t.Errorf("Session ID should be 32 chars, got %d", len(session.ID))
	}

	if len(session.CSRFToken) != 22 {
		t.Errorf("CSRF token should be 22 chars, got %d", len(session.CSRFToken))
	}

	if len(session.CSRFKey) != 22 {
		t.Errorf("CSRF key should be 22 chars, got %d", len(session.CSRFKey))
	}

	if session.Username != "testuser" {
		t.Errorf("Username should be 'testuser', got %q", session.Username)
	}

	// Verify session file exists
	expectedPath := filepath.Join(tmpDir, "sess_"+session.ID)
	if session.FilePath != expectedPath {
		t.Errorf("FilePath = %q, want %q", session.FilePath, expectedPath)
	}

	info, err := os.Stat(session.FilePath)
	if err != nil {
		t.Fatalf("Session file not found: %v", err)
	}

	// Verify file permissions (0600)
	if info.Mode().Perm() != 0600 {
		t.Errorf("Session file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Read and verify session content
	content, err := os.ReadFile(session.FilePath)
	if err != nil {
		t.Fatalf("Failed to read session file: %v", err)
	}

	if !strings.Contains(string(content), "testuser") {
		t.Error("Session file should contain username")
	}

	if !strings.Contains(string(content), "$PHALCON/CSRF$") {
		t.Error("Session file should contain CSRF token")
	}

	// Destroy session
	if err := sm.DestroySession(session.ID); err != nil {
		t.Fatalf("DestroySession failed: %v", err)
	}

	// Verify file is removed
	if _, err := os.Stat(session.FilePath); !os.IsNotExist(err) {
		t.Error("Session file should be removed after destroy")
	}

	// Destroying non-existent session should not error
	if err := sm.DestroySession(session.ID); err != nil {
		t.Errorf("Destroying non-existent session should not error: %v", err)
	}
}

func TestDestroySessionInvalidID(t *testing.T) {
	sm := NewSessionManager("root", "/tmp")

	// Invalid session IDs should be rejected
	invalidIDs := []string{
		"../../../etc/passwd",
		"short",
		"toolongtobeavalidphpsessionidvalue",
		"invalid!characters!in!id!!!!!!!!!!",
	}

	for _, id := range invalidIDs {
		err := sm.DestroySession(id)
		if err == nil {
			t.Errorf("DestroySession(%q) should return error for invalid ID", id)
		}
	}
}

func TestNewSessionManagerDefaults(t *testing.T) {
	sm := NewSessionManager("", "")

	if sm.username != "root" {
		t.Errorf("Default username should be 'root', got %q", sm.username)
	}

	if sm.sessionDir != defaultSessionDir {
		t.Errorf("Default session dir should be %q, got %q", defaultSessionDir, sm.sessionDir)
	}
}
