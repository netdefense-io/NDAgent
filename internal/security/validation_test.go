package security

import (
	"strings"
	"testing"
)

func TestValidatePingTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr error
	}{
		// Valid cases
		{"valid hostname", "example.com", nil},
		{"valid IP", "8.8.8.8", nil},
		{"valid hostname with hyphen", "my-server.example.com", nil},
		{"valid hostname with numbers", "server1.example.com", nil},
		{"valid subdomain", "sub.domain.example.com", nil},
		{"simple hostname", "localhost", nil},

		// Invalid cases
		{"empty target", "", ErrEmptyTarget},
		{"command injection semicolon", "8.8.8.8;ls", ErrInvalidTargetFormat},
		{"command injection pipe", "8.8.8.8|cat /etc/passwd", ErrInvalidTargetFormat},
		{"command injection backtick", "`whoami`", ErrInvalidTargetFormat},
		{"command injection subshell", "$(whoami)", ErrInvalidTargetFormat},
		{"command injection ampersand", "8.8.8.8&&ls", ErrInvalidTargetFormat},
		{"spaces in target", "8.8.8.8 -c 100", ErrInvalidTargetFormat},
		{"newline injection", "8.8.8.8\nls", ErrInvalidTargetFormat},
		{"unicode in target", "8.8.8.8\u0000ls", ErrInvalidTargetFormat},
		{"underscore not allowed", "my_server.com", ErrInvalidTargetFormat},
		{"slash in target", "example.com/path", ErrInvalidTargetFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePingTarget(tt.target)
			if err != tt.wantErr {
				t.Errorf("ValidatePingTarget(%q) = %v, want %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePingTargetLongHostname(t *testing.T) {
	// Create a hostname that exceeds 253 characters
	longHostname := strings.Repeat("a", 254)
	err := ValidatePingTarget(longHostname)
	if err != ErrTargetTooLong {
		t.Errorf("ValidatePingTarget(long hostname) = %v, want %v", err, ErrTargetTooLong)
	}

	// Hostname at exactly 253 should be valid
	maxHostname := strings.Repeat("a", 253)
	err = ValidatePingTarget(maxHostname)
	if err != nil {
		t.Errorf("ValidatePingTarget(253 char hostname) = %v, want nil", err)
	}
}

func TestValidateConfigFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		// Valid cases
		{"valid conf file", "ndagent.conf", nil},
		{"valid with underscore", "my_config.conf", nil},
		{"valid with hyphen", "my-config.conf", nil},
		{"valid with numbers", "config123.conf", nil},
		{"valid full path", "/etc/ndagent/ndagent.conf", nil},

		// Invalid cases
		{"wrong extension txt", "config.txt", ErrInvalidConfigExtension},
		{"wrong extension xml", "config.xml", ErrInvalidConfigExtension},
		{"no extension", "config", ErrInvalidConfigExtension},
		{"hidden file with .conf", ".hidden.conf", ErrInvalidConfigPath},
		{"path traversal", "../etc.conf", ErrInvalidConfigPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfigFilePath(tt.path)
			if err != tt.wantErr {
				t.Errorf("ValidateConfigFilePath(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFullConfigPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid cases
		{"valid absolute path", "/etc/ndagent/ndagent.conf", false},
		{"valid simple path", "ndagent.conf", false},
		{"valid usr local path", "/usr/local/etc/ndagent.conf", false},

		// Invalid cases
		{"wrong extension", "/etc/ndagent/config.txt", true},
		{"null byte", "/etc/ndagent\x00/config.conf", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFullConfigPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFullConfigPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeLogMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"normal message", "This is a log message", "This is a log message"},
		{"newline injection", "Line1\nLine2", "Line1 Line2"},
		{"carriage return", "Line1\rLine2", "Line1 Line2"},
		{"crlf injection", "Line1\r\nLine2", "Line1  Line2"},
		{"null byte", "Message\x00injection", "Messageinjection"},
		{"multiple newlines", "A\n\n\nB", "A   B"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLogMessage(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeLogMessage(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeLogMessageTruncation(t *testing.T) {
	// Create a message longer than MaxLogMessageLength
	longMessage := strings.Repeat("A", MaxLogMessageLength+100)
	result := SanitizeLogMessage(longMessage)

	if !strings.HasSuffix(result, "... [TRUNCATED]") {
		t.Errorf("Long message should be truncated with suffix")
	}

	// The result should be truncated to MaxLogMessageLength + suffix
	expectedLen := MaxLogMessageLength + len("... [TRUNCATED]")
	if len(result) != expectedLen {
		t.Errorf("Truncated message length = %d, want %d", len(result), expectedLen)
	}
}

func TestIsSafeFilePath(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		extensions []string
		want       bool
	}{
		// Valid cases
		{"valid xml file", "/conf/config.xml", []string{".xml"}, true},
		{"valid conf file", "/etc/ndagent.conf", []string{".conf"}, true},
		{"valid with multiple extensions", "/path/file.xml", []string{".conf", ".xml"}, true},
		{"no extension restriction", "/path/anyfile", []string{}, true},

		// Invalid cases
		{"empty path", "", []string{}, false},
		{"path traversal", "/etc/../passwd", []string{}, false},
		{"path traversal dots", "../../etc/passwd", []string{}, false},
		{"null byte", "/etc/config\x00.xml", []string{".xml"}, false},
		{"wrong extension", "/etc/config.txt", []string{".xml", ".conf"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSafeFilePath(tt.filePath, tt.extensions)
			if result != tt.want {
				t.Errorf("IsSafeFilePath(%q, %v) = %v, want %v", tt.filePath, tt.extensions, result, tt.want)
			}
		})
	}
}

func TestValidatePingCount(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"valid count 1", 1, false},
		{"valid count 4", 4, false},
		{"valid count 100", 100, false},
		{"zero count", 0, true},
		{"negative count", -1, true},
		{"too large count", 101, true},
		{"way too large", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePingCount(tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePingCount(%d) error = %v, wantErr %v", tt.count, err, tt.wantErr)
			}
		})
	}
}
