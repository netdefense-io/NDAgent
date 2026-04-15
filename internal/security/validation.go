// Package security provides input validation and sanitization functions.
package security

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// pingTargetRegex validates ping targets (alphanumeric, dots, hyphens only)
	pingTargetRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

	// configFilenameRegex validates config filenames
	configFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+\.conf$`)
)

const (
	// MaxHostnameLength is the RFC 1035 DNS hostname length limit
	MaxHostnameLength = 253

	// MaxLogMessageLength is the maximum length for sanitized log messages
	MaxLogMessageLength = 1000
)

// ErrEmptyTarget is returned when ping target is empty
var ErrEmptyTarget = errors.New("no target specified for ping")

// ErrInvalidTargetFormat is returned when ping target contains invalid characters
var ErrInvalidTargetFormat = errors.New("invalid target format: only alphanumeric characters, dots, and hyphens are allowed")

// ErrTargetTooLong is returned when ping target exceeds hostname length limit
var ErrTargetTooLong = errors.New("target hostname too long")

// ErrInvalidConfigExtension is returned when config file doesn't have .conf extension
var ErrInvalidConfigExtension = errors.New("invalid config file extension: only .conf files are allowed")

// ErrInvalidConfigPath is returned when config file path contains directory components
var ErrInvalidConfigPath = errors.New("invalid config file path: only files in current working directory are allowed")

// ErrInvalidConfigFilename is returned when config filename contains invalid characters
var ErrInvalidConfigFilename = errors.New("invalid config filename format: only alphanumeric characters, dots, hyphens, and underscores allowed")

// ValidatePingTarget validates a ping target to prevent command injection.
// Returns nil if valid, error otherwise.
func ValidatePingTarget(target string) error {
	if target == "" {
		return ErrEmptyTarget
	}

	// TASK-001 Security Fix: Validate target input to prevent command injection
	if !pingTargetRegex.MatchString(target) {
		return ErrInvalidTargetFormat
	}

	// RFC 1035 DNS hostname length limit
	if len(target) > MaxHostnameLength {
		return ErrTargetTooLong
	}

	return nil
}

// ValidateConfigFilePath validates a config file path for security.
// This is used when the path is provided via command line argument.
// For full paths (like /usr/local/etc/ndagent.conf), use ValidateFullConfigPath instead.
func ValidateConfigFilePath(configPath string) error {
	// Validate file extension - only .conf files allowed
	if !strings.HasSuffix(configPath, ".conf") {
		return ErrInvalidConfigExtension
	}

	// Check for path traversal in all paths
	if strings.Contains(configPath, "..") {
		return ErrInvalidConfigPath
	}

	// Check for hidden files (starting with dot)
	filename := filepath.Base(configPath)
	if strings.HasPrefix(filename, ".") {
		return ErrInvalidConfigPath
	}

	// For relative paths (no slashes), validate filename format
	if !strings.Contains(configPath, "/") && !strings.Contains(configPath, "\\") {
		// Validate filename format
		if !configFilenameRegex.MatchString(configPath) {
			return ErrInvalidConfigFilename
		}
	}

	return nil
}

// ValidateFullConfigPath validates a full config file path.
// This allows absolute paths but still checks for basic safety.
func ValidateFullConfigPath(configPath string) error {
	// Validate file extension - only .conf files allowed
	if !strings.HasSuffix(configPath, ".conf") {
		return ErrInvalidConfigExtension
	}

	// Check for null bytes
	if strings.Contains(configPath, "\x00") {
		return errors.New("invalid config path: contains null bytes")
	}

	// Check for path traversal in the path components
	// Clean the path first to normalize it
	cleanPath := filepath.Clean(configPath)

	// After cleaning, check if ".." still exists (which would indicate traversal attempt)
	parts := strings.Split(cleanPath, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return errors.New("invalid config path: path traversal not allowed")
		}
	}

	return nil
}

// SanitizeLogMessage sanitizes a log message to prevent log injection attacks.
func SanitizeLogMessage(message string) string {
	if message == "" {
		return ""
	}

	// Remove newlines and carriage returns to prevent log injection
	sanitized := strings.ReplaceAll(message, "\n", " ")
	sanitized = strings.ReplaceAll(sanitized, "\r", " ")

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Limit length to prevent log bombing
	if len(sanitized) > MaxLogMessageLength {
		sanitized = sanitized[:MaxLogMessageLength] + "... [TRUNCATED]"
	}

	return sanitized
}

// IsSafeFilePath checks if a file path is safe for operations.
func IsSafeFilePath(filePath string, allowedExtensions []string) bool {
	if filePath == "" {
		return false
	}

	// Check for path traversal attempts
	if strings.Contains(filePath, "..") {
		return false
	}

	// Check for null bytes
	if strings.Contains(filePath, "\x00") {
		return false
	}

	// Check file extension if specified
	if len(allowedExtensions) > 0 {
		ext := strings.ToLower(filepath.Ext(filePath))
		found := false
		for _, allowedExt := range allowedExtensions {
			if ext == strings.ToLower(allowedExt) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// ValidatePingCount validates the ping count parameter.
func ValidatePingCount(count int) error {
	if count < 1 {
		return errors.New("ping count must be at least 1")
	}
	if count > 100 {
		return errors.New("ping count cannot exceed 100")
	}
	return nil
}
