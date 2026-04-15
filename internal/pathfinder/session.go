package pathfinder

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// Default session directory for PHP on FreeBSD/OPNsense
const defaultSessionDir = "/var/lib/php/sessions"

// SessionManager manages PHP sessions for pre-authenticated webadmin access.
type SessionManager struct {
	username   string
	sessionDir string
	log        *zap.SugaredLogger
}

// Session represents an active PHP session.
type Session struct {
	ID        string
	CSRFToken string
	CSRFKey   string
	Username  string
	FilePath  string
	CreatedAt time.Time
}

// NewSessionManager creates a new session manager.
// username is the OPNsense user to authenticate as (default: "root").
// sessionDir is the PHP session directory (default: "/var/lib/php/sessions").
func NewSessionManager(username, sessionDir string) *SessionManager {
	if username == "" {
		username = "root"
	}
	if sessionDir == "" {
		sessionDir = defaultSessionDir
	}

	// Sanitize username to prevent path traversal
	username = sanitizeUsername(username)

	return &SessionManager{
		username:   username,
		sessionDir: sessionDir,
		log:        logging.Named("pathfinder.session"),
	}
}

// sanitizeUsername removes any characters that could be used for path traversal.
func sanitizeUsername(username string) string {
	// Only allow alphanumeric, underscore, hyphen
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	return re.ReplaceAllString(username, "")
}

// CreateSession creates a new PHP session file and returns the session.
func (sm *SessionManager) CreateSession() (*Session, error) {
	// Generate session ID (32 hex characters)
	sessionID, err := generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate CSRF token and key (22 random characters each)
	csrfToken, err := generateRandomString(22)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	csrfKey, err := generateRandomString(22)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}

	session := &Session{
		ID:        sessionID,
		CSRFToken: csrfToken,
		CSRFKey:   csrfKey,
		Username:  sm.username,
		FilePath:  filepath.Join(sm.sessionDir, "sess_"+sessionID),
		CreatedAt: time.Now(),
	}

	// Serialize session data
	sessionData := sm.serializePHPSession(session)

	// Write session file with restricted permissions (0600)
	if err := os.WriteFile(session.FilePath, sessionData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write session file: %w", err)
	}

	sm.log.Debugw("Created PHP session",
		"session_id", sessionID,
		"username", sm.username,
		"file", session.FilePath,
	)

	return session, nil
}

// DestroySession removes a session file.
func (sm *SessionManager) DestroySession(sessionID string) error {
	// Sanitize session ID to prevent path traversal
	if !isValidSessionID(sessionID) {
		return fmt.Errorf("invalid session ID format")
	}

	filePath := filepath.Join(sm.sessionDir, "sess_"+sessionID)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			sm.log.Warnw("Session file already removed", "session_id", sessionID)
			return nil
		}
		return fmt.Errorf("failed to remove session file: %w", err)
	}

	sm.log.Debugw("Destroyed PHP session", "session_id", sessionID)
	return nil
}

// serializePHPSession generates PHP-serialized session data.
// Format matches OPNsense's Phalcon-based session structure.
func (sm *SessionManager) serializePHPSession(sess *Session) []byte {
	timestamp := sess.CreatedAt.Unix()

	// PHP session serialization format:
	// key|serialized_value;key|serialized_value;...
	//
	// String format: s:length:"value";
	// Integer format: i:value;
	//
	// OPNsense uses these session keys:
	// - $PHALCON/CSRF$ : CSRF token
	// - $PHALCON/CSRF/KEY$ : CSRF key
	// - Username : authenticated username
	// - last_access : timestamp
	// - protocol : "https"

	data := fmt.Sprintf(
		`$PHALCON/CSRF$|s:%d:"%s";$PHALCON/CSRF/KEY$|s:%d:"%s";Username|s:%d:"%s";last_access|i:%d;protocol|s:5:"https";`,
		len(sess.CSRFToken), sess.CSRFToken,
		len(sess.CSRFKey), sess.CSRFKey,
		len(sess.Username), sess.Username,
		timestamp,
	)

	return []byte(data)
}

// generateRandomHex generates n random bytes and returns them as hex string.
func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateRandomString generates a random alphanumeric string of length n.
func generateRandomString(n int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i := range bytes {
		bytes[i] = charset[bytes[i]%byte(len(charset))]
	}

	return string(bytes), nil
}

// isValidSessionID checks if a session ID has valid format (32 hex chars).
func isValidSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
