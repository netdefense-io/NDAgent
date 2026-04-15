package tasks

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/netdefense-io/ndagent/internal/backup"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
)

// HandleBackup handles the BACKUP task.
// It reads the OPNsense config.xml, encrypts it, and returns it in the task response.
//
// Expected command payload:
//
//	{
//	  "encryption_key": "strong-passphrase"
//	}
//
// Response data:
//
//	{
//	  "content": "<base64-encoded PEM encrypted config>",
//	  "config_size": 79349
//	}
func HandleBackup(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("BACKUP")

	log.Infow("Received BACKUP command",
		"task_id", cmd.TaskID,
	)

	// Validate payload exists
	if cmd.Payload == nil {
		result := NewFailureResult("No payload provided in backup command")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Extract encryption_key (required)
	keyRaw, ok := cmd.Payload["encryption_key"]
	if !ok {
		result := NewFailureResult("No 'encryption_key' field in payload")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	encryptionKey, ok := keyRaw.(string)
	if !ok || encryptionKey == "" {
		result := NewFailureResult("Invalid 'encryption_key': must be a non-empty string")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Get config.xml path
	configPath := ws.GetConfigXMLPath()

	// Read config.xml
	configData, err := os.ReadFile(configPath)
	if err != nil {
		log.Errorw("Failed to read config.xml",
			"path", configPath,
			"error", err,
		)
		result := NewFailureResult(fmt.Sprintf("Failed to read config.xml: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("Read config.xml",
		"path", configPath,
		"size", len(configData),
	)

	// Check for context cancellation before encryption
	select {
	case <-ctx.Done():
		result := NewFailureResult("BACKUP task was cancelled")
		return SendTaskResponse(ws, cmd.TaskID, result)
	default:
	}

	// Encrypt the config
	encrypted, err := backup.EncryptConfig(configData, encryptionKey)
	if err != nil {
		log.Errorw("Failed to encrypt config",
			"error", err,
		)
		result := NewFailureResult(fmt.Sprintf("Failed to encrypt config: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Base64 encode the encrypted content to avoid JSON escaping issues
	encodedContent := base64.StdEncoding.EncodeToString([]byte(encrypted))

	log.Infow("Config encrypted successfully",
		"original_size", len(configData),
		"encrypted_size", len(encrypted),
		"encoded_size", len(encodedContent),
	)

	// Return base64-encoded encrypted config in response
	result := NewSuccessResultWithData("Backup completed successfully", map[string]interface{}{
		"content":     encodedContent,
		"config_size": len(configData),
	})

	return SendTaskResponse(ws, cmd.TaskID, result)
}
