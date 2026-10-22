package tasks

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/backup"
)

func writeBackupConfigXML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBackupConfig_EncryptsTheWholeFile(t *testing.T) {
	content := "<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <hostname>fw</hostname>\n  </system>\n</opnsense>\n"
	result := backupConfig(context.Background(), writeBackupConfigXML(t, content), "passphrase")
	if !result.Success {
		t.Fatalf("backup failed: %s", result.Message)
	}
	encoded, _ := result.Data["content"].(string)
	pem, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("content is not base64: %v", err)
	}
	plain, err := backup.DecryptConfig(string(pem), "passphrase")
	if err != nil {
		t.Fatalf("DecryptConfig: %v", err)
	}
	if string(plain) != content {
		t.Fatalf("backup holds %q, want the file as written", plain)
	}
	if size, _ := result.Data["config_size"].(int); size != len(content) {
		t.Fatalf("config_size = %v, want %d", result.Data["config_size"], len(content))
	}
}

// OPNsense saves config.xml by truncating it and writing it again in place. A
// backup that read the file in between must fail, never report success with
// what it got.
func TestBackupConfig_RefusesAnEmptyOrCutShortFile(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"cut short": "<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <hostname>fw</host",
	} {
		t.Run(name, func(t *testing.T) {
			result := backupConfig(context.Background(), writeBackupConfigXML(t, content), "passphrase")
			if result.Success {
				t.Fatalf("backup of a %s config.xml succeeded: %s", name, result.Message)
			}
			if _, ok := result.Data["content"]; ok {
				t.Error("a failed backup carried content")
			}
			if !strings.Contains(result.Message, "does not end with </opnsense>") {
				t.Errorf("message = %q, want the reason", result.Message)
			}
		})
	}
}

func TestBackupConfig_MissingFileFails(t *testing.T) {
	result := backupConfig(context.Background(), filepath.Join(t.TempDir(), "config.xml"), "passphrase")
	if result.Success || !strings.HasPrefix(result.Message, "Failed to read config.xml: ") {
		t.Fatalf("result = %+v, want a read failure", result)
	}
}

func TestBackupConfig_CancelledTask(t *testing.T) {
	content := "<opnsense>\n</opnsense>\n"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := backupConfig(ctx, writeBackupConfigXML(t, content), "passphrase")
	if result.Success || result.Message != "BACKUP task was cancelled" {
		t.Fatalf("result = %+v, want the cancellation", result)
	}
}
