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

// configOfSize is a config.xml of exactly n bytes.
func configOfSize(n int) string {
	head, tail := "<?xml version=\"1.0\"?>\n<opnsense>\n<!-- ", " -->\n</opnsense>\n"
	return head + strings.Repeat("x", n-len(head)-len(tail)) + tail
}

// A backup whose response the broker could not read fails here, naming the
// file's size, instead of dropping the connection (#174).
func TestBackupConfig_AConfigTooLargeForTheControlPlaneFails(t *testing.T) {
	content := configOfSize(500 * 1024)
	result := backupConfig(context.Background(), writeBackupConfigXML(t, content), "passphrase")
	if result.Success {
		t.Fatal("a 500 KiB config.xml cannot be delivered, want a failure")
	}
	for _, want := range []string{"config.xml is 512000 bytes", "1048576-byte limit", "about 425 KiB"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("message %q lacks %q", result.Message, want)
		}
	}
}

// maxBackupConfigKiB is the measured boundary: a config.xml of that many KiB
// fits, one KiB more does not.
func TestMaxBackupConfigKiBIsTheMeasuredBoundary(t *testing.T) {
	fits := func(kib int) bool {
		result := backupConfig(context.Background(), writeBackupConfigXML(t, configOfSize(kib*1024)), "passphrase")
		return result.Success
	}
	at, above := fits(maxBackupConfigKiB), fits(maxBackupConfigKiB+1)
	if !at || above {
		t.Errorf("maxBackupConfigKiB = %d: %d KiB fits=%v, %d KiB fits=%v", maxBackupConfigKiB,
			maxBackupConfigKiB, at, maxBackupConfigKiB+1, above)
	}
}
