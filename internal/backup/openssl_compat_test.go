package backup

import (
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestOpenSSLCompatibility verifies encrypted output can be decrypted by OpenSSL.
// This test requires OpenSSL to be installed.
func TestOpenSSLCompatibility(t *testing.T) {
	// Check if OpenSSL is available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL not found, skipping compatibility test")
	}

	plaintext := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>opnsense</hostname>
    <domain>localdomain</domain>
  </system>
</opnsense>`
	passphrase := "test-backup-password-123"

	// Encrypt using our implementation
	encrypted, err := EncryptConfig([]byte(plaintext), passphrase)
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	// Extract just the base64 content (skip PEM headers and metadata)
	base64Content := extractBase64(encrypted)

	// Decode base64 to get raw encrypted bytes (OpenSSL Salted__ format)
	rawEncrypted, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Write raw encrypted data to temp file
	tmpEncrypted, err := os.CreateTemp("", "encrypted-*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpEncryptedPath := tmpEncrypted.Name()
	defer os.Remove(tmpEncryptedPath)

	if _, err := tmpEncrypted.Write(rawEncrypted); err != nil {
		tmpEncrypted.Close()
		t.Fatalf("Failed to write encrypted data: %v", err)
	}
	tmpEncrypted.Close()

	// Create temp file for decrypted output
	tmpDecrypted, err := os.CreateTemp("", "decrypted-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpDecryptedPath := tmpDecrypted.Name()
	defer os.Remove(tmpDecryptedPath)
	tmpDecrypted.Close()

	// Decrypt using OpenSSL (without -base64 flag since we already decoded)
	cmd := exec.Command("openssl", "enc", "-d",
		"-aes-256-cbc",
		"-md", "sha512",
		"-pbkdf2",
		"-iter", "100000",
		"-in", tmpEncryptedPath,
		"-out", tmpDecryptedPath,
		"-pass", "pass:"+passphrase,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL decryption failed: %v\nOutput: %s\nEncrypted file: %s", err, string(output), tmpEncryptedPath)
	}

	// Read decrypted content
	decrypted, err := os.ReadFile(tmpDecryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	// Verify content matches
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted content does not match original\nGot: %s\nWant: %s", string(decrypted), plaintext)
	}

	t.Logf("OpenSSL compatibility test passed")
}

// TestOpenSSLEncryptOurDecrypt verifies we can decrypt OpenSSL-encrypted data.
func TestOpenSSLEncryptOurDecrypt(t *testing.T) {
	// Check if OpenSSL is available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL not found, skipping compatibility test")
	}

	plaintext := `<?xml version="1.0"?>
<opnsense>
  <test>openssl-encrypted</test>
</opnsense>`
	passphrase := "openssl-test-password"

	// Write plaintext to temp file
	tmpPlain, err := os.CreateTemp("", "plain-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpPlain.Name())

	if _, err := tmpPlain.WriteString(plaintext); err != nil {
		t.Fatalf("Failed to write plaintext: %v", err)
	}
	tmpPlain.Close()

	// Create temp file for encrypted output
	tmpEncrypted, err := os.CreateTemp("", "encrypted-*.enc")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpEncrypted.Name())
	tmpEncrypted.Close()

	// Encrypt using OpenSSL (matching OPNsense format)
	cmd := exec.Command("openssl", "enc", "-e",
		"-aes-256-cbc",
		"-md", "sha512",
		"-pbkdf2",
		"-iter", "100000",
		"-base64",
		"-in", tmpPlain.Name(),
		"-out", tmpEncrypted.Name(),
		"-pass", "pass:"+passphrase,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL encryption failed: %v\nOutput: %s", err, string(output))
	}

	// Read OpenSSL encrypted content
	encryptedData, err := os.ReadFile(tmpEncrypted.Name())
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Decrypt using our implementation
	decrypted, err := DecryptConfig(string(encryptedData), passphrase)
	if err != nil {
		t.Fatalf("DecryptConfig failed: %v", err)
	}

	// Verify content matches
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted content does not match original\nGot: %s\nWant: %s", string(decrypted), plaintext)
	}

	t.Logf("OpenSSL encrypt -> our decrypt test passed")
}

// TestRealConfigXML tests encryption with a realistic OPNsense config structure.
func TestRealConfigXML(t *testing.T) {
	// Realistic OPNsense config.xml snippet
	configXML := `<?xml version="1.0"?>
<opnsense>
  <version>25.7.10</version>
  <system>
    <optimization>normal</optimization>
    <hostname>fw01</hostname>
    <domain>example.local</domain>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver>8.8.4.4</dnsserver>
    <timezone>America/New_York</timezone>
  </system>
  <interfaces>
    <wan>
      <if>em0</if>
      <descr>WAN</descr>
      <enable>1</enable>
      <ipaddr>dhcp</ipaddr>
    </wan>
    <lan>
      <if>em1</if>
      <descr>LAN</descr>
      <enable>1</enable>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <descr>Default allow LAN to any rule</descr>
    </rule>
  </filter>
</opnsense>`

	passphrase := "strong-backup-key-!@#$%"

	// Encrypt
	encrypted, err := EncryptConfig([]byte(configXML), passphrase)
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	// Verify PEM format
	if !strings.Contains(encrypted, "---- BEGIN config.xml ----") {
		t.Error("Missing PEM header")
	}
	if !strings.Contains(encrypted, "Cipher: AES-256-CBC") {
		t.Error("Missing cipher metadata")
	}
	if !strings.Contains(encrypted, "PBKDF2: 100000") {
		t.Error("Missing PBKDF2 metadata")
	}

	// Decrypt
	decrypted, err := DecryptConfig(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptConfig failed: %v", err)
	}

	if string(decrypted) != configXML {
		t.Error("Decrypted config does not match original")
	}

	t.Logf("Encrypted size: %d bytes, Original size: %d bytes", len(encrypted), len(configXML))
}
