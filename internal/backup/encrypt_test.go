package backup

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		plaintext  string
		passphrase string
	}{
		{
			name:       "simple config",
			plaintext:  "<config><system>test</system></config>",
			passphrase: "test-passphrase-123",
		},
		{
			name:       "empty config",
			plaintext:  "",
			passphrase: "my-secret-key",
		},
		{
			name:       "large config",
			plaintext:  strings.Repeat("<config><system>test data block</system></config>\n", 100),
			passphrase: "complex-passphrase-with-special-chars!@#$%",
		},
		{
			name:       "unicode content",
			plaintext:  "<config><name>日本語テスト</name></config>",
			passphrase: "unicode-pass-日本語",
		},
		{
			name:       "binary-like content",
			plaintext:  string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}),
			passphrase: "binary-test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := EncryptConfig([]byte(tt.plaintext), tt.passphrase)
			if err != nil {
				t.Fatalf("EncryptConfig failed: %v", err)
			}

			// Verify PEM format
			if !strings.Contains(encrypted, pemHeader) {
				t.Error("encrypted data missing PEM header")
			}
			if !strings.Contains(encrypted, pemFooter) {
				t.Error("encrypted data missing PEM footer")
			}
			if !strings.Contains(encrypted, metaCipher) {
				t.Error("encrypted data missing cipher metadata")
			}

			// Decrypt
			decrypted, err := DecryptConfig(encrypted, tt.passphrase)
			if err != nil {
				t.Fatalf("DecryptConfig failed: %v", err)
			}

			// Verify roundtrip
			if !bytes.Equal(decrypted, []byte(tt.plaintext)) {
				t.Errorf("decrypted data does not match original\ngot:  %q\nwant: %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestEncryptEmptyPassphrase(t *testing.T) {
	_, err := EncryptConfig([]byte("test"), "")
	if err == nil {
		t.Error("expected error for empty passphrase")
	}
}

func TestDecryptEmptyPassphrase(t *testing.T) {
	encrypted, err := EncryptConfig([]byte("test"), "valid-pass")
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	_, err = DecryptConfig(encrypted, "")
	if err == nil {
		t.Error("expected error for empty passphrase")
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	encrypted, err := EncryptConfig([]byte("secret data"), "correct-password")
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	_, err = DecryptConfig(encrypted, "wrong-password")
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"not base64", "not-valid-base64!!!"},
		{"too short", "U2FsdGVk"},
		{"no salt prefix", "dGVzdGluZzEyMzQ1Njc4OTAxMjM0NTY3ODkw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptConfig(tt.data, "password")
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{"aligned", make([]byte, 16), 16},
		{"one byte short", make([]byte, 15), 16},
		{"empty", []byte{}, 16},
		{"one byte", []byte{1}, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, tt.blockSize)
			if len(padded)%tt.blockSize != 0 {
				t.Errorf("padded length %d not multiple of block size %d", len(padded), tt.blockSize)
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("pkcs7Unpad failed: %v", err)
			}

			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("unpadded data does not match original")
			}
		})
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"zero padding", []byte{1, 2, 3, 0}},
		{"padding too large", []byte{1, 2, 3, 17}},
		{"inconsistent padding", []byte{1, 2, 3, 3, 2, 3}}, // padding should be all 3s
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.data)
			if err == nil {
				t.Error("expected error for invalid padding")
			}
		})
	}
}

func TestExtractBase64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "full PEM",
			input: `---- BEGIN config.xml ----
Version: OPNsense 25.7.10
Cipher: AES-256-CBC
PBKDF2: 100000
Hash: SHA512

YWJjZGVm
Z2hpamts
---- END config.xml ----`,
			expected: "YWJjZGVmZ2hpamts",
		},
		{
			name:     "raw base64",
			input:    "U2FsdGVkX19hYmNkZWZnaGlqa2xtbm9wcQ==",
			expected: "U2FsdGVkX19hYmNkZWZnaGlqa2xtbm9wcQ==",
		},
		{
			name:     "base64 with whitespace",
			input:    "  U2FsdGVkX19hYmNkZWY=  ",
			expected: "U2FsdGVkX19hYmNkZWY=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBase64(tt.input)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatPEM(t *testing.T) {
	base64Data := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA=="
	pem := formatPEM(base64Data)

	if !strings.HasPrefix(pem, pemHeader) {
		t.Error("PEM missing header")
	}
	if !strings.HasSuffix(pem, pemFooter) {
		t.Error("PEM missing footer")
	}
	if !strings.Contains(pem, metaVersion) {
		t.Error("PEM missing version metadata")
	}
	if !strings.Contains(pem, metaCipher) {
		t.Error("PEM missing cipher metadata")
	}
	if !strings.Contains(pem, metaPBKDF2) {
		t.Error("PEM missing PBKDF2 metadata")
	}
	if !strings.Contains(pem, metaHash) {
		t.Error("PEM missing hash metadata")
	}
}

func TestEncryptDifferentSaltEachTime(t *testing.T) {
	plaintext := []byte("same content")
	passphrase := "same-password"

	encrypted1, err := EncryptConfig(plaintext, passphrase)
	if err != nil {
		t.Fatalf("first encryption failed: %v", err)
	}

	encrypted2, err := EncryptConfig(plaintext, passphrase)
	if err != nil {
		t.Fatalf("second encryption failed: %v", err)
	}

	// Same plaintext with same password should produce different ciphertext (due to random salt)
	if encrypted1 == encrypted2 {
		t.Error("expected different ciphertext due to random salt")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := DecryptConfig(encrypted1, passphrase)
	if err != nil {
		t.Fatalf("first decryption failed: %v", err)
	}

	decrypted2, err := DecryptConfig(encrypted2, passphrase)
	if err != nil {
		t.Fatalf("second decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("decrypted content does not match original")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	plaintext := []byte(strings.Repeat("<config>test</config>", 1000))
	passphrase := "benchmark-password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptConfig(plaintext, passphrase)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plaintext := []byte(strings.Repeat("<config>test</config>", 1000))
	passphrase := "benchmark-password"

	encrypted, _ := EncryptConfig(plaintext, passphrase)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptConfig(encrypted, passphrase)
	}
}
