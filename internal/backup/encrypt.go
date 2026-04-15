// Package backup provides configuration backup functionality for NDAgent.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Encryption constants matching OPNsense's backup encryption format.
const (
	// PBKDF2 iterations for key derivation
	pbkdf2Iterations = 100000

	// Salt size in bytes
	saltSize = 8

	// AES-256 key size in bytes
	keySize = 32

	// AES block size in bytes
	blockSize = aes.BlockSize

	// OpenSSL salted prefix
	saltedPrefix = "Salted__"

	// PEM-style header/footer for the encrypted config
	pemHeader = "---- BEGIN config.xml ----"
	pemFooter = "---- END config.xml ----"

	// Metadata lines in the output
	metaVersion = "Version: OPNsense 25.7.10"
	metaCipher  = "Cipher: AES-256-CBC"
	metaPBKDF2  = "PBKDF2: 100000"
	metaHash    = "Hash: SHA512"
)

// EncryptConfig encrypts the config data using OPNsense-compatible encryption.
// The output format is PEM-style wrapped base64 that can be decrypted with:
//
//	openssl enc -d -aes-256-cbc -md sha512 -pbkdf2 -iter 100000 -pass pass:<key>
//
// Returns the encrypted config in PEM format.
func EncryptConfig(plaintext []byte, passphrase string) (string, error) {
	if len(passphrase) == 0 {
		return "", fmt.Errorf("passphrase cannot be empty")
	}

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key and IV using PBKDF2 with SHA512
	// OpenSSL uses key + IV derived together
	keyIV := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keySize+blockSize, sha512.New)
	key := keyIV[:keySize]
	iv := keyIV[keySize : keySize+blockSize]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// PKCS7 padding
	padded := pkcs7Pad(plaintext, blockSize)

	// Encrypt using CBC mode
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Build OpenSSL format: "Salted__" + salt + ciphertext
	opensslData := make([]byte, len(saltedPrefix)+saltSize+len(ciphertext))
	copy(opensslData, saltedPrefix)
	copy(opensslData[len(saltedPrefix):], salt)
	copy(opensslData[len(saltedPrefix)+saltSize:], ciphertext)

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(opensslData)

	// Wrap in PEM-style format with metadata
	return formatPEM(encoded), nil
}

// DecryptConfig decrypts an OPNsense-compatible encrypted config.
// Accepts PEM-wrapped or raw base64 encoded data.
func DecryptConfig(encrypted string, passphrase string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	// Extract base64 content from PEM format
	base64Data := extractBase64(encrypted)

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Verify OpenSSL format: "Salted__" + salt + ciphertext
	if len(data) < len(saltedPrefix)+saltSize+blockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	if string(data[:len(saltedPrefix)]) != saltedPrefix {
		return nil, fmt.Errorf("invalid OpenSSL format: missing Salted__ prefix")
	}

	// Extract salt and ciphertext
	salt := data[len(saltedPrefix) : len(saltedPrefix)+saltSize]
	ciphertext := data[len(saltedPrefix)+saltSize:]

	// Verify ciphertext length is multiple of block size
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	// Derive key and IV using PBKDF2 with SHA512
	keyIV := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keySize+blockSize, sha512.New)
	key := keyIV[:keySize]
	iv := keyIV[keySize : keySize+blockSize]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Decrypt using CBC mode
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding: %w", err)
	}

	return unpadded, nil
}

// pkcs7Pad adds PKCS7 padding to the data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpad removes PKCS7 padding from the data.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}

	if padding > len(data) {
		return nil, fmt.Errorf("padding larger than data length")
	}

	// Verify all padding bytes are correct
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding byte at position %d", i)
		}
	}

	return data[:len(data)-padding], nil
}

// formatPEM wraps base64 data in PEM-style format with metadata.
func formatPEM(base64Data string) string {
	var sb strings.Builder
	sb.WriteString(pemHeader)
	sb.WriteString("\n")
	sb.WriteString(metaVersion)
	sb.WriteString("\n")
	sb.WriteString(metaCipher)
	sb.WriteString("\n")
	sb.WriteString(metaPBKDF2)
	sb.WriteString("\n")
	sb.WriteString(metaHash)
	sb.WriteString("\n\n")

	// Wrap base64 at 64 characters per line (standard PEM format)
	for i := 0; i < len(base64Data); i += 64 {
		end := i + 64
		if end > len(base64Data) {
			end = len(base64Data)
		}
		sb.WriteString(base64Data[i:end])
		sb.WriteString("\n")
	}

	sb.WriteString(pemFooter)
	return sb.String()
}

// extractBase64 extracts base64 content from PEM format.
func extractBase64(pem string) string {
	lines := strings.Split(pem, "\n")
	var base64Lines []string
	inBody := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header
		if strings.HasPrefix(line, "----") {
			if strings.Contains(line, "BEGIN") {
				inBody = true
			} else if strings.Contains(line, "END") {
				break
			}
			continue
		}

		// Skip metadata lines
		if strings.Contains(line, ":") || line == "" {
			continue
		}

		if inBody {
			base64Lines = append(base64Lines, line)
		}
	}

	// If no PEM format detected, assume raw base64
	if len(base64Lines) == 0 {
		return strings.TrimSpace(pem)
	}

	return strings.Join(base64Lines, "")
}
