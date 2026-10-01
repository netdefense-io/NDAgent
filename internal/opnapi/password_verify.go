package opnapi

// password_verify.go — does the hash an OPNsense user row holds belong to a
// given plaintext.
//
// OPNsense hashes every password it is sent, with a new salt each time, so
// posting an unchanged plaintext gives the account a new stored hash and resets
// its password-changed time. A caller that holds the plaintext and the stored
// hash can tell the two are the same password and leave it out.
//
// Only the schemes PHP's password_hash writes are verified: bcrypt, which
// OPNsense wrote until 26.7.4, and Argon2id, which it writes from 26.7.5. The
// `$6$` of password-policy compliance mode is not: anything this file cannot
// verify answers false, and the caller posts the plaintext as it always did.

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptMaxPassword is how many bytes of a password bcrypt reads. A longer
	// plaintext is never compared: PHP truncates it and Go does not.
	bcryptMaxPassword = 72

	// The most an Argon2id hash may ask of the agent. PHP's defaults are 64 MiB,
	// 4 passes and 1 lane; a stored value asking for more than these is not one
	// OPNsense wrote, and verifying it would let a planted hash hold the agent's
	// memory and CPU.
	argon2MaxMemoryKiB = 256 * 1024
	argon2MaxTime      = 10
	argon2MaxThreads   = 8
	argon2MinSaltLen   = 8
	argon2MaxHashLen   = 64
)

// StoredPasswordVerifies reports whether stored, the hash a user row holds, is a
// hash of plaintext.
func StoredPasswordVerifies(stored, plaintext string) bool {
	switch {
	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"), strings.HasPrefix(stored, "$2y$"):
		return bcryptVerifies(stored, plaintext)
	case strings.HasPrefix(stored, "$argon2id$"):
		return argon2idVerifies(stored, plaintext)
	}
	return false
}

// bcryptVerifies: $2x$ is not trusted (its 8-bit handling differs) and is not
// among the prefixes StoredPasswordVerifies passes on.
func bcryptVerifies(stored, plaintext string) bool {
	if len(plaintext) > bcryptMaxPassword {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plaintext)) == nil
}

// argon2idVerifies reads the PHC string PHP writes,
//
//	$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>
//
// with both values in unpadded standard base64, recomputes the hash of the
// plaintext with the same parameters and compares the two in constant time. A
// string in any other shape, or asking for more than the limits above, is false.
func argon2idVerifies(stored, plaintext string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	memory, okM := argon2Param(params[0], "m=")
	passes, okT := argon2Param(params[1], "t=")
	lanes, okP := argon2Param(params[2], "p=")
	if !okM || !okT || !okP {
		return false
	}
	if passes < 1 || passes > argon2MaxTime || lanes < 1 || lanes > argon2MaxThreads ||
		memory < 8*lanes || memory > argon2MaxMemoryKiB {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argon2MinSaltLen {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 4 || len(want) > argon2MaxHashLen {
		return false
	}

	got := argon2.IDKey([]byte(plaintext), salt, passes, memory, uint8(lanes), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// argon2Param reads one "<key>=<digits>" parameter of the PHC string.
func argon2Param(param, key string) (uint32, bool) {
	digits, ok := strings.CutPrefix(param, key)
	if !ok || digits == "" {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}
