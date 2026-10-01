package opnapi

import (
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The Argon2id hashes here were written by PHP's password_hash(PASSWORD_ARGON2ID),
// which is what OPNsense 26.7.5 and later call, so they pin the PHC string the
// verifier has to read, not the library's own idea of one. The plaintexts are
// test strings.
const (
	plainStartPassword = "Pw-Plain-Start-1"

	// PHP's own defaults: 64 MiB, 4 passes, 1 lane.
	argon2idPHPDefault = "$argon2id$v=19$m=65536,t=4,p=1$Z29sUy5VMjZ1bHBOcHc1Qg$qpLqv7eaCMl6ZQdfhcRupAcnLtP3FSonL88kGO1CW7Q"

	argon2idLight     = "$argon2id$v=19$m=1024,t=1,p=1$TGs4dE55VkF3djkzNGhRYw$z06MQNK1uGsolWRD2kAFCa5GrIaBsRIcdS2VgpUFIZI"
	argon2idTwoLanes  = "$argon2id$v=19$m=2048,t=2,p=2$OTYvaE54MEpjUXBDdWVQUQ$5Dpr9UtWeirTnluVWPiHFdq+1PzAjZfyWgJAA+nyC3A"
	argon2idNonASCII  = "$argon2id$v=19$m=1024,t=1,p=1$cW5NakFPVFMuYUFCWTZvdA$BVp6RYr2KO6X0NEbles6gkoiEErk7oeugdpcCCVEryY"
	nonASCIIPassword  = "Pássw0rd-ção"
	argon2idLongPlain = "$argon2id$v=19$m=1024,t=1,p=1$MS9TTFlRaWM4T1kycmpuMA$/U3qzSa/k+bhOa/xVFKFMjAVFlVRxTy0pjtQ6nKLhAs"
)

// hundredBytePassword is what argon2idLongPlain hashes.
var hundredBytePassword = strings.Repeat("x", 100)

func TestStoredPasswordVerifies_Argon2id(t *testing.T) {
	tests := []struct {
		name      string
		stored    string
		plaintext string
		want      bool
	}{
		{"PHP's hash of the plaintext", argon2idLight, plainStartPassword, true},
		{"two lanes", argon2idTwoLanes, plainStartPassword, true},
		{"non-ASCII plaintext", argon2idNonASCII, nonASCIIPassword, true},
		{"a plaintext longer than bcrypt's 72 bytes", argon2idLongPlain, hundredBytePassword, true},
		{"another plaintext", argon2idLight, plainStartPassword + "x", false},
		{"the plaintext's case changed", argon2idLight, strings.ToUpper(plainStartPassword), false},
		{"an empty plaintext", argon2idLight, "", false},
		{"another hash of the same length", argon2idTwoLanes, "Another-Password-2", false},
		{"one character of the hash changed", strings.Replace(argon2idLight, "z06MQNK1", "z06MQNK2", 1), plainStartPassword, false},
		{"one character of the salt changed", strings.Replace(argon2idLight, "TGs4dE55", "TGs4dE56", 1), plainStartPassword, false},
		{"another cost than the one the hash was made with", strings.Replace(argon2idLight, "t=1", "t=2", 1), plainStartPassword, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StoredPasswordVerifies(tt.stored, tt.plaintext); got != tt.want {
				t.Errorf("StoredPasswordVerifies = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStoredPasswordVerifies_Argon2idPHPDefaultParameters is the one test at the
// cost OPNsense writes by default. It takes a second or two under the race
// detector, which is why the rest use lighter parameters.
func TestStoredPasswordVerifies_Argon2idPHPDefaultParameters(t *testing.T) {
	if !StoredPasswordVerifies(argon2idPHPDefault, plainStartPassword) {
		t.Error("the hash PHP writes with its default parameters must verify")
	}
}

// TestStoredPasswordVerifies_Argon2idRefusesWhatItIsNotAskedToRead: a stored
// value that is not one OPNsense wrote is never verified, and one that asks for
// more than PHP's defaults never makes the agent spend the memory or the time.
func TestStoredPasswordVerifies_Argon2idRefusesWhatItIsNotAskedToRead(t *testing.T) {
	const (
		salt = "TGs4dE55VkF3djkzNGhRYw"
		hash = "z06MQNK1uGsolWRD2kAFCa5GrIaBsRIcdS2VgpUFIZI"
	)
	phc := func(version, params, s, h string) string {
		return "$argon2id$" + version + "$" + params + "$" + s + "$" + h
	}

	tests := []struct {
		name   string
		stored string
	}{
		{"an empty value", ""},
		{"the prefix alone", "$argon2id$"},
		{"a missing hash", "$argon2id$v=19$m=1024,t=1,p=1$" + salt},
		{"an extra section", argon2idLight + "$extra"},
		{"version 16", phc("v=16", "m=1024,t=1,p=1", salt, hash)},
		{"no version", "$argon2id$m=1024,t=1,p=1$" + salt + "$" + hash},
		{"parameters in another order", phc("v=19", "t=1,m=1024,p=1", salt, hash)},
		{"a missing parameter", phc("v=19", "m=1024,t=1", salt, hash)},
		{"an extra parameter", phc("v=19", "m=1024,t=1,p=1,x=1", salt, hash)},
		{"a parameter that is not a number", phc("v=19", "m=10k4,t=1,p=1", salt, hash)},
		{"a signed parameter", phc("v=19", "m=+1024,t=1,p=1", salt, hash)},
		{"an empty parameter", phc("v=19", "m=,t=1,p=1", salt, hash)},
		{"a parameter past 32 bits", phc("v=19", "m=1024,t=4294967297,p=1", salt, hash)},
		{"zero passes", phc("v=19", "m=1024,t=0,p=1", salt, hash)},
		{"more passes than the limit", phc("v=19", "m=1024,t=11,p=1", salt, hash)},
		{"zero lanes", phc("v=19", "m=1024,t=1,p=0", salt, hash)},
		{"more lanes than the limit", phc("v=19", "m=4096,t=1,p=9", salt, hash)},
		{"less memory than eight blocks a lane", phc("v=19", "m=15,t=1,p=2", salt, hash)},
		{"more memory than the limit", phc("v=19", "m=262145,t=1,p=1", salt, hash)},
		{"half a gibibyte", phc("v=19", "m=524288,t=1,p=1", salt, hash)},
		{"a salt that is not base64", phc("v=19", "m=1024,t=1,p=1", "!!!!", hash)},
		{"a padded salt", phc("v=19", "m=1024,t=1,p=1", salt+"==", hash)},
		{"a salt of seven bytes", phc("v=19", "m=1024,t=1,p=1", "AAAAAAAAAA", hash)},
		{"a hash that is not base64", phc("v=19", "m=1024,t=1,p=1", salt, "!!!!")},
		{"a hash of three bytes", phc("v=19", "m=1024,t=1,p=1", salt, "AAAA")},
		{"a hash of more than 64 bytes", phc("v=19", "m=1024,t=1,p=1", salt, strings.Repeat("A", 100))},
		{"argon2i", strings.Replace(argon2idLight, "argon2id", "argon2i", 1)},
		{"argon2d", strings.Replace(argon2idLight, "argon2id", "argon2d", 1)},
		{"a capital letter in the scheme", strings.Replace(argon2idLight, "argon2id", "Argon2id", 1)},
		{"padding before the scheme", " " + argon2idLight},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			got := StoredPasswordVerifies(tt.stored, plainStartPassword)
			runtime.ReadMemStats(&after)

			if got {
				t.Error("verified")
			}
			if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
				t.Errorf("a value that is refused allocated %d bytes", grown)
			}
		})
	}
}

func TestStoredPasswordVerifies_Bcrypt(t *testing.T) {
	const plaintext = "the-right-password"
	good, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	asPHP := "$2y$" + string(good)[4:] // PHP writes $2y$, the same algorithm under another prefix
	other, _ := bcrypt.GenerateFromPassword([]byte("another"), bcrypt.MinCost)
	long := strings.Repeat("x", 80)
	longHash, _ := bcrypt.GenerateFromPassword([]byte(long[:72]), bcrypt.MinCost)

	tests := []struct {
		name      string
		stored    string
		plaintext string
		want      bool
	}{
		{"the hash of the plaintext", string(good), plaintext, true},
		{"with the $2y$ prefix PHP writes", asPHP, plaintext, true},
		{"with the $2b$ prefix", "$2b$" + string(good)[4:], plaintext, true},
		{"the hash of another password", string(other), plaintext, false},
		{"the legacy $2x$ prefix is not trusted", "$2x$" + string(good)[4:], plaintext, false},
		{"a plaintext over bcrypt's 72 bytes is never compared", string(longHash), long, false},
		{"not a hash at all", "$2y$garbage", plaintext, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StoredPasswordVerifies(tt.stored, tt.plaintext); got != tt.want {
				t.Errorf("StoredPasswordVerifies = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStoredPasswordVerifies_OtherSchemesAreNeverVerified: password-policy
// compliance mode stores a SHA-512 crypt string, and anything else is whatever
// was planted. None is verified, so the caller posts the plaintext as before.
func TestStoredPasswordVerifies_OtherSchemesAreNeverVerified(t *testing.T) {
	for name, stored := range map[string]string{
		"empty":             "",
		"plain text":        plainStartPassword,
		"sha512 crypt":      "$6$saltsalt$" + strings.Repeat("A", 86),
		"sha512 and rounds": "$6$rounds=5000$saltsalt$" + strings.Repeat("B", 86),
		"sha256 crypt":      "$5$saltsalt$" + strings.Repeat("C", 43),
		"md5 crypt":         "$1$salt$" + strings.Repeat("D", 22),
	} {
		if StoredPasswordVerifies(stored, plainStartPassword) {
			t.Errorf("%s: verified", name)
		}
	}
}
