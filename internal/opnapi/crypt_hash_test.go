package opnapi

import (
	"encoding/json"
	"strings"
	"testing"
)

type cryptHashVectors struct {
	Pattern string `json:"pattern"`
	Vectors []struct {
		Family      string `json:"family"`
		Value       string `json:"value"`
		HashShaped  bool   `json:"hash_shaped"`
		Description string `json:"description"`
	} `json:"vectors"`
}

func TestCryptHashShapeVectors(t *testing.T) {
	raw := readTestdata(t, "testdata/crypt-hash-shape/vectors.json")
	if got := sha256Hex(raw); got != pinnedCryptVectorsSHA256 {
		t.Fatalf("crypt-hash-shape vectors sha256 = %s, want %s", got, pinnedCryptVectorsSHA256)
	}
	var v cryptHashVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	if v.Pattern != CryptHashShapePattern {
		t.Fatalf("CryptHashShapePattern differs from the shared pattern:\n got  %s\n want %s", CryptHashShapePattern, v.Pattern)
	}
	if len(v.Vectors) != 142 {
		t.Fatalf("%d vectors, want 142", len(v.Vectors))
	}

	families := map[string]bool{}
	for _, c := range v.Vectors {
		families[c.Family] = true
		if got := IsCryptHashShaped(c.Value); got != c.HashShaped {
			t.Errorf("IsCryptHashShaped(%q) = %v, want %v (%s: %s)", c.Value, got, c.HashShaped, c.Family, c.Description)
		}
	}
	for _, family := range []string{"bcrypt", "sha512", "sha256", "md5", "argon2", "plaintext"} {
		if !families[family] {
			t.Errorf("the vectors no longer cover the %s family", family)
		}
	}
}

// TestIsCryptHashShapedIsAFullMatch pins the anchors: the pattern carries none,
// so the wrapper is what stops a hash-like prefix, a suffix or a trailing
// newline from passing.
func TestIsCryptHashShapedIsAFullMatch(t *testing.T) {
	const bcrypt = "$2y$11$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
	if !IsCryptHashShaped(bcrypt) {
		t.Fatalf("control: %q must be hash-shaped", bcrypt)
	}
	for name, value := range map[string]string{
		"leading space":      " " + bcrypt,
		"trailing space":     bcrypt + " ",
		"trailing newline":   bcrypt + "\n",
		"leading newline":    "\n" + bcrypt,
		"suffix":             bcrypt + "x",
		"prefix":             "x" + bcrypt,
		"two hashes":         bcrypt + bcrypt,
		"empty":              "",
		"the old fixture":    "$2y$hash",
		"a dollar sign only": "$",
	} {
		if IsCryptHashShaped(value) {
			t.Errorf("%s: IsCryptHashShaped(%q) = true, want false", name, value)
		}
	}
	if IsCryptHashShaped(strings.Repeat("$", 64)) {
		t.Error("a run of dollar signs is not a hash")
	}
}
