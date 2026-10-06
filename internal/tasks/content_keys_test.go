package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// pinnedIgnoredContentKeysSHA256 is the digest of NDDataModels'
// tests/fixtures/ignored-content-keys/vectors.json, written out here and not
// read from the file: the copy in testdata must stay byte-identical to it, and
// a change is a deliberate re-copy, never an edit.
const pinnedIgnoredContentKeysSHA256 = "eb8100e8381188280f828f325d7c648e0678103d3ab7143e492fa3b5e8d81609"

type ignoredKeyVectors struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`
	Types  map[string]struct {
		Names    []string `json:"names"`
		Prefixes []string `json:"prefixes"`
	} `json:"types"`
	Vectors []struct {
		Type    string `json:"type"`
		Key     string `json:"key"`
		Ignored bool   `json:"ignored"`
	} `json:"vectors"`
}

// readIgnoredKeyVectors fails, never skips, when the shared file is missing: a
// vector set that silently stops running is worse than one that fails.
func readIgnoredKeyVectors(t *testing.T) ([]byte, ignoredKeyVectors) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ignored-content-keys", "vectors.json"))
	if err != nil {
		t.Fatalf("shared test data is missing: %v", err)
	}
	var doc ignoredKeyVectors
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode shared vectors: %v", err)
	}
	return raw, doc
}

func TestIgnoredContentKeys_CopyIsPinned(t *testing.T) {
	raw, doc := readIgnoredKeyVectors(t)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pinnedIgnoredContentKeysSHA256 {
		t.Fatalf("vectors.json sha256 = %s, want %s: the file must stay byte-identical to NDDataModels' copy", got, pinnedIgnoredContentKeysSHA256)
	}
	if doc.Schema != 1 || doc.Kind != "ignored-content-keys" {
		t.Errorf("schema %d kind %q", doc.Schema, doc.Kind)
	}
}

// TestIgnoredContentKeys_SetEqualsTheSharedTypes holds the Go set to the shared
// one, type by type: the control plane ignores exactly these keys too.
func TestIgnoredContentKeys_SetEqualsTheSharedTypes(t *testing.T) {
	_, doc := readIgnoredKeyVectors(t)

	sorted := func(items []string) []string {
		out := append([]string{}, items...)
		sort.Strings(out)
		return out
	}
	var shared, ours []string
	for name := range doc.Types {
		shared = append(shared, name)
	}
	for name := range ignoredContentKeys {
		ours = append(ours, name)
	}
	if !reflect.DeepEqual(sorted(ours), sorted(shared)) {
		t.Fatalf("snippet types = %v, want %v", sorted(ours), sorted(shared))
	}
	for name, want := range doc.Types {
		got := ignoredContentKeys[name]
		if !reflect.DeepEqual(sorted(got.names), sorted(want.Names)) {
			t.Errorf("%s names = %v, want %v", name, sorted(got.names), sorted(want.Names))
		}
		if !reflect.DeepEqual(sorted(got.prefixes), sorted(want.Prefixes)) {
			t.Errorf("%s prefixes = %v, want %v", name, sorted(got.prefixes), sorted(want.Prefixes))
		}
	}
}

func TestIgnoredContentKeys_EveryVerdict(t *testing.T) {
	_, doc := readIgnoredKeyVectors(t)
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors: this check would pass vacuously")
	}
	for _, v := range doc.Vectors {
		if got := isIgnoredContentKey(v.Type, v.Key); got != v.Ignored {
			t.Errorf("isIgnoredContentKey(%q, %q) = %v, want %v", v.Type, v.Key, got, v.Ignored)
		}
	}
}

// TestContractsSkipTheSharedKeysAndTheIdentity: what the RULE and ALIAS
// contracts never apply is their type's ignored keys and the uuid, nothing
// more.
func TestContractsSkipTheSharedKeysAndTheIdentity(t *testing.T) {
	for _, contract := range []fieldContract{ruleContract, aliasContract} {
		// A type the set does not hold, a misspelt one say, would skip
		// nothing, and the checks below would pass over an empty set.
		set, ok := ignoredContentKeys[contract.snippetType]
		if !ok || len(set.names) == 0 || len(set.prefixes) == 0 {
			t.Fatalf("%s: no ignored names and prefixes under that type: %+v", contract.snippetType, set)
		}
		if !contract.skipped("uuid") {
			t.Errorf("%s does not skip uuid", contract.snippetType)
		}
		for _, name := range set.names {
			if !contract.skipped(name) {
				t.Errorf("%s does not skip %q", contract.snippetType, name)
			}
		}
		for _, prefix := range set.prefixes {
			if !contract.skipped(prefix + "x") {
				t.Errorf("%s does not skip keys starting %q", contract.snippetType, prefix)
			}
		}
		for _, field := range []string{"enabled", "description", "log", "content", "name"} {
			if contract.skipped(field) {
				t.Errorf("%s skips the field %q", contract.snippetType, field)
			}
		}
	}
}
