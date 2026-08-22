package pkgrepo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Conflict is a repository name we manage that some file we did not write
// also defines.
type Conflict struct {
	Repository string
	File       string
}

func (c Conflict) Error() string {
	return fmt.Sprintf(
		"repository %q is already defined by %s, which is not managed by NetDefense; "+
			"remove or rename that definition, or drop the repository from the policy",
		c.Repository, c.File,
	)
}

// repoKeyPattern matches a UCL object key at the start of a line —
// `mimugmail: {`. Repository identity in pkg lives in this key, not in the
// filename, which is the entire reason this scan exists.
//
// Deliberately anchored at line start with only leading whitespace allowed, so
// a commented-out block (`# mimugmail: {`) is not treated as live config. A
// commented example in someone's notes file is not a real second definition,
// and failing a device's sync over one would be wrong.
var repoKeyPattern = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*:\s*\{`)

// ScanForeign reports repository names in `managed` that are defined by a file
// we do not own.
//
// Run this BEFORE writing anything (ruling R1). Scanning afterwards would only
// detect the collision once the device already carried two definitions of the
// repository — the exact state this feature exists to prevent — and failing the
// task at that point would leave the box dirty.
//
// Ownership is decided by the marker inside the file, not by its name. A file
// called OPNsense.conf that genuinely defines a name we manage is still a
// conflict; our own netdefense-*.conf files never conflict with themselves.
func ScanForeign(managed []string) ([]Conflict, error) {
	if len(managed) == 0 {
		return nil, nil
	}
	wanted := make(map[string]bool, len(managed))
	for _, name := range managed {
		wanted[name] = true
	}

	entries, err := os.ReadDir(reposDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No repos directory is unusual but not a failure: there is
			// nothing to collide with.
			return nil, nil
		}
		return nil, err
	}

	var conflicts []Conflict
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(reposDir, e.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			// A repo config we cannot read could be hiding a conflicting
			// definition, and silently skipping it would defeat the check.
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		if IsManaged(content) {
			continue // ours; reconcile rewrites it wholesale
		}
		for _, name := range definedRepositories(content) {
			if wanted[name] {
				conflicts = append(conflicts, Conflict{Repository: name, File: path})
			}
		}
	}

	// Stable order so the same device state always produces the same error
	// text, rather than following directory read order.
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Repository != conflicts[j].Repository {
			return conflicts[i].Repository < conflicts[j].Repository
		}
		return conflicts[i].File < conflicts[j].File
	})
	return conflicts, nil
}

// definedRepositories extracts the UCL object keys a repo config declares.
//
// This is a deliberately shallow parse, not a UCL implementation: we only need
// the top-level keys, and pulling in a parser to answer "which names does this
// file define" would be a large dependency for a small question. The tradeoff
// is that a key nested inside another object would also be reported — which
// errs toward flagging a conflict rather than missing one, the safe direction
// for a check whose job is to refuse ambiguity.
func definedRepositories(content []byte) []string {
	var names []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := repoKeyPattern.FindStringSubmatch(line); m != nil {
			if !seen[m[1]] {
				seen[m[1]] = true
				names = append(names, m[1])
			}
		}
	}
	return names
}
