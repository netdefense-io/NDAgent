package pkgmgr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOfferedBySingleRepositoryIsFine(t *testing.T) {
	defer SetOfferedByFunc(SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		return []string{"OPNsense"}, nil
	}))

	repos, err := OfferedBy(context.Background(), "os-haproxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0] != "OPNsense" {
		t.Fatalf("got %v", repos)
	}
}

// The hazard this exists for. Repository priority is NOT a safety boundary:
// pkg-repository(5) says the highest VERSION wins even when a lower-numbered
// version sits in a repository earlier in the priority list. So a custom repo
// at priority 5 can still beat OPNsense's base repo at priority 11 simply by
// publishing a higher version string. Refusing the ambiguous install is the
// only honest answer.
func TestShadowedPackageReportsEveryOfferingRepository(t *testing.T) {
	defer SetOfferedByFunc(SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		return []string{"OPNsense", "mimugmail"}, nil
	}))

	repos, err := OfferedBy(context.Background(), "os-haproxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected both repositories named so the operator can see the clash, got %v", repos)
	}
}

func TestParseOfferedByOutput(t *testing.T) {
	// `pkg rquery -U '%R'` prints one repository name per line, and repeats a
	// repository when it offers several matching packages.
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"single", "OPNsense\n", []string{"OPNsense"}},
		{"two distinct", "OPNsense\nmimugmail\n", []string{"OPNsense", "mimugmail"}},
		{"deduplicated", "OPNsense\nOPNsense\nmimugmail\n", []string{"OPNsense", "mimugmail"}},
		{"blank lines ignored", "\nOPNsense\n\n\nmimugmail\n\n", []string{"OPNsense", "mimugmail"}},
		{"whitespace trimmed", "  OPNsense  \n\tmimugmail\t\n", []string{"OPNsense", "mimugmail"}},
		{"not in any catalog", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOfferedBy(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A query failure must not be read as "only one repository offers it". Failing
// the package is the safe reading: we could not establish that the install is
// unambiguous, so we do not perform it.
func TestQueryErrorIsNotTreatedAsNoConflict(t *testing.T) {
	sentinel := errors.New("rquery exploded")
	defer SetOfferedByFunc(SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		return nil, sentinel
	}))

	_, err := OfferedBy(context.Background(), "os-haproxy")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the query error to propagate, got %v", err)
	}
}

func TestOfferedByIsSerializedLikeEveryOtherPkgCall(t *testing.T) {
	// It shells out to pkg, so it belongs behind the same mutex; otherwise it
	// could collide with an install and hit pkg's short database lock.
	var sawDeadline bool
	defer SetOfferedByFunc(SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		_, sawDeadline = ctx.Deadline()
		return nil, nil
	}))

	if _, err := OfferedBy(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
	if !sawDeadline {
		t.Error("OfferedBy ran without a deadline")
	}
}

func TestShadowErrorNamesBothSources(t *testing.T) {
	err := ShadowError{Package: "os-haproxy", Repositories: []string{"OPNsense", "mimugmail"}}
	msg := err.Error()
	for _, want := range []string{"os-haproxy", "OPNsense", "mimugmail"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q should name %q", msg, want)
		}
	}
}
