package pkgmgr

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestQuery_UsesStubbedFunc(t *testing.T) {
	want := []Status{
		{Name: "os-netdefense-prod", InstalledVersion: "1.2.3", AvailableVersion: "1.2.4"},
		{Name: "ghost-pkg", InstalledVersion: "", AvailableVersion: ""},
	}
	prev := queryFunc
	queryFunc = func(_ context.Context, names []string) ([]Status, error) {
		if !reflect.DeepEqual(names, []string{"os-netdefense-prod", "ghost-pkg"}) {
			t.Fatalf("unexpected names: %v", names)
		}
		return want, nil
	}
	t.Cleanup(func() { queryFunc = prev })

	got, err := Query(context.Background(), []string{"os-netdefense-prod", "ghost-pkg"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Query result mismatch.\n  got:  %#v\n  want: %#v", got, want)
	}
}

func TestQuery_PropagatesError(t *testing.T) {
	prev := queryFunc
	wantErr := errors.New("pkg(8) missing")
	queryFunc = func(_ context.Context, _ []string) ([]Status, error) { return nil, wantErr }
	t.Cleanup(func() { queryFunc = prev })

	_, err := Query(context.Background(), []string{"foo"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected propagated error %v, got %v", wantErr, err)
	}
}
