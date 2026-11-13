package pkgmgr

import (
	"context"
	"testing"
)

func TestParseArchiveNameVersion(t *testing.T) {
	name, version, err := parseArchiveNameVersion("os-example 1.2.3_1,1\n")
	if err != nil || name != "os-example" || version != "1.2.3_1,1" {
		t.Errorf("got %q %q %v", name, version, err)
	}
	for _, out := range []string{"", "os-example", "a b c"} {
		if _, _, err := parseArchiveNameVersion(out); err == nil {
			t.Errorf("%q: no error", out)
		}
	}
}

func TestArchiveNameVersionRefusesAnOptionLikePath(t *testing.T) {
	if _, _, err := pkgArchiveNameVersionFreeBSD(context.Background(), "-o/etc/passwd"); err == nil {
		t.Error("an option-like path reached pkg")
	}
}

func TestInstalledVersionRefusesANameThatIsNotOne(t *testing.T) {
	for _, name := range []string{"", "-x", "a b", "a'b", `a"b`, "a||b", "a)b"} {
		if _, err := installedVersionExact(context.Background(), name); err == nil {
			t.Errorf("%q reached pkg", name)
		}
	}
}

func TestParsePkgEnv(t *testing.T) {
	got := parsePkgEnv("HTTP_PROXY: http://proxy.lan:3128\nSSL_CA_CERT_FILE: /usr/local/etc/ssl/cert.pem\n\nnot a line\nA B: x\n")
	want := []string{"HTTP_PROXY=http://proxy.lan:3128", "SSL_CA_CERT_FILE=/usr/local/etc/ssl/cert.pem"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if env := parsePkgEnv(""); len(env) != 0 {
		t.Errorf("an empty PKG_ENV: %q", env)
	}
}
