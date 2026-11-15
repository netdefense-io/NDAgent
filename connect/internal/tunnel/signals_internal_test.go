package tunnel

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func TestClassifyRelayError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		// The two errors the library logs, as it wraps them.
		{"the relay closed the connection", fmt.Errorf("derp.Recv: %w", io.EOF), FailureRefused},
		{"the dial was refused", errors.New("derphttp.Client.Recv connect to region 900 (us): dial tcp4 203.0.113.5:443: connect: connection refused"), FailureUnreachable},
		{"unexpected end", io.ErrUnexpectedEOF, FailureRefused},
		{"end of stream as text only", errors.New("derp.Recv: EOF"), FailureRefused},
		{"timeout", errors.New("dial tcp4 203.0.113.5:443: i/o timeout"), FailureUnreachable},
		{"no error value", nil, FailureUnreachable},
	}
	for _, tc := range cases {
		if got := classifyRelayError(tc.err); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOSDetailKeepsOnlyTheOperatingSystemsWords(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"derphttp.Client.Recv connect to region 900 (us): dial tcp4 203.0.113.5:443: connect: connection refused", "dial tcp4 203.0.113.5:443: connect: connection refused"},
		{"derphttp.Client.Connect connect to region 900 (us): lookup relay.example.net: no such host", "lookup relay.example.net: no such host"},
		{"derphttp.Client.Recv connect to region 900 (us): tls: failed to verify certificate: x509: certificate signed by unknown authority", "tls: failed to verify certificate: x509: certificate signed by unknown authority"},
		{"derphttp.Client.Recv connect to region 900 (us): context deadline exceeded: dial tcp4 203.0.113.5:443: i/o timeout", "context deadline exceeded: dial tcp4 203.0.113.5:443: i/o timeout"},
		// The library's words after a marker: the tail that starts there is
		// passed over for the next one that is clean.
		{"context deadline exceeded: derphttp.Client.Recv connect to region 900 (us): dial tcp4 203.0.113.5:443: i/o timeout", "dial tcp4 203.0.113.5:443: i/o timeout"},
		{"lookup derp900.example.net: no such host", ""},
		{"derp.Recv: EOF", ""},
		{"something the library made up", ""},
	}
	for _, tc := range cases {
		got := osDetail(errors.New(tc.in))
		if got != tc.want {
			t.Errorf("osDetail(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if containsAny(strings.ToLower(got), libraryWords) {
			t.Errorf("osDetail(%q) = %q names the library", tc.in, got)
		}
	}
	if got := osDetail(nil); got != "" {
		t.Errorf("osDetail(nil) = %q", got)
	}
	long := osDetail(errors.New("dial tcp " + strings.Repeat("x", 500)))
	if len(long) != maxDetail {
		t.Errorf("a long detail is %d bytes, want it cut at %d", len(long), maxDetail)
	}
}

func TestShortKey(t *testing.T) {
	cases := map[string]string{
		"nodekey:42d015a2f8de35f1fef8af0a85b9198c71d5cf6c9925c28588b0a3ccf765bf54": "42d015a2",
		"42d015a2f8de35f1":   "42d015a2",
		"nodekey:zz":         "",
		"":                   "",
		"nodekey:ABCDEF0123": "",
	}
	for in, want := range cases {
		if got := shortKey(in); got != want {
			t.Errorf("shortKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNodeKeyRefusesAnUnclampedScalarAndChangesNothing(t *testing.T) {
	clamped := [32]byte{0: 0x48, 5: 0x99, 31: 0x41}
	k, err := NodeKey(clamped)
	if err != nil {
		t.Fatalf("a clamped key is refused: %v", err)
	}
	if k.Raw32() != clamped {
		t.Error("NodeKey changed the bytes it was given")
	}

	for name, raw := range map[string][32]byte{
		"low bits set":     {0: 0x49, 31: 0x41},
		"top bit set":      {0: 0x48, 31: 0xc1},
		"second bit clear": {0: 0x48, 31: 0x01},
		"all zero":         {},
		"all ones":         {0: 0xff, 31: 0xff},
	} {
		if _, err := NodeKey(raw); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: NodeKey = %v, want a refusal", name, err)
		}
	}
}

// A region handed to the library directly gets none of the library's own
// filling in, so every field it relies on must be set here.
func TestNewRegionLeavesNothingForTheLibraryToFillIn(t *testing.T) {
	r := NewRegion("us", 900, "relay-us.example.net", 443, 3478)
	if r.RegionID != 900 || r.RegionCode != "us" || r.RegionName == "" {
		t.Errorf("region = %+v", r)
	}
	if len(r.Nodes) != 1 {
		t.Fatalf("%d hosts, want 1", len(r.Nodes))
	}
	n := r.Nodes[0]
	if n.Name != "us-1" || n.RegionID != 900 || n.HostName != "relay-us.example.net" || n.DERPPort != 443 || n.STUNPort != 3478 {
		t.Errorf("host = %+v", n)
	}
	if n.InsecureForTests || n.STUNOnly || n.IPv4 != "" || n.IPv6 != "" || n.CertName != "" {
		t.Errorf("host = %+v: certificate checks, relaying and name resolution must be left as they are", n)
	}
	cfg := Config{NodeKey: mustNodeKey(t), PeerKey: PeerKey([32]byte{1}), PSK: [32]byte{1}, Region: r, Port: 1}
	if err := cfg.validate(); err != nil {
		t.Errorf("a region from NewRegion is refused: %v", err)
	}
}

func mustNodeKey(t *testing.T) key.NodePrivate {
	t.Helper()
	k, err := NodeKey([32]byte{0: 0x48, 31: 0x41})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestScrubEnvironmentEmptiesOnlyTheLibrarysSettings(t *testing.T) {
	environ := []string{
		"PATH=/sbin:/bin",
		"HOME=/nonexistent",
		"TS_DEBUG_ALWAYS_USE_DERP=1",
		"TS_NETSTACK_KEEPALIVE_IDLE=2h",
		"TAILSCALE_USE_WIP_CODE=true",
		"TAILCAT_DERPMAP_URL=https://elsewhere.example/map.json",
		"IN_TS_TEST=true",
		"TS_ALREADY_EMPTY=",
		"TSX_NOT_A_SETTING=1",
		"NOT_TS_EITHER=1",
		"SSL_CERT_FILE=/etc/ssl/cert.pem",
	}
	cleared := map[string]bool{}
	scrubEnvironment(environ, func(name, value string) {
		if value != "" {
			t.Errorf("%s set to %q, want it emptied", name, value)
		}
		cleared[name] = true
	})
	want := []string{"TS_DEBUG_ALWAYS_USE_DERP", "TS_NETSTACK_KEEPALIVE_IDLE", "TAILSCALE_USE_WIP_CODE", "TAILCAT_DERPMAP_URL", "IN_TS_TEST"}
	for _, name := range want {
		if !cleared[name] {
			t.Errorf("%s was left set", name)
		}
	}
	if len(cleared) != len(want) {
		t.Errorf("cleared %v, want only %v", cleared, want)
	}
}
