package connect

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/connect/internal/ipc"
)

// tunnelLibrary is the library the companion is built on.
const tunnelLibrary = "github.com/tailscale/tailcat"

// protocolOf is the tunnel protocol number of each library version the
// companion has shipped with. The control plane keeps the same table and lets
// two ends of a session meet only when their numbers agree, which is what
// keeps a library release that changes the wire from being found out by
// sessions that fail.
var protocolOf = map[string]int{
	"v0.7.0": 1,
}

// thisProtocol is ipc.Protocol, spelled out: the two must be changed
// together, and by hand.
const thisProtocol = 1

// libraryModule asks go which version of the library this module is built
// with and where its source is.
func libraryModule(t *testing.T) (version, dir string) {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}\t{{.Dir}}", tunnelLibrary).Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", tunnelLibrary, err)
	}
	version, dir, ok := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if !ok || version == "" || dir == "" {
		t.Fatalf("go list -m %s printed %q", tunnelLibrary, out)
	}
	return version, dir
}

func TestTheLibraryVersionHasAProtocolNumber(t *testing.T) {
	version, _ := libraryModule(t)
	number, known := protocolOf[version]
	if !known {
		t.Fatalf("the tunnel library is at %s, which has no protocol number. Read its changelog for anything that changes what goes on the wire (address format, handshake, framing): if nothing does, give it the current number in this table; if something does, give it the next one, raise ipc.Protocol and the agent's copy, and tell the control plane's table.", version)
	}
	if number != thisProtocol {
		t.Errorf("library %s is protocol %d and this build says %d", version, number, thisProtocol)
	}
	if ipc.Protocol != thisProtocol {
		t.Errorf("ipc.Protocol = %d, this file says %d", ipc.Protocol, thisProtocol)
	}
}

// The companion is built with the library's own release tags, which leave out
// the features that reach out on their own (captive-portal checks, port
// mapping at the gateway, log upload, self-update), and without its SSH
// server. A library version that changes its list fails here until the copy
// is refreshed:
//
//	printf '%s,ts_omit_ssh\n' "$(tr -d '\n' < "$(go list -m -f '{{.Dir}}' github.com/tailscale/tailcat)/build-tags.txt")" > build-tags.txt
func TestBuildTagsAreTheLibrarysReleaseTags(t *testing.T) {
	ours, err := os.ReadFile("build-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, dir := libraryModule(t)
	theirs, err := os.ReadFile(dir + "/build-tags.txt")
	if err != nil {
		t.Fatalf("the library no longer ships its release tags: %v", err)
	}
	want := strings.TrimSpace(string(theirs)) + ",ts_omit_ssh"
	if got := strings.TrimSpace(string(ours)); got != want {
		t.Errorf("build-tags.txt differs from the library's release tags plus ts_omit_ssh.\n got: %s\nwant: %s", got, want)
	}
	for _, needed := range []string{"ts_omit_captiveportal", "ts_omit_portmapper", "ts_omit_logtail", "ts_omit_clientupdate", "ts_omit_ssh"} {
		if !strings.Contains(","+strings.TrimSpace(string(ours))+",", ","+needed+",") {
			t.Errorf("build-tags.txt lacks %s", needed)
		}
	}
	if strings.ContainsAny(strings.TrimSpace(string(ours)), " \n\t") {
		t.Error("build-tags.txt must be one comma-separated line: the Makefile passes it to -tags as it is")
	}
}
