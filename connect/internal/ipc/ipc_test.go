package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// The vectors are the agent's: its tests check that it writes the
// configuration and reads the events exactly as they are there, and these
// check the companion against the same files.
const vectorDir = "../../../internal/directpeer/testdata/ipc/"

func vector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(vectorDir + name)
	if err != nil {
		t.Fatalf("the shared vectors are part of the agent's tree: %v", err)
	}
	return data
}

func framed(body []byte) []byte {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	return append(head[:], body...)
}

func repeat(b byte) Key32 {
	var k Key32
	for i := range k {
		k[i] = b
	}
	return k
}

func TestReadConfigReadsTheSharedVector(t *testing.T) {
	cfg, err := ReadConfig(bytes.NewReader(framed(vector(t, "config.json"))))
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	want := Config{
		V:              1,
		Role:           "server",
		Protocol:       1,
		Relay:          Relay{ID: "us", RegionID: 900, Host: "relay-us.example.net", Port: 443, STUNPort: 3478},
		Port:           1,
		NodeKey:        repeat(0x40),
		PeerKey:        repeat(0x02),
		PSK:            repeat(0x03),
		StartTimeoutMS: 8000,
	}
	if *cfg != want {
		t.Errorf("config = %+v\nwant     %+v", *cfg, want)
	}
}

// The session's bytes follow the configuration on the same stream, so reading
// the configuration must not take any of them.
func TestReadConfigReadsNothingPastTheMessage(t *testing.T) {
	stream := bytes.NewReader(append(framed(vector(t, "config.json")), "the session"...))
	if _, err := ReadConfig(stream); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	rest, _ := io.ReadAll(stream)
	if string(rest) != "the session" {
		t.Errorf("left on the stream: %q, want %q", rest, "the session")
	}
}

// edit returns the shared vector with one change made to its JSON object.
func edit(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(vector(t, "config.json"), &obj); err != nil {
		t.Fatal(err)
	}
	change(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func relayOf(obj map[string]any) map[string]any { return obj["relay"].(map[string]any) }

func b64(n int, b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n)) }

func TestReadConfigRefusesAnythingMissingOrUnknown(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
		want   string // part of the error
	}{
		{"another exchange version", func(o map[string]any) { o["v"] = 2 }, "v:"},
		{"no exchange version", func(o map[string]any) { delete(o, "v") }, "v:"},
		{"another role", func(o map[string]any) { o["role"] = "client" }, "role:"},
		{"no role", func(o map[string]any) { delete(o, "role") }, "role:"},
		{"another protocol number", func(o map[string]any) { o["protocol"] = 2 }, "protocol:"},
		{"no protocol number", func(o map[string]any) { delete(o, "protocol") }, "protocol:"},
		{"no relay", func(o map[string]any) { delete(o, "relay") }, "relay.id"},
		{"no relay id", func(o map[string]any) { delete(relayOf(o), "id") }, "relay.id"},
		{"relay id with a space", func(o map[string]any) { relayOf(o)["id"] = "u s" }, "relay.id"},
		{"relay id in capitals", func(o map[string]any) { relayOf(o)["id"] = "US" }, "relay.id"},
		{"no region number", func(o map[string]any) { delete(relayOf(o), "region_id") }, "relay.region_id"},
		{"region number too large", func(o map[string]any) { relayOf(o)["region_id"] = 65536 }, "relay.region_id"},
		{"no relay host", func(o map[string]any) { delete(relayOf(o), "host") }, "relay.host"},
		{"relay host is a URL", func(o map[string]any) { relayOf(o)["host"] = "https://relay.example.net" }, "relay.host"},
		{"relay host with a port", func(o map[string]any) { relayOf(o)["host"] = "relay.example.net:443" }, "relay.host"},
		{"relay host with a path", func(o map[string]any) { relayOf(o)["host"] = "relay.example.net/x" }, "relay.host"},
		{"relay host with a space", func(o map[string]any) { relayOf(o)["host"] = "relay example" }, "relay.host"},
		{"relay host too long", func(o map[string]any) { relayOf(o)["host"] = strings.Repeat("a.", 127) + "a" }, "relay.host"},
		{"no relay port", func(o map[string]any) { delete(relayOf(o), "port") }, "relay.port"},
		{"relay port too large", func(o map[string]any) { relayOf(o)["port"] = 70000 }, "relay.port"},
		{"no STUN port", func(o map[string]any) { delete(relayOf(o), "stun_port") }, "relay.stun_port"},
		{"STUN turned off", func(o map[string]any) { relayOf(o)["stun_port"] = -1 }, "relay.stun_port"},
		{"no served port", func(o map[string]any) { delete(o, "port") }, "port:"},
		{"served port 0", func(o map[string]any) { o["port"] = 0 }, "port:"},
		{"no node key", func(o map[string]any) { delete(o, "node_key") }, "node_key"},
		{"node key all zero", func(o map[string]any) { o["node_key"] = b64(32, 0) }, "node_key"},
		{"no peer key", func(o map[string]any) { delete(o, "peer_key") }, "peer_key"},
		{"peer key all zero", func(o map[string]any) { o["peer_key"] = b64(32, 0) }, "peer_key"},
		{"no pre-shared key", func(o map[string]any) { delete(o, "psk") }, "psk"},
		{"pre-shared key all zero", func(o map[string]any) { o["psk"] = b64(32, 0) }, "psk"},
		{"a key of 31 bytes", func(o map[string]any) { o["psk"] = b64(31, 7) }, "key field"},
		{"a key of 33 bytes", func(o map[string]any) { o["node_key"] = b64(33, 7) }, "key field"},
		{"a key that is not base64", func(o map[string]any) { o["peer_key"] = "not base64 !!" }, "key field"},
		{"a key that is a number", func(o map[string]any) { o["peer_key"] = 7 }, "key field"},
		{"a field this build does not know", func(o map[string]any) { o["insecure"] = true }, "does not know"},
		{"a wait that is too short", func(o map[string]any) { o["start_timeout_ms"] = 10 }, "start_timeout_ms"},
		{"a wait that is too long", func(o map[string]any) { o["start_timeout_ms"] = 600000 }, "start_timeout_ms"},
		{"a string where a number goes", func(o map[string]any) { o["port"] = "1" }, "port"},
	}
	secrets := []string{b64(32, 0x40), b64(32, 0x02), b64(32, 0x03), b64(31, 7), b64(33, 7), "not base64 !!"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ReadConfig(bytes.NewReader(framed(edit(t, tc.change))))
			if err == nil {
				t.Fatalf("accepted: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
			for _, secret := range secrets {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error = %q quotes key material", err)
				}
			}
		})
	}
}

func TestReadConfigRefusesABrokenMessage(t *testing.T) {
	good := vector(t, "config.json")
	tooLong := make([]byte, 4)
	binary.BigEndian.PutUint32(tooLong, MaxConfigSize+1)
	cases := []struct {
		name   string
		stream []byte
		want   string
	}{
		{"half a length", []byte{0, 0}, "truncated length"},
		{"length 0", []byte{0, 0, 0, 0}, "out of range"},
		{"length over the limit", tooLong, "out of range"},
		{"a message cut short", framed(good)[:40], "truncated message"},
		{"not JSON", framed([]byte("hello")), "not valid JSON"},
		{"two JSON values", framed(append(append([]byte{}, good...), good...)), "more than one"},
		{"a JSON array", framed([]byte("[1,2]")), "configuration message"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ReadConfig(bytes.NewReader(tc.stream))
			if err == nil {
				t.Fatalf("accepted: %+v", cfg)
			}
			if errors.Is(err, ErrNoConfig) {
				t.Errorf("error = %v: that is for a stream that ended before any message", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to say %q", err, tc.want)
			}
		})
	}

	if _, err := ReadConfig(bytes.NewReader(nil)); !errors.Is(err, ErrNoConfig) {
		t.Errorf("an empty stream: %v, want ErrNoConfig", err)
	}
}

func TestAKeyNeverPrintsItself(t *testing.T) {
	cfg, err := ReadConfig(bytes.NewReader(framed(vector(t, "config.json"))))
	if err != nil {
		t.Fatal(err)
	}
	printed := fmt.Sprintf("%v %+v %#v %s %q %x", *cfg, *cfg, *cfg, cfg.NodeKey, cfg.PSK, cfg.PeerKey)
	for name, bad := range map[string]string{
		"the node key in base64":        b64(32, 0x40),
		"the node key as text":          strings.Repeat("@", 32),
		"the node key in hex":           strings.Repeat("40", 32),
		"the node key as numbers":       "64 64 64 64",
		"the pre-shared key in base64":  b64(32, 0x03),
		"the pre-shared key in hex":     strings.Repeat("03", 32),
		"the pre-shared key as numbers": "3 3 3 3",
		"the peer key in hex":           strings.Repeat("02", 32),
	} {
		if strings.Contains(printed, bad) {
			t.Errorf("a printed configuration shows %s:\n%s", name, printed)
		}
	}

	cfg.Wipe()
	if !cfg.NodeKey.IsZero() || !cfg.PeerKey.IsZero() || !cfg.PSK.IsZero() {
		t.Error("Wipe left key material")
	}
}

// Every event the companion can emit, in the bytes the agent's tests read.
func TestEmitterWritesTheSharedVectorsByteForByte(t *testing.T) {
	lines := strings.Split(strings.TrimSuffix(string(vector(t, "events.jsonl")), "\n"), "\n")
	var out bytes.Buffer
	em := NewEmitter(&out)
	for _, line := range lines {
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		var e Event
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("vector line %q: %v", line, err)
		}
		em.Emit(e)
	}
	if got := out.String(); got != strings.Join(lines, "\n")+"\n" {
		t.Errorf("emitted:\n%s\nwant:\n%s", got, strings.Join(lines, "\n"))
	}

	// A name or reason added here without a line in the vectors is one the
	// agent's tests have never read.
	all := string(vector(t, "events.jsonl"))
	for _, name := range []string{
		EventHello, EventListening, EventConnected, EventPath, EventRelay, EventRefused, EventClosed, EventError, EventLog,
	} {
		if !strings.Contains(all, `{"event":"`+name+`"`) {
			t.Errorf("no vector for event %q", name)
		}
	}
	for _, value := range []string{
		`"path":"` + PathDirect + `"`, `"path":"` + PathRelayed + `"`,
		`"state":"` + RelayConnected + `"`, `"state":"` + RelayLost + `"`,
		`"reason":"` + ReasonStdinClosed + `"`, `"reason":"` + ReasonPeerClosed + `"`,
		`"reason":"` + ReasonConnectionLost + `"`, `"reason":"` + ReasonStdoutClosed + `"`,
		`"reason":"` + ReasonTerminated + `"`, `"reason":"` + ReasonBadConfig + `"`,
		`"reason":"` + ReasonNoConfig + `"`, `"reason":"` + ReasonRelayRefused + `"`,
		`"reason":"` + ReasonRelayUnreachable + `"`, `"reason":"` + ReasonStartFailed + `"`,
		`"reason":"` + ReasonInternal + `"`, `"reason":"` + ReasonUnknownPeer + `"`,
	} {
		if !strings.Contains(all, value) {
			t.Errorf("no vector with %s", value)
		}
	}
}

// What the agent and the peer must agree on is spelled out here, not taken
// from the constants: a change to either is a change to a contract.
func TestTheNumbersOtherPartiesRelyOn(t *testing.T) {
	if Version != 1 {
		t.Errorf("exchange version = %d: the agent's copy and the vectors say 1", Version)
	}
	if Protocol != 1 {
		t.Errorf("tunnel protocol number = %d: the control plane's table says 1 for this build", Protocol)
	}
	if RoleServer != "server" {
		t.Errorf("role = %q", RoleServer)
	}
}
