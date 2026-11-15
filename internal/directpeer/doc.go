// Package directpeer is the device side of the "direct-peer + encrypted
// relay" transport of a remote access session.
//
// One session is carried by one companion process, ndagent-connect, which is
// the only thing on the device that touches the tunnel. The agent starts it,
// checks that it is the build the agent came with, hands it that session's
// keys on its stdin, speaks the session's frames over its stdin and stdout,
// and ends it by closing its stdin. The device key and the agent's
// credentials never reach it.
//
// The companion is a module of its own (connect/ at the top of the
// repository), so the two share no code. What they say to each other is
// written twice, here and in connect/internal/ipc, and both are tested
// against the files in testdata/ipc.
package directpeer

// What the two ends of a session agree on. The numbers are the cross-module
// contract's and change only with it.
const (
	// Protocol is the tunnel protocol number of this build: two ends meet
	// only when theirs is the same.
	Protocol = 1

	// ServedPort is the one TCP port a session is served on. A session is one
	// connection to it.
	ServedPort = 1

	// RelayRegionID is the number both ends give the session's relay.
	RelayRegionID = 900

	// DefaultRelayPort and DefaultRelaySTUNPort are a relay's ports when the
	// control plane names none.
	DefaultRelayPort     = 443
	DefaultRelaySTUNPort = 3478
)

// DefaultCompanionPath is where the package installs the companion. The agent
// starts it by this absolute path, never through PATH.
const DefaultCompanionPath = "/usr/local/libexec/ndagent-connect"

// DefaultRunAs is the user the companion runs as when the agent is root. It
// needs outbound sockets and its three pipes, nothing else.
const DefaultRunAs = "nobody"
