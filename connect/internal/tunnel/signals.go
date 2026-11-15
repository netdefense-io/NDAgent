package tunnel

import (
	"errors"
	"io"
	"strings"
)

// The library reports three things this package needs only through its log
// callback: the relay accepted the connection, a connection to the relay
// ended, and a peer outside the allow list was ignored. The callback receives
// the format before it is filled in, so these are compared whole. They are the
// library's wording, and signals_test.go runs the real library against each: a
// version that rewords one fails there, not on a device.
const (
	formatRelayConnected = "magicsock: derp-%d connected; connGen=%v"
	formatRelayRecvError = "magicsock: [%p] derp.Recv(derp-%d): %v"
	formatPeerIgnored    = "ignoring meow from %v: not in allowedClients"
)

// logf is the library's log callback. It runs on the library's goroutines, so
// it only records and queues.
func (s *Server) logf(format string, args ...any) {
	switch format {
	case formatRelayConnected:
		s.relayConnected()
	case formatRelayRecvError:
		var err error
		if len(args) == 3 {
			err, _ = args[2].(error)
		}
		s.relayEnded(err)
	case formatPeerIgnored:
		var peer string
		if len(args) == 1 {
			if text, ok := args[0].(string); ok {
				peer = shortKey(text)
			}
		}
		s.notify(Notice{Kind: NoticePeerRefused, Peer: peer})
	}
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func (s *Server) relayConnected() {
	s.mu.Lock()
	first := !s.everUp
	back := s.everUp && !s.up
	s.everUp, s.up = true, true
	s.refusedInRow = 0
	s.mu.Unlock()
	if first {
		close(s.relayUp)
	}
	if back {
		s.notify(Notice{Kind: NoticeRelayConnected})
	}
}

// relayEnded handles one failed read from the relay. The library reads in a
// loop and reconnects inside it, so after the relay was up the first failure
// is the connection ending and each later one is a reconnection that failed.
func (s *Server) relayEnded(err error) {
	failure := StartError{Failure: classifyRelayError(err), Detail: osDetail(err)}

	s.mu.Lock()
	wasUp := s.up
	s.up = false
	s.lastFailure = failure
	giveUp := false
	var report *Notice
	switch {
	case !s.everUp:
		if failure.Failure == FailureRefused {
			s.refusedInRow++
			giveUp = s.refusedInRow >= refusalsBeforeGivingUp
		} else {
			s.refusedInRow = 0
		}
	case wasUp:
		s.reportedWhileDown = nil
		report = &Notice{Kind: NoticeRelayLost}
	case !s.reportedWhileDown[failure.Failure]:
		if s.reportedWhileDown == nil {
			s.reportedWhileDown = make(map[string]bool)
		}
		s.reportedWhileDown[failure.Failure] = true
		report = &Notice{Kind: NoticeRelayLost, Failure: failure.Failure, Detail: failure.Detail}
	}
	s.mu.Unlock()

	if giveUp {
		s.gaveUpOnce.Do(func() { close(s.gaveUp) })
	}
	if report != nil {
		s.notify(*report)
	}
}

// classifyRelayError tells a relay that closed the connection it had taken
// (the stream just ends) from one that could not be reached at all.
func classifyRelayError(err error) string {
	if err == nil {
		return FailureUnreachable
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.HasSuffix(err.Error(), "EOF") {
		return FailureRefused
	}
	return FailureUnreachable
}

// osDetailMarkers are how the operating system's and the TLS stack's own
// messages begin inside a relay connection error.
var osDetailMarkers = []string{"context deadline exceeded", "dial tcp", "lookup ", "tls: ", "x509: ", "remote error: ", "i/o timeout"}

// libraryWords are the tunnel library's names for itself and its parts. A
// detail goes to the device's log and may be shown to a user, where the
// transport is never called by the library's name.
var libraryWords = []string{"derp", "magicsock", "wgengine", "netstack", "tailscale", "tailcat"}

const maxDetail = 200

// osDetail is the operating system's part of a relay connection error: "dial
// tcp4 203.0.113.5:443: connect: connection refused", "lookup relay.example:
// no such host". The library puts its own words in front without wrapping the
// error, so the part is found by how such messages begin: the longest tail
// that starts like one and holds none of the library's words. An error with
// no such tail has no detail.
func osDetail(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	for at := 0; at < len(text); at++ {
		tail := text[at:]
		if !hasAnyPrefix(tail, osDetailMarkers) || containsAny(strings.ToLower(tail), libraryWords) {
			continue
		}
		if len(tail) > maxDetail {
			tail = tail[:maxDetail]
		}
		return tail
	}
	return ""
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// shortKey shortens a public key as the library prints it ("nodekey:" and 64
// hex digits) to its first eight digits: enough to tell two peers apart in a
// log, and public either way.
func shortKey(text string) string {
	hex := strings.TrimPrefix(text, "nodekey:")
	if len(hex) > 8 {
		hex = hex[:8]
	}
	for _, r := range hex {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	return hex
}
