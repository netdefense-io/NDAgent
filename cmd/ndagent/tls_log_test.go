package main

import "testing"

func TestRelayHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://pathfinder.netdefense.io":     "pathfinder.netdefense.io",
		"https://relay.example.com:8443/":      "relay.example.com",
		"relay.example.com":                    "relay.example.com",
		" wss://dev-pathfinder.netdefense.io ": "dev-pathfinder.netdefense.io",
		"":                                     "",
	} {
		if got := relayHost(in); got != want {
			t.Errorf("relayHost(%q) = %q, want %q", in, got, want)
		}
	}
}
