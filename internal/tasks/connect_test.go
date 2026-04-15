package tasks

import (
	"testing"
)

func TestBuildPathfinderWSURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "https with path",
			host: "https://pathfinder.example.com",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "https with trailing slash",
			host: "https://pathfinder.example.com/",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "https already has /ws",
			host: "https://pathfinder.example.com/ws",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "http to ws",
			host: "http://localhost:8080",
			want: "ws://localhost:8080/ws",
		},
		{
			name: "wss already correct",
			host: "wss://relay.example.com/ws",
			want: "wss://relay.example.com/ws",
		},
		{
			name: "bare hostname",
			host: "pathfinder.example.com",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "hostname with port",
			host: "pathfinder.example.com:9443",
			want: "wss://pathfinder.example.com:9443/ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPathfinderWSURL(tt.host)
			if got != tt.want {
				t.Errorf("buildPathfinderWSURL(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
