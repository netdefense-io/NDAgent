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

func TestPayloadBool(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]interface{}
		key     string
		want    bool
	}{
		{
			name:    "missing key defaults false",
			payload: map[string]interface{}{},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "nil payload entry defaults false",
			payload: map[string]interface{}{"read_only": nil},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "bool true",
			payload: map[string]interface{}{"read_only": true},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "bool false",
			payload: map[string]interface{}{"read_only": false},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "json number 1",
			payload: map[string]interface{}{"read_only": float64(1)},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "json number 0",
			payload: map[string]interface{}{"read_only": float64(0)},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "string true",
			payload: map[string]interface{}{"read_only": "true"},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "string 1",
			payload: map[string]interface{}{"read_only": "1"},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "string false",
			payload: map[string]interface{}{"read_only": "false"},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "unexpected type defaults false",
			payload: map[string]interface{}{"read_only": []string{"x"}},
			key:     "read_only",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := payloadBool(tt.payload, tt.key); got != tt.want {
				t.Errorf("payloadBool(%v, %q) = %v, want %v", tt.payload, tt.key, got, tt.want)
			}
		})
	}
}
