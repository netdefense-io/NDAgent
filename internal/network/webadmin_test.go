package network

import (
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
)

func TestGetWebadminReadOnlyUser(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "configured value used verbatim",
			cfg:  "ro-operator",
			want: "ro-operator",
		},
		{
			name: "empty config falls back to default (never the admin user)",
			cfg:  "",
			want: "netdefense-readonly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := &WebSocketClient{cfg: &config.Config{
				WebadminUser:         "root",
				WebadminReadOnlyUser: tt.cfg,
			}}
			if got := ws.GetWebadminReadOnlyUser(); got != tt.want {
				t.Errorf("GetWebadminReadOnlyUser() = %q, want %q", got, tt.want)
			}
			// The read-only getter must never collapse to the admin user.
			if ws.GetWebadminReadOnlyUser() == ws.GetWebadminUser() {
				t.Errorf("read-only user resolved to the admin user %q — privilege escalation", ws.GetWebadminUser())
			}
		})
	}
}
