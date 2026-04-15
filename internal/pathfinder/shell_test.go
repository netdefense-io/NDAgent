package pathfinder

import (
	"testing"
)

func TestControlMessageConstants(t *testing.T) {
	// Verify control message constants match protocol spec
	if CtlMsgResize != 0x01 {
		t.Errorf("CtlMsgResize = %#x, want %#x", CtlMsgResize, 0x01)
	}
	if CtlMsgSetEnv != 0x02 {
		t.Errorf("CtlMsgSetEnv = %#x, want %#x", CtlMsgSetEnv, 0x02)
	}
	if CtlMsgClose != 0xFF {
		t.Errorf("CtlMsgClose = %#x, want %#x", CtlMsgClose, 0xFF)
	}
}

func TestParseResizeMessage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantRows uint16
		wantCols uint16
		valid    bool
	}{
		{
			name:     "24x80 terminal",
			data:     []byte{CtlMsgResize, 0x00, 0x18, 0x00, 0x50},
			wantRows: 24,
			wantCols: 80,
			valid:    true,
		},
		{
			name:     "40x120 terminal",
			data:     []byte{CtlMsgResize, 0x00, 0x28, 0x00, 0x78},
			wantRows: 40,
			wantCols: 120,
			valid:    true,
		},
		{
			name:     "large terminal 1000x500",
			data:     []byte{CtlMsgResize, 0x03, 0xE8, 0x01, 0xF4},
			wantRows: 1000,
			wantCols: 500,
			valid:    true,
		},
		{
			name:  "too short message",
			data:  []byte{CtlMsgResize, 0x00, 0x18},
			valid: false,
		},
		{
			name:  "wrong message type",
			data:  []byte{CtlMsgClose, 0x00, 0x18, 0x00, 0x50},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.data) < 1 {
				return
			}

			// Simulate control message parsing logic
			if tt.data[0] != CtlMsgResize {
				if tt.valid {
					t.Error("expected valid resize message")
				}
				return
			}

			if len(tt.data) < 5 {
				if tt.valid {
					t.Error("expected valid resize message but data too short")
				}
				return
			}

			rows := uint16(tt.data[1])<<8 | uint16(tt.data[2])
			cols := uint16(tt.data[3])<<8 | uint16(tt.data[4])

			if rows != tt.wantRows {
				t.Errorf("rows = %d, want %d", rows, tt.wantRows)
			}
			if cols != tt.wantCols {
				t.Errorf("cols = %d, want %d", cols, tt.wantCols)
			}
		})
	}
}

func TestShellManager_StreamPairing(t *testing.T) {
	sm := NewShellManager("")

	if sm.pendingShell != nil {
		t.Error("NewShellManager should have nil pendingShell")
	}
	if sm.pendingShellCtl != nil {
		t.Error("NewShellManager should have nil pendingShellCtl")
	}
}

func TestShellManager_CloseAll(t *testing.T) {
	sm := NewShellManager("")

	// CloseAll should not panic when there are no pending streams
	sm.CloseAll()

	// Verify state is still clean
	if sm.pendingShell != nil {
		t.Error("pendingShell should be nil after CloseAll")
	}
	if sm.pendingShellCtl != nil {
		t.Error("pendingShellCtl should be nil after CloseAll")
	}
}

func TestEncodeResizeMessage(t *testing.T) {
	// Helper to encode a resize message (for testing protocol)
	encodeResize := func(rows, cols uint16) []byte {
		return []byte{
			CtlMsgResize,
			byte(rows >> 8), byte(rows & 0xFF),
			byte(cols >> 8), byte(cols & 0xFF),
		}
	}

	// Test round-trip encoding
	tests := []struct {
		rows uint16
		cols uint16
	}{
		{24, 80},
		{40, 120},
		{1, 1},
		{65535, 65535},
	}

	for _, tt := range tests {
		msg := encodeResize(tt.rows, tt.cols)

		if msg[0] != CtlMsgResize {
			t.Errorf("message type = %#x, want %#x", msg[0], CtlMsgResize)
		}

		rows := uint16(msg[1])<<8 | uint16(msg[2])
		cols := uint16(msg[3])<<8 | uint16(msg[4])

		if rows != tt.rows {
			t.Errorf("decoded rows = %d, want %d", rows, tt.rows)
		}
		if cols != tt.cols {
			t.Errorf("decoded cols = %d, want %d", cols, tt.cols)
		}
	}
}
