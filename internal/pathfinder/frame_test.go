package pathfinder

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "data frame with payload",
			frame: Frame{
				Type:     FrameTypeData,
				StreamID: 123,
				Data:     []byte("hello world"),
			},
		},
		{
			name: "data frame empty payload",
			frame: Frame{
				Type:     FrameTypeData,
				StreamID: 456,
				Data:     nil,
			},
		},
		{
			name: "open frame with service name",
			frame: Frame{
				Type:     FrameTypeOpen,
				StreamID: 1,
				Data:     []byte("ssh"),
			},
		},
		{
			name: "close frame",
			frame: Frame{
				Type:     FrameTypeClose,
				StreamID: 789,
				Data:     nil,
			},
		},
		{
			name: "ack frame",
			frame: Frame{
				Type:     FrameTypeAck,
				StreamID: 42,
				Data:     nil,
			},
		},
		{
			name: "large data frame",
			frame: Frame{
				Type:     FrameTypeData,
				StreamID: 999,
				Data:     bytes.Repeat([]byte("x"), 64*1024),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := EncodeFrame(&tt.frame)

			// Decode
			decoded, err := DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("DecodeFrame failed: %v", err)
			}

			// Verify
			if decoded.Type != tt.frame.Type {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, tt.frame.Type)
			}
			if decoded.StreamID != tt.frame.StreamID {
				t.Errorf("StreamID mismatch: got %v, want %v", decoded.StreamID, tt.frame.StreamID)
			}
			if !bytes.Equal(decoded.Data, tt.frame.Data) {
				t.Errorf("Data mismatch: got %v bytes, want %v bytes", len(decoded.Data), len(tt.frame.Data))
			}
		})
	}
}

func TestDecodeFrameErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "frame too short",
		},
		{
			name:    "partial header",
			data:    []byte{0x01, 0x00, 0x00},
			wantErr: "frame too short",
		},
		{
			name:    "truncated data",
			data:    []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05}, // claims 5 bytes but has 0
			wantErr: "frame truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeFrame(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error()[:len(tt.wantErr)] != tt.wantErr {
				t.Errorf("error mismatch: got %q, want prefix %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestFrameTypeString(t *testing.T) {
	tests := []struct {
		frameType byte
		want      string
	}{
		{FrameTypeData, "DATA"},
		{FrameTypeClose, "CLOSE"},
		{FrameTypeOpen, "OPEN"},
		{FrameTypeAck, "ACK"},
		{0xFF, "UNKNOWN(0xff)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			f := Frame{Type: tt.frameType}
			got := f.TypeString()
			if got != tt.want {
				t.Errorf("TypeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFrameHeaderSize(t *testing.T) {
	// Verify header size is exactly 9 bytes
	f := Frame{
		Type:     FrameTypeData,
		StreamID: 0,
		Data:     nil,
	}
	encoded := EncodeFrame(&f)
	if len(encoded) != frameHeaderSize {
		t.Errorf("empty frame size = %d, want %d", len(encoded), frameHeaderSize)
	}
}

func BenchmarkEncodeFrame(b *testing.B) {
	frame := &Frame{
		Type:     FrameTypeData,
		StreamID: 123,
		Data:     bytes.Repeat([]byte("x"), 1024),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeFrame(frame)
	}
}

func BenchmarkDecodeFrame(b *testing.B) {
	frame := &Frame{
		Type:     FrameTypeData,
		StreamID: 123,
		Data:     bytes.Repeat([]byte("x"), 1024),
	}
	encoded := EncodeFrame(frame)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeFrame(encoded)
	}
}
