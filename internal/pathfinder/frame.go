// Package pathfinder provides WebSocket tunneling to Pathfinder relay servers.
package pathfinder

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame types for the binary protocol
const (
	FrameTypeData  byte = 0x01 // Payload data
	FrameTypeClose byte = 0x02 // Close stream
	FrameTypeOpen  byte = 0x03 // Open stream (data = service name)
	FrameTypeAck   byte = 0x04 // Acknowledge open
)

// Frame header size: type (1) + stream_id (4) + length (4) = 9 bytes
const frameHeaderSize = 9

// Maximum frame data size (16MB)
const maxFrameDataSize = 16 * 1024 * 1024

// Frame represents a binary frame in the Pathfinder protocol.
// Format: [type:1][stream_id:4][length:4][data:variable]
type Frame struct {
	Type     byte
	StreamID uint32
	Data     []byte
}

// EncodeFrame encodes a Frame into binary format.
func EncodeFrame(f *Frame) []byte {
	dataLen := len(f.Data)
	buf := make([]byte, frameHeaderSize+dataLen)

	buf[0] = f.Type
	binary.BigEndian.PutUint32(buf[1:5], f.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(dataLen))

	if dataLen > 0 {
		copy(buf[9:], f.Data)
	}

	return buf
}

// DecodeFrame decodes a binary frame into a Frame struct.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < frameHeaderSize {
		return nil, errors.New("frame too short: missing header")
	}

	frameType := data[0]
	streamID := binary.BigEndian.Uint32(data[1:5])
	dataLen := binary.BigEndian.Uint32(data[5:9])

	// Validate data length
	if dataLen > maxFrameDataSize {
		return nil, fmt.Errorf("frame data too large: %d bytes", dataLen)
	}

	expectedLen := frameHeaderSize + int(dataLen)
	if len(data) < expectedLen {
		return nil, fmt.Errorf("frame truncated: expected %d bytes, got %d", expectedLen, len(data))
	}

	frame := &Frame{
		Type:     frameType,
		StreamID: streamID,
	}

	if dataLen > 0 {
		frame.Data = make([]byte, dataLen)
		copy(frame.Data, data[frameHeaderSize:expectedLen])
	}

	return frame, nil
}

// String returns a human-readable representation of the frame type.
func (f *Frame) TypeString() string {
	switch f.Type {
	case FrameTypeData:
		return "DATA"
	case FrameTypeClose:
		return "CLOSE"
	case FrameTypeOpen:
		return "OPEN"
	case FrameTypeAck:
		return "ACK"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", f.Type)
	}
}
