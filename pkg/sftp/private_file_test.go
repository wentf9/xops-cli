package sftp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	sshfx "github.com/pkg/sftp/v2/encoding/ssh/filexfer"
)

type privatePacketSink struct{ bytes.Buffer }

func (*privatePacketSink) Close() error { return nil }

func TestPrivateFileRejectsMalformedOrOversizedResponses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id       uint32
		packet   sshfx.PacketMarshaller
		oversize bool
	}{
		{name: "wrong request ID", id: 2, packet: &sshfx.StatusPacket{}},
		{name: "wrong response type", id: 1, packet: &sshfx.HandlePacket{Handle: "unexpected"}},
		{name: "permission denied", id: 1, packet: &sshfx.StatusPacket{StatusCode: sshfx.StatusPermissionDenied}},
		{name: "oversized", oversize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response []byte
			if tc.oversize {
				response = make([]byte, 4)
				binary.BigEndian.PutUint32(response, 1<<20)
			} else {
				header, payload, err := tc.packet.MarshalPacket(tc.id, nil)
				if err != nil {
					t.Fatal(err)
				}
				response = append(header, payload...)
			}
			stream := privateFileStream{ctx: t.Context(), reader: bytes.NewReader(response), writer: &privatePacketSink{}, handle: "h"}
			n, err := stream.Write([]byte("secret"))
			if err == nil || n != 0 || stream.offset != 0 {
				t.Fatalf("malformed write confirmation accepted: %d %v", n, err)
			}
		})
	}
}
func TestPrivateFileCancellationDoesNotSendMoreData(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sink := &privatePacketSink{}
	stream := privateFileStream{ctx: ctx, reader: bytes.NewReader(nil), writer: sink, handle: "h"}
	if _, err := stream.Write([]byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
	if sink.Len() != 0 {
		t.Fatal("sent data after cancellation")
	}
}
