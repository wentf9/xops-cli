package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	sshfx "github.com/pkg/sftp/v2/encoding/ssh/filexfer"
)

// CreatePrivateExclusive creates a file with mode 0600 in the initial SFTP OPEN,
// invokes write while holding that exact handle, then closes it. The v1 client
// cannot send creation permissions; a separate bounded subsystem with the upstream packet codec is used
// only for this operation, preserving existing v1 rename/extension semantics.
// created distinguishes an acknowledged exclusive open from a lost/rejected
// reply; callers must not infer ownership from a failed open.
func (c *Client) CreatePrivateExclusive(ctx context.Context, name string, write func(io.Writer) error) (attempted, created bool, retErr error) {
	if ctx == nil || c == nil || c.state == nil || c.state.sshClient == nil || write == nil {
		return false, false, errors.New("private file creation requires an SSH client and writer")
	}
	setupCtx, cancel := context.WithTimeout(ctx, defaultSubsystemSetupTimeout)
	defer cancel()
	raw, interrupt, err := newSubsystemProtocol(setupCtx, c.state.sshClient, func(rd io.Reader, wr io.WriteCloser) (io.Closer, error) {
		return newPrivateFileStream(ctx, rd, wr)
	})
	if err != nil {
		return false, false, err
	}
	client := raw.(*privateFileStream)
	stop := sync.OnceValue(func() error {
		if err := interrupt(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("interrupt private SFTP subsystem: %w", err)
		}
		return nil
	})
	defer func() { retErr = errors.Join(retErr, stop(), closeTransferResource(client, "private SFTP client")) }()
	retErr = runInterruptibleOperation(ctx, stop, func() (opErr error) {
		attempted = true
		response, err := client.exchange(&sshfx.OpenPacket{Filename: name, PFlags: sshfx.FlagWrite | sshfx.FlagCreate | sshfx.FlagExclusive, Attrs: sshfx.Attributes{Flags: sshfx.AttrPermissions, Permissions: 0600}})
		if err != nil {
			return fmt.Errorf("create private remote file: %w", err)
		}
		handle, ok := response.(*sshfx.HandlePacket)
		if !ok || handle.Handle == "" {
			return errors.New("private file OPEN did not return a handle")
		}
		client.handle = handle.Handle
		created = true
		defer func() { opErr = errors.Join(opErr, client.closeHandle()) }()
		return write(client)
	})
	return attempted, created, retErr
}

// This single-handle stream uses only INIT, OPEN, WRITE and CLOSE. All metadata
// and rename operations stay on the existing v1 client. There is no receiver
// worker or in-flight queue: closing the owned SSH subsystem interrupts the
// pending packet read/write directly, including a lost OPEN/WRITE/CLOSE reply.
type privateFileStream struct {
	ctx       context.Context
	reader    io.Reader
	writer    io.WriteCloser
	requestID uint32
	handle    string
	offset    uint64
}

func newPrivateFileStream(ctx context.Context, rd io.Reader, wr io.WriteCloser) (*privateFileStream, error) {
	init, err := (&sshfx.InitPacket{Version: 3}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := writePrivatePacket(wr, init); err != nil {
		return nil, err
	}
	var version sshfx.VersionPacket
	if err := version.ReadFrom(rd, nil, 64<<10); err != nil {
		return nil, err
	}
	if version.Version != 3 {
		return nil, errors.New("private file creation requires SFTP v3")
	}
	return &privateFileStream{ctx: ctx, reader: rd, writer: wr}, nil
}
func writePrivatePacket(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
func (c *privateFileStream) exchange(request sshfx.PacketMarshaller) (sshfx.Packet, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	c.requestID++
	header, payload, err := request.MarshalPacket(c.requestID, nil)
	if err != nil {
		return nil, err
	}
	if err := writePrivatePacket(c.writer, header); err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		if err := writePrivatePacket(c.writer, payload); err != nil {
			return nil, err
		}
	}
	var raw sshfx.RawPacket
	if err := raw.ReadFrom(c.reader, nil, 64<<10); err != nil {
		return nil, err
	}
	if raw.RequestID != c.requestID {
		return nil, errors.New("private file response ID mismatch")
	}
	packet, err := raw.PacketBody()
	if err != nil {
		return nil, err
	}
	if status, ok := packet.(*sshfx.StatusPacket); ok && status.StatusCode != sshfx.StatusOK {
		return nil, status
	}
	return packet, nil
}
func (c *privateFileStream) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		n := min(len(data), 32*1024)
		packet, err := c.exchange(&sshfx.WritePacket{Handle: c.handle, Offset: c.offset, Data: data[:n]})
		if err != nil {
			return written, fmt.Errorf("write private remote file: %w", err)
		}
		if _, ok := packet.(*sshfx.StatusPacket); !ok {
			return written, errors.New("private file WRITE did not return status")
		}
		c.offset += uint64(n)
		written += n
		data = data[n:]
	}
	return written, nil
}
func (c *privateFileStream) closeHandle() error {
	packet, err := c.exchange(&sshfx.ClosePacket{Handle: c.handle})
	if err != nil {
		return fmt.Errorf("close private remote file: %w", err)
	}
	if _, ok := packet.(*sshfx.StatusPacket); !ok {
		return errors.New("private file CLOSE did not return status")
	}
	return nil
}
func (c *privateFileStream) Close() error { return c.writer.Close() }
