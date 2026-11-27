package memtree_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"go.uber.org/goleak"
)

func TestBlockingTUNConn_ReadBlocksUntilWriteOrClose(t *testing.T) {
	defer goleak.VerifyNone(t)

	conn := memtree.NewBlockingTUNConn("local:tun0")
	var _ net.Conn = conn
	if conn.LocalAddr().String() != "local:tun0" || conn.RemoteAddr().String() != "local:tun0" {
		t.Fatalf("unexpected addr: local=%q remote=%q", conn.LocalAddr(), conn.RemoteAddr())
	}

	readDone := make(chan struct{})
	var got string
	var readErr error
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(context.Context) error {
			defer close(readDone)
			buf := make([]byte, 32)
			k, rErr := conn.Read(buf)
			got, readErr = string(buf[:k]), rErr
			return nil
		}); err != nil {
			return err
		}
		return n.Go(func(context.Context) error {
			if _, wErr := conn.Write([]byte("frame-1")); wErr != nil {
				return wErr
			}
			<-readDone
			return nil
		})
	})
	if err != nil {
		t.Fatalf("RunWait(write->read): %v", err)
	}
	if readErr != nil || got != "frame-1" {
		t.Fatalf("Read() = (%q, %v), want (%q, nil)", got, readErr, "frame-1")
	}
}

func TestBlockingTUNConn_CloseWakesBlockedReadAndRejectsWrite(t *testing.T) {
	defer goleak.VerifyNone(t)

	conn := memtree.NewBlockingTUNConn("local:tun1")
	readStarted := make(chan struct{})
	var readErr error
	var readN int
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(context.Context) error {
			close(readStarted)
			buf := make([]byte, 16)
			readN, readErr = conn.Read(buf)
			return nil
		}); err != nil {
			return err
		}
		return n.Go(func(context.Context) error {
			<-readStarted
			if err := conn.Close(); err != nil {
				return err
			}
			return conn.Close()
		})
	})
	if err != nil {
		t.Fatalf("RunWait(close->wake): %v", err)
	}
	if readN != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("Read() after Close = (%d, %v), want (0, io.EOF)", readN, readErr)
	}
	if _, wErr := conn.Write([]byte("late")); !errors.Is(wErr, ports.ErrClosed) {
		t.Fatalf("Write() after Close = %v, want ports.ErrClosed", wErr)
	}
}

func TestBlockingTUNConn_ZeroValueFailClosed(t *testing.T) {
	var zero memtree.BlockingTUNConn
	if n, err := zero.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("zero.Read() = (%d, %v), want (0, io.EOF)", n, err)
	}
	if n, err := zero.Write([]byte("x")); n != 0 || !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("zero.Write() = (%d, %v), want (0, ports.ErrClosed)", n, err)
	}
	if err := zero.Close(); err != nil {
		t.Fatalf("zero.Close() = %v, want nil", err)
	}
}
