package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func startMockDirectTCPIPServer(t *testing.T, onChannel func(newChan cryptoSSH.NewChannel)) (net.Listener, *Client, func()) {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	serverWg := &sync.WaitGroup{}
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serverWg.Add(1)
			go func(c net.Conn) {
				defer serverWg.Done()
				sConn, chans, reqs, sErr := cryptoSSH.NewServerConn(c, serverConfig)
				if sErr != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for newChan := range chans {
					if onChannel != nil {
						onChannel(newChan)
					} else {
						_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unhandled")
					}
				}
			}(conn)
		}
	}()

	rawClient := dialKeepAliveTestClient(t, listener.Addr().String())
	teardown := func() {
		_ = rawClient.Close()
		_ = listener.Close()
		serverWg.Wait()
	}

	client := &Client{
		sshClient: rawClient,
	}
	return listener, client, teardown
}

func TestForwardStdio_BidirectionalAndHalfClose(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var (
		destAddrReceived string
		destPortReceived uint32
		serverReceived   bytes.Buffer
	)
	serverDone := make(chan struct{})

	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
			return
		}
		var msg directTCPIPOpenMsg
		if err := cryptoSSH.Unmarshal(newChan.ExtraData(), &msg); err != nil {
			_ = newChan.Reject(cryptoSSH.ConnectionFailed, "bad payload")
			return
		}
		destAddrReceived = msg.DestAddr
		destPortReceived = msg.DestPort

		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)

		go func() {
			defer close(serverDone)
			defer func() { _ = ch.Close() }()

			// 1. Read until client half-closes (EOF on client stdin triggers CloseWrite)
			buf := make([]byte, 1024)
			for {
				n, rErr := ch.Read(buf)
				if n > 0 {
					serverReceived.Write(buf[:n])
				}
				if rErr != nil {
					if !errors.Is(rErr, io.EOF) {
						t.Errorf("server read error: %v", rErr)
					}
					break
				}
			}

			// 2. Write tail response to client
			tailResponse := []byte("SERVER TAIL RESPONSE\n")
			if _, wErr := ch.Write(tailResponse); wErr != nil {
				t.Errorf("server write error: %v", wErr)
			}
		}()
	})
	defer teardown()

	clientInput := "hello from client stdin\n"
	stdinReader := strings.NewReader(clientInput)
	var stdoutBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.ForwardStdio(ctx, "target.example.internal", 8080, stdinReader, &stdoutBuf)
	if err != nil {
		t.Fatalf("ForwardStdio failed: %v", err)
	}

	<-serverDone

	if destAddrReceived != "target.example.internal" {
		t.Errorf("destAddr = %q, want %q", destAddrReceived, "target.example.internal")
	}
	if destPortReceived != 8080 {
		t.Errorf("destPort = %d, want 8080", destPortReceived)
	}
	if got := serverReceived.String(); got != clientInput {
		t.Errorf("server received = %q, want %q", got, clientInput)
	}
	if got := stdoutBuf.String(); got != "SERVER TAIL RESPONSE\n" {
		t.Errorf("client stdout = %q, want %q", got, "SERVER TAIL RESPONSE\n")
	}
}

func TestForwardStdio_RemoteProhibited(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		_ = newChan.Reject(cryptoSSH.Prohibited, "administratively prohibited by policy")
	})
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdoutBuf bytes.Buffer
	err := client.ForwardStdio(ctx, "forbidden.host", 2222, strings.NewReader("data"), &stdoutBuf)
	if err == nil {
		t.Fatal("ForwardStdio() error = nil, want rejection error")
	}

	var openChanErr *cryptoSSH.OpenChannelError
	if !errors.As(err, &openChanErr) {
		t.Fatalf("expected OpenChannelError, got: %v", err)
	}
	if openChanErr.Reason != cryptoSSH.Prohibited {
		t.Errorf("openChanErr.Reason = %v, want %v", openChanErr.Reason, cryptoSSH.Prohibited)
	}
}

func TestForwardStdio_ContextCancel_DoesNotCloseCallerFiles(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelOpened := make(chan struct{})
	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		close(channelOpened)
		// Server holds connection open without writing or closing
		buf := make([]byte, 1024)
		for {
			if _, rErr := ch.Read(buf); rErr != nil {
				break
			}
		}
		_ = ch.Close()
	})
	defer teardown()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	}()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer func() {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.ForwardStdio(ctx, "target.slow", 9000, stdinR, stdoutW)
	}()

	select {
	case <-channelOpened:
	case <-time.After(3 * time.Second):
		t.Fatal("channel was not opened")
	}

	// Cancel context to interrupt
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ForwardStdio did not return after context cancellation")
	}

	// Verify caller's *os.File handles are NOT closed by ForwardStdio
	testByte := []byte("a")
	if _, wErr := stdinW.Write(testByte); wErr != nil {
		t.Errorf("stdinW was closed or corrupted: %v", wErr)
	}
	readBuf := make([]byte, 1)
	if _, rErr := stdinR.Read(readBuf); rErr != nil || readBuf[0] != 'a' {
		t.Errorf("stdinR was closed or corrupted: %v (read: %v)", rErr, readBuf)
	}

	if _, wErr := stdoutW.Write(testByte); wErr != nil {
		t.Errorf("stdoutW was closed or corrupted: %v", wErr)
	}
	if _, rErr := stdoutR.Read(readBuf); rErr != nil || readBuf[0] != 'a' {
		t.Errorf("stdoutR was closed or corrupted: %v (read: %v)", rErr, readBuf)
	}
}

func TestForwardStdio_NilStdin(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		go func() {
			defer func() { _ = ch.Close() }()
			_, _ = ch.Write([]byte("SERVER BANNER ONLY\n"))
		}()
	})
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdoutBuf bytes.Buffer
	err := client.ForwardStdio(ctx, "banner.host", 22, nil, &stdoutBuf)
	if err != nil {
		t.Fatalf("ForwardStdio with nil stdin failed: %v", err)
	}
	if got := stdoutBuf.String(); got != "SERVER BANNER ONLY\n" {
		t.Errorf("got %q, want %q", got, "SERVER BANNER ONLY\n")
	}
}

func TestForwardStdio_ParameterValidation(t *testing.T) {
	client := &Client{} // disconnected

	//nolint:staticcheck // SA1012: intentionally verifying defensive nil context rejection
	if err := client.ForwardStdio(nil, "host", 80, nil, &bytes.Buffer{}); err == nil {
		t.Error("expected error for nil context")
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.ForwardStdio(canceledCtx, "host", 80, nil, &bytes.Buffer{}); err == nil {
		t.Error("expected error for canceled context")
	}

	if err := client.ForwardStdio(context.Background(), "host", 80, nil, &bytes.Buffer{}); err == nil {
		t.Error("expected error for disconnected client")
	}

	client.sshClient = &cryptoSSH.Client{}
	if err := client.ForwardStdio(context.Background(), "", 80, nil, &bytes.Buffer{}); err == nil {
		t.Error("expected error for empty destHost")
	}
	if err := client.ForwardStdio(context.Background(), "host", 0, nil, &bytes.Buffer{}); err == nil {
		t.Error("expected error for destPort 0")
	}
	if err := client.ForwardStdio(context.Background(), "host", 80, nil, nil); err == nil {
		t.Error("expected error for nil stdout")
	}
}

func mustCreatePipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	return r, w
}

func handleMockHalfCloseChannel(newChan cryptoSSH.NewChannel, greeting string, serverReceived chan<- string, serverErr chan<- error) {
	if newChan.ChannelType() != "direct-tcpip" {
		_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
		return
	}
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	go cryptoSSH.DiscardRequests(reqs)

	go func() {
		defer func() { _ = ch.Close() }()

		if _, wErr := ch.Write([]byte(greeting)); wErr != nil {
			serverErr <- fmt.Errorf("server write greeting: %w", wErr)
			return
		}
		if cwErr := ch.CloseWrite(); cwErr != nil {
			serverErr <- fmt.Errorf("server close write: %w", cwErr)
			return
		}

		var buf bytes.Buffer
		if _, rErr := io.Copy(&buf, ch); rErr != nil && !errors.Is(rErr, io.EOF) {
			serverErr <- fmt.Errorf("server read upload: %w", rErr)
			return
		}
		serverReceived <- buf.String()
	}()
}

func TestForwardStdio_RemoteHalfCloseAllowsRemainingStdin(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const (
		serverGreeting = "SERVER READY\n"
		clientPayload  = "CLIENT UPLOAD AFTER REMOTE EOF\n"
	)

	serverReceived := make(chan string, 1)
	serverErr := make(chan error, 1)

	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		handleMockHalfCloseChannel(newChan, serverGreeting, serverReceived, serverErr)
	})
	defer teardown()

	stdinR, stdinW := mustCreatePipe(t)
	defer func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	}()

	stdoutR, stdoutW := mustCreatePipe(t)
	defer func() {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- client.ForwardStdio(ctx, "target.halfclose", 9999, stdinR, stdoutW)
	}()

	greetingBuf := make([]byte, len(serverGreeting))
	if _, rErr := io.ReadFull(stdoutR, greetingBuf); rErr != nil {
		t.Fatalf("read server greeting: %v", rErr)
	}
	if string(greetingBuf) != serverGreeting {
		t.Fatalf("got greeting %q, want %q", string(greetingBuf), serverGreeting)
	}

	time.Sleep(20 * time.Millisecond)

	if _, wErr := stdinW.Write([]byte(clientPayload)); wErr != nil {
		t.Fatalf("write client payload: %v", wErr)
	}
	if cErr := stdinW.Close(); cErr != nil {
		t.Fatalf("close stdinW: %v", cErr)
	}

	select {
	case err := <-forwardDone:
		if err != nil {
			t.Fatalf("ForwardStdio failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ForwardStdio timed out")
	}

	select {
	case err := <-serverErr:
		t.Fatalf("server error: %v", err)
	case got := <-serverReceived:
		if got != clientPayload {
			t.Fatalf("server received %q, want %q", got, clientPayload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server verification timed out")
	}
}

func TestForwardStdio_RemoteFullCloseExitsWithIdleStdinPipe(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const goodbyeMsg = "SERVER GOODBYE\n"

	_, client, teardown := startMockDirectTCPIPServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)

		go func() {
			defer func() { _ = ch.Close() }()
			_, _ = ch.Write([]byte(goodbyeMsg))
		}()
	})
	defer teardown()

	stdinR, stdinW := mustCreatePipe(t)
	defer func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	}()

	var stdoutBuf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- client.ForwardStdio(ctx, "target.fullclose", 9999, stdinR, &stdoutBuf)
	}()

	select {
	case err := <-forwardDone:
		if err != nil {
			t.Fatalf("ForwardStdio failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ForwardStdio timed out waiting for remote close on idle stdin")
	}

	if got := stdoutBuf.String(); got != goodbyeMsg {
		t.Fatalf("stdout = %q, want %q", got, goodbyeMsg)
	}

	testByte := []byte("x")
	if _, wErr := stdinW.Write(testByte); wErr != nil {
		t.Errorf("stdinW was closed or corrupted by ForwardStdio: %v", wErr)
	}
	readBuf := make([]byte, 1)
	if _, rErr := stdinR.Read(readBuf); rErr != nil || readBuf[0] != 'x' {
		t.Errorf("stdinR was closed or corrupted by ForwardStdio: %v", rErr)
	}
}
