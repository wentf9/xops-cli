//go:build linux

package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestRunInteractiveUsesExecWithPTY(t *testing.T) {
	testInteractiveExecRequest(t, false, "bash -l -c 'printf '\\''%s'\\'' hello'")
}

func TestRunInteractiveSudoerUsesExecWithPTY(t *testing.T) {
	testInteractiveExecRequest(t, true, "sudo -i -- bash -c 'printf '\\''%s'\\'' hello'")
}

func testInteractiveExecRequest(t *testing.T, sudo bool, wantCommand string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := master.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := slave.Close(); err != nil {
			t.Error(err)
		}
	}()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = slave, slave
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	listener, cfg := startKeepAliveTestSSHServer(t)
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	requestsSeen := make(chan string, 8)
	go func() {
		defer close(done)
		serveInteractiveExecTest(t, ctx, listener, cfg, requestsSeen)
	}()
	defer func() {
		cancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		<-done
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Log(err)
		}
	}()
	raw, channels, requests, err := cryptoSSH.NewClientConn(conn, listener.Addr().String(), &cryptoSSH.ClientConfig{User: "test", Auth: []cryptoSSH.AuthMethod{cryptoSSH.Password("test")}, HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(cryptoSSH.NewClient(raw, channels, requests), conn, &ClientConfig{SudoMode: SudoModeSudoer}, nil, "test")
	defer func() {
		if err := client.Close(); err != nil {
			t.Log(err)
		}
	}()
	run := client.RunInteractive
	if sudo {
		run = client.RunInteractiveWithSudo
	}
	if err := run(ctx, "printf '%s' hello"); err != nil {
		t.Fatal(err)
	}
	<-done
	close(requestsSeen)
	var got []string
	for request := range requestsSeen {
		got = append(got, request)
	}
	want := []string{"pty-req", "exec", wantCommand}
	if !slices.Equal(got, want) {
		t.Fatalf("SSH requests: %q, want %q", got, want)
	}
}

func serveInteractiveExecTest(t *testing.T, ctx context.Context, listener net.Listener, cfg *cryptoSSH.ServerConfig, requestsSeen chan<- string) {
	conn, err := listener.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Error(err)
		return
	}
	server, channels, requests, err := cryptoSSH.NewServerConn(conn, cfg)
	if err != nil {
		t.Error(err)
		return
	}
	stop := context.AfterFunc(ctx, func() {
		if err := server.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Log(err)
		}
	})
	defer stop()
	discardDone := make(chan struct{})
	go func() { cryptoSSH.DiscardRequests(requests); close(discardDone) }()
	defer func() {
		if err := server.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Log(err)
		}
		<-discardDone
	}()
	serveInteractiveExecChannel(t, channels, requestsSeen)
}

func serveInteractiveExecChannel(t *testing.T, channels <-chan cryptoSSH.NewChannel, requestsSeen chan<- string) {
	channelRequest := <-channels
	if channelRequest == nil {
		return
	}
	ch, reqs, err := channelRequest.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() {
		if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Log(err)
		}
	}()
	for req := range reqs {
		requestsSeen <- req.Type
		if req.Type == "exec" {
			var payload struct{ Command string }
			if err := cryptoSSH.Unmarshal(req.Payload, &payload); err != nil {
				t.Error(err)
				return
			}
			requestsSeen <- payload.Command
		}
		if err := req.Reply(req.Type == "pty-req" || req.Type == "exec", nil); err != nil {
			t.Error(err)
			return
		}
		if req.Type == "exec" {
			if _, err := io.WriteString(ch, "command-output\n"); err != nil {
				t.Error(err)
				return
			}
			if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
				t.Error(err)
			}
			return
		}
	}
}
