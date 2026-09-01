package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	projectssh "github.com/wentf9/xops-cli/pkg/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

type subsystemTestStore struct {
	config *projectssh.ClientConfig
}

func (s subsystemTestStore) GetConfig(string) (*projectssh.ClientConfig, error) {
	return s.config, nil
}

func (subsystemTestStore) UpdateAuth(context.Context, string, string, string, string, string) error {
	return nil
}

func (subsystemTestStore) UpdateSudo(context.Context, string, string, projectssh.SudoMode, string) error {
	return nil
}

type subsystemTestInteraction struct{}

func (subsystemTestInteraction) PromptPassword(string) (string, error) {
	return "test-password", nil
}

func (subsystemTestInteraction) ConfirmHostKey(string, string) (bool, error) {
	return true, nil
}

func TestClient_InterruptClosesOnlyOwnSFTPSubsystem(t *testing.T) {
	address := startSubsystemTestSSHServer(t, false)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split test SSH address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test SSH port: %v", err)
	}
	t.Setenv("HOME", t.TempDir())

	connector := projectssh.NewConnector(
		subsystemTestStore{config: &projectssh.ClientConfig{
			NodeID:   "node-1",
			Address:  host,
			Port:     port,
			User:     "test-user",
			AuthType: "password",
			Password: "test-password",
			SudoMode: projectssh.SudoModeNone,
		}},
		subsystemTestInteraction{},
	)
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
		if false {
			t.Errorf("close test SSH connector: %v", err)
		}
	})

	connectCtx, cancelConnect := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelConnect()
	firstSSHClient, err := connector.Connect(connectCtx, "node-1")
	if err != nil {
		t.Fatalf("connect first SSH client: %v", err)
	}
	secondSSHClient, err := connector.Connect(connectCtx, "node-1")
	if err != nil {
		t.Fatalf("connect second SSH client: %v", err)
	}
	if firstSSHClient.SSHClient() != secondSSHClient.SSHClient() {
		t.Fatal("test setup did not reuse the underlying SSH transport")
	}

	firstSFTPClient, err := NewClient(connectCtx, firstSSHClient)
	if err != nil {
		t.Fatalf("create first SFTP client: %v", err)
	}
	t.Cleanup(func() {
		if err := firstSFTPClient.Close(); err != nil {
			t.Errorf("close first SFTP client: %v", err)
		}
	})
	secondSFTPClient, err := NewClient(connectCtx, secondSSHClient)
	if err != nil {
		t.Fatalf("create second SFTP client: %v", err)
	}
	t.Cleanup(func() {
		if err := secondSFTPClient.Close(); err != nil {
			t.Errorf("close second SFTP client: %v", err)
		}
	})

	if err := firstSFTPClient.interruptTransfers(); err != nil {
		t.Fatalf("interrupt first SFTP subsystem: %v", err)
	}
	if _, err := firstSFTPClient.Cwd(t.Context()); err == nil {
		t.Fatal("interrupted SFTP client remained usable")
	}
	if _, err := secondSFTPClient.Cwd(t.Context()); err != nil {
		t.Fatalf("sibling SFTP subsystem stopped after first subsystem interruption: %v", err)
	}
	if _, _, err := secondSSHClient.SSHClient().SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("shared SSH transport stopped after SFTP subsystem interruption: %v", err)
	}
}

func TestNewClient_CanceledSubsystemSetupKeepsSSHTransportOpen(t *testing.T) {
	address := startSubsystemTestSSHServer(t, true)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split test SSH address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test SSH port: %v", err)
	}
	t.Setenv("HOME", t.TempDir())

	connector := projectssh.NewConnector(
		subsystemTestStore{config: &projectssh.ClientConfig{
			NodeID:   "node-1",
			Address:  host,
			Port:     port,
			User:     "test-user",
			AuthType: "password",
			Password: "test-password",
			SudoMode: projectssh.SudoModeNone,
		}},
		subsystemTestInteraction{},
	)
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
		if false {
			t.Errorf("close test SSH connector: %v", err)
		}
	})

	connectCtx, cancelConnect := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelConnect()
	sshClient, err := connector.Connect(connectCtx, "node-1")
	if err != nil {
		t.Fatalf("connect SSH client: %v", err)
	}
	setupCtx, cancelSetup := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelSetup()
	client, err := NewClient(setupCtx, sshClient)
	if client != nil {
		t.Fatal("NewClient returned a client after canceled setup")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("NewClient error = %v, want context deadline exceeded", err)
	}
	if _, _, err := sshClient.SSHClient().SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("SSH transport stopped after canceled SFTP setup: %v", err)
	}
}

func startSubsystemTestSSHServer(t *testing.T, stallSubsystem bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for test SSH server: %v", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test SSH host key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create test SSH signer: %v", err)
	}
	serverConfig := &cryptossh.ServerConfig{
		PasswordCallback: func(_ cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			if string(password) != "test-password" {
				return nil, errors.New("invalid test password")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveSubsystemTestSSHConnection(listener, serverConfig, stallSubsystem)
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close test SSH listener: %v", err)
		}
		select {
		case serveErr := <-serverDone:
			if serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, net.ErrClosed) {
				t.Errorf("serve test SSH connection: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("test SSH server did not exit")
		}
	})
	return listener.Addr().String()
}

func serveSubsystemTestSSHConnection(listener net.Listener, config *cryptossh.ServerConfig, stallSubsystem bool) (retErr error) {
	connection, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept test SSH connection failed: %w", err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close test SSH network connection failed: %w", closeErr))
		}
	}()

	serverConnection, channels, requests, err := cryptossh.NewServerConn(connection, config)
	if err != nil {
		return fmt.Errorf("handshake test SSH connection failed: %w", err)
	}
	defer func() {
		if closeErr := serverConnection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close test SSH server connection failed: %w", closeErr))
		}
	}()

	var workers sync.WaitGroup
	workerErrors := make(chan error, 32)
	workers.Go(func() {
		for request := range requests {
			if err := request.Reply(true, nil); err != nil {
				workerErrors <- fmt.Errorf("reply to test SSH global request failed: %w", err)
				return
			}
		}
	})
	for newChannel := range channels {
		workers.Go(func() {
			if err := serveSubsystemTestChannel(newChannel, stallSubsystem); err != nil {
				workerErrors <- err
			}
		})
	}
	workers.Wait()
	close(workerErrors)
	var joinedErr error
	for workerErr := range workerErrors {
		joinedErr = errors.Join(joinedErr, workerErr)
	}
	return errors.Join(retErr, joinedErr)
}

func serveSubsystemTestChannel(newChannel cryptossh.NewChannel, stallSubsystem bool) (retErr error) {
	if newChannel.ChannelType() != "session" {
		if err := newChannel.Reject(cryptossh.UnknownChannelType, "unsupported channel type"); err != nil {
			return fmt.Errorf("reject test SSH channel failed: %w", err)
		}
		return nil
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return fmt.Errorf("accept test SSH session channel failed: %w", err)
	}
	defer func() {
		if closeErr := channel.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
			retErr = errors.Join(retErr, fmt.Errorf("close test SSH session channel failed: %w", closeErr))
		}
	}()

	for request := range requests {
		accepted := request.Type == "subsystem"
		if accepted {
			var payload struct {
				Name string
			}
			if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				accepted = false
			}
		}
		if accepted && stallSubsystem {
			_, copyErr := io.Copy(io.Discard, channel)
			if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) {
				return fmt.Errorf("wait for canceled test SFTP subsystem failed: %w", copyErr)
			}
			return retErr
		}
		if err := request.Reply(accepted, nil); err != nil {
			return fmt.Errorf("reply to test SSH session request failed: %w", err)
		}
		if !accepted {
			continue
		}

		server := pkgsftp.NewRequestServer(channel, pkgsftp.InMemHandler())
		serveErr := server.Serve()
		if serveErr != nil && !errors.Is(serveErr, io.EOF) {
			return fmt.Errorf("serve test SFTP subsystem failed: %w", serveErr)
		}
		return retErr
	}
	return retErr
}
