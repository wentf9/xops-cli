package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func closeTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	err := closer.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("close test resource failed: %v", err)
	}
}

func atoi(t *testing.T, value string) int {
	t.Helper()
	n, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("parse integer %q failed: %v", value, err)
	}
	return n
}

//nolint:gocyclo
func TestProxyJump_Integration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var wg sync.WaitGroup

	// 启动目标节点 (Target)
	targetListener, targetConfig := startKeepAliveTestSSHServer(t)
	t.Cleanup(func() {
		closeTestResource(t, targetListener)
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				sConn, chans, reqs, err := ssh.NewServerConn(c, targetConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()

				wg.Add(1)
				go func() {
					defer wg.Done()
					ssh.DiscardRequests(reqs)
				}()

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, chReqs, chErr := newChannel.Accept()
					if chErr != nil {
						continue
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						ssh.DiscardRequests(chReqs)
					}()
					_ = channel.Close()
				}
			}(conn)
		}
	}()

	// 启动跳板机节点 (Jump)
	jumpListener, jumpConfig := startKeepAliveTestSSHServer(t)
	t.Cleanup(func() {
		closeTestResource(t, jumpListener)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := jumpListener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				sConn, chans, reqs, err := ssh.NewServerConn(c, jumpConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()

				wg.Add(1)
				go func() {
					defer wg.Done()
					ssh.DiscardRequests(reqs)
				}()

				for newChannel := range chans {
					if newChannel.ChannelType() == "direct-tcpip" {
						channel, reqs, acceptErr := newChannel.Accept()
						if acceptErr != nil {
							continue
						}
						wg.Add(1)
						go func() {
							defer wg.Done()
							ssh.DiscardRequests(reqs)
						}()

						targetConn, dialErr := net.Dial("tcp", targetListener.Addr().String())
						if dialErr != nil {
							_ = channel.Close()
							continue
						}

						wg.Add(1)
						go func() {
							defer wg.Done()
							closeBoth := sync.OnceFunc(func() {
								_ = channel.Close()
								_ = targetConn.Close()
							})
							defer closeBoth()

							var copyWg sync.WaitGroup
							copyWg.Add(2)
							go func() {
								defer copyWg.Done()
								_, _ = io.Copy(targetConn, channel)
								closeBoth()
							}()
							go func() {
								defer copyWg.Done()
								_, _ = io.Copy(channel, targetConn)
								closeBoth()
							}()
							copyWg.Wait()
						}()

					} else {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
					}
				}
			}(conn)
		}
	}()

	targetHost, targetPort, err := net.SplitHostPort(targetListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort target failed: %v", err)
	}
	jumpHost, jumpPort, err := net.SplitHostPort(jumpListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort jump failed: %v", err)
	}

	store := &mockProxyJumpStore{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID:    "target",
				Address:   targetHost,
				Port:      atoi(t, targetPort),
				User:      "test",
				AuthType:  "password",
				Password:  "password",
				ProxyJump: "jump",
			},
			"jump": {
				NodeID:   "jump",
				Address:  jumpHost,
				Port:     atoi(t, jumpPort),
				User:     "test",
				AuthType: "password",
				Password: "password",
			},
		},
	}

	connector := NewConnector(store, WithInteractionHandler(&mockUI{}))
	t.Cleanup(func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("close connector failed: %v", closeErr)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if client.cfg.NodeID != "target" {
		t.Errorf("expected target client, got %s", client.cfg.NodeID)
	}
}

func TestProxyJump_HandshakeTimeout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var wg sync.WaitGroup
	proxyListener, proxyConfig := startKeepAliveTestSSHServer(t)
	t.Cleanup(func() {
		closeTestResource(t, proxyListener)
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				sConn, chans, reqs, err := ssh.NewServerConn(c, proxyConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()

				wg.Add(1)
				go func() {
					defer wg.Done()
					ssh.DiscardRequests(reqs)
				}()

				for newChannel := range chans {
					if newChannel.ChannelType() != "direct-tcpip" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					channel, chReqs, chErr := newChannel.Accept()
					if chErr != nil {
						continue
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						ssh.DiscardRequests(chReqs)
					}()

					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() { _ = channel.Close() }()
						buf := make([]byte, 1024)
						for {
							if _, rErr := channel.Read(buf); rErr != nil {
								return
							}
						}
					}()
				}
			}(conn)
		}
	}()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort proxy failed: %v", err)
	}

	store := &mockProxyJumpStore{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID:    "target",
				Address:   "1.2.3.4",
				Port:      22,
				User:      "test",
				AuthType:  "password",
				Password:  "password",
				ProxyJump: "jump",
			},
			"jump": {
				NodeID:   "jump",
				Address:  proxyHost,
				Port:     atoi(t, proxyPort),
				User:     "test",
				AuthType: "password",
				Password: "password",
			},
		},
	}
	connector := NewConnector(store, WithInteractionHandler(&mockUI{}))
	t.Cleanup(func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("close connector failed: %v", closeErr)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = connector.Connect(ctx, "target")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}
