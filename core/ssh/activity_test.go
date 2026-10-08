package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
)

type activityTestIO struct {
	net.Conn
	n   int
	err error
}

func (c *activityTestIO) Read([]byte) (int, error)    { return c.n, c.err }
func (c *activityTestIO) Write(p []byte) (int, error) { return len(p), nil }

type activityProbeConn struct {
	monitoredTestConn
	requests atomic.Int32
	reply    chan bool
}

func (c *activityProbeConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	c.requests.Add(1)
	select {
	case ok := <-c.reply:
		return ok, nil, nil
	case <-c.closed:
		return false, nil, io.EOF
	}
}

func newActivityTestClient(t *testing.T) (*Client, *activityProbeConn, *sshActivityConn) {
	t.Helper()
	conn := &activityProbeConn{
		monitoredTestConn: monitoredTestConn{closed: make(chan struct{})},
		reply:             make(chan bool),
	}
	activity := &sshActivityConn{Conn: &activityTestIO{n: 1}, startedAt: time.Now()}
	client := &Client{sshClient: &ssh.Client{Conn: &activitySSHConn{Conn: conn, activity: activity}}}
	t.Cleanup(func() { closeTestResource(t, client) })
	return client, conn, activity
}

func runActivityTestMonitor(ctx context.Context, client *Client, mode string, interval, timeout time.Duration) <-chan error {
	done := make(chan error, 1)
	go func() {
		if mode == "wait" {
			done <- client.wait(ctx, interval, timeout)
			return
		}
		var probeErr error
		<-startKeepAlive(ctx, client.sshClient, interval, timeout, func(err error) { probeErr = err }, client.Interrupt)
		done <- probeErr
	}()
	return done
}

func recordActivityTestRead(t *testing.T, activity *sshActivityConn) {
	t.Helper()
	if n, err := activity.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("read = %d, %v, want receive progress", n, err)
	}
}

func activityTestMonitorResult(t *testing.T, done <-chan error) error {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-done:
		return err
	default:
		t.Fatal("monitor did not stop within its receive timeout or cancellation")
		return nil
	}
}

func TestKeepAliveDefersProbesWhileReceiving(t *testing.T) {
	for _, mode := range []string{"wait", "periodic"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, conn, activity := newActivityTestClient(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := runActivityTestMonitor(ctx, client, mode, DefaultKeepAliveInterval, DefaultKeepAliveTimeout)
				synctest.Wait()
				for range 12 {
					time.Sleep(5 * time.Second)
					recordActivityTestRead(t, activity)
					synctest.Wait()
				}
				if got := conn.requests.Load(); got != 0 {
					t.Fatalf("sent %d unnecessary probes during receive progress", got)
				}
				time.Sleep(DefaultKeepAliveInterval)
				synctest.Wait()
				if got := conn.requests.Load(); got != 1 {
					t.Fatalf("sent %d probes after idle interval, want 1", got)
				}
				cancel()
				if err := activityTestMonitorResult(t, done); err != nil {
					t.Fatalf("cancel idle monitor: %v", err)
				}
			})
		})
	}
}

func TestKeepAlivePendingProbeReceiveProgress(t *testing.T) {
	for _, mode := range []string{"wait", "periodic"} {
		for _, outcome := range []string{"reply", "blackhole", "cancel"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client, conn, activity := newActivityTestClient(t)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					done := runActivityTestMonitor(ctx, client, mode, DefaultKeepAliveInterval, DefaultKeepAliveTimeout)
					synctest.Wait()
					time.Sleep(DefaultKeepAliveInterval)
					synctest.Wait()
					for range 12 {
						time.Sleep(5 * time.Second)
						recordActivityTestRead(t, activity)
						synctest.Wait()
					}
					if got := conn.requests.Load(); got != 1 {
						t.Fatalf("sent %d probes while first reply pending, want 1", got)
					}
					select {
					case err := <-done:
						t.Fatalf("monitor stopped despite receive progress: %v", err)
					default:
					}
					var want error
					switch outcome {
					case "reply":
						// A late negative reply also proves liveness. Monitoring
						// must resume once the one pending request completes.
						conn.reply <- false
						synctest.Wait()
						time.Sleep(DefaultKeepAliveInterval)
						synctest.Wait()
						if got := conn.requests.Load(); got != 2 {
							t.Fatalf("sent %d probes after late reply, want 2", got)
						}
					case "blackhole":
						time.Sleep(DefaultKeepAliveTimeout)
						synctest.Wait()
						want = errKeepaliveTimeout
					}
					if outcome != "blackhole" {
						cancel()
					}
					if err := activityTestMonitorResult(t, done); !errors.Is(err, want) {
						t.Fatalf("monitor = %v, want %v", err, want)
					}
					select {
					case <-conn.closed:
					default:
						t.Fatal("pending request left transport open")
					}
				})
			})
		}
	}
}

func TestKeepAliveWritesDoNotHideBlackhole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, conn, activity := newActivityTestClient(t)
		done := runActivityTestMonitor(t.Context(), client, "wait", DefaultKeepAliveInterval, DefaultKeepAliveTimeout)
		synctest.Wait()
		for range 5 {
			time.Sleep(5 * time.Second)
			if _, err := activity.Write([]byte("buffered upload")); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		if err := activityTestMonitorResult(t, done); !errors.Is(err, errKeepaliveTimeout) {
			t.Fatalf("monitor = %v, want silent receive timeout", err)
		}
		if got := conn.requests.Load(); got != 1 {
			t.Fatalf("sent %d probes, want 1", got)
		}
	})
}

func TestSSHActivityRequiresReceivedBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		underlying := &activityTestIO{err: io.EOF}
		activity := &sshActivityConn{Conn: underlying, startedAt: time.Now()}
		time.Sleep(time.Second)
		if n, err := activity.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("empty read = %d, %v", n, err)
		}
		if idle := activity.readIdle(); idle != time.Second {
			t.Fatalf("empty read refreshed activity: idle = %v", idle)
		}
		underlying.n = 1
		if n, err := activity.Read(make([]byte, 1)); n != 1 || !errors.Is(err, io.EOF) {
			t.Fatalf("final data read = %d, %v", n, err)
		}
		if idle := activity.readIdle(); idle != 0 {
			t.Fatalf("nonempty read did not refresh activity: idle = %v", idle)
		}
	})
}
