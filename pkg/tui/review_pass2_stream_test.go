package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestReviewPass2_M10_TUIStreamsOmitAgentForwardAndSessionEnv verifies that both
// MetricsCollector.Start and logStreamerModel.startStream invoke RunProbeStream
// so neither ssh-agent forwarding nor user SetEnv/SendEnv leaks into TUI loops.
func TestReviewPass2_M10_TUIStreamsOmitAgentForwardAndSessionEnv(t *testing.T) {
	var (
		mu        sync.Mutex
		seenAgent int
		seenEnvs  []string
		seenExecs []string
	)

	rawCli, cleanup := startTUIPass2TestSSHServer(t, func(req *cryptoSSH.Request, ch cryptoSSH.Channel) {
		switch req.Type {
		case "auth-agent-req@openssh.com":
			mu.Lock()
			seenAgent++
			mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env":
			var kv struct {
				Name  string
				Value string
			}
			if cryptoSSH.Unmarshal(req.Payload, &kv) == nil {
				mu.Lock()
				seenEnvs = append(seenEnvs, kv.Name+"="+kv.Value)
				mu.Unlock()
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var cmd struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &cmd)
			mu.Lock()
			seenExecs = append(seenExecs, cmd.Command)
			mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() {
				if strings.Contains(cmd.Command, "uname -s") {
					_, _ = ch.Write([]byte("Linux\n"))
				} else if strings.Contains(cmd.Command, "tail -n 100 -f") {
					_, _ = ch.Write([]byte("log-entry-1\n"))
				} else {
					_, _ = ch.Write([]byte("{\"type\":\"sys\",\"uptime\":42}\n{\"type\":\"eof\"}\n"))
				}
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				_ = ch.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	})
	defer cleanup()

	client := ssh.NewTestClientWithRaw(rawCli, ssh.ConnectionConfig{
		Address: "tui-target.example",
		Options: ssh.MustOptions(
			ssh.OptionForwardAgent, "/tmp/should-not-forward.sock",
			ssh.OptionSetEnv, "SECRET_TOKEN=do-not-leak",
		),
	})

	// 1. MetricsCollector.Start + NextFrame
	mc := NewMetricsCollector(client)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := mc.Start(ctx); err != nil {
		t.Fatalf("MetricsCollector.Start: %v", err)
	}
	metrics, err := mc.NextFrame(ctx)
	if err != nil || metrics.Uptime != "00:00" {
		t.Fatalf("MetricsCollector.NextFrame = (%+v, %v), want uptime 00:00", metrics, err)
	}
	if err := mc.Close(); err != nil {
		t.Fatalf("MetricsCollector.Close: %v", err)
	}

	// 2. logStreamerModel.startStream
	logCtx, logCancel := context.WithCancel(t.Context())
	defer logCancel()
	lm := logStreamerModel{
		client:    client,
		file:      "/var/log/app.log",
		ctx:       logCtx,
		cancel:    logCancel,
		lineChan:  make(chan string, 8),
		sessionID: 1,
	}
	msg := lm.startStream()()
	sessMsg, ok := msg.(logStreamSessionMsg)
	if !ok {
		t.Fatalf("logStreamerModel.startStream returned %T (%v), want logStreamSessionMsg", msg, msg)
	}
	_ = sessMsg.reader.Close()

	mu.Lock()
	defer mu.Unlock()
	if seenAgent != 0 || len(seenEnvs) != 0 {
		t.Fatalf("TUI streams leaked agent=%d envs=%v, want 0 and empty", seenAgent, seenEnvs)
	}
	if len(seenExecs) != 3 {
		t.Fatalf("expected 3 exec requests (uname, probe.sh, tail), got %d: %v", len(seenExecs), seenExecs)
	}
}

func startTUIPass2TestSSHServer(
	t *testing.T,
	onReq func(req *cryptoSSH.Request, ch cryptoSSH.Channel),
) (*cryptoSSH.Client, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	srvCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sConn, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		sshSrv, chans, reqs, sErr := cryptoSSH.NewServerConn(sConn, srvCfg)
		if sErr != nil {
			_ = sConn.Close()
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		for newCh := range chans {
			ch, chReqs, chErr := newCh.Accept()
			if chErr != nil {
				continue
			}
			go func(c cryptoSSH.Channel, rCh <-chan *cryptoSSH.Request) {
				for req := range rCh {
					onReq(req, c)
				}
			}(ch, chReqs)
		}
		_ = sshSrv.Close()
	}()

	cConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("net.DialTimeout: %v", err)
	}
	cliConn, chans, reqs, err := cryptoSSH.NewClientConn(cConn, ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = cConn.Close()
		_ = ln.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	rawCli := cryptoSSH.NewClient(cliConn, chans, reqs)
	return rawCli, func() {
		_ = rawCli.Close()
		_ = cConn.Close()
		_ = ln.Close()
		wg.Wait()
	}
}
