package tui

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP1BuildLogStreamCommand_QuotingAndValidation(t *testing.T) {
	validCases := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "plain file",
			target: "/var/log/syslog",
			want:   "tail -n 100 -f -- '/var/log/syslog'",
		},
		{
			name:   "shell command substitution neutralized",
			target: "/var/log/x$(id).log",
			want:   "tail -n 100 -f -- '/var/log/x$(id).log'",
		},
		{
			name:   "spaces backticks semicolons and single quote",
			target: "/var/log/my 'app'; `uname` && id.log",
			want:   `tail -n 100 -f -- '/var/log/my '"'"'app'"'"'; ` + "`uname`" + ` && id.log'`,
		},
		{
			name:   "leading dash neutralized by double dash",
			target: "-f /etc/shadow",
			want:   "tail -n 100 -f -- '-f /etc/shadow'",
		},
		{
			name:   "valid docker container",
			target: "docker:web_app-1.2",
			want:   "docker logs --tail 100 -f -- 'web_app-1.2'",
		},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildLogStreamCommand(tc.target)
			if err != nil {
				t.Fatalf("buildLogStreamCommand(%q) unexpected error: %v", tc.target, err)
			}
			if got != tc.want {
				t.Errorf("buildLogStreamCommand(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}

	invalidCases := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"nul byte", "/var/log/a\x00b.log"},
		{"newline", "/var/log/a\nid"},
		{"carriage return", "/var/log/a\rid"},
		{"tab control char", "/var/log/a\tb.log"},
		{"escape control char", "/var/log/a\x1bb.log"},
		{"del control char", "/var/log/a\x7fb.log"},
		{"docker empty container", "docker:"},
		{"docker leading dash", "docker:-f"},
		{"docker leading dot", "docker:.hidden"},
		{"docker semicolon injection", "docker:web;id"},
		{"docker subshell injection", "docker:web$(id)"},
		{"docker space", "docker:web app"},
		{"docker slash", "docker:../web"},
		{"docker control char", "docker:web\nid"},
	}

	for _, tc := range invalidCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if cmd, err := buildLogStreamCommand(tc.target); err == nil {
				t.Fatalf("buildLogStreamCommand(%q) succeeded with %q, want error", tc.target, cmd)
			}
		})
	}
}

func TestP1LogStreamerStartStream_EndToEndCommandQuotingAndRejection(t *testing.T) {
	var (
		mu        sync.Mutex
		seenExecs []string
	)

	rawCli, cleanup := startTUIPass2TestSSHServer(t, func(req *cryptoSSH.Request, ch cryptoSSH.Channel) {
		if req.Type == "exec" {
			var cmd struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &cmd)
			mu.Lock()
			seenExecs = append(seenExecs, cmd.Command)
			mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() {
				_, _ = ch.Write([]byte("ok\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				_ = ch.Close()
			}()
			return
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	})
	defer cleanup()

	client := ssh.NewTestClientWithRaw(rawCli, ssh.ConnectionConfig{Address: "tui-sec.example"})

	// 1. Malicious filename must be single-quoted with -- separator.
	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	lm1 := logStreamerModel{
		client:    client,
		file:      "/var/log/x$(id) 'quoted'.log",
		ctx:       ctx1,
		cancel:    cancel1,
		lineChan:  make(chan string, 4),
		sessionID: 1,
	}
	msg1 := lm1.startStream()()
	sess1, ok := msg1.(logStreamSessionMsg)
	if !ok {
		t.Fatalf("expected logStreamSessionMsg, got %T (%v)", msg1, msg1)
	}
	_ = sess1.reader.Close()

	// 2. Invalid docker container name must fail locally without sending any SSH exec.
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	lm2 := logStreamerModel{
		client:    client,
		file:      "docker:web;whoami",
		ctx:       ctx2,
		cancel:    cancel2,
		lineChan:  make(chan string, 4),
		sessionID: 2,
	}
	msg2 := lm2.startStream()()
	closedMsg, ok := msg2.(logStreamClosedMsg)
	if !ok || closedMsg.err == nil {
		t.Fatalf("expected error logStreamClosedMsg for bad docker container, got %T (%+v)", msg2, msg2)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenExecs) != 1 {
		t.Fatalf("expected exactly 1 SSH exec (rejected docker target must not execute), got %d: %v", len(seenExecs), seenExecs)
	}
	wantInner := `tail -n 100 -f -- '/var/log/x$(id) '"'"'quoted'"'"'.log'`
	wantWrapped := "bash -c '" + strings.ReplaceAll(wantInner, "'", `'\''`) + "'"
	if seenExecs[0] != wantWrapped {
		t.Fatalf("SSH exec command = %q, want %q", seenExecs[0], wantWrapped)
	}
}

func TestP1RejectsInterpreterPwshAcrossLogAndMonitor(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterPwsh,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	client := ssh.NewTestClient(connCfg)

	t.Run("log_select", func(t *testing.T) {
		m := newLogSelectModel(context.Background(), "node-pwsh", client, tea.WindowSizeMsg{Width: 80, Height: 24})
		msg := m.scanLogs()()
		res, ok := msg.(logScanResultMsg)
		if !ok || res.err == nil || !strings.Contains(res.err.Error(), "Linux/POSIX") {
			t.Fatalf("logSelectModel.scanLogs() = (%T, %+v), want Linux/POSIX error", msg, msg)
		}
	})

	t.Run("log_stream", func(t *testing.T) {
		m := newLogStreamerModel(context.Background(), 1, client, "/var/log/syslog", tea.WindowSizeMsg{Width: 80, Height: 24})
		msg := m.startStream()()
		res, ok := msg.(logStreamClosedMsg)
		if !ok || res.err == nil || !strings.Contains(res.err.Error(), "Linux/POSIX") {
			t.Fatalf("logStreamerModel.startStream() = (%T, %+v), want Linux/POSIX error", msg, msg)
		}
	})

	t.Run("monitor_collector", func(t *testing.T) {
		mc := NewMetricsCollector(client)
		err := mc.Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "Linux/POSIX") {
			t.Fatalf("MetricsCollector.Start() error = %v, want Linux/POSIX error", err)
		}
	})
}

func TestP1MetricsCollector_UnderflowGuards(t *testing.T) {
	t.Run("iowait_jitter_idle_decreases", func(t *testing.T) {
		mc := &MetricsCollector{
			lastTicks: &CPUTicks{User: 100, Sys: 50, Idle: 800, Iowait: 100}, // Total=1050, Idle=900
		}
		metrics := &SystemMetrics{}
		// Total increases (+50), but Iowait jitter causes IdleTicks to decrease (895 < 900).
		curr := &CPUTicks{User: 150, Sys: 55, Idle: 800, Iowait: 95} // Total=1100, Idle=895
		mc.processCPU(curr, metrics)
		if math.IsNaN(metrics.CPUUsage) || math.IsInf(metrics.CPUUsage, 0) || metrics.CPUUsage < 0 || metrics.CPUUsage > 100 {
			t.Fatalf("processCPU with iowait jitter produced out-of-range CPUUsage = %v", metrics.CPUUsage)
		}
		if metrics.CPUUsage != 100.0 {
			t.Errorf("processCPU with idleDelta clamped to 0 = %v, want 100.0", metrics.CPUUsage)
		}
	})

	t.Run("total_ticks_decrease", func(t *testing.T) {
		mc := &MetricsCollector{
			lastTicks: &CPUTicks{User: 500, Idle: 500}, // Total=1000
		}
		metrics := &SystemMetrics{}
		curr := &CPUTicks{User: 100, Idle: 100} // Total=200 < 1000
		mc.processCPU(curr, metrics)
		if metrics.CPUUsage != 0 {
			t.Fatalf("processCPU with decreasing total ticks = %v, want 0", metrics.CPUUsage)
		}
	})

	t.Run("idle_delta_exceeds_total_delta", func(t *testing.T) {
		mc := &MetricsCollector{
			lastTicks: &CPUTicks{User: 100, Idle: 800}, // Total=900, Idle=800
		}
		metrics := &SystemMetrics{}
		// User dropped (counter jitter) while Idle rose more than Total rose.
		curr := &CPUTicks{User: 90, Idle: 820} // Total=910 (+10), Idle=820 (+20)
		mc.processCPU(curr, metrics)
		if metrics.CPUUsage != 0 {
			t.Fatalf("processCPU with idleDelta > totalDelta = %v, want 0", metrics.CPUUsage)
		}
	})

	t.Run("processEOF_pid_reuse_and_total_underflow", func(t *testing.T) {
		mc := &MetricsCollector{
			coresCount: 4,
			lastTicks:  &CPUTicks{User: 1000, Idle: 1000}, // Total=2000
			lastProcs: map[int]procTick{
				42: {Utime: 5000, Stime: 1000, Name: "old-proc", State: "S", RssKB: 2048},
			},
		}
		metrics := &SystemMetrics{}
		currTicks := &CPUTicks{User: 1100, Idle: 1100} // Total=2200 (+200)
		currProcs := map[int]procTick{
			// PID 42 reused by a new process with far fewer ticks (10 < 6000).
			42: {Utime: 6, Stime: 4, Name: "new-proc", State: "R", RssKB: 1024},
		}
		mc.processEOF(metrics, currProcs, currTicks)
		if len(metrics.TopProcesses) != 1 {
			t.Fatalf("expected 1 process entry, got %d", len(metrics.TopProcesses))
		}
		if !strings.Contains(metrics.TopProcesses[0], "  0.0%") {
			t.Fatalf("PID reuse underflowed CPU percentage: %q", metrics.TopProcesses[0])
		}

		// Also verify totalTicks underflow in processEOF does not wrap around.
		metrics2 := &SystemMetrics{}
		mc.processEOF(metrics2, map[int]procTick{
			42: {Utime: 100, Stime: 100, Name: "new-proc", State: "R", RssKB: 1024},
		}, &CPUTicks{User: 10, Idle: 10}) // Total=20 < 2200
		if len(metrics2.TopProcesses) != 1 || !strings.Contains(metrics2.TopProcesses[0], "  0.0%") {
			t.Fatalf("totalTicks decrease underflowed process CPU: %v", metrics2.TopProcesses)
		}
	})
}

func newP1FormTestRepo(t *testing.T) *config.Repository {
	t.Helper()
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	return newTestRepository(t, cfg)
}

func TestP1FormValidation_PortsAddressesAliases(t *testing.T) {
	t.Run("port_bounds", func(t *testing.T) {
		repo := newP1FormTestRepo(t)
		for _, badPort := range []string{"", " ", "0", "-1", "65536", "70000", "999999", "22a"} {
			m := Model{
				repository: repo,
				formState:  &nodeFormState{user: "ops", address: "10.0.0.1", port: badPort},
			}
			if err := m.validateFormState(); err == nil {
				t.Errorf("validateFormState() accepted invalid port %q", badPort)
			}
			if cmd := m.saveFormCmd(); cmd != nil {
				t.Errorf("saveFormCmd() returned non-nil cmd for invalid port %q", badPort)
			}
		}
		for _, goodPort := range []string{"1", "22", " 2222 ", "65535"} {
			m := Model{
				repository: repo,
				formState:  &nodeFormState{user: "ops", address: "10.0.0.1", port: goodPort},
			}
			if err := m.validateFormState(); err != nil {
				t.Errorf("validateFormState() rejected valid port %q: %v", goodPort, err)
			}
		}
	})

	t.Run("address_and_alias_validation", func(t *testing.T) {
		repo := newP1FormTestRepo(t)
		for _, badAddr := range []string{"openssh:web1", "OPENSSH:web1", "bad host", "[10.0.0.1]", "[2001:db8::1", "10.0.0.1\n"} {
			m := Model{
				repository: repo,
				formState:  &nodeFormState{user: "ops", address: badAddr, port: "22"},
			}
			if err := m.validateFormState(); err == nil {
				t.Errorf("validateFormState() accepted invalid address %q", badAddr)
			}
		}
		for _, badAlias := range []string{"openssh", "openssh:prod", "OPENSSH:dev"} {
			m := Model{
				repository: repo,
				formState:  &nodeFormState{user: "ops", address: "10.0.0.1", port: "22", alias: badAlias},
			}
			if err := m.validateAliases(badAlias); err == nil {
				t.Errorf("validateAliases(%q) succeeded, want reserved alias error", badAlias)
			}
			if err := m.validateFormState(); err == nil {
				t.Errorf("validateFormState() accepted reserved alias %q", badAlias)
			}
		}
	})
}

func TestP1FormSave_IPv6AndTrimmedIDs(t *testing.T) {
	for _, rawAddr := range []string{" 2001:db8::1 ", " [2001:db8::1] "} {
		t.Run(strings.TrimSpace(rawAddr), func(t *testing.T) {
			repo := newP1FormTestRepo(t)
			m := Model{
				repository: repo,
				state:      viewForm,
				formState: &nodeFormState{
					skipVerify: true,
					user:       " ops ",
					address:    rawAddr,
					port:       " 2222 ",
					authType:   "password",
					sudoMode:   "auto",
				},
			}
			if err := m.validateFormState(); err != nil {
				t.Fatalf("validateFormState() failed for %q: %v", rawAddr, err)
			}
			completeConfigurationMutation(t, &m, m.saveFormCmd())

			wantNodeID := "ops@[2001:db8::1]:2222"
			wantHostID := "[2001:db8::1]:2222"
			wantIdentityID := "ops@[2001:db8::1]"

			node, ok := repo.GetNode(wantNodeID)
			if !ok {
				t.Fatalf("expected node %q to exist in repository", wantNodeID)
			}
			if node.HostRef != wantHostID {
				t.Errorf("node.HostRef = %q, want %q", node.HostRef, wantHostID)
			}
			if node.IdentityRef != wantIdentityID {
				t.Errorf("node.IdentityRef = %q, want %q", node.IdentityRef, wantIdentityID)
			}
			snap := repo.Snapshot()
			host, ok := snap.Hosts.Get(wantHostID)
			if !ok || host.Address != "2001:db8::1" || host.Port != 2222 {
				t.Fatalf("saved host = (%+v, %v), want Address=2001:db8::1 Port=2222", host, ok)
			}
			ident, ok := snap.Identities.Get(wantIdentityID)
			if !ok || ident.User != "ops" {
				t.Fatalf("saved identity = (%+v, %v), want User=ops", ident, ok)
			}
		})
	}
}
