package sim_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

func mustParseLocalDir(t *testing.T, raw string) pathalg.LocalDir {
	t.Helper()
	d, err := pathalg.ParseLocalDir(raw)
	if err != nil {
		t.Fatalf("ParseLocalDir(%q) failed: %v", raw, err)
	}
	return d
}

func mustParseLocalSource(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath(%q) failed: %v", raw, err)
	}
	return p
}

func mustParseRemotePath(t *testing.T, raw string) pathalg.RemotePath {
	t.Helper()
	p, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		t.Fatalf("ParseRemotePath(%q) failed: %v", raw, err)
	}
	return p
}

func mustProcessSpec(t *testing.T, cmd string) ports.ProcessSpec {
	t.Helper()
	spec, err := ports.NewProcessSpec(ports.ProcessSpecInput{Command: cmd})
	if err != nil {
		t.Fatalf("NewProcessSpec(%q) failed: %v", cmd, err)
	}
	return spec
}

// TestSim_TCK_StoreAndConfig 验证资产存储、传输日志、格式导入与 OpenSSH 配置源全部通过 TCK 契约。
func TestSim_TCK_StoreAndConfig(t *testing.T) {
	defer tck.VerifyNoLeaks(t)

	t.Run("InventoryStore", func(t *testing.T) {
		tck.RunInventoryStoreSuite(t, func(t *testing.T) ports.InventoryStore {
			empty, err := inventory.NewGraph(inventory.GraphSpec{})
			if err != nil {
				t.Fatalf("NewGraph failed: %v", err)
			}
			s, err := sim.NewSimInventoryStore(empty)
			if err != nil {
				t.Fatalf("NewSimInventoryStore failed: %v", err)
			}
			return s
		})
	})

	t.Run("JournalStore", runJournalStoreTCK)

	t.Run("FormatImporter", func(t *testing.T) {
		tck.RunFormatImporterSuite(t, tck.FormatImporterFixture{
			NewImporter:  func(*testing.T) ports.FormatImporter { return sim.NewSimFormatImporter("csv") },
			ValidInput:   func() io.Reader { return strings.NewReader("# comment\nweb1,10.0.0.10,22,ops\n") },
			InvalidInput: func() io.Reader { return strings.NewReader("malformed-row\n") },
			SourceName:   "sim-inventory.csv",
		})
	})

	t.Run("OpenSSHConfigSource", runOpenSSHConfigTCK)
}

func runJournalStoreTCK(t *testing.T) {
	tck.RunJournalStoreSuite(t, tck.JournalStoreFixture{
		NewStore: func(*testing.T) ports.JournalStore { return sim.NewSimJournalStore() },
		CorruptGeneration: func(_ *testing.T, s ports.JournalStore, id security.OperationID, gen uint64) {
			s.(*sim.SimJournalStore).CorruptGeneration(id, gen, ports.ErrCorruptData)
		},
	})
	// 验证 SimJournalStore 模拟尾部撕裂损坏时保留有效前缀 PartialRecords()，头部空损坏时 PartialRecords()==nil。
	js := sim.NewSimJournalStore()
	ctx := context.Background()
	id, err := security.NewOperationIDFrom(tck.NewDeterministicEntropy(91))
	if err != nil {
		t.Fatalf("NewOperationIDFrom: %v", err)
	}
	prefix := tck.MustV2JournalChainGen(t, id, 2)[:4]
	for _, rec := range prefix {
		if err := js.Append(ctx, rec); err != nil {
			t.Fatalf("Append(prefix): %v", err)
		}
	}
	js.CorruptGeneration(id, 2, ports.ErrCorruptData)
	js.CorruptGeneration(id, 3, ports.ErrCorruptData)
	snaps, err := js.LoadGenerations(ctx, id)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("LoadGenerations: snaps=%d err=%v", len(snaps), err)
	}
	if !snaps[0].Corrupt() || snaps[0].Records() != nil || len(snaps[0].PartialRecords()) != len(prefix) {
		t.Fatalf("Gen 2 撕裂损坏须保留全部 %d 条前缀且 Records()==nil: got=%d", len(prefix), len(snaps[0].PartialRecords()))
	}
	if !snaps[1].Corrupt() || snaps[1].Records() != nil || snaps[1].PartialRecords() != nil {
		t.Fatalf("Gen 3 头部空损坏须返回 Records()==nil 且 PartialRecords()==nil")
	}
}

func runOpenSSHConfigTCK(t *testing.T) {
	ep := tck.MustEndpoint(t, "10.10.0.5", 22)
	target, err := option.ParseOriginalHost("prod-app")
	if err != nil {
		t.Fatalf("ParseOriginalHost failed: %v", err)
	}
	vh, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      "prod-app",
		SourceFile: "/sim/ssh_config",
		Endpoint:   algebraic.Some(ep),
		Proxy:      option.NewProxyUnset(),
		Layer:      option.UnsetOptionLayer(),
	})
	if err != nil {
		t.Fatalf("NewOpenSSHVirtualHost failed: %v", err)
	}
	tck.RunOpenSSHConfigSourceSuite(t, tck.OpenSSHConfigFixture{
		NewSource:  func(*testing.T) ports.OpenSSHConfigSource { return sim.NewSimOpenSSHConfigSource(vh) },
		TargetHost: target,
		Endpoint:   ep,
	})
}

// TestSim_TCK_LocalAndRemoteFS 验证 ScopedRootFS（含策略 (b) 软链）、OperatorReadFS 与 RemoteFSPort 全部通过 TCK。
func TestSim_TCK_LocalAndRemoteFS(t *testing.T) {
	defer tck.VerifyNoLeaks(t)

	t.Run("ScopedRootFS", func(t *testing.T) {
		tck.RunScopedRootFSSuite(t, tck.ScopedRootFSFixture{
			NewRoot: func(t *testing.T) (ports.ScopedRootFS, pathalg.LocalDir) {
				return sim.NewSimScopedRootFS(sim.NewSimClock(tck.BaseTime())), mustParseLocalDir(t, "/sim/sandbox")
			},
			CheckSymlink: true,
		})
	})

	t.Run("OperatorReadFS", runOperatorReadTCK)
	t.Run("RemoteFS", runRemoteFSTCK)
}

func runOperatorReadTCK(t *testing.T) {
	reg := mustParseLocalSource(t, "/sim/etc/ssh_config")
	sym := mustParseLocalSource(t, "/sim/etc/ssh_config_link")
	missing := mustParseLocalSource(t, "/sim/etc/does_not_exist")
	payload := []byte("Host app\n  User ops\n")
	tck.RunOperatorReadFSSuite(t, tck.OperatorReadFSFixture{
		NewReader: func(t *testing.T) ports.OperatorReadFS {
			opFS := sim.NewSimOperatorReadFS()
			if err := opFS.PutFile(reg, payload); err != nil {
				t.Fatalf("PutFile failed: %v", err)
			}
			if err := opFS.PutSymlink(sym, reg); err != nil {
				t.Fatalf("PutSymlink failed: %v", err)
			}
			return opFS
		},
		RegularFile:     reg,
		ExpectedContent: payload,
		MissingFile:     missing,
		SymlinkFile:     sym,
	})
}

func runRemoteFSTCK(t *testing.T) {
	tck.RunRemoteFSSuite(t, tck.RemoteFSFixture{
		NewRemoteFS: func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath) {
			rfs := sim.NewSimRemoteFS(sim.NewSimClock(tck.BaseTime()))
			workDir := mustParseRemotePath(t, "/tmp/tck")
			if err := rfs.MkdirAll(context.Background(), workDir, 0o755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			return rfs, workDir
		},
		CheckDevInoAnchor: true,
	})
}

// TestSim_TCK_VaultAndTransport 验证 SimVault、SimKeySigner、SimHostTrust、SimDialer 与 SimMuxSocket 全部通过 TCK。
func TestSim_TCK_VaultAndTransport(t *testing.T) {
	defer tck.VerifyNoLeaks(t)

	t.Run("SecretVault", func(t *testing.T) {
		tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
			NewVault: func(*testing.T) ports.SecretVault { return sim.NewSimVault(sim.NewSeededRand(101)) },
			NewLockedVault: func(t *testing.T) ports.SecretVault {
				v := sim.NewSimVault(sim.NewSeededRand(102))
				if err := v.Lock(context.Background()); err != nil {
					t.Fatalf("Lock failed: %v", err)
				}
				return v
			},
		})
	})

	t.Run("VaultControl", func(t *testing.T) {
		tck.RunVaultControlSuite(t, tck.VaultControlFixture{
			NewUninitialized: func(*testing.T) ports.VaultControlPort {
				return sim.NewUninitializedSimVault(sim.NewSeededRand(103))
			},
		})
	})

	t.Run("KeySigner", runKeySignerTCK)

	t.Run("HostTrust", func(t *testing.T) {
		tck.RunHostTrustSuite(t, tck.HostTrustFixture{
			NewTrust:   func(*testing.T) ports.HostTrustPort { return sim.NewSimHostTrust() },
			KnownHosts: option.UnsetKnownHostsList(),
		})
	})

	t.Run("Dialer", func(t *testing.T) {
		tck.RunDialerSuite(t, tck.DialerFixture{
			NewDialer: func(*testing.T) ports.DialerPort {
				return sim.NewSimDialer(sim.NewSimClock(tck.BaseTime()), sim.NewSeededRand(202))
			},
			TestCommand:           "echo tck-ok",
			CheckMultiHop:         true,
			CheckRemoteFS:         true,
			CheckTunnelExtensions: true,
		})
	})

	t.Run("MuxSocket", func(t *testing.T) {
		existing := mustParseLocalSource(t, "/sim/mux/ops@10.0.0.1:22.sock")
		listenPath := mustParseLocalSource(t, "/sim/mux/ops@10.0.0.2:2222.sock")
		tck.RunMuxSocketSuite(t, tck.MuxSocketFixture{
			NewMux: func(*testing.T) (ports.MuxSocketPort, pathalg.LocalSourcePath) {
				dialer := sim.NewSimDialer(sim.NewSimClock(tck.BaseTime()), sim.NewSeededRand(204))
				mux := sim.NewSimMuxSocket(dialer)
				mux.RegisterMaster(existing, 9001)
				return mux, listenPath
			},
			ExistingSocket: algebraic.Some(existing),
			NewUpstream: func(t *testing.T) ports.TransportConn {
				dialer := sim.NewSimDialer(sim.NewSimClock(tck.BaseTime()), sim.NewSeededRand(205))
				single, _ := tck.MustHopAndPlan(t)
				hop0, _ := single.HopAt(0)
				dig0, _ := single.HopDigestAt(0)
				c, err := dialer.DialHop(context.Background(), hop0, dig0, nil)
				if err != nil {
					t.Fatalf("DialHop(mux upstream): %v", err)
				}
				t.Cleanup(func() { _ = c.Close() })
				return c
			},
			NewForwarder: func(*testing.T) ports.ForwarderPort { return sim.NewSimForwarder() },
		})
	})
}

func runKeySignerTCK(t *testing.T) {
	keyPath, err := inventory.ParseKeyPathSpec("/sim/keys/id_ed25519")
	if err != nil {
		t.Fatalf("ParseKeyPathSpec failed: %v", err)
	}
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent failed: %v", err)
	}
	tck.RunKeySignerSuite(t, tck.KeySignerFixture{
		NewSigner: func(t *testing.T) ports.KeySignerPort {
			ks := sim.NewSimKeySigner()
			ks.AddKey(tck.MustPublicKey(t, tck.TestFingerprintA, 1), keyPath.String())
			return ks
		},
		Auth:    auth,
		KeyPath: algebraic.Some(keyPath),
	})
}

// TestSim_TCK_AuditAndClock 验证审计集群、虚拟时钟与确定性熵源全部通过 TCK。
func TestSim_TCK_AuditAndClock(t *testing.T) {
	defer tck.VerifyNoLeaks(t)
	t.Run("Audit", runAuditTCK)
	t.Run("Clock", runClockTCK)
	t.Run("Entropy", func(t *testing.T) {
		tck.RunEntropySuite(t, func(*testing.T) ports.Entropy { return sim.NewSeededRand(404) })
	})
}

func runAuditTCK(t *testing.T) {
	var mu sync.Mutex
	var cluster *sim.SimAuditCluster
	rng := sim.NewSeededRand(303)
	tck.RunAuditSuite(t, tck.AuditFixture{
		NewAudit: func(t *testing.T) (ports.AuditSink, ports.AuditReconciler) {
			mu.Lock()
			defer mu.Unlock()
			cluster = sim.NewSimAuditCluster()
			sink, err := cluster.NewSinkFromEntropy(rng)
			if err != nil {
				t.Fatalf("NewSinkFromEntropy failed: %v", err)
			}
			return sink, cluster
		},
		SimulateCrash: func(t *testing.T) security.OperationID {
			mu.Lock()
			c := cluster
			mu.Unlock()
			return stageAndSIGKILL(t, c, rng, false)
		},
		SimulatePostDrainCrash: func(t *testing.T) security.OperationID {
			mu.Lock()
			c := cluster
			mu.Unlock()
			return stageAndSIGKILL(t, c, rng, true)
		},
	})
}

func stageAndSIGKILL(t *testing.T, c *sim.SimAuditCluster, rng *sim.SeededRand, drainFirst bool) security.OperationID {
	t.Helper()
	deadSink, err := c.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("deadSink NewSinkFromEntropy failed: %v", err)
	}
	traceID, _ := security.NewTraceIDFrom(rng)
	ctx := context.Background()
	if drainFirst {
		op1, _ := security.NewOperationIDFrom(rng)
		if err := deadSink.StageOperation(ctx, op1); err != nil {
			t.Fatalf("deadSink StageOperation(1) failed: %v", err)
		}
		if err := deadSink.Record(ctx, tck.MustAuditEntry(t, deadSink.ProcessInstanceID(), traceID, op1, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
			t.Fatalf("deadSink Record(1 Auth) failed: %v", err)
		}
		if err := deadSink.Record(ctx, tck.MustAuditEntry(t, deadSink.ProcessInstanceID(), traceID, op1, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)); err != nil {
			t.Fatalf("deadSink Record(1 Fin) failed: %v", err)
		}
		if err := deadSink.UnstageOperation(ctx, op1); err != nil {
			t.Fatalf("deadSink UnstageOperation(1) failed: %v", err)
		}
	}
	opID, _ := security.NewOperationIDFrom(rng)
	if err := deadSink.StageOperation(ctx, opID); err != nil {
		t.Fatalf("deadSink StageOperation failed: %v", err)
	}
	entry := tck.MustAuditEntry(t, deadSink.ProcessInstanceID(), traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)
	if err := deadSink.Record(ctx, entry); err != nil {
		t.Fatalf("deadSink Record failed: %v", err)
	}
	deadSink.SimulateSIGKILL()
	return opID
}

func runClockTCK(t *testing.T) {
	var mu sync.Mutex
	var cur *sim.SimClock
	tck.RunClockSuite(t, tck.ClockFixture{
		NewClock: func(*testing.T) ports.Clock {
			mu.Lock()
			defer mu.Unlock()
			cur = sim.NewSimClock(tck.BaseTime())
			return cur
		},
		Advance: func(d time.Duration) {
			mu.Lock()
			c := cur
			mu.Unlock()
			if c != nil {
				c.Advance(d)
			}
		},
		SleepDuration: 15 * time.Millisecond,
	})
}

// TestSim_TCK_SystemPorts 验证进程、交互式/非交互式终端与人工交互端口全部通过 TCK。
func TestSim_TCK_SystemPorts(t *testing.T) {
	defer tck.VerifyNoLeaks(t)

	t.Run("Process", func(t *testing.T) {
		tck.RunProcessSuite(t, tck.ProcessFixture{
			NewProcess:    func(*testing.T) ports.ProcessPort { return sim.NewSimProcessPort() },
			EchoSpec:      mustProcessSpec(t, "echo-sim"),
			FailSpec:      mustProcessSpec(t, "fail"),
			DialStdioSpec: mustProcessSpec(t, "stdio-sim"),
		})
	})

	t.Run("TerminalInteractive", func(t *testing.T) {
		sz2, err := ports.NewTerminalSize(120, 40)
		if err != nil {
			t.Fatalf("NewTerminalSize failed: %v", err)
		}
		tck.RunTerminalSuite(t, tck.TerminalFixture{
			NewTerminal: func(*testing.T) ports.TerminalPort {
				tp := sim.NewSimTerminalPort(true, 100, 32)
				tp.SetInput([]byte("local-input-ok"))
				tp.QueueResize(sz2)
				return tp
			},
			NewBlockingInputTerminal: func(*testing.T) ports.TerminalPort {
				tp := sim.NewSimTerminalPort(true, 100, 32)
				tp.SetBlockInputAfterData(true)
				return tp
			},
			ExpectInteractive:  true,
			ExpectedRelayInput: "local-input-ok",
			ExpectResizeCount:  1,
		})
	})

	t.Run("TerminalNonInteractive", func(t *testing.T) {
		tck.RunTerminalSuite(t, tck.TerminalFixture{
			NewTerminal:       func(*testing.T) ports.TerminalPort { return sim.NewSimTerminalPort(false, 80, 24) },
			ExpectInteractive: false,
		})
	})

	t.Run("Interaction", func(t *testing.T) {
		tck.RunInteractionSuite(t, tck.InteractionFixture{
			NewInteraction: func(*testing.T) ports.InteractionPort {
				ui := sim.NewSimInteractionPort(true)
				ui.SetReplies("sim-text", []byte(tck.TestSecretTokenA))
				return ui
			},
			ExpectedSecret: tck.TestSecretTokenA,
			ExpectedText:   "sim-text",
		})
	})

	t.Run("DownstreamPorts", runDownstreamPortsTCK)
}

func runDownstreamPortsTCK(t *testing.T) {
	idInfo, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "devbox.local", LocalUser: "ops", LocalUID: "1000", HomeDir: "/home/ops",
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	tck.RunEnvSuite(t, tck.EnvFixture{
		NewEnv: func(*testing.T) ports.EnvPort {
			return sim.NewSimEnvPort(map[string]string{"TERM": "xterm-256color"}, idInfo)
		},
		KnownKey: "TERM", ExpectedValue: "xterm-256color", MissingKey: "MISSING_VAR", ExpectIdentity: true,
	})

	host, err := netaddr.ParseCanonicalHost("sshfp.example.test")
	if err != nil {
		t.Fatalf("ParseCanonicalHost: %v", err)
	}
	rec, err := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{
		Algorithm: 4, FingerprintType: 2, Digest: bytes.Repeat([]byte{0xab}, 32), Authenticated: true,
	})
	if err != nil {
		t.Fatalf("NewSSHFPRecord: %v", err)
	}
	tck.RunSSHFPLookupSuite(t, tck.SSHFPLookupFixture{
		NewLookup: func(*testing.T) ports.SSHFPLookupPort {
			lp := sim.NewSimSSHFPLookup()
			lp.SetRecords(host, rec)
			return lp
		},
		KnownHost: host, MinCount: 1,
	})

	tck.RunSSHAgentSuite(t, tck.SSHAgentFixture{
		NewAgent: func(t *testing.T) ports.SSHAgentPort {
			return sim.NewSimSSHAgent(tck.MustPublicKey(t, tck.TestFingerprintA, 7))
		},
		NewUnavailableAgent: func(*testing.T) ports.SSHAgentPort {
			ag := sim.NewSimSSHAgent()
			ag.SetAvailable(false)
			return ag
		},
		Spec: algebraic.None[inventory.AgentSpec](),
	})

	openSimConn := func(t *testing.T) ports.TransportConn {
		t.Helper()
		dialer := sim.NewSimDialer(sim.NewSimClock(tck.BaseTime()), sim.NewSeededRand(606))
		single, _ := tck.MustHopAndPlan(t)
		hop0, _ := single.HopAt(0)
		dig0, _ := single.HopDigestAt(0)
		c, dErr := dialer.DialHop(context.Background(), hop0, dig0, nil)
		if dErr != nil {
			t.Fatalf("DialHop: %v", dErr)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	tck.RunPrivilegeEscalationSuite(t, tck.PrivilegeEscalationFixture{
		NewEscalator: func(t *testing.T) (ports.PrivilegeEscalationPort, ports.SessionOpener) {
			esc := sim.NewSimPrivilegeEscalator()
			esc.SetRequiredPassword([]byte(tck.TestSecretTokenA))
			return esc, openSimConn(t)
		},
		CorrectPassword: tck.TestSecretTokenA, WrongPassword: tck.TestSecretTokenB, RequirePassword: true,
	})

	probeRes, err := ports.NewShellProbeResult(ports.ShellProbeResultSpec{
		Dialect: execution.DialectPOSIX, Interpreter: execution.InterpreterBash, OSFamily: "linux", ProbeStage: 2, RawBanner: "GNU bash",
	})
	if err != nil {
		t.Fatalf("NewShellProbeResult: %v", err)
	}
	tck.RunShellProbeSuite(t, tck.ShellProbeFixture{
		NewProbe: func(t *testing.T) (ports.ShellProbePort, ports.SessionOpener) {
			return sim.NewSimShellProbe(probeRes), openSimConn(t)
		},
	})

	fLocal, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:8080", "10.0.0.5:80")
	fRemote, _ := ports.NewForwardSpec(ports.ForwardRemote, "0.0.0.0:9090", "127.0.0.1:3000")
	fDyn, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:1080", "")
	fLocalUnix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointUnix, "/tmp/local.sock", ports.ForwardEndpointUnix, "/run/remote.sock")
	fLocalMix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, "127.0.0.1:8081", ports.ForwardEndpointUnix, "/run/remote-mix.sock")
	fRemoteUnix, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointUnix, "/run/remote-bind.sock", ports.ForwardEndpointUnix, "/tmp/local-target.sock")
	fRemoteMix, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointUnix, "/run/remote-mix-bind.sock", ports.ForwardEndpointTCP, "127.0.0.1:3001")
	tunP2P, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, ports.TUNUnitAny)
	fTUNP2P, _ := ports.NewForwardTUNSpec(tunP2P)
	tunEth, _ := ports.NewTUNSpec(ports.TUNModeEthernet, 2, 3)
	fTUNEth, _ := ports.NewForwardTUNSpec(tunEth)
	tck.RunForwarderSuite(t, tck.ForwarderFixture{
		NewForwarder: func(t *testing.T) (ports.ForwarderPort, ports.TunnelTransport) {
			return sim.NewSimForwarder(), openSimConn(t)
		},
		Specs: []ports.ForwardSpec{fLocal, fRemote, fDyn, fLocalUnix, fLocalMix, fRemoteUnix, fRemoteMix, fTUNP2P, fTUNEth},
		ExerciseHandle: func(ctx context.Context, h ports.ForwardHandle) error {
			return h.(*sim.SimForwardHandle).OpenChannel(ctx)
		},
	})
	tck.RunTUNDeviceSuite(t, tck.TUNDeviceFixture{
		NewDevice: func(*testing.T) ports.TUNDevicePort { return sim.NewSimTUNDevicePort() },
		NewUnavailableDevice: func(*testing.T) ports.TUNDevicePort {
			d := sim.NewSimTUNDevicePort()
			d.SetAvailable(false)
			return d
		},
	})
}

// TestSim_VaultAESGCMAtRest 验证 SimVault 静态密文存储、独立 Nonce、密文篡改拦截与回读失配校验。
func TestSim_VaultAESGCMAtRest(t *testing.T) {
	defer tck.VerifyNoLeaks(t)
	ctx := context.Background()
	v := sim.NewSimVault(sim.NewSeededRand(777))
	ref1, ref2 := tck.MustRef(t, "sim", "k1"), tck.MustRef(t, "sim", "k2")
	plain := []byte("top-secret-password-for-sim-vault")

	if err := secret.WithBytes(bytes.Clone(plain), func(box *secret.SecretBox) error {
		if err := v.PutAndVerify(ctx, ref1, box); err != nil {
			return err
		}
		return v.PutAndVerify(ctx, ref2, box)
	}); err != nil {
		t.Fatalf("PutAndVerify failed: %v", err)
	}

	ct1, ok1 := v.CiphertextFor(ref1)
	ct2, ok2 := v.CiphertextFor(ref2)
	if !ok1 || !ok2 || bytes.Contains(ct1, plain) || bytes.Equal(ct1, ct2) {
		t.Fatalf("ciphertext must hide plaintext and use distinct nonces")
	}
	if !v.TamperCiphertext(ref1) {
		t.Fatalf("TamperCiphertext failed")
	}
	if err := v.WithSecret(ctx, ref1, func(*secret.SecretBox) error { return nil }); err == nil {
		t.Fatalf("tampered ciphertext must fail closed")
	}

	ref3 := tck.MustRef(t, "sim", "k3")
	v.SetVerifyMismatch(true)
	err := secret.WithBytes([]byte("mismatch-check"), func(box *secret.SecretBox) error {
		return v.PutAndVerify(ctx, ref3, box)
	})
	if !errors.Is(err, ports.ErrSecretVerifyFailed) {
		t.Fatalf("SetVerifyMismatch got %v, want ErrSecretVerifyFailed", err)
	}
	if err := secret.WithBytes([]byte("overwrite-fail"), func(box *secret.SecretBox) error {
		return v.PutAndVerify(ctx, ref2, box)
	}); !errors.Is(err, ports.ErrSecretVerifyFailed) {
		t.Fatalf("overwrite mismatch got %v, want ErrSecretVerifyFailed", err)
	}
	v.SetVerifyMismatch(false)
	if err := v.WithSecret(ctx, ref3, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("failed PutAndVerify(ref3) must roll back entry, got %v", err)
	}
	if err := v.WithSecret(ctx, ref2, func(got *secret.SecretBox) error {
		return secret.WithBytes(bytes.Clone(plain), func(want *secret.SecretBox) error {
			if !got.Equal(want) {
				return errors.New("rollback did not preserve prior secret")
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("failed overwrite PutAndVerify(ref2) must roll back to previous value: %v", err)
	}
}

// TestSim_AuditO1ZeroScanAndENOSPC 验证审计集群 O(1) 零扫描不变量、ENOSPC 终态错误类型与空闲截断计数。
func TestSim_AuditO1ZeroScanAndENOSPC(t *testing.T) {
	defer tck.VerifyNoLeaks(t)
	ctx := context.Background()
	cluster := sim.NewSimAuditCluster()
	rng := sim.NewSeededRand(888)
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy failed: %v", err)
	}
	traceID, _ := security.NewTraceIDFrom(rng)
	opID, _ := security.NewOperationIDFrom(rng)

	if err := sink.StageOperation(ctx, opID); err != nil {
		t.Fatalf("StageOperation failed: %v", err)
	}
	authEnt := tck.MustAuditEntry(t, sink.ProcessInstanceID(), traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)
	if err := sink.Record(ctx, authEnt); err != nil {
		t.Fatalf("Record(Authorized) failed: %v", err)
	}

	rep, err := cluster.ReconcileCrashedAudits(ctx, sim.DefaultBaseTime())
	if err != nil || rep.LiveLocksSkipped() != 1 || cluster.AuditLogScans() != 0 {
		t.Fatalf("expected O(1) zero-scan with live lock: rep=%v err=%v scans=%d", rep, err, cluster.AuditLogScans())
	}

	cluster.SetENOSPC(true)
	finEnt := tck.MustAuditEntry(t, sink.ProcessInstanceID(), traceID, opID, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)
	if _, ok := errors.AsType[*ports.AuditPostWriteError](sink.Record(ctx, finEnt)); !ok {
		t.Fatalf("expected AuditPostWriteError under ENOSPC")
	}
	cluster.SetENOSPC(false)

	if err := sink.Record(ctx, finEnt); err != nil {
		t.Fatalf("Record(Finalized) after ENOSPC clear failed: %v", err)
	}
	if err := sink.UnstageOperation(ctx, opID); err != nil || cluster.LockTruncations() != 1 {
		t.Fatalf("UnstageOperation/truncation failed: err=%v trunc=%d", err, cluster.LockTruncations())
	}
	_ = sink.Close()
	if _, err := cluster.ReconcileCrashedAudits(ctx, sim.DefaultBaseTime().Add(time.Second)); err != nil || cluster.AuditLogScans() != 0 {
		t.Fatalf("clean restart must keep AuditLogScans == 0, got %d (err=%v)", cluster.AuditLogScans(), err)
	}
}

// TestSim_ClockOrderAndRandReplay 验证虚拟时钟 AdvanceToNext 确定性调度顺序与 SeededRand 逐位复现。
func TestSim_ClockOrderAndRandReplay(t *testing.T) {
	defer tck.VerifyNoLeaks(t)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	t1 := clk.NewTimer(50 * time.Millisecond)
	t2 := clk.NewTimer(20 * time.Millisecond)
	if delta, ok := clk.AdvanceToNext(); !ok || delta != 20*time.Millisecond {
		t.Fatalf("AdvanceToNext got (%v, %v), want (20ms, true)", delta, ok)
	}
	select {
	case <-t2.C():
	default:
		t.Fatalf("t2 must fire at 20ms")
	}
	select {
	case <-t1.C():
		t.Fatalf("t1 must not fire early")
	default:
	}
	if delta, ok := clk.AdvanceToNext(); !ok || delta != 30*time.Millisecond {
		t.Fatalf("second AdvanceToNext got (%v, %v), want (30ms, true)", delta, ok)
	}
	<-t1.C()

	rA, rB := sim.NewSeededRand(12345), sim.NewSeededRand(12345)
	for range 32 {
		if rA.Uint64() != rB.Uint64() {
			t.Fatalf("SeededRand must be bit-for-bit deterministic")
		}
	}
}
