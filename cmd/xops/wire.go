package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/audit"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/sys/agent"
	"github.com/wentf9/xops-cli/internal/host/sys/interact"
	"github.com/wentf9/xops-cli/internal/host/sys/sshfp"
	"github.com/wentf9/xops-cli/internal/host/sys/tun"
)

const engineRollbackTimeout = 5 * time.Second

type wiredRuntime struct {
	engine     *engine.Engine
	engineCfg  engine.Config
	env        ports.EnvPort
	scopedFS   ports.ScopedRootFS
	readFS     ports.OperatorReadFS
	stateDir   pathalg.LocalDir
	auditRoot  pathalg.LocalDir
	auditFile  algebraic.Option[pathalg.LocalRootedDest]
	shutdown   *shutdownStack
	reconciled bool
}

func (r *wiredRuntime) Close(ctx context.Context) error {
	if r == nil || r.shutdown == nil {
		return nil
	}
	return r.shutdown.Close(ctx)
}

type hostAdapters struct {
	scopedFS     ports.ScopedRootFS
	readFS       ports.OperatorReadFS
	clock        ports.Clock
	entropy      ports.Entropy
	env          ports.EnvPort
	proc         ports.ProcessPort
	term         ports.TerminalPort
	interaction  ports.InteractionPort
	sshAgent     ports.SSHAgentPort
	tunDevice    ports.TUNDevicePort
	sshfpLookup  ports.SSHFPLookupPort
	openSSH      ports.OpenSSHConfigSource
	invStore     *store.YAMLInventoryStore
	journalStore *store.WALJournalStore
	importers    []ports.FormatImporter
	auditSink    *audit.FileSink
	reconciler   *audit.FileReconciler
	vault        wiredVault
	homeDir      pathalg.LocalDir
	stateDir     pathalg.LocalDir
	policyCfg    resolvedPolicyConfig
}

// wireEngine 供 CLI EngineFactory 按需装配完整 CLI 模式核心引擎，并执行启动期 O(1) 崩溃审计对账。
func wireEngine(ctx context.Context, opts cli.EngineInitOptions, stdin io.Reader, stdout io.Writer) (cli.EngineHandle, error) {
	rt, err := wireRuntime(ctx, opts, runtimeModeCLI, stdin, stdout)
	if err != nil {
		return cli.EngineHandle{}, err
	}
	return cli.EngineHandle{
		Runner: rt.engine,
		Close:  rt.Close,
	}, nil
}

// wireRuntime 统一装配全部 Phase 4 真实宿主适配器与核心引擎，按严格启动正序登记逆序停机栈：
// Sys/Relay -> Audit -> Store -> Vault -> Engine（停机时自动逆序关闭，含可选 Entry 阶段）。
// MCP 模式严格保证 engine.Config.OperatorReadFS == nil、Interaction == nil，且将对账交由 MCPServer.Prepare(ctx) 统一执行。
func wireRuntime(
	ctx context.Context,
	opts cli.EngineInitOptions,
	mode runtimeMode,
	stdin io.Reader,
	stdout io.Writer,
) (rt *wiredRuntime, err error) {
	stack := newShutdownStack(defaultShutdownGrace)
	defer func() {
		if err != nil {
			rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), engineRollbackTimeout)
			defer cancel()
			_ = stack.Close(rbCtx)
		}
	}()

	adapters, err := assembleHostAdapters(ctx, opts, mode, stdin, stdout, stack)
	if err != nil {
		return nil, err
	}

	engCfg := buildEngineConfig(adapters, mode)
	eng, err := engine.New(engCfg)
	if err != nil {
		return nil, err
	}
	stack.Add("engine", eng.Close)

	reconciled := false
	if mode == runtimeModeCLI {
		if _, err := eng.ReconcileCrashedAudits(ctx); err != nil {
			return nil, fmt.Errorf("startup crash audit reconciliation failed: %w", err)
		}
		reconciled = true
	}

	return &wiredRuntime{
		engine:     eng,
		engineCfg:  engCfg,
		env:        adapters.env,
		scopedFS:   adapters.scopedFS,
		readFS:     adapters.readFS,
		stateDir:   adapters.stateDir,
		auditRoot:  adapters.policyCfg.auditRootDir,
		auditFile:  adapters.policyCfg.auditFileOpt,
		shutdown:   stack,
		reconciled: reconciled,
	}, nil
}

func assembleHostAdapters(
	ctx context.Context,
	opts cli.EngineInitOptions,
	mode runtimeMode,
	stdin io.Reader,
	stdout io.Writer,
	stack *shutdownStack,
) (hostAdapters, error) {
	var a hostAdapters
	a.scopedFS = osfs.NewScopedRootFS()
	a.clock = sys.NewSystemClock()
	a.entropy = sys.NewCryptoEntropy()
	a.env = newHomeAwareEnv(sys.NewSystemEnv())
	a.proc = sys.NewSystemProcess()
	a.sshAgent = agent.NewSystemAgent(agent.Spec{Env: a.env})
	a.tunDevice = tun.NewSystemTUNDevice()
	// 登记 Sys/Relay 阶段：停机逆序中恒处于最后释放（晚于 Audit 与 Store）。
	stack.Add("sys", func(context.Context) error { return nil })

	var localID ports.LocalIdentityInfo
	var err error
	if a.homeDir, a.stateDir, localID, err = resolveHostDirs(a.env); err != nil {
		return hostAdapters{}, err
	}
	// 先校验模式相关入口前置约束（含显式 `-F <configfile>` 存在性校验），避免配置错误时提前触碰 audit 目录。
	if err = initModeSpecificAdapters(ctx, opts, mode, localID, stdin, stdout, &a); err != nil {
		return hostAdapters{}, err
	}
	if err = initStoreAndPolicy(ctx, opts, mode, localID, &a, stack); err != nil {
		return hostAdapters{}, err
	}
	return a, nil
}

func initStoreAndPolicy(
	ctx context.Context,
	opts cli.EngineInitOptions,
	mode runtimeMode,
	localID ports.LocalIdentityInfo,
	a *hostAdapters,
	stack *shutdownStack,
) error {
	var err error
	if a.invStore, err = store.NewYAMLInventoryStore(store.InventoryStoreSpec{
		ScopedFS: a.scopedFS,
		RootDir:  a.stateDir,
	}); err != nil {
		return fmt.Errorf("initialize inventory store failed: %w", err)
	}
	doc, _, err := a.invStore.LoadDocument(ctx)
	if err != nil {
		return fmt.Errorf("load config.yaml failed: %w", err)
	}
	if a.policyCfg, err = resolveDocumentConfig(doc, opts.PolicyProfile, mode, a.stateDir, a.homeDir); err != nil {
		return err
	}
	if a.journalStore, err = store.NewWALJournalStore(store.JournalStoreSpec{
		ScopedFS: a.scopedFS,
		RootDir:  a.stateDir,
	}); err != nil {
		return fmt.Errorf("initialize WAL journal store failed: %w", err)
	}
	if a.importers, err = buildFormatImporters(localID); err != nil {
		return err
	}
	if a.auditSink, a.reconciler, err = buildAuditAdapters(
		a.scopedFS, a.policyCfg.auditRootDir, a.policyCfg.auditFileOpt, a.entropy,
	); err != nil {
		return err
	}
	stack.Add("audit", func(context.Context) error { return a.auditSink.Close() })
	stack.Add("store", func(context.Context) error { return nil })

	a.vault, err = buildVaultAdapters(doc.Vault, doc.Inventory.KnownStores, vaultWireDeps{
		scopedFS: a.scopedFS,
		stateDir: a.stateDir,
		homeDir:  a.homeDir,
		env:      a.env,
		entropy:  a.entropy,
		proc:     a.proc,
	})
	if err != nil {
		return err
	}
	stack.Add("vault", func(context.Context) error { return a.vault.router.Close() })
	return nil
}

func initModeSpecificAdapters(
	ctx context.Context,
	opts cli.EngineInitOptions,
	mode runtimeMode,
	localID ports.LocalIdentityInfo,
	stdin io.Reader,
	stdout io.Writer,
	a *hostAdapters,
) error {
	if mode == runtimeModeMCP {
		// MCP 严格沙箱边界：物理不注入 OperatorReadFS、Interaction 与本地 TTY 终端，仅暴露 ScopedRootFS。
		if trimmed := strings.TrimSpace(opts.OpenSSHConfigFile); trimmed != "" && !strings.EqualFold(trimmed, "none") {
			openSSH, err := buildOpenSSHSource(ctx, trimmed, a.homeDir, localID, a.scopedFS, osfs.NewOperatorReadFS())
			if err != nil {
				return err
			}
			a.openSSH = openSSH
		}
		return nil
	}
	a.readFS = osfs.NewOperatorReadFS()
	var err error
	if a.term, err = buildTerminalAdapter(stdin, stdout); err != nil {
		return fmt.Errorf("initialize terminal adapter failed: %w", err)
	}
	if a.interaction, err = buildInteractionAdapter(stdin, stdout); err != nil {
		return fmt.Errorf("initialize interaction adapter failed: %w", err)
	}
	if a.sshfpLookup, err = sshfp.NewSystemLookup(sshfp.Spec{
		OperatorFS: a.readFS,
		Entropy:    a.entropy,
	}); err != nil {
		return fmt.Errorf("initialize sshfp lookup adapter failed: %w", err)
	}
	if a.openSSH, err = buildOpenSSHSource(ctx, opts.OpenSSHConfigFile, a.homeDir, localID, a.scopedFS, a.readFS); err != nil {
		return err
	}
	return nil
}

func buildEngineConfig(a hostAdapters, mode runtimeMode) engine.Config {
	cfg := engine.Config{
		Profile:        a.policyCfg.profile,
		Guardrail:      a.policyCfg.guardrail,
		Clock:          a.clock,
		Entropy:        a.entropy,
		AuditSink:      a.auditSink,
		Reconciler:     a.reconciler,
		ScopedFS:       a.scopedFS,
		HomeDir:        algebraic.Some(a.homeDir),
		Env:            a.env,
		Process:        a.proc,
		OpenSSH:        a.openSSH,
		Vault:          a.vault.router,
		VaultControl:   a.vault.control,
		Agent:          a.sshAgent,
		InventoryStore: a.invStore,
		JournalStore:   a.journalStore,
		Importers:      a.importers,
		KnownStores:    a.vault.knownStores,
		TUNDevice:      a.tunDevice,
		GlobalOptions:  a.policyCfg.globalOptions,
	}
	if mode == runtimeModeCLI {
		cfg.OperatorReadFS = a.readFS
		cfg.Terminal = a.term
		cfg.Interaction = a.interaction
		cfg.SSHFPLookup = a.sshfpLookup
	}
	return cfg
}

func buildFormatImporters(localID ports.LocalIdentityInfo) ([]ports.FormatImporter, error) {
	openSSHImp, err := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{
		LocalIdentity: algebraic.Some(localID),
	})
	if err != nil {
		return nil, fmt.Errorf("initialize openssh importer failed: %w", err)
	}
	csvImp, err := store.NewCSVImporter(store.CSVImporterSpec{})
	if err != nil {
		return nil, fmt.Errorf("initialize csv importer failed: %w", err)
	}
	return []ports.FormatImporter{openSSHImp, csvImp}, nil
}

// buildTerminalAdapter 按注入流类型构造本机终端适配器：
//   - 当 stdin 与 stdout 均为非 nil *os.File 时绑定对应 OS 文件句柄（sys.NewFileTerminal）；
//   - 当为自定义缓冲/管道流时构造非交互流终端（sys.NewStreamTerminal），避免误探测父进程 TTY。
func buildTerminalAdapter(stdin io.Reader, stdout io.Writer) (ports.TerminalPort, error) {
	inFile, inOK := stdin.(*os.File)
	outFile, outOK := stdout.(*os.File)
	if inOK && outOK && inFile != nil && outFile != nil {
		return sys.NewFileTerminal(inFile, outFile)
	}
	return sys.NewStreamTerminal(sys.StreamTerminalSpec{
		In:          stdin,
		Out:         stdout,
		Interactive: false,
	})
}

// buildInteractionAdapter 按注入流类型构造交互确认与口令输入适配器：
//   - 当直接绑定进程 os.Stdin/os.Stdout 时使用 NewTTYInteraction（支持 Unix /dev/tty 回退）；
//   - 当为显式 *os.File 时使用 NewFileInteraction（不回退 /dev/tty）；
//   - 当为内存流或测试缓冲时使用非交互 NewStreamInteraction（避免测试误触发真实控制终端）。
func buildInteractionAdapter(stdin io.Reader, stdout io.Writer) (ports.InteractionPort, error) {
	inFile, inOK := stdin.(*os.File)
	outFile, outOK := stdout.(*os.File)
	if inOK && outOK && inFile != nil && outFile != nil {
		if inFile == os.Stdin && outFile == os.Stdout {
			return interact.NewTTYInteraction(), nil
		}
		return interact.NewFileInteraction(inFile, outFile)
	}
	in := stdin
	if in == nil {
		in = strings.NewReader("")
	}
	out := stdout
	if out == nil {
		out = io.Discard
	}
	return interact.NewStreamInteraction(interact.StreamSpec{
		In:          in,
		Out:         out,
		Interactive: false,
	})
}

func buildAuditAdapters(
	scopedFS ports.ScopedRootFS,
	rootDir pathalg.LocalDir,
	auditFile algebraic.Option[pathalg.LocalRootedDest],
	entropy ports.Entropy,
) (*audit.FileSink, *audit.FileReconciler, error) {
	procID, err := ports.NewProcessInstanceIDFrom(entropy)
	if err != nil {
		return nil, nil, fmt.Errorf("generate process instance id failed: %w", err)
	}
	sink, err := audit.NewFileSink(audit.SinkSpec{
		ScopedFS:  scopedFS,
		RootDir:   rootDir,
		ProcessID: procID,
		AuditFile: auditFile,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize audit sink failed: %w", err)
	}
	reconciler, err := audit.NewFileReconciler(audit.ReconcilerSpec{
		ScopedFS:  scopedFS,
		RootDir:   rootDir,
		AuditFile: auditFile,
	})
	if err != nil {
		_ = sink.Close()
		return nil, nil, fmt.Errorf("initialize audit reconciler failed: %w", err)
	}
	return sink, reconciler, nil
}
