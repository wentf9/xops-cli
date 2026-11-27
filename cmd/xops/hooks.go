package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/mcpcmd"
	"github.com/wentf9/xops-cli/internal/entry/muxdaemon"
	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
	"github.com/wentf9/xops-cli/internal/entry/tui"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/host/sys"
)

const (
	defaultAuditReadMaxBytes    int64 = 64 << 20
	defaultOperatorReadMaxBytes int64 = 16 << 20
	auditFileNameDefault              = "audit.jsonl"
)

// runTUISubEntry 装配完整 CLI 运行期并启动 Bubble Tea v2 实时工作台，退出时严格逆序停机。
func runTUISubEntry(ctx context.Context, req cli.TUIStartRequest) (retErr error) {
	rt, err := wireRuntime(ctx, req.InitOptions, runtimeModeCLI, req.Stdin, req.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, rt.Close(ctx)) }()

	return tui.Run(ctx, tui.Config{
		Engine:               rt.engine,
		Input:                req.Stdin,
		Output:               req.Stdout,
		Environment:          envMapToSlice(rt.env),
		DisableAltScreen:     req.NoAltScreen,
		DisableSignalHandler: true,
		InitialTarget:        req.InitialNode,
		MetricsInterval:      req.RefreshInterval,
		OnTakeover:           buildTUITakeover(rt.engine, req.Stdin, req.Stdout, req.Stderr),
	})
}

// buildTUITakeover 构造 TUI 终端接管回调：调用 Engine.InteractiveSSH 启动交互式远端 Shell，
// 并对封闭和类型 ExecutionOutcome 执行穷尽失败关闭判定，避免将空命令误送入 Exec 触发 ErrInvalidRequest。
func buildTUITakeover(eng *engine.Engine, stdin io.Reader, stdout, stderr io.Writer) tui.TakeoverFunc {
	return func(tCtx context.Context, tReq tui.TakeoverRequest) error {
		target := strings.TrimSpace(tReq.TargetSpec)
		if target == "" {
			target = strings.TrimSpace(tReq.NodeID)
		}
		out, sshErr := eng.InteractiveSSH(tCtx, engine.InteractiveSSHRequest{
			TargetSpec: target,
			Stdin:      stdin,
			Stdout:     stdout,
			Stderr:     stderr,
			RequestTTY: engine.RequestTTYAuto,
		})
		if sshErr != nil {
			return sshErr
		}
		return checkTakeoverOutcome(out)
	}
}

func checkTakeoverOutcome(out execution.ExecutionOutcome) error {
	switch v := out.(type) {
	case *execution.OutcomeCompleted:
		if !v.IsValid() {
			return errors.New("interactive ssh takeover returned invalid completed outcome")
		}
		return nil
	case *execution.OutcomeNotStarted:
		return fmt.Errorf("interactive ssh takeover not started (%s/%s): %s", v.Phase(), v.Code(), v.Reason())
	case *execution.OutcomeUnknown:
		return fmt.Errorf("interactive ssh takeover outcome unknown (%s/%s): %s", v.Phase(), v.Code(), v.Reason())
	default:
		return errors.New("interactive ssh takeover returned unexpected outcome")
	}
}

// runSFTPShellSubEntry 装配完整 CLI 运行期与基于 ScopedRootFS 的本机目录适配器，启动交互式 SFTP Shell。
func runSFTPShellSubEntry(ctx context.Context, req cli.SFTPShellStartRequest) (retErr error) {
	rt, err := wireRuntime(ctx, req.InitOptions, runtimeModeCLI, req.Stdin, req.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, rt.Close(ctx)) }()

	var initRemote algebraic.Option[pathalg.RemotePath]
	if trimmed := strings.TrimSpace(req.InitialDir); trimmed != "" {
		rp, pErr := pathalg.ParseRemotePath(trimmed)
		if pErr != nil {
			return fmt.Errorf("invalid initial remote dir %q: %w", req.InitialDir, pErr)
		}
		initRemote = algebraic.Some(rp)
	}
	var initLocal algebraic.Option[pathalg.LocalDir]
	if wd, wdErr := resolveWorkDir(); wdErr == nil && wd.IsValid() {
		initLocal = algebraic.Some(wd)
	}

	return sftpshell.Run(ctx, sftpshell.Config{
		Engine:           rt.engine,
		TargetSpec:       req.TargetSpec,
		CLIOptions:       req.CLIOptions,
		Stdin:            req.Stdin,
		Stdout:           req.Stdout,
		Stderr:           req.Stderr,
		InitialRemoteDir: initRemote,
		InitialLocalDir:  initLocal,
		LocalFS:          newScopedLocalFSAdapter(rt.scopedFS),
		SymlinkPolicy:    pathalg.SymlinkFollowOperatorSource,
		ShowProgress:     true,
	})
}

// runMCPSubEntry 装配零 OperatorReadFS 的严格 MCP 运行期，委托 internal/entry/mcpcmd 启动服务并逆序收尾。
func runMCPSubEntry(ctx context.Context, req cli.MCPStartRequest, buildInfo cli.BuildInfo) (retErr error) {
	transport, err := mcpcmd.ParseTransportKind(req.Transport)
	if err != nil {
		return err
	}
	rt, err := wireRuntime(ctx, req.InitOptions, runtimeModeMCP, req.Stdin, req.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, rt.Close(ctx)) }()

	return mcpcmd.Run(ctx, mcpcmd.Config{
		Engine: rt.engine,
		ServerConfig: engine.MCPConfig{
			ServerName:           "xops-mcp",
			ServerVersion:        buildInfo.Normalized().Version,
			TransferRoot:         req.TransferRoot,
			ArtifactRoot:         req.ArtifactRoot,
			AllowNonLoopbackHTTP: req.AllowNonLoopbackHTTP,
			HTTPAllowedOrigins:   req.HTTPAllowedOrigins,
			HTTPAllowedHosts:     req.HTTPAllowedHosts,
		},
		Transport:  transport,
		ListenAddr: req.ListenAddr,
		Stdin:      req.Stdin,
		Stdout:     req.Stdout,
		Stderr:     req.Stderr,
	})
}

// runMuxDaemonSubEntry 装配完整 CLI 运行期并启动受 Nursery 监督的 ControlMaster/ControlPersist 守护进程。
// 后台守护进程无交互标准输入，因此传入空 Reader；若策略要求 ControlMaster=ask/autoask 将自动失败关闭。
func runMuxDaemonSubEntry(ctx context.Context, req cli.MuxDaemonStartRequest) (retErr error) {
	rt, err := wireRuntime(ctx, req.InitOptions, runtimeModeCLI, strings.NewReader(""), req.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, rt.Close(ctx)) }()

	return muxdaemon.Run(ctx, muxdaemon.Config{
		Client:     rt.engine,
		TargetSpec: req.TargetSpec,
		CLIOptions: req.CLIOptions,
		SocketPath: req.SocketPath,
		Forwards:   req.Forwards,
		Stdout:     req.Stdout,
		Stderr:     req.Stderr,
	})
}

// readAuditLogHook 经 ScopedRootFS + 共享旁路锁只读检索本地 audit.jsonl，支持条件过滤与分页/尾部裁剪。
func readAuditLogHook(ctx context.Context, req cli.AuditQueryRequest) (cli.AuditQueryResult, error) {
	if ctx == nil {
		return cli.AuditQueryResult{}, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return cli.AuditQueryResult{}, err
	}
	scopedFS := osfs.NewScopedRootFS()
	env := newHomeAwareEnv(sys.NewSystemEnv())
	homeDir, stateDir, _, err := resolveHostDirs(env)
	if err != nil {
		return cli.AuditQueryResult{}, err
	}
	auditRoot, auditDest, err := resolveAuditReadTarget(ctx, scopedFS, stateDir, homeDir)
	if err != nil {
		return cli.AuditQueryResult{}, err
	}
	return readAndFilterAuditLog(ctx, scopedFS, auditRoot, auditDest, req)
}

func resolveAuditReadTarget(
	ctx context.Context,
	scopedFS ports.ScopedRootFS,
	stateDir, homeDir pathalg.LocalDir,
) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	invStore, err := store.NewYAMLInventoryStore(store.InventoryStoreSpec{
		ScopedFS: scopedFS,
		RootDir:  stateDir,
	})
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	doc, _, err := invStore.LoadDocument(ctx)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	auditRoot, auditFileOpt, err := resolveAuditLocation(stateDir, homeDir, doc.Policy)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	if dest, ok := auditFileOpt.Get(); ok {
		return auditRoot, dest, nil
	}
	defDest, err := pathalg.ParseLocalRootedDest(auditFileNameDefault)
	return auditRoot, defDest, err
}

func readAndFilterAuditLog(
	ctx context.Context,
	scopedFS ports.ScopedRootFS,
	auditRoot pathalg.LocalDir,
	auditDest pathalg.LocalRootedDest,
	req cli.AuditQueryRequest,
) (cli.AuditQueryResult, error) {
	limits, err := ports.NewReadLimits(defaultAuditReadMaxBytes)
	if err != nil {
		return cli.AuditQueryResult{}, err
	}
	var raw []byte
	readErr := scopedFS.WithRoot(auditRoot, func(root ports.RootHandle) error {
		if _, stErr := root.Lstat(auditDest); stErr != nil {
			return stErr
		}
		return osfs.WithSidecarLock(ctx, root, auditDest, ports.LockShared, 0o600, func(ports.LockedFile) error {
			var rErr error
			raw, rErr = root.ReadAllBounded(auditDest, limits)
			return rErr
		})
	})
	if errors.Is(readErr, ports.ErrNotFound) {
		return cli.AuditQueryResult{}, nil
	}
	if readErr != nil {
		return cli.AuditQueryResult{}, fmt.Errorf("read audit log failed: %w", readErr)
	}
	return filterAuditRecords(raw, req)
}

func filterAuditRecords(raw []byte, req cli.AuditQueryRequest) (cli.AuditQueryResult, error) {
	var matched []cli.AuditRecordView
	lineNo := 0
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		lineNo++
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry ports.AuditEntry
		if err := jsonv2.Unmarshal(trimmed, &entry); err != nil {
			return cli.AuditQueryResult{}, fmt.Errorf("audit log line %d invalid: %w", lineNo, err)
		}
		if matchesAuditFilter(entry, req) {
			matched = append(matched, auditEntryToView(entry))
		}
	}
	total := len(matched)
	truncated := false
	if req.Limit > 0 && len(matched) > req.Limit {
		truncated = true
		if req.Tail {
			matched = matched[len(matched)-req.Limit:]
		} else {
			matched = matched[:req.Limit]
		}
	}
	return cli.AuditQueryResult{
		TotalMatched: total,
		Truncated:    truncated,
		Entries:      matched,
	}, nil
}

func matchesAuditFilter(entry ports.AuditEntry, req cli.AuditQueryRequest) bool {
	if p := strings.TrimSpace(req.Phase); p != "" && !strings.EqualFold(entry.Phase().String(), p) {
		return false
	}
	if o := strings.TrimSpace(req.Outcome); o != "" && !strings.EqualFold(entry.Outcome().String(), o) {
		return false
	}
	if opID, ok := req.OperationID.Get(); ok && !entry.OperationID().Equal(opID) {
		return false
	}
	if traceID, ok := req.TraceID.Get(); ok && !entry.TraceID().Equal(traceID) {
		return false
	}
	if node := strings.TrimSpace(req.NodeID); node != "" && !strings.EqualFold(entry.Binding().NodeID(), node) {
		return false
	}
	return true
}

func auditEntryToView(entry ports.AuditEntry) cli.AuditRecordView {
	b := entry.Binding()
	return cli.AuditRecordView{
		ProcessID:   entry.ProcessID().String(),
		TraceID:     entry.TraceID(),
		OperationID: entry.OperationID(),
		Phase:       entry.Phase().String(),
		Outcome:     entry.Outcome().String(),
		Risk:        entry.Risk(),
		Decision:    entry.Decision(),
		Capability:  b.Capability(),
		Tool:        b.Tool(),
		Action:      b.Action(),
		NodeID:      b.NodeID(),
		Timestamp:   entry.Timestamp(),
		Duration:    entry.Duration(),
		ErrorCode:   entry.ErrorCode(),
		Reason:      entry.Reason(),
	}
}

// readOperatorFileHook 经 ports.OperatorReadFS 有界读取显式操作员本地文件，超限严格返回 engine.ErrLimitExceeded。
func readOperatorFileHook(
	ctx context.Context,
	srcPath pathalg.LocalSourcePath,
	policy pathalg.SymlinkPolicy,
	maxBytes int64,
) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultOperatorReadMaxBytes
	}
	readFS := osfs.NewOperatorReadFS()
	var data []byte
	err := readFS.WithOperatorRead(ctx, srcPath, policy, func(rd ports.BoundedReadHandle, size int64) error {
		if size > maxBytes {
			return fmt.Errorf("%w: 文件 %q 大小 %d 字节超过上限 %d 字节", engine.ErrLimitExceeded, srcPath.String(), size, maxBytes)
		}
		buf, rErr := io.ReadAll(io.LimitReader(rd, maxBytes+1))
		if rErr != nil {
			return rErr
		}
		if int64(len(buf)) > maxBytes {
			return fmt.Errorf("%w: 文件 %q 超过最大允许大小 %d 字节", engine.ErrLimitExceeded, srcPath.String(), maxBytes)
		}
		data = buf
		return nil
	})
	return data, err
}

// resolveWorkDir 经 filepath.Abs(".") 解析当前本地工作目录（避免直调受 osboundary 封禁的 os.Getwd）。
func resolveWorkDir() (pathalg.LocalDir, error) {
	abs, err := filepath.Abs(".")
	if err != nil {
		return zeroVal[pathalg.LocalDir](), fmt.Errorf("resolve working directory failed: %w", err)
	}
	return pathalg.ParseLocalDir(abs)
}

func envMapToSlice(env ports.EnvPort) []string {
	if env == nil {
		return nil
	}
	m := env.Environ()
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, k+"="+m[k])
	}
	return out
}
