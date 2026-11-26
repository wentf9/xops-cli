package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口契约断言集中于外置测试文件，验证全量仿真测试桩满足端口契约。
var (
	_ ports.DialerPort    = (*fullFacadeDialer)(nil)
	_ ports.TransportConn = (*fullFacadeConn)(nil)
	_ ports.RemoteSession = (*fullFacadeSession)(nil)
)

type fullFacadeDialer struct {
	inner     *sim.SimDialer
	remoteFS  *sim.SimRemoteFS
	mu        sync.Mutex
	lastStdin string
	onCmd     func(ctx context.Context, cmd execution.CommandPlan, stdout, stderr io.Writer) (execution.ExecutionOutcome, error)
}

func (d *fullFacadeDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if wrapped, ok := parent.(*fullFacadeConn); ok {
		parent = wrapped.TransportConn
	}
	conn, err := d.inner.DialHop(ctx, hop, dig, parent)
	if err != nil {
		return nil, err
	}
	return &fullFacadeConn{TransportConn: conn, owner: d}, nil
}

type fullFacadeConn struct {
	ports.TransportConn
	owner *fullFacadeDialer
}

// nonClosingRemoteFS 包装共享 SimRemoteFS，使单次用例操作退出调用 Close() 时不关闭整个测试共享的远端文件系统。
type nonClosingRemoteFS struct{ ports.RemoteFSPort }

func (nonClosingRemoteFS) Close() error { return nil }

func (c *fullFacadeConn) OpenRemoteFS(_ context.Context) (ports.RemoteFSPort, error) {
	if !c.IsAlive() {
		return nil, ports.ErrClosed
	}
	return nonClosingRemoteFS{RemoteFSPort: c.owner.remoteFS}, nil
}

func (c *fullFacadeConn) OpenSession(_ context.Context) (ports.RemoteSession, error) {
	if !c.IsAlive() {
		return nil, ports.ErrClosed
	}
	return &fullFacadeSession{owner: c.owner}, nil
}

type fullFacadeSession struct {
	owner    *fullFacadeDialer
	mu       sync.Mutex
	started  bool
	isShell  bool
	doneCh   chan struct{}
	doneOnce sync.Once
	execOut  execution.ExecutionOutcome
	execErr  error
	echo     *facadeEchoBuf
}

type facadeEchoBuf struct {
	mu     sync.Mutex
	closed bool
	buf    bytes.Buffer
	notify chan struct{}
}

func (e *facadeEchoBuf) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, io.ErrClosedPipe
	}
	_, _ = e.buf.WriteString("pty:")
	n, _ := e.buf.Write(p)
	select {
	case e.notify <- struct{}{}:
	default:
	}
	return n, nil
}

func (e *facadeEchoBuf) Read(p []byte) (int, error) {
	for {
		e.mu.Lock()
		if e.buf.Len() > 0 {
			n, err := e.buf.Read(p)
			e.mu.Unlock()
			return n, err
		}
		closed := e.closed
		notify := e.notify
		e.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-notify
	}
}

func (e *facadeEchoBuf) Close() error {
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		close(e.notify)
	}
	e.mu.Unlock()
	return nil
}

func (s *fullFacadeSession) ensureEcho() *facadeEchoBuf {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.echo == nil {
		s.echo = &facadeEchoBuf{notify: make(chan struct{}, 1)}
	}
	return s.echo
}

func (s *fullFacadeSession) StdinPipe() (io.WriteCloser, error) { return s.ensureEcho(), nil }
func (s *fullFacadeSession) StdoutPipe() (io.Reader, error)     { return s.ensureEcho(), nil }
func (s *fullFacadeSession) StderrPipe() (io.Reader, error)     { return strings.NewReader(""), nil }
func (s *fullFacadeSession) ResizePTY(_ context.Context, _ ports.TerminalSize) error {
	return nil
}
func (s *fullFacadeSession) Signal(_ context.Context, _ string) error { return nil }

func (s *fullFacadeSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	s.mu.Lock()
	s.started = true
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	s.owner.mu.Lock()
	fn := s.owner.onCmd
	s.owner.mu.Unlock()
	if streams.Stdin != nil {
		rawIn, _ := io.ReadAll(io.LimitReader(streams.Stdin, 4096))
		s.owner.mu.Lock()
		s.owner.lastStdin = string(rawIn)
		s.owner.mu.Unlock()
	}

	outW := streams.Stdout
	if outW == nil {
		outW = io.Discard
	}
	errW := streams.Stderr
	if errW == nil {
		errW = io.Discard
	}
	if fn != nil {
		s.execOut, s.execErr = fn(ctx, cmd, outW, errW)
	} else {
		_, _ = io.WriteString(outW, "ok:"+cmd.Command()+"\n")
		s.execOut, s.execErr = execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	s.doneOnce.Do(func() { close(s.doneCh) })
	return nil
}

func (s *fullFacadeSession) StartShell(_ context.Context, streams ports.ExecStreams) error {
	s.ensureEcho()
	s.mu.Lock()
	s.started = true
	s.isShell = true
	if s.doneCh == nil {
		s.doneCh = make(chan struct{})
	}
	ch := s.doneCh
	s.mu.Unlock()
	if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, "shell-ok\n")
		s.doneOnce.Do(func() { close(ch) })
	}
	return nil
}

func (s *fullFacadeSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	s.mu.Lock()
	isShell := s.isShell
	ch := s.doneCh
	out := s.execOut
	err := s.execErr
	s.mu.Unlock()
	if !isShell {
		return out, err
	}
	select {
	case <-ch:
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fullFacadeSession) Close() error {
	s.mu.Lock()
	echo := s.echo
	ch := s.doneCh
	s.mu.Unlock()
	if echo != nil {
		_ = echo.Close()
	}
	if ch != nil {
		s.doneOnce.Do(func() { close(ch) })
	}
	return nil
}

type fullSimRig struct {
	clk          *sim.SimClock
	rng          *sim.SeededRand
	auditClust   *sim.SimAuditCluster
	auditSink    *sim.SimAuditSink
	scopedFS     *sim.SimScopedRootFS
	opReadFS     *sim.SimOperatorReadFS
	remoteFS     *sim.SimRemoteFS
	invStore     *sim.SimInventoryStore
	journalStore *sim.SimJournalStore
	vault        *sim.SimVault
	dialer       *fullFacadeDialer
	transferRoot pathalg.LocalDir
	artifactRoot pathalg.LocalDir
	haltCount    atomic.Int32
	eng          *engine.Engine
}

func newFullSimRig(t *testing.T, profile engine.PolicyProfile, threshold security.RiskLevel, withOpReadFS bool) *fullSimRig {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261126)
	auditClust := sim.NewSimAuditCluster()
	auditSink, err := auditClust.NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	scopedFS := sim.NewSimScopedRootFS(clk)
	remoteFS := sim.NewSimRemoteFS(clk)
	for _, dir := range []string{"/tmp", "/srv", "/work", "/stream", "/py"} {
		rp, _ := pathalg.ParseRemotePath(dir)
		if err := remoteFS.MkdirAll(context.Background(), rp, 0o755); err != nil {
			t.Fatalf("remoteFS.MkdirAll(%s): %v", dir, err)
		}
	}
	var emptyGraph inventory.Graph
	invStore, err := sim.NewSimInventoryStore(emptyGraph)
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	journalStore := sim.NewSimJournalStore()
	vault := sim.NewSimVault(rng.Fork())
	innerDialer := sim.NewSimDialer(clk, rng.Fork())
	dialer := &fullFacadeDialer{inner: innerDialer, remoteFS: remoteFS}

	transferRoot, _ := pathalg.ParseLocalDir("/engine-sandbox/transfers")
	artifactRoot, _ := pathalg.ParseLocalDir("/engine-sandbox/artifacts")
	if err := scopedFS.EnsureRoot(transferRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot transfer: %v", err)
	}
	if err := scopedFS.EnsureRoot(artifactRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot artifact: %v", err)
	}

	var opReadFS *sim.SimOperatorReadFS
	var opReadPort ports.OperatorReadFS
	if withOpReadFS {
		opReadFS = sim.NewSimOperatorReadFS()
		opReadPort = opReadFS
	}

	rig := &fullSimRig{
		clk: clk, rng: rng, auditClust: auditClust, auditSink: auditSink,
		scopedFS: scopedFS, opReadFS: opReadFS, remoteFS: remoteFS,
		invStore: invStore, journalStore: journalStore, vault: vault,
		dialer: dialer, transferRoot: transferRoot, artifactRoot: artifactRoot,
	}

	gCfg := engine.DefaultGuardrailConfig()
	gCfg.ApprovalThreshold = threshold
	gCfg.NoElicitFallback = engine.NoElicitFallbackChallenge

	interact := sim.NewSimInteractionPort(true)
	interact.SetApprovalPolicy(security.VerdictAllow, nil, false)
	var zeroLocalID ports.LocalIdentityInfo
	var zeroProbe ports.ShellProbeResult

	eng, err := engine.New(engine.Config{
		Profile:             profile,
		Guardrail:           gCfg,
		Clock:               clk,
		Entropy:             rng.Fork(),
		AuditSink:           auditSink,
		Reconciler:          auditClust,
		Interaction:         interact,
		ScopedFS:            scopedFS,
		OperatorReadFS:      opReadPort,
		HostTrust:           sim.NewSimHostTrust(),
		Env:                 sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroLocalID),
		Vault:               vault,
		VaultControl:        vault,
		InventoryStore:      invStore,
		JournalStore:        journalStore,
		Importers:           []ports.FormatImporter{sim.NewSimFormatImporter("csv")},
		KnownStores:         []string{"vault"},
		PrivilegeEscalation: sim.NewSimPrivilegeEscalator(),
		ShellProbe:          sim.NewSimShellProbe(zeroProbe),
		Forwarder:           sim.NewSimForwarder(),
		TUNDevice:           sim.NewSimTUNDevicePort(),
		MuxSocket:           sim.NewSimMuxSocket(innerDialer),
		Dialer:              dialer,
		OnHalt:              func(_ engine.HaltInfo) { rig.haltCount.Add(1) },
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	rig.eng = eng
	return rig
}

func (r *fullSimRig) close(t *testing.T) {
	t.Helper()
	if err := r.eng.Close(context.Background()); err != nil {
		t.Errorf("Engine.Close: %v", err)
	}
	_ = r.auditSink.Close()
}

func TestEngine_FullFacade_AllSixUsecasesAndProjection(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSimRig(t, engine.PolicyProfileDirectOperator, security.RiskDangerous, true)
	defer rig.close(t)
	ctx := context.Background()

	secRef := assertFacadeInventoryAndCred(t, ctx, rig)
	_ = secRef
	assertFacadeSession(t, ctx, rig)
	assertFacadeTransfer(t, ctx, rig)
	assertFacadeAutoObsAndProjection(t, ctx, rig)
}

func assertFacadeInventoryAndCred(t *testing.T, ctx context.Context, rig *fullSimRig) secret.Ref {
	t.Helper()
	hID, _ := inventory.ParseHostID("h1")
	ep, _ := netaddr.ParseEndpoint("10.10.0.1:22")
	hostObj, err := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if _, err := rig.eng.CreateHost(ctx, engine.HostMutationRequest{Host: hostObj}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	idID, _ := inventory.ParseIdentityID("id1")
	secRef, _ := secret.NewRef("vault", "pass-1")
	if err := secret.WithBytes([]byte("s3cr3t-v1"), func(box *secret.SecretBox) error {
		return rig.vault.PutAndVerify(ctx, secRef, box)
	}); err != nil {
		t.Fatalf("PutAndVerify: %v", err)
	}
	userOps, _ := option.ParseUsername("ops")
	authPass, err := inventory.NewAuthPassword(secRef)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	identObj, err := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: userOps, Auth: authPass})
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if _, err := rig.eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: identObj}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	nID, _ := inventory.ParseNodeID("app-1")
	nodeObj, err := inventory.NewNode(inventory.NodeSpec{
		ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged(),
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if _, err := rig.eng.CreateNode(ctx, engine.NodeMutationRequest{Node: nodeObj}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	assertFacadeInventoryQueriesAndVault(t, ctx, rig, secRef)
	return secRef
}

func assertFacadeInventoryQueriesAndVault(t *testing.T, ctx context.Context, rig *fullSimRig, secRef secret.Ref) {
	t.Helper()
	if nodes, _, err := rig.eng.ListNodes(ctx, engine.InventoryQueryRequest{}); err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes: len=%d err=%v", len(nodes), err)
	}
	if _, err := rig.eng.ValidateDAG(ctx, engine.InventoryQueryRequest{}); err != nil {
		t.Fatalf("ValidateDAG: %v", err)
	}
	if _, err := rig.eng.InventoryDoctor(ctx, engine.InventoryDoctorRequest{CheckVaultSecrets: true}); err != nil {
		t.Fatalf("InventoryDoctor: %v", err)
	}
	if fmts := rig.eng.SupportedImportFormats(); len(fmts) != 1 || fmts[0] != "csv" {
		t.Fatalf("SupportedImportFormats: %v", fmts)
	}
	if _, err := rig.eng.PlanImport(ctx, engine.ImportRequest{
		Format: "csv", SourceName: "a.csv", Reader: strings.NewReader("n2,10.10.0.2,22,ops\n"),
	}); err != nil {
		t.Fatalf("PlanImport: %v", err)
	}

	st, err := rig.eng.VaultStatus(ctx, engine.VaultOpRequest{})
	if err != nil || st.State() != ports.VaultStateUnlocked {
		t.Fatalf("VaultStatus: st=%+v err=%v", st, err)
	}
	var gotValidBox bool
	if err := rig.eng.WithSecret(ctx, engine.WithSecretRequest{Ref: secRef}, func(box *secret.SecretBox) error {
		gotValidBox = box.IsValid()
		return nil
	}); err != nil || !gotValidBox {
		t.Fatalf("WithSecret: ok=%v err=%v", gotValidBox, err)
	}
	newRef, _ := secret.NewRef("vault", "pass-2")
	var rotRes engine.SagaResult
	if err := secret.WithBytes([]byte("s3cr3t-v2"), func(box *secret.SecretBox) error {
		var rErr error
		rotRes, rErr = rig.eng.RotateSecret(ctx, engine.RotateSecretRequest{OldRef: secRef, NewRef: newRef}, box)
		return rErr
	}); err != nil || rotRes.NewRef() != newRef {
		t.Fatalf("RotateSecret: res=%+v err=%v", rotRes, err)
	}
	if _, err := rig.eng.VaultDoctor(ctx, engine.VaultDoctorRequest{SkipSecretProbe: false}); err != nil {
		t.Fatalf("VaultDoctor: %v", err)
	}
}

func assertFacadeSession(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "app-1"}}
	privCmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: "id",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan: %v", err)
	}
	privReq, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method: ports.PrivilegeMethodSudo, Command: privCmd, NonInteractive: true,
	})
	if err != nil {
		t.Fatalf("NewPrivilegeRequest: %v", err)
	}
	if _, err := rig.eng.ExecPrivileged(ctx, engine.PrivilegeExecRequest{RemoteCall: rc, Privilege: privReq}); err != nil {
		t.Fatalf("ExecPrivileged: %v", err)
	}
	if _, err := rig.eng.ProbeShell(ctx, engine.ProbeShellRequest{RemoteCall: rc}); err != nil {
		t.Fatalf("ProbeShell: %v", err)
	}
	ptyH, err := rig.eng.OpenPTY(ctx, engine.OpenPTYRequest{RemoteCall: rc, Term: "xterm-256color"})
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	if _, err := rig.eng.WritePTY(ctx, ptyH, []byte("ping\n")); err != nil {
		t.Fatalf("WritePTY: %v", err)
	}
	if rdRes, err := rig.eng.ReadPTY(ctx, engine.PTYReadRequest{Handle: ptyH, MaxBytes: 128, Wait: true}); err != nil || !strings.Contains(string(rdRes.Data()), "pty:ping") {
		t.Fatalf("ReadPTY: res=%+v err=%v", rdRes, err)
	}
	if err := rig.eng.ClosePTY(ctx, ptyH); err != nil {
		t.Fatalf("ClosePTY: %v", err)
	}

	fwdSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.10.0.1:8080")
	fwdInfo, err := rig.eng.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: fwdSpec})
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	if err := rig.eng.StopForward(ctx, fwdInfo.Handle()); err != nil {
		t.Fatalf("StopForward: %v", err)
	}
}

func assertFacadeTransfer(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "app-1"}}
	localSrc, _ := pathalg.ParseLocalSourcePath("/home/ops/upload.txt")
	if err := rig.opReadFS.PutFile(localSrc, []byte("cli-operator-data")); err != nil {
		t.Fatalf("opReadFS.PutFile: %v", err)
	}
	upSrc, err := engine.NewOperatorUploadSource(localSrc, pathalg.SymlinkFollowOperatorSource)
	if err != nil {
		t.Fatalf("NewOperatorUploadSource: %v", err)
	}
	remDest, _ := pathalg.ParseRemotePath("/srv/upload.txt")
	if _, err := rig.eng.SCPUpload(ctx, engine.SCPUploadRequest{RemoteCall: rc, Source: upSrc, RemoteDest: remDest}); err != nil {
		t.Fatalf("SCPUpload: %v", err)
	}
	dlDest, _ := pathalg.ParseLocalRootedDest("dl/upload.txt")
	if _, err := rig.eng.SCPDownload(ctx, engine.SCPDownloadRequest{
		RemoteCall: rc, RemoteSource: remDest, LocalRoot: rig.transferRoot, LocalDest: dlDest,
	}); err != nil {
		t.Fatalf("SCPDownload: %v", err)
	}
	edit, _ := engine.NewTextEdit("cli-operator", "patched-op", false)
	if _, err := rig.eng.PatchRemoteFile(ctx, engine.RemoteFilePatchRequest{
		RemoteCall: rc, Path: remDest, Edits: []engine.TextEdit{edit},
	}); err != nil {
		t.Fatalf("PatchRemoteFile: %v", err)
	}
	if readOut, err := rig.eng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{RemoteCall: rc, Path: remDest}); err != nil || string(readOut.Content) != "patched-op-data" {
		t.Fatalf("ReadRemoteFile: content=%q err=%v", readOut.Content, err)
	}
}

func assertFacadeAutoObsAndProjection(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	resolved, err := rig.eng.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: "app-1"})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	batchCmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: "uptime",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan batch: %v", err)
	}
	if bRep, err := rig.eng.BatchExec(ctx, engine.BatchExecRequest{
		Targets: []engine.ResolvedTarget{resolved}, Command: batchCmd,
	}); err != nil || len(bRep.Results()) != 1 {
		t.Fatalf("BatchExec: rep=%+v err=%v", bRep, err)
	}
	s1ID, _ := playbook.ParseStepID("s1")
	s1Act, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "echo hi"})
	pbStep, _ := playbook.NewStep(playbook.StepSpec{ID: s1ID, Name: "s1", Action: s1Act})
	p1ID, _ := playbook.ParsePlaybookID("p1")
	p1Sel, _ := playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true})
	pb, _ := playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: p1ID, Name: "p1", OnError: playbook.OnErrorFailFast,
		Target: p1Sel, Steps: algebraic.NewNonEmpty(pbStep),
	})
	if _, err := rig.eng.RunPlaybook(ctx, engine.PlaybookRequest{Playbook: pb, Targets: []engine.ResolvedTarget{resolved}}); err != nil {
		t.Fatalf("RunPlaybook: %v", err)
	}

	var pngBuf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	img.Set(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	_ = png.Encode(&pngBuf, img)
	framed := "XOPS_GUI_SHOT_BEGIN_V2\n" + base64.StdEncoding.EncodeToString(pngBuf.Bytes()) + "\nXOPS_GUI_SHOT_END_V2\n"
	rig.dialer.mu.Lock()
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, framed)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	rig.dialer.mu.Unlock()
	artFile, _ := pathalg.ParseLocalRootedDest("shot.png")
	shotKind, _ := engine.ParseGUIActionKind("screenshot")
	if guiRes, err := rig.eng.ExecuteGUI(ctx, engine.GUIExecRequest{
		RemoteCall: engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "app-1"}},
		Spec:       engine.GUIActionSpec{Action: shotKind, Display: ":1"},
		Artifact:   algebraic.Some(engine.GUIArtifactDest{RootDir: rig.artifactRoot, File: artFile}),
	}); err != nil || guiRes.Screenshot().IsNone() {
		t.Fatalf("ExecuteGUI: err=%v", err)
	}
	proj, err := rig.eng.NewProjection(ctx, engine.ProjectionConfig{})
	if err != nil {
		t.Fatalf("NewProjection: %v", err)
	}
	if err := proj.Close(); err != nil {
		t.Fatalf("Projection.Close: %v", err)
	}
}

func TestEngine_MCPServerSandboxIsolationAndReverseShutdown(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSimRig(t, engine.PolicyProfileStrictAgent, security.RiskDangerous, true)
	defer rig.close(t)
	ctx := context.Background()

	hostSecretPath, _ := pathalg.ParseLocalSourcePath("/etc/operator-only.conf")
	if err := rig.opReadFS.PutFile(hostSecretPath, []byte("operator-only-secret")); err != nil {
		t.Fatalf("opReadFS.PutFile: %v", err)
	}
	opSrc, _ := engine.NewOperatorUploadSource(hostSecretPath, pathalg.SymlinkFollowOperatorSource)
	remDst, _ := pathalg.ParseRemotePath("/tmp/from-cli.conf")
	if _, err := rig.eng.SCPUpload(ctx, engine.SCPUploadRequest{
		RemoteCall: engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.10.0.1:22"}},
		Source:     opSrc, RemoteDest: remDst,
	}); err != nil {
		t.Fatalf("CLI SCPUpload 应成功: %v", err)
	}

	mcpSrv, err := rig.eng.NewMCPServer(engine.MCPConfig{
		TransferRoot: algebraic.Some(rig.transferRoot),
		ArtifactRoot: algebraic.Some(rig.artifactRoot),
	})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	if _, err := mcpSrv.Prepare(ctx); err != nil {
		t.Fatalf("MCPServer.Prepare: %v", err)
	}
	assertMCPSandboxBlocksOperatorCopy(t, ctx, mcpSrv, hostSecretPath, remDst)

	if err := rig.eng.Close(ctx); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if !mcpSrv.IsClosed() {
		t.Fatalf("Engine.Close 必须先关闭所有派生 MCPServer")
	}
	if _, err := rig.eng.NewMCPServer(engine.MCPConfig{}); !errors.Is(err, engine.ErrEngineClosed) {
		t.Fatalf("关闭后 NewMCPServer 必须返回 ErrEngineClosed，实际=%v", err)
	}
}

func assertMCPSandboxBlocksOperatorCopy(t *testing.T, ctx context.Context, mcpSrv *engine.MCPServer, localSrc pathalg.LocalSourcePath, remDst pathalg.RemotePath) {
	t.Helper()
	copyStepID, _ := playbook.ParseStepID("copy-attempt")
	copyAct, _ := playbook.NewStepCopy(playbook.StepCopySpec{
		Source: localSrc, SymlinkPolicy: pathalg.SymlinkFollowOperatorSource, Dest: remDst, Overwrite: true, Atomic: true,
	})
	pbStep, _ := playbook.NewStep(playbook.StepSpec{ID: copyStepID, Name: "copy-attempt", Action: copyAct})
	escID, _ := playbook.ParsePlaybookID("sandbox-escape")
	escSel, _ := playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true})
	pb, _ := playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: escID, Name: "sandbox-escape",
		OnError: playbook.OnErrorFailFast, Target: escSel, Steps: algebraic.NewNonEmpty(pbStep),
	})
	rawReq, _ := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "terminal_exec",
			"arguments": map[string]any{"action": "run_playbook", "targets": []string{"ops@10.10.0.1:22"}, "playbook": pb},
		},
	})
	respBytes, hasResp, err := mcpSrv.HandleMessage(ctx, rawReq)
	if err != nil || !hasResp {
		t.Fatalf("HandleMessage: hasResp=%v err=%v", hasResp, err)
	}
	if strings.Contains(string(respBytes), `"succeeded":true`) {
		t.Fatalf("MCP 沙箱绝不允许经 OperatorReadFS 读取宿主机文件: %s", respBytes)
	}
}

func TestEngine_Adversarial_DualGenRecoveryUncertainCommitCrashReconcileAndHalted(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSimRig(t, engine.PolicyProfileStrictAgent, security.RiskDangerous, false)
	defer rig.close(t)
	ctx := context.Background()

	crashedOp := seedCrashedSiblingAudit(t, ctx, rig)
	uncertainID, _ := security.ParseOperationID("op-eng-uncertain-1")
	upPath, _ := pathalg.ParseRemotePath("/srv/unc.bin")
	upDest, _ := fsm.NewUploadDest(upPath)
	seedEngineCommitStarted(t, rig.journalStore, uncertainID, upDest)
	beforeRecs, err := rig.journalStore.Load(ctx, uncertainID)
	if err != nil || len(beforeRecs) == 0 {
		t.Fatalf("Load before Prepare: len=%d err=%v", len(beforeRecs), err)
	}

	recRep, err := rig.eng.ReconcileCrashedAudits(ctx)
	if err != nil || recRep.DeadLocksClaimed() != 1 || len(recRep.AbortedOperations()) != 1 || recRep.AbortedOperations()[0] != crashedOp {
		t.Fatalf("ReconcileCrashedAudits 失配: rep=%+v err=%v", recRep, err)
	}
	mcpSrv, err := rig.eng.NewMCPServer(engine.MCPConfig{
		TransferRoot: algebraic.Some(rig.transferRoot),
		ArtifactRoot: algebraic.Some(rig.artifactRoot),
	})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	startRep, err := mcpSrv.Prepare(ctx)
	if err != nil {
		t.Fatalf("MCPServer.Prepare: %v", err)
	}
	if u := startRep.UncertainTransfers(); len(u) != 1 || u[0].TransferID != uncertainID {
		t.Fatalf("Prepare 未暴露 UncertainTransfers: %+v", u)
	}
	if recs, lErr := rig.journalStore.Load(ctx, uncertainID); lErr != nil || len(recs) != len(beforeRecs) {
		t.Fatalf("UncertainCommit 日志被篡改: after=%d before=%d err=%v", len(recs), len(beforeRecs), lErr)
	}
	assertHaltedRevokesAllFourHandleKinds(t, ctx, rig, mcpSrv)
	_ = time.UTC
}

func seedCrashedSiblingAudit(t *testing.T, ctx context.Context, rig *fullSimRig) security.OperationID {
	t.Helper()
	deadSink, err := rig.auditClust.NewSinkFromEntropy(rig.rng.Fork())
	if err != nil {
		t.Fatalf("deadSink: %v", err)
	}
	crashedOp, _ := security.ParseOperationID("op-eng-crash-1")
	crashedTID, _ := security.ParseTraceID("trace-eng-crash-1")
	binding, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapExecute](), Tool: "exec", Action: "exec", NodeID: "app-1",
	})
	if err := deadSink.StageOperation(ctx, crashedOp); err != nil {
		t.Fatalf("StageOperation: %v", err)
	}
	entry, _ := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: deadSink.ProcessInstanceID(), TraceID: crashedTID, OperationID: crashedOp,
		Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomePending,
		Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: binding,
		Timestamp: rig.clk.Now().UTC(), Reason: "authorized before crash",
	})
	if err := deadSink.Record(ctx, entry); err != nil {
		t.Fatalf("Record crashed: %v", err)
	}
	deadSink.SimulateSIGKILL()
	return crashedOp
}

func assertHaltedRevokesAllFourHandleKinds(t *testing.T, ctx context.Context, rig *fullSimRig, mcpSrv *engine.MCPServer) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.10.0.1:22"}}
	ptyH, err := rig.eng.OpenPTY(ctx, engine.OpenPTYRequest{RemoteCall: rc})
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	fwdSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.10.0.1:9000")
	fwdInfo, err := rig.eng.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: fwdSpec})
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	trPath, _ := pathalg.ParseRemotePath("/srv/live-tr.bin")
	trDest, _ := fsm.NewUploadDest(trPath)
	trInfo, err := rig.eng.StartTransfer(ctx, engine.StartTransferRequest{RemoteCall: rc, Dest: trDest, TotalBytes: 64})
	if err != nil {
		t.Fatalf("StartTransfer: %v", err)
	}
	x11Kind, _ := engine.ParseGUISessionKind("x11")
	guiInfo, err := rig.eng.OpenGUISession(ctx, engine.OpenGUISessionRequest{
		RemoteCall: rc, Spec: engine.GUISessionSpec{Kind: x11Kind, DisplayNum: 2},
	})
	if err != nil {
		t.Fatalf("OpenGUISession: %v", err)
	}

	rig.auditSink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			rig.auditClust.SetENOSPC(true)
		}
	})
	_, _ = rig.eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.10.0.1:22", Command: "boom"})
	rig.auditSink.SetBoundaryHook(nil)
	rig.auditClust.SetENOSPC(false)

	if !rig.eng.IsHalted() || rig.haltCount.Load() != 1 {
		t.Fatalf("Engine 必须进入 Halted 且 OnHalt 精确触发 1 次: halted=%v count=%d", rig.eng.IsHalted(), rig.haltCount.Load())
	}
	if _, ok := rig.eng.HaltInfo(); !ok {
		t.Fatalf("HaltInfo 应有效")
	}
	if _, err := rig.eng.WritePTY(ctx, ptyH, []byte("x")); err == nil {
		t.Fatalf("Halted 后 WritePTY 必须失败")
	}
	if _, err := rig.eng.InspectForward(ctx, fwdInfo.Handle()); err == nil {
		t.Fatalf("Halted 后 InspectForward 必须失败")
	}
	if _, err := rig.eng.WriteTransferChunk(ctx, engine.WriteTransferChunkRequest{
		RemoteCall: rc, Handle: trInfo.Handle, Offset: 0, Data: []byte("abcd"),
	}); !errors.Is(err, engine.ErrEngineHalted) {
		t.Fatalf("Halted 后 WriteTransferChunk 必须返回 ErrEngineHalted，实际=%v", err)
	}
	if _, err := rig.eng.InspectGUISession(ctx, guiInfo.Handle()); err == nil {
		t.Fatalf("Halted 后 InspectGUISession 必须失败")
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	mcpSrv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Halted 后 MCPServer HTTP 必须返回 503，实际=%d", rec.Code)
	}
}

func appendJournalEffects(t *testing.T, ctx context.Context, js *sim.SimJournalStore, effs []fsm.TransferEffect) {
	t.Helper()
	for _, ef := range effs {
		if rec, ok := ef.Record().Get(); ok {
			if err := js.Append(ctx, rec); err != nil {
				t.Fatalf("Append journal: %v", err)
			}
		}
	}
}

func seedEngineCommitStarted(t *testing.T, js *sim.SimJournalStore, id security.OperationID, dest fsm.TransferDest) {
	t.Helper()
	ctx := context.Background()
	meta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{
		TransferID: id, Dest: dest, TotalBytes: 4, JournalVersion: fsm.JournalVersionV2, Generation: 1,
	})
	if err != nil {
		t.Fatalf("NewTransferMeta: %v", err)
	}
	initSt, err := fsm.NewTransferState(meta)
	if err != nil {
		t.Fatalf("NewTransferState: %v", err)
	}
	var st fsm.TransferState = initSt
	inChunk, _ := fsm.TransferInputChunk(0, 4, security.DigestBytes([]byte("abcd")))
	vIn, _ := fsm.TransferInputVerifyResult(true, security.DigestBytes([]byte("abcd")), "")
	for _, in := range []fsm.TransferInput{fsm.TransferInputStart(), inChunk, vIn} {
		var effs []fsm.TransferEffect
		st, effs, _, err = fsm.TransitionTransfer(st, in)
		if err != nil {
			t.Fatalf("TransitionTransfer: %v", err)
		}
		appendJournalEffects(t, ctx, js, effs)
	}
}
