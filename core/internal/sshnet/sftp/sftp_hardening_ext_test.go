package sftp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/internal/sshnet/sftp"
	"github.com/wentf9/xops-cli/core/ports"
)

// TestSFTP_ReviewHardening_VersionWriteChunkFIFOAndFallbacks 覆盖全部审查强化回归项：
//   - SSH_FXP_VERSION=4 拒绝（仅接受严格 v3，#124 M4）；
//   - WriteChunk 预检拒绝根/目录/软链接/FIFO 且绝不发送 SSH_FXP_OPEN（#124 M3, #123 Nit 2）；
//   - WithReadFile 与 RenameAtomic(ExpectedAnchor) 对 FIFO/目录绝不发 SSH_FXP_OPEN 且精准返回语义错误（#123 M5）；
//   - ReadDir 空批次熔断防死循环（#123 m2）；
//   - hardlink@openssh.com OP_UNSUPPORTED 平滑回退 SFTP v3 RENAME（#123 m4）；
//   - ReadChunk 拒绝超长 SSH_FXP_DATA（#124 m2）。
func TestSFTP_ReviewHardening_VersionWriteChunkFIFOAndFallbacks(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	t.Run("RejectSFTPv4Handshake", func(t *testing.T) {
		verifyRejectVersion4(t, ctx)
	})
	t.Run("WriteChunkAndFIFOSafety", func(t *testing.T) {
		verifyWriteChunkAndFIFOSafety(t, ctx)
	})
	t.Run("ReadDirEmptyBatchHardlinkFallbackAndOversizedRead", func(t *testing.T) {
		verifyReadDirHardlinkAndOversized(t, ctx)
	})
}

func verifyRejectVersion4(t *testing.T, ctx context.Context) {
	t.Helper()
	srv := newStubSFTPServer(stubSFTPServerOpts{protoVersion: 4})
	cliConn, srvConn := net.Pipe()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			srv.serve(srvConn)
			return nil
		}); gErr != nil {
			return gErr
		}
		_, oErr := sftp.OpenStream(ctx, cliConn, sftp.Config{})
		_ = cliConn.Close()
		if !errors.Is(oErr, ports.ErrUnsupported) {
			return errors.New("SSH_FXP_VERSION=4 必须返回 ErrUnsupported")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("v4 拒绝校验失败: %v", err)
	}
}

func verifyWriteChunkAndFIFOSafety(t *testing.T, ctx context.Context) {
	t.Helper()
	cli, srv := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true}, sftp.Config{})
	defer func() { _ = cli.Close() }()

	if err := cli.MkdirAll(ctx, mustParseRemotePath(t, "/guard/sub"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	srv.putRegularFile("/guard/real.txt", []byte("real-content"))
	srv.putSymlink("/guard/link.txt", "/guard/real.txt")
	srv.putSymlink("/guard/dangling.txt", "/guard/nonexistent.txt")
	srv.putFIFO("/guard/pipe.fifo")

	// 1. WriteChunk 拒绝根目录、目录、有效软链接、悬空软链接与 FIFO，且零 SSH_FXP_OPEN。
	checkWriteChunkErr(t, ctx, cli, "/", ports.ErrRemoteIsDir)
	checkWriteChunkErr(t, ctx, cli, "/guard/sub", ports.ErrRemoteIsDir)
	checkWriteChunkErr(t, ctx, cli, "/guard/link.txt", ports.ErrSymlinkRejected)
	checkWriteChunkErr(t, ctx, cli, "/guard/dangling.txt", ports.ErrSymlinkRejected)
	checkWriteChunkErr(t, ctx, cli, "/guard/pipe.fifo", ports.ErrNotRegularFile)

	// 2. WithReadFile 与 RenameAtomic(ExpectedAnchor) 对 FIFO/目录绝不触发 SSH_FXP_OPEN。
	lim, _ := ports.NewReadLimits(1024)
	if err := cli.WithReadFile(ctx, mustParseRemotePath(t, "/guard/pipe.fifo"), lim, func(io.Reader, int64) error { return nil }); !errors.Is(err, ports.ErrNotRegularFile) {
		t.Fatalf("WithReadFile(FIFO) = %v, 期望 ErrNotRegularFile", err)
	}
	realStat, err := cli.Lstat(ctx, mustParseRemotePath(t, "/guard/real.txt"))
	if err != nil {
		t.Fatalf("Lstat(real): %v", err)
	}
	renSpec, _ := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: algebraic.Some(realStat.Anchor())})
	if err := cli.RenameAtomic(ctx, mustParseRemotePath(t, "/guard/real.txt"), mustParseRemotePath(t, "/guard/sub"), renSpec); !errors.Is(err, ports.ErrRemoteAnchorMismatch) {
		t.Fatalf("RenameAtomic 目标为目录时期望 ErrRemoteAnchorMismatch，实际 %v", err)
	}
	if err := cli.RenameAtomic(ctx, mustParseRemotePath(t, "/guard/real.txt"), mustParseRemotePath(t, "/guard/pipe.fifo"), renSpec); !errors.Is(err, ports.ErrRemoteAnchorMismatch) {
		t.Fatalf("RenameAtomic 目标为 FIFO 时期望 ErrRemoteAnchorMismatch，实际 %v", err)
	}
	for _, forbidden := range []string{"/guard/link.txt", "/guard/dangling.txt", "/guard/pipe.fifo", "/guard/sub"} {
		if srv.openedPath(forbidden) {
			t.Fatalf("不得向非法目标 %q 发送 SSH_FXP_OPEN", forbidden)
		}
	}
}

func checkWriteChunkErr(t *testing.T, ctx context.Context, cli *sftp.Client, raw string, want error) {
	t.Helper()
	err := cli.WriteChunk(ctx, mustParseRemotePath(t, raw), 0, strings.NewReader("evil"), 4)
	if !errors.Is(err, want) {
		t.Fatalf("WriteChunk(%q) = %v, 期望 %v", raw, err, want)
	}
}

func verifyReadDirHardlinkAndOversized(t *testing.T, ctx context.Context) {
	t.Helper()
	// 1. ReadDir 空批次熔断防无限自旋。
	emptyCli, _ := openStubSFTPClient(t, stubSFTPServerOpts{emptyReadDirOnce: true}, sftp.Config{})
	if _, err := emptyCli.ReadDir(ctx, mustParseRemotePath(t, "/")); !errors.Is(err, ports.ErrCorruptData) {
		_ = emptyCli.Close()
		t.Fatalf("空批次 ReadDir = %v, 期望 ErrCorruptData", err)
	}
	_ = emptyCli.Close()

	// 2. hardlink@openssh.com 返回 OP_UNSUPPORTED 时平滑回退非覆写 SFTP v3 RENAME。
	hlCli, _ := openStubSFTPClient(t, stubSFTPServerOpts{emitDevIno: true, failHardlinkUnsupported: true}, sftp.Config{})
	if err := hlCli.MkdirAll(ctx, mustParseRemotePath(t, "/hl"), 0o755); err != nil {
		_ = hlCli.Close()
		t.Fatalf("MkdirAll: %v", err)
	}
	ncSpec, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o600, NoClobber: true, AtomicRename: true})
	if _, err := hlCli.WriteFileAtomic(ctx, mustParseRemotePath(t, "/hl/one.txt"), ncSpec, strings.NewReader("ok")); err != nil {
		_ = hlCli.Close()
		t.Fatalf("hardlink OP_UNSUPPORTED 回退 RENAME 应成功: %v", err)
	}
	_ = hlCli.Close()

	// 3. ReadChunk 拒绝超长 SSH_FXP_DATA。
	overCli, overSrv := openStubSFTPClient(t, stubSFTPServerOpts{oversizedRead: true}, sftp.Config{})
	overSrv.putRegularFile("/over.txt", []byte("0123456789"))
	var dst bytes.Buffer
	if _, err := overCli.ReadChunk(ctx, mustParseRemotePath(t, "/over.txt"), 0, &dst, 4); !errors.Is(err, ports.ErrCorruptData) {
		_ = overCli.Close()
		t.Fatalf("超长 SSH_FXP_DATA ReadChunk = %v, 期望 ErrCorruptData", err)
	}
	_ = overCli.Close()
}
