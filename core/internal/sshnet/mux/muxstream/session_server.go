package muxstream

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

type startedSessionIO struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR io.Reader
	stderrR io.Reader
}

// ServeSessionBridge 在服务端将单条 AF_UNIX 帧流桥接至上游 ports.RemoteSession，
// 全程受 core/conc.Nursery 与 chanconn.RunWithAbortWatchdog 监督（0 裸 go，零泄漏）。
func ServeSessionBridge(ctx context.Context, conn net.Conn, sess ports.RemoteSession) {
	fw := NewSyncFrameWriter(conn)
	var (
		msgType uint32
		body    []byte
	)
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		t, b, err := ReadPacket(conn)
		if err != nil {
			return err
		}
		msgType, body = t, b
		return nil
	}); err != nil {
		return
	}
	ioSet, err := claimAndStartRemoteSession(ctx, sess, msgType, body)
	if err != nil {
		_ = fw.Write(SessMsgStarted, AppendStr(AppendU32(nil, 0), err.Error()))
		GracefulHalfClose(conn, DefaultHalfCloseDrainTimeout)
		return
	}
	defer func() {
		_ = ioSet.stdinR.Close()
		_ = ioSet.stdinW.Close()
	}()
	if err := fw.Write(SessMsgStarted, AppendStr(AppendU32(nil, 1), "")); err != nil {
		return
	}
	runSessionPumps(ctx, conn, fw, sess, ioSet)
}

func claimAndStartRemoteSession(ctx context.Context, sess ports.RemoteSession, msgType uint32, body []byte) (startedSessionIO, error) {
	stdoutR, e1 := sess.StdoutPipe()
	stderrR, e2 := sess.StderrPipe()
	if err := FirstErr(e1, e2); err != nil {
		return startedSessionIO{}, err
	}
	// 通过 io.Pipe 将复用 stdin 经 ExecStreams.Stdin 注入，兼顾普通命令、PlanKindScript 与 StartShell（避免 StdinPipe 冲突）；
	// 同时将 inR 交由 runSessionPumps 统一托管关闭，确保远端进程不读 stdin 提前退出时绝不阻塞 stdinW.Write。
	inR, inW := io.Pipe()
	rd := NewReader(body)
	var startErr error
	switch msgType {
	case SessMsgStartExec:
		startErr = startExecOnUpstream(ctx, sess, &rd, inR)
	case SessMsgStartShell:
		startErr = startShellOnUpstream(ctx, sess, &rd, inR)
	default:
		startErr = fmt.Errorf("%w: 会话首帧非法 %#x", ports.ErrCorruptData, msgType)
	}
	if startErr != nil {
		_ = inR.Close()
		_ = inW.Close()
		return startedSessionIO{}, startErr
	}
	return startedSessionIO{stdinR: inR, stdinW: inW, stdoutR: stdoutR, stderrR: stderrR}, nil
}

func startExecOnUpstream(ctx context.Context, sess ports.RemoteSession, rd *Reader, inR io.Reader) error {
	rawCmd, err := rd.ReadBytes()
	if err != nil {
		return err
	}
	cmd, err := DecodeCommandPlan(rawCmd)
	if err != nil {
		return err
	}
	ptyOpt, env, err := DecodePTYAndEnv(rd)
	if err != nil {
		return err
	}
	return sess.Start(ctx, cmd, ports.ExecStreams{Stdin: inR, PTY: ptyOpt, Env: env})
}

func startShellOnUpstream(ctx context.Context, sess ports.RemoteSession, rd *Reader, inR io.Reader) error {
	ptyOpt, env, err := DecodePTYAndEnv(rd)
	if err != nil {
		return err
	}
	return sess.StartShell(ctx, ports.ExecStreams{Stdin: inR, PTY: ptyOpt, Env: env})
}

func runSessionPumps(ctx context.Context, conn net.Conn, fw *SyncFrameWriter, sess ports.RemoteSession, ioSet startedSessionIO) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = conc.RunScoped(sessCtx, func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error {
			<-c.Done()
			_ = ioSet.stdinR.Close()
			_ = ioSet.stdinW.Close()
			_ = sess.Close()
			_ = conn.Close()
			return nil
		})
		clientReadDone := make(chan struct{})
		_ = n.Go(func(c context.Context) error {
			defer close(clientReadDone)
			defer func() { _ = ioSet.stdinW.Close() }()
			pumpClientSessionFrames(c, conn, fw, sess, ioSet.stdinW, cancel)
			return nil
		})
		outDone := make(chan struct{})
		_ = n.Go(func(context.Context) error {
			defer close(outDone)
			_ = conc.RunWait(wCtx, func(_ context.Context, pn *conc.Nursery) error {
				_ = pn.Go(func(context.Context) error {
					pumpRemoteOutputFrames(fw, ioSet.stdoutR, SessMsgStdoutData, SessMsgStdoutEOF)
					return nil
				})
				pumpRemoteOutputFrames(fw, ioSet.stderrR, SessMsgStderrData, SessMsgStderrEOF)
				return nil
			})
			return nil
		})
		outcome, waitErr := sess.Wait(wCtx)
		// 远端进程已退出，立即关闭 stdinR 以解阻任何仍在等待的 stdinW.Write（防快速退出命令不读 stdin 死锁）。
		_ = ioSet.stdinR.Close()
		<-outDone
		if payload, pErr := EncodeOutcomePayload(outcome, waitErr); pErr == nil {
			_ = fw.Write(SessMsgOutcome, payload)
		}
		// 半关闭写方向并在有界时间内等待客户端读毕 SessMsgOutcome 后关闭连接，
		// 避免 Windows afunix.sys 立即 closesocket 截断结果帧引发 WSAECONNRESET。
		waitPeerHalfClose(wCtx, conn, clientReadDone)
		cancel()
		return nil
	})
}

func waitPeerHalfClose(ctx context.Context, conn net.Conn, clientReadDone <-chan struct{}) {
	if hc, ok := conn.(HalfWriteCloser); ok {
		_ = hc.CloseWrite()
	}
	timer := time.NewTimer(DefaultHalfCloseDrainTimeout)
	defer timer.Stop()
	select {
	case <-clientReadDone:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func pumpRemoteOutputFrames(fw *SyncFrameWriter, src io.Reader, dataType, eofType uint32) {
	buf := make([]byte, CopyChunkBytes)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if wErr := fw.Write(dataType, AppendBytes(nil, buf[:n])); wErr != nil {
				return
			}
		}
		if err != nil {
			_ = fw.Write(eofType, nil)
			return
		}
	}
}

func pumpClientSessionFrames(ctx context.Context, conn net.Conn, fw *SyncFrameWriter, sess ports.RemoteSession, stdinW io.WriteCloser, cancel context.CancelFunc) {
	for {
		msgType, body, err := ReadPacket(conn)
		if err != nil {
			cancel()
			return
		}
		if stop, _ := handleSingleSessionFrame(ctx, fw, sess, stdinW, msgType, body); stop {
			cancel()
			return
		}
	}
}

func handleSingleSessionFrame(ctx context.Context, fw *SyncFrameWriter, sess ports.RemoteSession, stdinW io.WriteCloser, msgType uint32, body []byte) (bool, error) {
	rd := NewReader(body)
	switch msgType {
	case SessMsgStdinData:
		if data, err := rd.ReadBytes(); err != nil {
			return false, err
		} else if len(data) > 0 {
			_, _ = stdinW.Write(data)
		}
	case SessMsgStdinEOF:
		_ = stdinW.Close()
	case SessMsgResizePTY:
		handleSessionResizeFrame(ctx, fw, sess, &rd)
	case SessMsgSignal:
		handleSessionSignalFrame(ctx, fw, sess, &rd)
	case SessMsgClose:
		_ = sess.Close()
		return true, nil
	}
	return false, nil
}

func handleSessionResizeFrame(ctx context.Context, fw *SyncFrameWriter, sess ports.RemoteSession, rd *Reader) {
	reqID, e0 := rd.ReadUint32()
	cols, e1 := rd.ReadUint32()
	rows, e2 := rd.ReadUint32()
	if err := FirstErr(e0, e1, e2); err != nil {
		sendSessionCtrlReply(fw, reqID, err)
		return
	}
	if cols == 0 || cols > math.MaxUint16 || rows == 0 || rows > math.MaxUint16 {
		sendSessionCtrlReply(fw, reqID, fmt.Errorf("%w: PTY 尺寸越界 (%dx%d)", ports.ErrInvalidTTYSize, cols, rows))
		return
	}
	sz, err := ports.NewTerminalSize(uint16(cols), uint16(rows))
	if err == nil {
		err = sess.ResizePTY(ctx, sz)
	}
	sendSessionCtrlReply(fw, reqID, err)
}

func handleSessionSignalFrame(ctx context.Context, fw *SyncFrameWriter, sess ports.RemoteSession, rd *Reader) {
	reqID, e0 := rd.ReadUint32()
	sig, e1 := rd.ReadString()
	err := FirstErr(e0, e1)
	if err == nil {
		err = sess.Signal(ctx, sig)
	}
	sendSessionCtrlReply(fw, reqID, err)
}

func sendSessionCtrlReply(fw *SyncFrameWriter, reqID uint32, err error) {
	if err == nil {
		_ = fw.Write(SessMsgCtrlReply, AppendStr(AppendU32(AppendU32(nil, reqID), 1), ""))
		return
	}
	_ = fw.Write(SessMsgCtrlReply, AppendStr(AppendU32(AppendU32(nil, reqID), 0), err.Error()))
}
