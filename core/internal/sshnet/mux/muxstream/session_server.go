package muxstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

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
	stdinW, stdoutR, stderrR, err := claimAndStartRemoteSession(ctx, sess, msgType, body)
	if err != nil {
		_ = fw.Write(SessMsgStarted, AppendStr(AppendU32(nil, 0), err.Error()))
		GracefulHalfClose(conn, DefaultHalfCloseDrainTimeout)
		return
	}
	if err := fw.Write(SessMsgStarted, AppendStr(AppendU32(nil, 1), "")); err != nil {
		_ = stdinW.Close()
		return
	}
	runSessionPumps(ctx, conn, fw, sess, stdinW, stdoutR, stderrR)
}

func claimAndStartRemoteSession(ctx context.Context, sess ports.RemoteSession, msgType uint32, body []byte) (io.WriteCloser, io.Reader, io.Reader, error) {
	stdoutR, e1 := sess.StdoutPipe()
	stderrR, e2 := sess.StderrPipe()
	if err := FirstErr(e1, e2); err != nil {
		return nil, nil, nil, err
	}
	// 通过 io.Pipe 将复用 stdin 经 ExecStreams.Stdin 注入，兼顾普通命令、PlanKindScript 与 StartShell（避免 StdinPipe 冲突）。
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
		return nil, nil, nil, startErr
	}
	return inW, stdoutR, stderrR, nil
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

func runSessionPumps(ctx context.Context, conn net.Conn, fw *SyncFrameWriter, sess ports.RemoteSession, stdinW io.WriteCloser, stdoutR, stderrR io.Reader) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = conc.RunScoped(sessCtx, func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error {
			<-c.Done()
			_ = sess.Close()
			_ = conn.Close()
			return nil
		})
		clientReadDone := make(chan struct{})
		_ = n.Go(func(c context.Context) error {
			defer close(clientReadDone)
			defer func() { _ = stdinW.Close() }()
			pumpClientSessionFrames(c, conn, fw, sess, stdinW, cancel)
			return nil
		})
		outDone := make(chan struct{})
		_ = n.Go(func(context.Context) error {
			defer close(outDone)
			_ = conc.RunWait(wCtx, func(_ context.Context, pn *conc.Nursery) error {
				_ = pn.Go(func(context.Context) error {
					pumpRemoteOutputFrames(fw, stdoutR, SessMsgStdoutData, SessMsgStdoutEOF)
					return nil
				})
				pumpRemoteOutputFrames(fw, stderrR, SessMsgStderrData, SessMsgStderrEOF)
				return nil
			})
			return nil
		})
		outcome, waitErr := sess.Wait(wCtx)
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
		sig, err := rd.ReadString()
		if err == nil {
			err = sess.Signal(ctx, sig)
		}
		sendSessionCtrlReply(fw, err)
	case SessMsgClose:
		_ = sess.Close()
		return true, nil
	}
	return false, nil
}

func handleSessionResizeFrame(ctx context.Context, fw *SyncFrameWriter, sess ports.RemoteSession, rd *Reader) {
	cols, e1 := rd.ReadUint32()
	rows, e2 := rd.ReadUint32()
	var rErr error
	if sz, sErr := ports.NewTerminalSize(uint16(cols), uint16(rows)); FirstErr(e1, e2, sErr) != nil {
		rErr = FirstErr(e1, e2, sErr)
	} else {
		rErr = sess.ResizePTY(ctx, sz)
	}
	sendSessionCtrlReply(fw, rErr)
}

func sendSessionCtrlReply(fw *SyncFrameWriter, err error) {
	if err == nil {
		_ = fw.Write(SessMsgCtrlReply, AppendStr(AppendU32(nil, 1), ""))
		return
	}
	_ = fw.Write(SessMsgCtrlReply, AppendStr(AppendU32(nil, 0), err.Error()))
}
