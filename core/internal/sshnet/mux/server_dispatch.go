package mux

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/ports"
)

type subsystemOpener interface {
	OpenSubsystem(ctx context.Context, subsystem string) (*chanconn.WatchedConn, error)
}

func (st *muxServerState) dispatchStreamPacket(ctx context.Context, conn net.Conn, msgType uint32, body []byte) (bool, error) {
	switch msgType {
	case muxstream.XOpsCOpenSession:
		st.handleOpenSession(ctx, conn, body)
		return true, nil
	case muxstream.XOpsCOpenSFTP:
		st.handleOpenSFTP(ctx, conn, body)
		return true, nil
	case muxstream.XOpsCDialTCP:
		st.handleDialTCP(ctx, conn, body)
		return true, nil
	case muxstream.XOpsCDialStreamLocal:
		st.handleDialStreamLocal(ctx, conn, body)
		return true, nil
	case muxstream.XOpsCOpenTUN:
		st.handleOpenTUN(ctx, conn, body)
		return true, nil
	case muxstream.XOpsCListenTCP:
		st.handleRemoteListen(ctx, conn, body, false)
		return true, nil
	case muxstream.XOpsCListenStreamLocal:
		st.handleRemoteListen(ctx, conn, body, true)
		return true, nil
	default:
		rd := muxstream.NewReader(body)
		reqID, err := rd.ReadUint32()
		if err != nil {
			return true, err
		}
		return false, muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, fmt.Sprintf("unsupported mux message %#x", msgType))
	}
}

func replyStreamFailure(conn net.Conn, reqID uint32, reason string) {
	_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, reason)
	muxstream.GracefulHalfClose(conn, muxstream.DefaultHalfCloseDrainTimeout)
}

func (st *muxServerState) handleOpenSFTP(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, err := rd.ReadUint32()
	if err != nil {
		return
	}
	so, ok := st.upstream.(subsystemOpener)
	if !ok {
		replyStreamFailure(conn, reqID, "upstream does not support raw sftp subsystem")
		return
	}
	wc, err := so.OpenSubsystem(ctx, "sftp")
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = wc.Close() }()
	if err := muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, ""); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = muxstream.SpliceStreams(ctx, conn, wc)
}

func (st *muxServerState) handleDialTCP(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, e1 := rd.ReadUint32()
	host, e2 := rd.ReadString()
	port, e3 := rd.ReadUint32()
	if err := muxstream.FirstErr(e1, e2, e3); err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	if port == 0 || port > math.MaxUint16 {
		replyStreamFailure(conn, reqID, fmt.Sprintf("tcp port out of range: %d", port))
		return
	}
	ch, err := netaddr.ParseCanonicalHost(host)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	hp, err := netaddr.NewHostPort(ch, uint16(port))
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	remote, err := st.upstream.DialTCP(ctx, hp)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = remote.Close() }()
	if err := muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, ""); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = muxstream.SpliceStreams(ctx, conn, remote)
}

func (st *muxServerState) handleDialStreamLocal(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, e1 := rd.ReadUint32()
	rawPath, e2 := rd.ReadString()
	if err := muxstream.FirstErr(e1, e2); err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	rp, err := pathalg.ParseRemotePath(rawPath)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	remote, err := st.upstream.DialStreamLocal(ctx, rp)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = remote.Close() }()
	if err := muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, ""); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = muxstream.SpliceStreams(ctx, conn, remote)
}

func (st *muxServerState) handleOpenTUN(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, e1 := rd.ReadUint32()
	modeRaw, e2 := rd.ReadUint32()
	lUnit, e3 := rd.ReadUint32()
	rUnit, e4 := rd.ReadUint32()
	if err := muxstream.FirstErr(e1, e2, e3, e4); err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	mode, err := muxstream.WireToTUNMode(modeRaw)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	ts, err := ports.NewTUNSpec(mode, lUnit, rUnit)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	remote, err := st.upstream.OpenTUN(ctx, ts)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = remote.Close() }()
	if err := muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, ""); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = muxstream.SpliceStreamsStrict(ctx, conn, remote)
}

func (st *muxServerState) handleOpenSession(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, err := rd.ReadUint32()
	if err != nil {
		return
	}
	sess, err := st.upstream.OpenSession(ctx)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = sess.Close() }()
	if err := muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, ""); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	muxstream.ServeSessionBridge(ctx, conn, sess)
}

func (st *muxServerState) handleRemoteListen(ctx context.Context, conn net.Conn, body []byte, isUnix bool) {
	rd := muxstream.NewReader(body)
	reqID, e1 := rd.ReadUint32()
	addr, e2 := rd.ReadString()
	if err := muxstream.FirstErr(e1, e2); err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	ln, err := openUpstreamRemoteListener(ctx, st.upstream, isUnix, addr)
	if err != nil {
		replyStreamFailure(conn, reqID, err.Error())
		return
	}
	defer func() { _ = ln.Close() }()
	bound := addr
	if ln.Addr() != nil && ln.Addr().String() != "" {
		bound = ln.Addr().String()
	}
	if err := muxstream.WritePacket(conn, muxstream.XOpsSBoundAddr, muxstream.AppendStr(muxstream.AppendU32(nil, reqID), bound)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	muxstream.ServeListenerBridge(ctx, conn, ln)
}

func openUpstreamRemoteListener(ctx context.Context, upstream ports.TransportConn, isUnix bool, addr string) (net.Listener, error) {
	if isUnix {
		rp, err := pathalg.ParseRemotePath(addr)
		if err != nil {
			return nil, err
		}
		return upstream.ListenStreamLocal(ctx, rp)
	}
	return upstream.ListenTCP(ctx, addr)
}
