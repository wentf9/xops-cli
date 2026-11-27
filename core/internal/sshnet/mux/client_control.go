package mux

import (
	"fmt"
	"net"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/ports"
)

// execControlAction 在已建立 HELLO 的本地 Unix 连接上执行单个 PROTOCOL.mux v4 控制动作。
func (m *MuxSocket) execControlAction(conn *net.UnixConn, req ports.MuxControlRequest, exts map[string]string) (ports.MuxControlResponse, error) {
	pid, err := muxstream.SendAliveCheck(conn, 1)
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), domi18n.WrapSentinel(ports.ErrMuxUnavailable, err)
	}
	if req.Action() == ports.MuxActionCheck {
		return ports.NewMuxControlResponse(true, pid, "check")
	}
	detail, err := sendControlCommand(conn, 2, req, exts[muxstream.ExtXOpsStreamMux] == "1")
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	return ports.NewMuxControlResponse(true, pid, detail)
}

func sendControlCommand(conn *net.UnixConn, reqID uint32, req ports.MuxControlRequest, hasXOps bool) (string, error) {
	switch req.Action() {
	case ports.MuxActionExit:
		return "exit", roundTripControlOK(conn, muxstream.CTerminate, muxstream.AppendU32(nil, reqID), reqID)
	case ports.MuxActionStop:
		return "stop", roundTripControlOK(conn, muxstream.CStopListening, muxstream.AppendU32(nil, reqID), reqID)
	case ports.MuxActionForward:
		return sendForwardControl(conn, reqID, req, true, hasXOps)
	case ports.MuxActionCancel:
		return sendForwardControl(conn, reqID, req, false, hasXOps)
	default:
		return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyMuxControlActionUnsup, domi18n.Str("action", req.Action().String()))
	}
}

func sendForwardControl(conn *net.UnixConn, reqID uint32, req ports.MuxControlRequest, isOpen, hasXOps bool) (string, error) {
	fwd, ok := req.Forward().Get()
	if !ok || !fwd.IsValid() {
		return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ForwardSpec"))
	}
	msgType, body, err := muxstream.EncodeForwardWire(reqID, fwd)
	if err != nil {
		return "", err
	}
	if msgType == muxstream.XOpsCOpenTUNFwd && !hasXOps {
		return "", domi18n.EF(ports.ErrUnsupported, domi18n.KeyMuxTUNDynamicUnsup)
	}
	if !isOpen {
		if msgType == muxstream.XOpsCOpenTUNFwd {
			msgType = muxstream.XOpsCCloseTUNFwd
		} else {
			msgType = muxstream.CCloseFwd
		}
	}
	if err := muxstream.WritePacket(conn, msgType, body); err != nil {
		return "", err
	}
	respType, respBody, err := muxstream.ReadPacket(conn)
	if err != nil {
		return "", err
	}
	return parseForwardControlReply(respType, respBody, reqID, isOpen)
}

func parseForwardControlReply(respType uint32, respBody []byte, reqID uint32, isOpen bool) (string, error) {
	if respType == muxstream.SOK {
		rd := muxstream.NewReader(respBody)
		gotID, err := rd.ReadUint32()
		if err != nil || gotID != reqID {
			return "", ports.ErrCorruptData
		}
		if isOpen {
			return "forward", nil
		}
		return "cancel", nil
	}
	if respType == muxstream.SRemotePort && isOpen {
		rd := muxstream.NewReader(respBody)
		gotID, e1 := rd.ReadUint32()
		port, e2 := rd.ReadUint32()
		if err := muxstream.FirstErr(e1, e2); err != nil || gotID != reqID {
			return "", ports.ErrCorruptData
		}
		return fmt.Sprintf("forward:%d", port), nil
	}
	return "", muxstream.DecodeServerError(respType, respBody)
}

func roundTripControlOK(conn *net.UnixConn, msgType uint32, body []byte, reqID uint32) error {
	if err := muxstream.WritePacket(conn, msgType, body); err != nil {
		return err
	}
	respType, respBody, err := muxstream.ReadPacket(conn)
	if err != nil {
		return err
	}
	if respType != muxstream.SOK {
		return muxstream.DecodeServerError(respType, respBody)
	}
	rd := muxstream.NewReader(respBody)
	gotID, err := rd.ReadUint32()
	if err != nil || gotID != reqID {
		return ports.ErrCorruptData
	}
	return nil
}

func negotiateProxyMode(conn *net.UnixConn) error {
	if _, err := muxstream.ExchangeClientHello(conn); err != nil {
		return domi18n.WrapSentinel(ports.ErrMuxUnavailable, err)
	}
	if err := muxstream.WritePacket(conn, muxstream.CProxy, muxstream.AppendU32(nil, 1)); err != nil {
		return err
	}
	respType, respBody, err := muxstream.ReadPacket(conn)
	if err != nil {
		return err
	}
	if respType != muxstream.SProxy {
		return muxstream.DecodeServerError(respType, respBody)
	}
	return nil
}
