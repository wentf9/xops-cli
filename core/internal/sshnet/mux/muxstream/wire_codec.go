package muxstream

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/ports"
)

// OpenSSH PROTOCOL.mux v4 标准报文类型与转发类别常量（严格对齐 openssh-portable/PROTOCOL.mux）。
const (
	ProtocolVersion uint32 = 4

	MsgHello          uint32 = 0x00000001
	CAliveCheck       uint32 = 0x10000004
	CTerminate        uint32 = 0x10000005
	COpenFwd          uint32 = 0x10000006
	CCloseFwd         uint32 = 0x10000007
	CStopListening    uint32 = 0x10000009
	CProxy            uint32 = 0x1000000f
	SOK               uint32 = 0x80000001
	SPermissionDenied uint32 = 0x80000002
	SFailure          uint32 = 0x80000003
	SAlive            uint32 = 0x80000005
	SRemotePort       uint32 = 0x80000007
	SProxy            uint32 = 0x8000000f

	FwdLocal    uint32 = 1
	FwdRemote   uint32 = 2
	FwdDynamic  uint32 = 3
	FwdPortUnix uint32 = 0xfffffffe // OpenSSH StreamLocal 端口哨兵值 (-2)
)

// XOps v4 跨平台流式扩展常量（经 MUX_MSG_HELLO 扩展对协商，零 SCM_RIGHTS 依赖，四平台一致）。
const (
	ExtXOpsStreamMux = "xops-stream-mux@xops.dev"

	XOpsCOpenSession       uint32 = 0x7f000001
	XOpsCOpenSFTP          uint32 = 0x7f000002
	XOpsCDialTCP           uint32 = 0x7f000003
	XOpsCDialStreamLocal   uint32 = 0x7f000004
	XOpsCOpenTUN           uint32 = 0x7f000005
	XOpsCListenTCP         uint32 = 0x7f000006
	XOpsCListenStreamLocal uint32 = 0x7f000007
	XOpsCOpenTUNFwd        uint32 = 0x7f000008
	XOpsCCloseTUNFwd       uint32 = 0x7f000009
	XOpsSBoundAddr         uint32 = 0x7f800001

	SessMsgStartExec  uint32 = 0x7f100001
	SessMsgStartShell uint32 = 0x7f100002
	SessMsgStdinData  uint32 = 0x7f100003
	SessMsgStdinEOF   uint32 = 0x7f100004
	SessMsgResizePTY  uint32 = 0x7f100005
	SessMsgSignal     uint32 = 0x7f100006
	SessMsgClose      uint32 = 0x7f100007

	SessMsgStarted    uint32 = 0x7f200001
	SessMsgStdoutData uint32 = 0x7f200002
	SessMsgStdoutEOF  uint32 = 0x7f200003
	SessMsgStderrData uint32 = 0x7f200004
	SessMsgStderrEOF  uint32 = 0x7f200005
	SessMsgOutcome    uint32 = 0x7f200006
	SessMsgCtrlReply  uint32 = 0x7f200007

	LstMsgAccept         uint32 = 0x7f300001
	LstMsgData           uint32 = 0x7f300002
	LstMsgCloseWrite     uint32 = 0x7f300003
	LstMsgClose          uint32 = 0x7f300004
	LstMsgListenerClosed uint32 = 0x7f300005
)

// Reader 为 PROTOCOL.mux 大端变长字段提供边界安全的顺序解码游标。
type Reader struct {
	buf []byte
}

// NewReader 构造基于字节切片的 PROTOCOL.mux 解码游标。
func NewReader(buf []byte) Reader { return Reader{buf: buf} }

// Remaining 返回尚未消费的剩余字节数。
func (r *Reader) Remaining() int { return len(r.buf) }

// ReadUint32 读取一个大端 32 位无符号整数。
func (r *Reader) ReadUint32() (uint32, error) {
	if len(r.buf) < 4 {
		return 0, fmt.Errorf("%w: PROTOCOL.mux 报文截断（缺少 uint32）", ports.ErrCorruptData)
	}
	v := binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]
	return v, nil
}

// ReadBytes 读取一个带 32 位长度前缀的字节切片。
func (r *Reader) ReadBytes() ([]byte, error) {
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.buf)) {
		return nil, fmt.Errorf("%w: PROTOCOL.mux 字节段越界 %d > %d", ports.ErrCorruptData, n, len(r.buf))
	}
	out := r.buf[:n]
	r.buf = r.buf[n:]
	return out, nil
}

// ReadString 读取一个带 32 位长度前缀的 UTF-8/字节字符串。
func (r *Reader) ReadString() (string, error) {
	b, err := r.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AppendU32 追加大端 uint32 字段。
func AppendU32(dst []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(dst, v) }

// AppendBytes 追加长度前缀字节切片字段。
func AppendBytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

// AppendStr 追加长度前缀字符串字段。
func AppendStr(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// WritePacket 编码并完整写出单条 PROTOCOL.mux 帧（[4B len][4B type][body]）。
func WritePacket(w io.Writer, msgType uint32, body []byte) error {
	pktLen := 4 + len(body)
	if pktLen > MaxPacketBytes {
		return fmt.Errorf("%w: PROTOCOL.mux 出站报文 %d 超过上限", ports.ErrLimitExceeded, pktLen)
	}
	frame := make([]byte, 4+pktLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(pktLen))
	binary.BigEndian.PutUint32(frame[4:8], msgType)
	copy(frame[8:], body)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// ReadPacket 完整读取并校验单条 PROTOCOL.mux 帧，返回报文类型与负载。
func ReadPacket(r io.Reader) (uint32, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	pktLen := binary.BigEndian.Uint32(hdr[:])
	if pktLen < 4 || pktLen > MaxPacketBytes {
		return 0, nil, fmt.Errorf("%w: PROTOCOL.mux 入站报文长度 %d 非法", ports.ErrCorruptData, pktLen)
	}
	buf := make([]byte, pktLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(buf[:4]), buf[4:], nil
}

// WriteHello 发送 PROTOCOL.mux v4 MUX_MSG_HELLO（可选通告 XOps 跨平台流式复用扩展）。
func WriteHello(w io.Writer, advertiseXOps bool) error {
	body := AppendU32(nil, ProtocolVersion)
	if advertiseXOps {
		body = AppendStr(AppendStr(body, ExtXOpsStreamMux), "1")
	}
	return WritePacket(w, MsgHello, body)
}

// ReadHello 读取并校验对端 MUX_MSG_HELLO v4 及扩展键值对。
func ReadHello(r io.Reader) (map[string]string, error) {
	msgType, body, err := ReadPacket(r)
	if err != nil {
		return nil, err
	}
	if msgType != MsgHello {
		return nil, fmt.Errorf("%w: 期望 MUX_MSG_HELLO，收到 %#x", ports.ErrCorruptData, msgType)
	}
	rd := NewReader(body)
	ver, err := rd.ReadUint32()
	if err != nil {
		return nil, err
	}
	if ver != ProtocolVersion {
		return nil, fmt.Errorf("%w: 不支持的 PROTOCOL.mux 版本 %d（仅支持 v4）", ports.ErrUnsupported, ver)
	}
	exts := make(map[string]string)
	for rd.Remaining() > 0 {
		k, e1 := rd.ReadString()
		v, e2 := rd.ReadString()
		if err := FirstErr(e1, e2); err != nil {
			return nil, err
		}
		exts[k] = v
	}
	return exts, nil
}

// ExchangeClientHello 发送客户端 HELLO 并读取服务端 HELLO 扩展表。
func ExchangeClientHello(rw io.ReadWriter) (map[string]string, error) {
	if err := WriteHello(rw, true); err != nil {
		return nil, err
	}
	return ReadHello(rw)
}

// SendAliveCheck 发送 MUX_C_ALIVE_CHECK 并解析对端通告的 ControlMaster PID。
func SendAliveCheck(rw io.ReadWriter, reqID uint32) (uint32, error) {
	if err := WritePacket(rw, CAliveCheck, AppendU32(nil, reqID)); err != nil {
		return 0, err
	}
	msgType, body, err := ReadPacket(rw)
	if err != nil {
		return 0, err
	}
	if msgType != SAlive {
		return 0, DecodeServerError(msgType, body)
	}
	rd := NewReader(body)
	gotID, e1 := rd.ReadUint32()
	pid, e2 := rd.ReadUint32()
	if err := FirstErr(e1, e2); err != nil {
		return 0, err
	}
	if gotID != reqID {
		return 0, fmt.Errorf("%w: MUX_S_ALIVE reqID 不匹配 (%d != %d)", ports.ErrCorruptData, gotID, reqID)
	}
	return pid, nil
}

// DecodeServerError 将 ControlMaster 返回的 MUX_S_PERMISSION_DENIED / MUX_S_FAILURE 映射为标准端口哨兵错误。
func DecodeServerError(msgType uint32, body []byte) error {
	rd := NewReader(body)
	_, _ = rd.ReadUint32() // reqID
	reason, _ := rd.ReadString()
	switch msgType {
	case SPermissionDenied:
		return fmt.Errorf("%w: %s", ports.ErrPermissionDenied, reason)
	case SFailure:
		if reason == "" {
			return ports.ErrInvalidArgument
		}
		return fmt.Errorf("%w: %s", ports.ErrInvalidArgument, reason)
	default:
		return fmt.Errorf("%w: 非预期 PROTOCOL.mux 响应类型 %#x", ports.ErrCorruptData, msgType)
	}
}

// WriteStatusReply 发送 MUX_S_OK、MUX_S_FAILURE 或 MUX_S_PERMISSION_DENIED 应答。
func WriteStatusReply(w io.Writer, msgType, reqID uint32, reason string) error {
	body := AppendU32(nil, reqID)
	if msgType == SFailure || msgType == SPermissionDenied {
		body = AppendStr(body, reason)
	}
	return WritePacket(w, msgType, body)
}

// EncodeForwardWire 将 ports.ForwardSpec 编码为标准 MUX_C_OPEN_FWD 或 XOps TUN 扩展控制帧。
func EncodeForwardWire(reqID uint32, spec ports.ForwardSpec) (uint32, []byte, error) {
	if spec.Direction() == ports.ForwardTUN {
		ts, ok := spec.TUN().Get()
		if !ok || !ts.IsValid() {
			return 0, nil, ports.ErrInvalidArgument
		}
		body := AppendU32(nil, reqID)
		body = AppendU32(body, uint32(ts.Mode()))
		body = AppendU32(body, ts.LocalUnit())
		body = AppendU32(body, ts.RemoteUnit())
		return XOpsCOpenTUNFwd, body, nil
	}
	fwdType, err := directionToWireFwdType(spec.Direction())
	if err != nil {
		return 0, nil, err
	}
	lHost, lPort, err := encodeEndpointHostPort(spec.BindKind(), spec.BindAddr())
	if err != nil {
		return 0, nil, err
	}
	var cHost string
	var cPort uint32
	if spec.Direction() != ports.ForwardDynamic {
		cHost, cPort, err = encodeEndpointHostPort(spec.TargetKind(), spec.TargetAddr())
		if err != nil {
			return 0, nil, err
		}
	}
	body := AppendU32(nil, reqID)
	body = AppendU32(body, fwdType)
	body = AppendStr(body, lHost)
	body = AppendU32(body, lPort)
	body = AppendStr(body, cHost)
	body = AppendU32(body, cPort)
	return COpenFwd, body, nil
}

// DecodeForwardWire 解码标准 PROTOCOL.mux v4 MUX_C_OPEN_FWD / MUX_C_CLOSE_FWD 负载。
func DecodeForwardWire(body []byte) (uint32, ports.ForwardSpec, error) {
	rd := NewReader(body)
	reqID, e1 := rd.ReadUint32()
	fwdType, e2 := rd.ReadUint32()
	lHost, e3 := rd.ReadString()
	lPort, e4 := rd.ReadUint32()
	cHost, e5 := rd.ReadString()
	cPort, e6 := rd.ReadUint32()
	if err := FirstErr(e1, e2, e3, e4, e5, e6); err != nil {
		return 0, ZeroVal[ports.ForwardSpec](), err
	}
	dir, err := wireFwdTypeToDirection(fwdType)
	if err != nil {
		return reqID, ZeroVal[ports.ForwardSpec](), err
	}
	bindKind, bindAddr, err := decodeEndpointHostPort(lHost, lPort)
	if err != nil {
		return reqID, ZeroVal[ports.ForwardSpec](), err
	}
	if dir == ports.ForwardDynamic {
		sp, err := ports.NewForwardSpec(ports.ForwardDynamic, bindAddr, "")
		return reqID, sp, err
	}
	targetKind, targetAddr, err := decodeEndpointHostPort(cHost, cPort)
	if err != nil {
		return reqID, ZeroVal[ports.ForwardSpec](), err
	}
	sp, err := ports.NewTypedForwardSpec(dir, bindKind, bindAddr, targetKind, targetAddr)
	return reqID, sp, err
}

// DecodeTUNForwardWire 解码 XOps TUN 动态转发控制帧负载。
func DecodeTUNForwardWire(body []byte) (uint32, ports.ForwardSpec, error) {
	rd := NewReader(body)
	reqID, e1 := rd.ReadUint32()
	modeRaw, e2 := rd.ReadUint32()
	lUnit, e3 := rd.ReadUint32()
	rUnit, e4 := rd.ReadUint32()
	if err := FirstErr(e1, e2, e3, e4); err != nil {
		return 0, ZeroVal[ports.ForwardSpec](), err
	}
	mode, err := WireToTUNMode(modeRaw)
	if err != nil {
		return reqID, ZeroVal[ports.ForwardSpec](), err
	}
	ts, err := ports.NewTUNSpec(mode, lUnit, rUnit)
	if err != nil {
		return reqID, ZeroVal[ports.ForwardSpec](), err
	}
	sp, err := ports.NewForwardTUNSpec(ts)
	return reqID, sp, err
}

// WireToTUNMode 以 fail-closed 枚举映射将线缆整数还原为合法 ports.TUNMode。
func WireToTUNMode(v uint32) (ports.TUNMode, error) {
	switch v {
	case uint32(ports.TUNModePointToPoint):
		return ports.TUNModePointToPoint, nil
	case uint32(ports.TUNModeEthernet):
		return ports.TUNModeEthernet, nil
	default:
		return ports.TUNModeInvalid, fmt.Errorf("%w: 非法 TUNMode 线缆值 %d", ports.ErrInvalidArgument, v)
	}
}

func directionToWireFwdType(dir ports.ForwardDirection) (uint32, error) {
	switch dir {
	case ports.ForwardLocal:
		return FwdLocal, nil
	case ports.ForwardRemote:
		return FwdRemote, nil
	case ports.ForwardDynamic:
		return FwdDynamic, nil
	default:
		return 0, fmt.Errorf("%w: 不支持的转发方向 %s", ports.ErrInvalidArgument, dir)
	}
}

func wireFwdTypeToDirection(t uint32) (ports.ForwardDirection, error) {
	switch t {
	case FwdLocal:
		return ports.ForwardLocal, nil
	case FwdRemote:
		return ports.ForwardRemote, nil
	case FwdDynamic:
		return ports.ForwardDynamic, nil
	default:
		return ports.ForwardDirectionInvalid, fmt.Errorf("%w: 非法 PROTOCOL.mux 转发类型 %d", ports.ErrInvalidArgument, t)
	}
}

func encodeEndpointHostPort(kind ports.ForwardEndpointKind, addr string) (string, uint32, error) {
	if kind == ports.ForwardEndpointUnix {
		return addr, FwdPortUnix, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 非法 TCP 地址 %q: %w", ports.ErrInvalidArgument, addr, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 非法 TCP 端口 %q: %w", ports.ErrInvalidArgument, portStr, err)
	}
	return host, uint32(p), nil
}

func decodeEndpointHostPort(host string, port uint32) (ports.ForwardEndpointKind, string, error) {
	if port == FwdPortUnix {
		return ports.ForwardEndpointUnix, host, nil
	}
	if port > math.MaxUint16 {
		return ports.ForwardEndpointTCP, "", fmt.Errorf("%w: PROTOCOL.mux TCP 端口越界 %d", ports.ErrInvalidArgument, port)
	}
	return ports.ForwardEndpointTCP, net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), nil
}

// EncodeCommandPlan 使用确定性 json/v2 编码不可变 execution.CommandPlan。
func EncodeCommandPlan(cmd execution.CommandPlan) ([]byte, error) {
	return jsonv2.Marshal(cmd, jsonv2.Deterministic(true))
}

// DecodeCommandPlan 反序列化并严格校验 execution.CommandPlan。
func DecodeCommandPlan(raw []byte) (execution.CommandPlan, error) {
	var cmd execution.CommandPlan
	if err := jsonv2.Unmarshal(raw, &cmd); err != nil {
		return ZeroVal[execution.CommandPlan](), err
	}
	if !cmd.IsValid() {
		return ZeroVal[execution.CommandPlan](), ports.ErrInvalidArgument
	}
	return cmd, nil
}

// EncodeOutcomePayload 使用 execution.MarshalOutcomeTo 编码封闭执行结果与错误文本。
func EncodeOutcomePayload(outcome execution.ExecutionOutcome, waitErr error) ([]byte, error) {
	var buf bytes.Buffer
	if outcome != nil && outcome.IsValid() {
		enc := jsontext.NewEncoder(&buf)
		if err := execution.MarshalOutcomeTo(enc, outcome); err != nil {
			return nil, err
		}
	}
	errStr := ""
	if waitErr != nil {
		errStr = waitErr.Error()
	}
	return AppendStr(AppendBytes(nil, buf.Bytes()), errStr), nil
}

// DecodeOutcomePayload 解码远端会话退出帧携带的 execution.ExecutionOutcome 与等待错误。
func DecodeOutcomePayload(body []byte) (execution.ExecutionOutcome, error, error) {
	rd := NewReader(body)
	rawJSON, e1 := rd.ReadBytes()
	errStr, e2 := rd.ReadString()
	if err := FirstErr(e1, e2); err != nil {
		return nil, nil, err
	}
	var outcome execution.ExecutionOutcome
	if len(rawJSON) > 0 {
		dec := jsontext.NewDecoder(bytes.NewReader(rawJSON))
		var uErr error
		outcome, uErr = execution.UnmarshalOutcomeFrom(dec)
		if uErr != nil {
			return nil, nil, uErr
		}
	}
	var waitErr error
	if errStr != "" {
		waitErr = errors.New(errStr)
	}
	return outcome, waitErr, nil
}

// EncodePTYAndEnv 编码可选 PTY 请求与会话环境变量映射。
func EncodePTYAndEnv(dst []byte, ptyOpt algebraic.Option[ports.PTYRequest], env map[string]string) []byte {
	if p, ok := ptyOpt.Get(); ok && p.IsValid() {
		dst = AppendU32(dst, 1)
		dst = AppendStr(dst, p.Term())
		dst = AppendU32(dst, uint32(p.Size().Cols()))
		dst = AppendU32(dst, uint32(p.Size().Rows()))
	} else {
		dst = AppendU32(dst, 0)
	}
	dst = AppendU32(dst, uint32(len(env)))
	for k, v := range env {
		dst = AppendStr(AppendStr(dst, k), v)
	}
	return dst
}

// DecodePTYAndEnv 解码可选 PTY 请求与有界环境变量映射。
func DecodePTYAndEnv(rd *Reader) (algebraic.Option[ports.PTYRequest], map[string]string, error) {
	ptyOpt, err := decodePTYOpt(rd)
	if err != nil {
		return ptyOpt, nil, err
	}
	env, err := decodeEnvMap(rd)
	return ptyOpt, env, err
}

func decodePTYOpt(rd *Reader) (algebraic.Option[ports.PTYRequest], error) {
	hasPTY, err := rd.ReadUint32()
	if err != nil || hasPTY == 0 {
		return algebraic.None[ports.PTYRequest](), err
	}
	term, e1 := rd.ReadString()
	cols, e2 := rd.ReadUint32()
	rows, e3 := rd.ReadUint32()
	if err := FirstErr(e1, e2, e3); err != nil {
		return algebraic.None[ports.PTYRequest](), err
	}
	if cols == 0 || cols > math.MaxUint16 || rows == 0 || rows > math.MaxUint16 {
		return algebraic.None[ports.PTYRequest](), fmt.Errorf("%w: PTY 尺寸越界 (%dx%d)", ports.ErrInvalidTTYSize, cols, rows)
	}
	sz, err := ports.NewTerminalSize(uint16(cols), uint16(rows))
	if err != nil {
		return algebraic.None[ports.PTYRequest](), err
	}
	pr, err := ports.NewPTYRequest(term, sz)
	if err != nil {
		return algebraic.None[ports.PTYRequest](), err
	}
	return algebraic.Some(pr), nil
}

func decodeEnvMap(rd *Reader) (map[string]string, error) {
	envCount, err := rd.ReadUint32()
	if err != nil || envCount == 0 {
		return nil, err
	}
	if envCount > 512 {
		return nil, ports.ErrLimitExceeded
	}
	env := make(map[string]string, envCount)
	for range envCount {
		k, e1 := rd.ReadString()
		v, e2 := rd.ReadString()
		if err := FirstErr(e1, e2); err != nil {
			return nil, err
		}
		env[k] = v
	}
	return env, nil
}
