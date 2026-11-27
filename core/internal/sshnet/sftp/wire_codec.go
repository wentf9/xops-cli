package sftp

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"math"
	"strconv"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// SFTP v3 报文类型常量（draft-ietf-secsh-filexfer-02）。
const (
	sshFXPInit          byte = 1
	sshFXPVersion       byte = 2
	sshFXPOpen          byte = 3
	sshFXPClose         byte = 4
	sshFXPRead          byte = 5
	sshFXPWrite         byte = 6
	sshFXPLstat         byte = 7
	sshFXPFstat         byte = 8
	sshFXPSetstat       byte = 9
	sshFXPFsetstat      byte = 10
	sshFXPOpendir       byte = 11
	sshFXPReaddir       byte = 12
	sshFXPRemove        byte = 13
	sshFXPMkdir         byte = 14
	sshFXPRmdir         byte = 15
	sshFXPRealpath      byte = 16
	sshFXPStat          byte = 17
	sshFXPRename        byte = 18
	sshFXPReadlink      byte = 19
	sshFXPStatus        byte = 101
	sshFXPHandle        byte = 102
	sshFXPData          byte = 103
	sshFXPName          byte = 104
	sshFXPAttrs         byte = 105
	sshFXPExtended      byte = 200
	sshFXPExtendedReply byte = 201
)

// SFTP v3 打开标志位（严禁在锚点核验与分片写路径使用 sshFXFTrunc）。
const (
	sshFXFRead  uint32 = 0x00000001
	sshFXFWrite uint32 = 0x00000002
	sshFXFCreat uint32 = 0x00000008
	sshFXFExcl  uint32 = 0x00000020
)

// SFTP v3 属性掩码位与状态码。
const (
	attrFlagSize        uint32 = 0x00000001
	attrFlagUIDGID      uint32 = 0x00000002
	attrFlagPermissions uint32 = 0x00000004
	attrFlagACModTime   uint32 = 0x00000008
	attrFlagExtended    uint32 = 0x80000000

	sshFXOK               uint32 = 0
	sshFXEOF              uint32 = 1
	sshFXNoSuchFile       uint32 = 2
	sshFXPermissionDenied uint32 = 3
	sshFXFailure          uint32 = 4
	sshFXBadMessage       uint32 = 5
	sshFXNoConnection     uint32 = 6
	sshFXConnectionLost   uint32 = 7
	sshFXOpUnsupported    uint32 = 8
)

// POSIX st_mode 文件类型与特殊权限位掩码。
const (
	posixIFMT   uint32 = 0o170000
	posixIFIFO  uint32 = 0o010000
	posixIFCHR  uint32 = 0o020000
	posixIFDIR  uint32 = 0o040000
	posixIFBLK  uint32 = 0o060000
	posixIFREG  uint32 = 0o100000
	posixIFLNK  uint32 = 0o120000
	posixIFSOCK uint32 = 0o140000
	posixISUID  uint32 = 0o004000
	posixISGID  uint32 = 0o002000
	posixISVTX  uint32 = 0o001000
)

// sftpStatusError 封装服务端返回的 SSH_FXP_STATUS 原始错误码与说明文本，并映射至规范 ports 哨兵；
// 实现 domi18n.LocalizableNode 并将 Error() 委托给 domi18n.CanonicalError，确保边界延迟本地化一致。
type sftpStatusError struct {
	code uint32
	msg  string
}

// LocalizableView 返回 *sftpStatusError 的只读结构化错误视图（以 BoundStr 净化服务端原始说明文本）。
func (e *sftpStatusError) LocalizableView() domi18n.ErrorNode {
	if e == nil {
		return domi18n.ErrorNode{}
	}
	if e.msg == "" {
		return domi18n.ErrorNode{
			Sentinel: e.Unwrap(),
			Message:  domi18n.NewMessage(domi18n.KeySFTPStatusCode, domi18n.Uint64("code", uint64(e.code))),
		}
	}
	return domi18n.ErrorNode{
		Sentinel: e.Unwrap(),
		Message:  domi18n.NewMessage(domi18n.KeySFTPStatusCodeDetail, domi18n.Uint64("code", uint64(e.code)), domi18n.BoundStr("detail", e.msg)),
	}
}

func (e *sftpStatusError) Error() string { return domi18n.CanonicalError(e) }

func (e *sftpStatusError) Unwrap() error {
	if e == nil {
		return nil
	}
	switch e.code {
	case sshFXNoSuchFile:
		return ports.ErrNotFound
	case sshFXPermissionDenied:
		return ports.ErrPermissionDenied
	case sshFXBadMessage:
		return ports.ErrInvalidArgument
	case sshFXNoConnection, sshFXConnectionLost:
		return ports.ErrClosed
	case sshFXOpUnsupported:
		return ports.ErrUnsupported
	default:
		return nil
	}
}

func isStatusCode(err error, code uint32) bool {
	if se, ok := errors.AsType[*sftpStatusError](err); ok {
		return se.code == code
	}
	return false
}

// wireAttrs 表示 SFTP v3 ATTRS 线缆结构（含可选扩展 (dev, ino) 锚点字段）。
type wireAttrs struct {
	flags     uint32
	size      uint64
	uid       uint32
	gid       uint32
	perm      uint32
	atime     uint32
	mtime     uint32
	hasDevIno bool
	dev       uint64
	ino       uint64
}

type wireNameEntry struct {
	filename string
	longname string
	attrs    wireAttrs
}

// wireReader 提供带边界校验的零分配 SFTP 大端解码器。
type wireReader struct {
	buf []byte
}

func (r *wireReader) remaining() int { return len(r.buf) }

func (r *wireReader) readUint32() (uint32, error) {
	if len(r.buf) < 4 {
		return 0, domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPPacketTruncated)
	}
	v := binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]
	return v, nil
}

func (r *wireReader) readUint64() (uint64, error) {
	if len(r.buf) < 8 {
		return 0, domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPPacketTruncated)
	}
	v := binary.BigEndian.Uint64(r.buf[:8])
	r.buf = r.buf[8:]
	return v, nil
}

func (r *wireReader) readBytes() ([]byte, error) {
	n, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.buf)) {
		return nil, domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPPacketTruncated)
	}
	out := r.buf[:n]
	r.buf = r.buf[n:]
	return out, nil
}

func (r *wireReader) readString() (string, error) {
	b, err := r.readBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func appendUint32(dst []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(dst, v) }
func appendUint64(dst []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(dst, v) }

func appendBytes(dst, v []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(v)))
	return append(dst, v...)
}

func appendString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

func appendAttrs(dst []byte, a wireAttrs) []byte {
	dst = appendUint32(dst, a.flags)
	if a.flags&attrFlagSize != 0 {
		dst = appendUint64(dst, a.size)
	}
	if a.flags&attrFlagUIDGID != 0 {
		dst = appendUint32(dst, a.uid)
		dst = appendUint32(dst, a.gid)
	}
	if a.flags&attrFlagPermissions != 0 {
		dst = appendUint32(dst, a.perm)
	}
	if a.flags&attrFlagACModTime != 0 {
		dst = appendUint32(dst, a.atime)
		dst = appendUint32(dst, a.mtime)
	}
	return dst
}

func decodeAttrs(r *wireReader) (wireAttrs, error) {
	flags, err := r.readUint32()
	if err != nil {
		return wireAttrs{}, err
	}
	a := wireAttrs{flags: flags}
	if err := decodeCoreAttrs(r, &a); err != nil {
		return wireAttrs{}, err
	}
	if flags&attrFlagExtended != 0 {
		if err := decodeExtendedAttrs(r, &a); err != nil {
			return wireAttrs{}, err
		}
	}
	return a, nil
}

func decodeCoreAttrs(r *wireReader, a *wireAttrs) error {
	if a.flags&attrFlagSize != 0 {
		v, err := r.readUint64()
		if err != nil {
			return err
		}
		a.size = v
	}
	if err := decodeUIDGIDAndPerm(r, a); err != nil {
		return err
	}
	if a.flags&attrFlagACModTime != 0 {
		at, e1 := r.readUint32()
		mt, e2 := r.readUint32()
		if err := firstErr(e1, e2); err != nil {
			return err
		}
		a.atime, a.mtime = at, mt
	}
	return nil
}

func decodeUIDGIDAndPerm(r *wireReader, a *wireAttrs) error {
	if a.flags&attrFlagUIDGID != 0 {
		uid, e1 := r.readUint32()
		gid, e2 := r.readUint32()
		if err := firstErr(e1, e2); err != nil {
			return err
		}
		a.uid, a.gid = uid, gid
	}
	if a.flags&attrFlagPermissions != 0 {
		p, err := r.readUint32()
		if err != nil {
			return err
		}
		a.perm = p
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeExtendedAttrs(r *wireReader, a *wireAttrs) error {
	count, err := r.readUint32()
	if err != nil {
		return err
	}
	var gotDev, gotIno bool
	var dev, ino uint64
	for range count {
		k, e1 := r.readString()
		val, e2 := r.readBytes()
		if err := firstErr(e1, e2); err != nil {
			return err
		}
		applyExtendedAnchorAttr(k, val, &dev, &gotDev, &ino, &gotIno)
	}
	if gotDev && gotIno {
		a.hasDevIno, a.dev, a.ino = true, dev, ino
	}
	return nil
}

func applyExtendedAnchorAttr(k string, val []byte, dev *uint64, gotDev *bool, ino *uint64, gotIno *bool) {
	switch k {
	case extStatDev:
		if parsed, pErr := parseUint64Attr(val); pErr == nil {
			*dev, *gotDev = parsed, true
		}
	case extStatIno:
		if parsed, pErr := parseUint64Attr(val); pErr == nil {
			*ino, *gotIno = parsed, true
		}
	}
}

func parseUint64Attr(raw []byte) (uint64, error) {
	if len(raw) == 8 {
		return binary.BigEndian.Uint64(raw), nil
	}
	return strconv.ParseUint(string(raw), 10, 64)
}

func decodeStatus(payload []byte) error {
	r := wireReader{buf: payload}
	code, err := r.readUint32()
	if err != nil {
		return err
	}
	if code == sshFXOK {
		return nil
	}
	var msg string
	if r.remaining() >= 4 {
		if m, mErr := r.readString(); mErr == nil {
			msg = m
		}
	}
	return &sftpStatusError{code: code, msg: msg}
}

func decodeNameList(payload []byte) ([]wireNameEntry, error) {
	r := wireReader{buf: payload}
	count, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if count > maxReadDirEntries {
		return nil, domi18n.EF(ports.ErrLimitExceeded, domi18n.KeySFTPDirEntriesLimit, domi18n.Uint64("count", uint64(count)), domi18n.Int("limit", maxReadDirEntries))
	}
	entries := make([]wireNameEntry, 0, min(int(count), 1024))
	for range count {
		fn, err := r.readString()
		if err != nil {
			return nil, err
		}
		ln, err := r.readString()
		if err != nil {
			return nil, err
		}
		attrs, err := decodeAttrs(&r)
		if err != nil {
			return nil, err
		}
		entries = append(entries, wireNameEntry{filename: fn, longname: ln, attrs: attrs})
	}
	return entries, nil
}

// posixModeToRemote 将 POSIX st_mode 投影为强类型 ports.RemoteFileType 与 Go fs.FileMode；
// 若服务端未携带 PERMISSIONS 标志或为未知类型，一律按 RemoteFileOther 失败关闭。
func posixModeToRemote(a wireAttrs) (ports.RemoteFileType, fs.FileMode) {
	if a.flags&attrFlagPermissions == 0 {
		return ports.RemoteFileOther, 0
	}
	mode := fs.FileMode(a.perm & 0o777)
	if a.perm&posixISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if a.perm&posixISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if a.perm&posixISVTX != 0 {
		mode |= fs.ModeSticky
	}
	switch a.perm & posixIFMT {
	case posixIFREG:
		return ports.RemoteFileRegular, mode
	case posixIFDIR:
		return ports.RemoteFileDir, mode | fs.ModeDir
	case posixIFLNK:
		return ports.RemoteFileSymlink, mode | fs.ModeSymlink
	case posixIFIFO:
		return ports.RemoteFileOther, mode | fs.ModeNamedPipe
	case posixIFCHR:
		return ports.RemoteFileOther, mode | fs.ModeDevice | fs.ModeCharDevice
	case posixIFBLK:
		return ports.RemoteFileOther, mode | fs.ModeDevice
	case posixIFSOCK:
		return ports.RemoteFileOther, mode | fs.ModeSocket
	default:
		return ports.RemoteFileOther, mode
	}
}

func attrsToAnchor(a wireAttrs) (ports.RemoteFileAnchor, fs.FileMode, error) {
	ft, fm := posixModeToRemote(a)
	anc, err := ports.NewRemoteFileAnchor(ft, a.hasDevIno, a.dev, a.ino)
	return anc, fm, err
}

func attrsToRemoteStat(p pathalg.RemotePath, a wireAttrs) (ports.RemoteFileStat, error) {
	if a.size > math.MaxInt64 {
		return zeroVal[ports.RemoteFileStat](), domi18n.EF(ports.ErrLimitExceeded, domi18n.KeySFTPRemoteSizeLimit, domi18n.Uint64("size", a.size), domi18n.Int64("limit", math.MaxInt64))
	}
	anc, fm, err := attrsToAnchor(a)
	if err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	var modTime time.Time
	if a.flags&attrFlagACModTime != 0 && a.mtime > 0 {
		modTime = time.Unix(int64(a.mtime), 0).UTC()
	}
	return ports.NewRemoteFileStat(ports.RemoteFileStatSpec{
		Path:    p,
		Size:    int64(a.size),
		Mode:    fm,
		ModTime: modTime,
		Anchor:  anc,
	})
}

func isValidSFTPTimestamp(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	utc := t.UTC()
	if utc.Year() < 1 || utc.Year() > 9999 {
		return false
	}
	sec := utc.Unix()
	return sec >= 0 && sec <= math.MaxUint32
}
