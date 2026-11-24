package pathalg

import (
	"net/netip"
	"path"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

type pathNamespace uint8

const (
	nsInvalid pathNamespace = iota
	nsPOSIX
	nsWinDrive
	nsWinUNC
	nsWinDevice
	nsRelative
	nsUniversal
)

type matchCandidate struct {
	ns     pathNamespace
	drive  byte
	server string
	share  string
	segs   []string
}

// win32HeaderSpec 是规则编译与目标提取共用的 Win32 前缀规范化结果，
// 保证 \\?\、\\.\、\??\、GLOBALROOT/GLOBAL/DosDevices、混合分隔符 UNC 与盘符路径在规则端与目标端 100% 对称。
type win32HeaderSpec struct {
	ns     pathNamespace
	drive  byte
	server string
	share  string
	rest   string
}

// extractMatchCandidates 将已完成 NFC 规范化的路径同时投影为 POSIX 原始候选与 Win32 规范化候选。
//
// 防御原则（INV-E3）：
//   - POSIX 优先保真：若输入以 '/' 开头，先保留字面反斜杠按 POSIX path.Clean 生成候选，
//     确保类似 "/opt/protected/\../file" 在 Linux 语义下仍命中 "/opt/protected/**"，且 "//?/opt/x" 零 POSIX 误报；
//   - Win32 与反斜杠纵深覆盖：经统一 Win32 前缀规范化器迭代剥离 \\?\、\\.\、\??\、GLOBALROOT、GLOBAL、
//     DosDevices、混合分隔符 UNC、回环管理共享（复用 core/domain/netaddr + *.ipv6-literal.net，非规范主干失败关闭）、
//     NTFS ADS 及尾随点/空格，并与 POSIX 候选取并集（逻辑或）。
func extractMatchCandidates(nfcTarget string) []matchCandidate {
	var out []matchCandidate
	if strings.HasPrefix(nfcTarget, "/") {
		out = appendCandidateUnique(out, matchCandidate{
			ns:   nsPOSIX,
			segs: splitCleanAbsSegments(path.Clean(nfcTarget)),
		})
	}
	collapsed := collapseLeadingPosixForWin32(nfcTarget)
	winCands, handled := extractWin32Candidates(collapsed)
	for _, c := range winCands {
		out = appendCandidateUnique(out, c)
	}
	if !handled && strings.ContainsRune(nfcTarget, '\\') {
		out = appendBackslashFallbackCandidates(out, nfcTarget)
	}
	if len(out) == 0 {
		slashed := path.Clean(strings.ReplaceAll(nfcTarget, "\\", "/"))
		out = appendCandidateUnique(out, matchCandidate{
			ns:   nsRelative,
			segs: splitCleanRelSegments(slashed),
		})
	}
	return out
}

func appendBackslashFallbackCandidates(out []matchCandidate, nfcTarget string) []matchCandidate {
	slashed := strings.ReplaceAll(nfcTarget, "\\", "/")
	if !strings.HasPrefix(slashed, "/") {
		return out
	}
	cleaned := path.Clean(slashed)
	out = appendCandidateUnique(out, matchCandidate{
		ns:   nsPOSIX,
		segs: splitCleanAbsSegments(cleaned),
	})
	// 处理如 "\tmp\..\C:\Windows\win.ini" 经斜杠折叠后暴露的盘符路径。
	if collapsed := collapseLeadingPosixForWin32(cleaned); collapsed != cleaned {
		if winCands, ok := extractWin32Candidates(collapsed); ok {
			for _, c := range winCands {
				out = appendCandidateUnique(out, c)
			}
		}
	}
	return out
}

func appendCandidateUnique(dst []matchCandidate, cand matchCandidate) []matchCandidate {
	for _, existing := range dst {
		if existing.ns == cand.ns && existing.drive == cand.drive &&
			existing.server == cand.server && existing.share == cand.share &&
			equalStringSlice(existing.segs, cand.segs) {
			return dst
		}
	}
	return append(dst, cand)
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// collapseLeadingPosixForWin32 折叠可能遮蔽 Win32 设备/UNC/盘符前缀的前导 POSIX 段
// （如 "/tmp/../C:/Windows"、"/tmp/../\?\C:\Windows"、"//\?\C:\Windows"、"/tmp/../\localhost\C$\Windows"）。
func collapseLeadingPosixForWin32(raw string) string {
	if !strings.HasPrefix(raw, "/") || hasWin32DevicePrefix(raw) || hasTwoSepPrefix(raw) {
		return raw
	}
	cleaned := path.Clean(raw)
	if hasWin32DevicePrefix(cleaned) || hasTwoSepPrefix(cleaned) {
		return cleaned
	}
	if len(cleaned) > 1 {
		tail := cleaned[1:]
		if hasWin32DevicePrefix(tail) || hasTwoSepPrefix(tail) || hasDrivePrefix(tail) {
			return tail
		}
	}
	return raw
}

func extractWin32Candidates(p string) ([]matchCandidate, bool) {
	spec, ok := parseWin32HeaderSpec(p)
	if !ok {
		return nil, false
	}
	segs := canonicalWin32Segments(spec.rest)
	switch spec.ns {
	case nsWinDrive:
		return []matchCandidate{{ns: nsWinDrive, drive: spec.drive, segs: segs}}, true
	case nsWinDevice:
		return []matchCandidate{{ns: nsWinDevice, segs: segs}}, true
	case nsWinUNC:
		cands := []matchCandidate{{ns: nsWinUNC, server: spec.server, share: spec.share, segs: segs}}
		return appendLoopbackAdminDrive(cands, spec.server, spec.share, segs), true
	default:
		return nil, false
	}
}

// parseWin32HeaderSpec 是规则编译与目标提取共享的 Win32 前缀规范化入口。
// 按序识别：4 字符设备前缀（含任意 '/'/'\' 混合，并迭代剥离 GLOBALROOT/GLOBAL/DosDevices/??/UNC） ->
// 2 字符混合分隔符 UNC/盘符（\\、//、/\、\/） -> 盘符前缀（C:\、C:/、/C:/）。
func parseWin32HeaderSpec(p string) (win32HeaderSpec, bool) {
	if tail, ok := stripWin32DevicePrefix(p); ok {
		return peelWin32DeviceTail(tail), true
	}
	if body, ok := stripTwoSepPrefix(p); ok {
		if drive, rest, isDrive := extractDrivePrefix(body); isDrive {
			return win32HeaderSpec{ns: nsWinDrive, drive: drive, rest: rest}, true
		}
		if srv, sh, rest, isUNC := parseWin32UNCBody(body); isUNC {
			return win32HeaderSpec{ns: nsWinUNC, server: srv, share: sh, rest: rest}, true
		}
		return win32HeaderSpec{}, false
	}
	if drive, rest, ok := extractDrivePrefix(p); ok {
		return win32HeaderSpec{ns: nsWinDrive, drive: drive, rest: rest}, true
	}
	return win32HeaderSpec{}, false
}

// peelWin32DeviceTail 迭代剥离 NT 对象命名空间修饰前缀（GLOBALROOT、GLOBAL、DosDevices、??、UNC），
// 最终归约为 nsWinDrive、nsWinUNC 或 nsWinDevice。
func peelWin32DeviceTail(tail string) win32HeaderSpec {
	cur := trimLeadingSeps(tail)
	for {
		if drive, rest, ok := extractDrivePrefix(cur); ok {
			return win32HeaderSpec{ns: nsWinDrive, drive: drive, rest: rest}
		}
		seg, after, hasAfter := cutWin32FirstSegment(cur)
		if !hasAfter {
			return win32HeaderSpec{ns: nsWinDevice, rest: cur}
		}
		if strings.EqualFold(seg, "UNC") {
			if srv, sh, rest, ok := parseWin32UNCBody(after); ok {
				return win32HeaderSpec{ns: nsWinUNC, server: srv, share: sh, rest: rest}
			}
			return win32HeaderSpec{ns: nsWinDevice, rest: cur}
		}
		if isPeelableNTNamespaceSeg(seg) {
			cur = trimLeadingSeps(after)
			continue
		}
		return win32HeaderSpec{ns: nsWinDevice, rest: cur}
	}
}

func isPeelableNTNamespaceSeg(seg string) bool {
	return seg == "??" ||
		strings.EqualFold(seg, "GLOBALROOT") ||
		strings.EqualFold(seg, "GLOBAL") ||
		strings.EqualFold(seg, "DosDevices")
}

func cutWin32FirstSegment(s string) (seg, after string, ok bool) {
	idx := strings.IndexAny(s, `/\`)
	if idx < 0 {
		return s, "", false
	}
	return s[:idx], s[idx+1:], true
}

func trimLeadingSeps(s string) string {
	return strings.TrimLeft(s, `/\`)
}

func isPathSep(b byte) bool { return b == '/' || b == '\\' }

// hasWin32DevicePrefix 识别任意 '/' 与 '\' 混合的 4 字符 Win32/NT 设备前缀（[\/][\/][?.][\/] 或 [\/]\?\?[\/]）。
func hasWin32DevicePrefix(p string) bool {
	if len(p) < 4 {
		return false
	}
	if isPathSep(p[0]) && isPathSep(p[1]) && (p[2] == '?' || p[2] == '.') && isPathSep(p[3]) {
		return true
	}
	return isPathSep(p[0]) && p[1] == '?' && p[2] == '?' && isPathSep(p[3])
}

func stripWin32DevicePrefix(p string) (string, bool) {
	if !hasWin32DevicePrefix(p) {
		return "", false
	}
	return p[4:], true
}

// hasTwoSepPrefix 识别任意 2 字符分隔符组合（\\、//、/\、\/）且第 3 字节为非分隔符的前缀。
func hasTwoSepPrefix(p string) bool {
	return len(p) > 2 && isPathSep(p[0]) && isPathSep(p[1]) && !isPathSep(p[2])
}

func stripTwoSepPrefix(p string) (string, bool) {
	if !hasTwoSepPrefix(p) {
		return "", false
	}
	return p[2:], true
}

func hasDrivePrefix(p string) bool {
	_, _, ok := extractDrivePrefix(p)
	return ok
}

func extractDrivePrefix(p string) (drive byte, rest string, ok bool) {
	s := strings.TrimLeft(p, "/")
	if len(s) < 2 || !isASCIIAlpha(s[0]) || s[1] != ':' {
		return 0, "", false
	}
	tail := s[2:]
	if tail != "" && !isPathSep(tail[0]) {
		return 0, "", false
	}
	return toUpperASCII(s[0]), tail, true
}

func parseWin32UNCBody(body string) (server, share, rest string, ok bool) {
	slashed := strings.TrimLeft(strings.ReplaceAll(body, "\\", "/"), "/")
	if slashed == "" {
		return "", "", "", false
	}
	srv, afterSrv, hasAfter := strings.Cut(slashed, "/")
	if srv == "" {
		return "", "", "", false
	}
	server = strings.ToLower(srv)
	if !hasAfter {
		return server, "", "", true
	}
	afterSrv = strings.TrimLeft(afterSrv, "/")
	if afterSrv == "" {
		return server, "", "", true
	}
	sh, tail, _ := strings.Cut(afterSrv, "/")
	return server, strings.ToLower(sh), tail, true
}

// appendLoopbackAdminDrive 检测 UNC 路径是否经本机回环访问管理盘符共享（如 \\127.0.0.1\C$\...、
// \\[::1%1]\C$\...、\\--1.ipv6-literal.net\C$\...、\\127.1\C$\...）。
//
// 安全策略（复用 core/domain/netaddr + net/netip，零重复手写 IP 解析器）：
//   - 对合法 *.ipv6-literal.net 解码为 IPv6 后用 netip.ParseAddr 判回环，解码/解析失败则失败关闭补充盘符候选；
//   - 对其他主机名调用 netaddr.ParseCanonicalHost：非规范数字伪装主机（如 WinSock inet_aton 127.1/0177.0.0.1/
//     0x7f000001/2130706433）解析失败时失败关闭补充盘符候选；合法主机仅在为 localhost 或回环 IP（含区段与
//     IPv4-mapped IPv6）时补充，确保普通远端服务器（如 \\filesrv\C$\Windows）零误报。
func appendLoopbackAdminDrive(cands []matchCandidate, server, share string, segs []string) []matchCandidate {
	if len(share) != 2 || !isASCIIAlpha(share[0]) || share[1] != '$' {
		return cands
	}
	drive := toUpperASCII(share[0])
	trimmed := strings.TrimRight(strings.ToLower(server), ".")
	if trimmed == "" {
		return append(cands, matchCandidate{ns: nsWinDrive, drive: drive, segs: segs})
	}
	if prefix, isIPv6Lit := strings.CutSuffix(trimmed, ".ipv6-literal.net"); isIPv6Lit {
		return appendIPv6LiteralAdminDrive(cands, prefix, drive, segs)
	}
	host, err := netaddr.ParseCanonicalHost(trimmed)
	if err != nil {
		return append(cands, matchCandidate{ns: nsWinDrive, drive: drive, segs: segs})
	}
	if host.String() == "localhost" {
		return append(cands, matchCandidate{ns: nsWinDrive, drive: drive, segs: segs})
	}
	if addr, isIP := host.Addr(); isIP && addr.Unmap().IsLoopback() {
		return append(cands, matchCandidate{ns: nsWinDrive, drive: drive, segs: segs})
	}
	return cands
}

func appendIPv6LiteralAdminDrive(cands []matchCandidate, prefix string, drive byte, segs []string) []matchCandidate {
	addrPart, zonePart, hasZone := strings.Cut(prefix, "s")
	rawIP := strings.ReplaceAll(addrPart, "-", ":")
	if hasZone {
		rawIP += "%" + zonePart
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil || addr.Unmap().IsLoopback() {
		return append(cands, matchCandidate{ns: nsWinDrive, drive: drive, segs: segs})
	}
	return cands
}

// canonicalWin32Segments 对 Win32 盘符/UNC/设备后续路径执行分隔符统一、NTFS ADS 剥离、
// 尾随空格优先裁剪（确保 ".. " 与 "..:$DATA" 正确识别为 ".." 弹出父段）、尾随点/空格裁剪与词法清洗。
func canonicalWin32Segments(rest string) []string {
	slashed := strings.ReplaceAll(rest, "\\", "/")
	var rawSegs []string
	for seg := range strings.SplitSeq(slashed, "/") {
		if seg == "" {
			continue
		}
		if colon := strings.IndexByte(seg, ':'); colon >= 0 {
			seg = seg[:colon]
		}
		seg = strings.TrimRight(seg, " ")
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			rawSegs = append(rawSegs, "..")
			continue
		}
		seg = strings.TrimRight(seg, ". ")
		if seg == "" {
			continue
		}
		rawSegs = append(rawSegs, seg)
	}
	cleaned := path.Clean("/" + strings.Join(rawSegs, "/"))
	return splitCleanAbsSegments(cleaned)
}

func splitCleanAbsSegments(cleaned string) []string {
	if cleaned == "" || cleaned == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
}

func splitCleanRelSegments(cleaned string) []string {
	if cleaned == "" || cleaned == "." {
		return nil
	}
	return strings.Split(cleaned, "/")
}
