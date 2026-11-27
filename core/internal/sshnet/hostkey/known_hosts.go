package hostkey

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type knownHostsTarget struct {
	dir  pathalg.LocalDir
	dest pathalg.LocalRootedDest
}

// PreferredAlgorithms 在共享旁路锁与 O_NOFOLLOW 约束下读取 known_hosts 快照，
// 返回指定端点已记录的主机密钥算法去重顺序列表，供 SSH 握手优先协商。
func (db *KnownHostsDB) PreferredAlgorithms(ctx context.Context, endpoint netaddr.Endpoint, knownHosts option.KnownHostsList) ([]string, error) {
	if err := db.checkCall(ctx, endpoint.IsValid()); err != nil {
		return nil, err
	}
	entries, err := db.loadAllSnapshots(ctx, endpoint, knownHosts)
	if err != nil {
		return nil, err
	}
	return collectPreferredAlgorithms(entries, endpoint), nil
}

// VerifyHostKey 在单次共享旁路锁与 O_NOFOLLOW 约束下读取 known_hosts 快照并核验远端呈递公钥（INV-C5 / INV-E2）。
// 核验严格遵循安全优先级：@revoked > @cert-authority/已信任匹配 > 已知端点冲突（Mismatch）> 已认证 DNSSEC SSHFP > 未知（Unknown）。
func (db *KnownHostsDB) VerifyHostKey(ctx context.Context, req ports.HostTrustRequest) (ports.HostTrustCheck, error) {
	var zero ports.HostTrustCheck
	if err := db.checkCall(ctx, req.IsValid()); err != nil {
		return zero, err
	}
	entries, err := db.loadAllSnapshots(ctx, req.Endpoint(), req.KnownHosts())
	if err != nil {
		return zero, err
	}
	spec := db.evaluateHostTrust(req, entries)
	if spec.Status == ports.HostTrustUnknown && !isHostCertificateAlgorithm(req.Presented().Algorithm()) && db.sshfpLookup != nil {
		verdict, sErr := db.verifyViaSSHFP(ctx, req.Endpoint().Host(), req.Presented())
		if sErr != nil {
			return zero, sErr
		}
		switch verdict {
		case sshfpMatched:
			spec.Status = ports.HostTrustTrusted
			spec.Reason = "verified via DNSSEC-authenticated SSHFP"
		case sshfpMismatch:
			spec.Status = ports.HostTrustMismatch
			spec.Reason = "presented host key conflicts with DNSSEC-authenticated SSHFP"
		}
	}
	return ports.NewHostTrustCheck(spec)
}

// RecordHostKey 在独占旁路锁 <name>.lock 保护下读取并合并首个可写 known_hosts 文件，
// 随后以同目录临时文件原子替换落盘（绝不对数据文件本身加锁后 Rename，兼容 Windows）。
// 严格拒绝以 TOFU 方式记录原始 SSH 主机证书（*-cert-v01@openssh.com）。
func (db *KnownHostsDB) RecordHostKey(ctx context.Context, endpoint netaddr.Endpoint, key ports.PublicKeyInfo, knownHosts option.KnownHostsList) error {
	if err := db.checkCall(ctx, endpoint.IsValid() && key.IsValid()); err != nil {
		return err
	}
	if isHostCertificateAlgorithm(key.Algorithm()) {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyHostKeyCertTOFU, domi18n.BoundStr("key", key.Algorithm()))
	}
	targets, err := db.resolveTargets(endpoint, knownHosts)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}
	target := targets[0]
	if err := db.ensureTargetDir(target.dir); err != nil {
		return err
	}
	return db.rootFS.WithRoot(target.dir, func(root ports.RootHandle) error {
		return db.recordInRoot(ctx, root, target.dest, endpoint, key)
	})
}

// ensureTargetDir 对默认私有目录强制 0700 Owner-Only DACL；对操作员显式外部 UserKnownHostsFile
// 若目录尚不存在则以 0700 创建，若已存在则以 0755 校验非软链真实目录（避免误杀 Windows 临时/主目录继承 DACL），
// 同时内部 WithSidecarLock 与 AtomicReplace(..., 0o600, ...) 保证落盘文件本身具备 Owner-Only DACL。
func (db *KnownHostsDB) ensureTargetDir(dir pathalg.LocalDir) error {
	if dir.Equal(db.defaultDir) {
		return db.rootFS.EnsureRoot(dir, knownHostsDirPerm)
	}
	err := db.rootFS.WithRoot(dir, func(ports.RootHandle) error { return nil })
	if errors.Is(err, ports.ErrNotFound) {
		return db.rootFS.EnsureRoot(dir, knownHostsDirPerm)
	}
	if err != nil {
		return err
	}
	return db.rootFS.EnsureRoot(dir, externalParentDirPerm)
}

// CleanupSidecarLock 按三平台 Windows 安全删锁协议清理首个目标文件对应的旁路锁 <name>.lock：
// 持独占锁截断清空 -> 解锁关句柄 -> 删除（忽略 ErrNotFound），消除 Windows 共享冲突。
func (db *KnownHostsDB) CleanupSidecarLock(ctx context.Context, endpoint netaddr.Endpoint, knownHosts option.KnownHostsList) (bool, error) {
	if err := db.checkCall(ctx, endpoint.IsValid()); err != nil {
		return false, err
	}
	targets, err := db.resolveTargets(endpoint, knownHosts)
	if err != nil || len(targets) == 0 {
		return false, err
	}
	target := targets[0]
	lockDest, err := osfs.SidecarLockDest(target.dest)
	if err != nil {
		return false, err
	}
	var removed bool
	err = db.rootFS.WithRoot(target.dir, func(root ports.RootHandle) error {
		var rErr error
		removed, rErr = osfs.RemoveLockedFileSafely(root, lockDest)
		return rErr
	})
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	return removed, err
}

func (db *KnownHostsDB) recordInRoot(ctx context.Context, root ports.RootHandle, dest pathalg.LocalRootedDest, endpoint netaddr.Endpoint, key ports.PublicKeyInfo) error {
	if parent, ok := dest.Parent(); ok {
		if err := root.MkdirAll(parent, knownHostsDirPerm); err != nil {
			return err
		}
	}
	return osfs.WithSidecarLock(ctx, root, dest, ports.LockExclusive, knownHostsFilePerm, func(ports.LockedFile) error {
		existing, rErr := readSnapshotOrEmpty(root, dest, db.readLimits)
		if rErr != nil {
			return rErr
		}
		if hasActiveMatchingEntry(parseKnownHostsSnapshot(existing), endpoint, key) {
			return nil
		}
		hostField, fErr := formatHostField(endpoint, db.hashHostnames, db.entropy)
		if fErr != nil {
			return fErr
		}
		updated := appendKnownHostsLine(existing, formatKnownHostsRecord(hostField, key))
		return root.AtomicReplace(dest, knownHostsFilePerm, func(w io.Writer) error {
			_, wErr := w.Write(updated)
			return wErr
		})
	})
}

func (db *KnownHostsDB) checkCall(ctx context.Context, argsValid bool) error {
	if db == nil || !db.valid {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "KnownHostsDB"))
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !argsValid {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (db *KnownHostsDB) loadAllSnapshots(ctx context.Context, endpoint netaddr.Endpoint, knownHosts option.KnownHostsList) ([]parsedEntry, error) {
	targets, err := db.resolveTargets(endpoint, knownHosts)
	if err != nil || len(targets) == 0 {
		return nil, err
	}
	var all []parsedEntry
	for _, target := range targets {
		entries, rErr := db.loadSingleSnapshot(ctx, target)
		if rErr != nil {
			return nil, rErr
		}
		all = append(all, entries...)
	}
	return all, nil
}

func (db *KnownHostsDB) loadSingleSnapshot(ctx context.Context, target knownHostsTarget) ([]parsedEntry, error) {
	var raw []byte
	err := db.rootFS.WithRoot(target.dir, func(root ports.RootHandle) error {
		if _, stErr := root.Lstat(target.dest); errors.Is(stErr, ports.ErrNotFound) {
			return nil
		} else if stErr != nil {
			return stErr
		}
		return osfs.WithSidecarLock(ctx, root, target.dest, ports.LockShared, knownHostsFilePerm, func(ports.LockedFile) error {
			var rErr error
			raw, rErr = readSnapshotOrEmpty(root, target.dest, db.readLimits)
			return rErr
		})
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseKnownHostsSnapshot(raw), nil
}

func readSnapshotOrEmpty(root ports.RootHandle, dest pathalg.LocalRootedDest, limits ports.ReadLimits) ([]byte, error) {
	data, err := root.ReadAllBounded(dest, limits)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	return data, err
}

func (db *KnownHostsDB) resolveTargets(ep netaddr.Endpoint, list option.KnownHostsList) ([]knownHostsTarget, error) {
	if list.IsDisabled() {
		return nil, nil
	}
	if list.IsUnset() {
		return []knownHostsTarget{{dir: db.defaultDir, dest: db.defaultDest}}, nil
	}
	items := list.Items()
	targets := make([]knownHostsTarget, 0, len(items))
	for _, entry := range items {
		t, skip, err := db.resolveOneTarget(ep, entry)
		if err != nil {
			return nil, err
		}
		if !skip {
			targets = append(targets, t)
		}
	}
	return targets, nil
}

func (db *KnownHostsDB) resolveOneTarget(ep netaddr.Endpoint, entry option.PathEntry) (knownHostsTarget, bool, error) {
	raw := strings.TrimSpace(entry.String())
	if raw == "" || raw == "/dev/null" || strings.EqualFold(raw, "NUL") {
		return knownHostsTarget{}, true, nil
	}
	expanded, err := db.expandKnownHostsPath(ep, entry, raw)
	if err != nil {
		return knownHostsTarget{}, false, err
	}
	src, err := pathalg.ParseLocalSourcePath(expanded)
	if err != nil {
		return knownHostsTarget{}, false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "UserKnownHostsFile"), domi18n.BoundStr("value", raw))
	}
	if !src.IsAbs() {
		dest, dErr := pathalg.ParseLocalRootedDest(src.String())
		if dErr != nil {
			return knownHostsTarget{}, false, domi18n.WrapS(ports.ErrInvalidArgument, dErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "known_hosts_path"), domi18n.BoundStr("value", raw))
		}
		return knownHostsTarget{dir: db.defaultDir, dest: dest}, false, nil
	}
	dest, err := pathalg.ParseLocalRootedDest(src.Base())
	if err != nil {
		return knownHostsTarget{}, false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "known_hosts_filename"), domi18n.BoundStr("value", src.Base()))
	}
	return knownHostsTarget{dir: src.Dir(), dest: dest}, false, nil
}

func (db *KnownHostsDB) expandKnownHostsPath(ep netaddr.Endpoint, entry option.PathEntry, raw string) (string, error) {
	out := raw
	hasTildePrefix := strings.HasPrefix(out, "~/") || strings.HasPrefix(out, `~\`)
	// 先对模板部分执行 % 令牌展开，再展开前置 ~/，防止 HomeDir 中含字面 '%' 时被二次误解析。
	if entry.IsTemplate() {
		tc := option.TokenContext{
			TargetHost: ep.Host().String(),
			Port:       ep.Port(),
		}
		if home, ok := db.homeDir.Get(); ok {
			tc.HomeDir = home.String()
		}
		target := out
		if hasTildePrefix {
			target = out[2:]
		}
		expanded, err := option.ExpandPathTokens(target, tc)
		if err != nil {
			return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonPathTemplateFailed, domi18n.BoundStr("target", raw))
		}
		if hasTildePrefix {
			out = "~/" + expanded
		} else {
			out = expanded
		}
	}
	if strings.HasPrefix(out, "~/") || strings.HasPrefix(out, `~\`) {
		home, ok := db.homeDir.Get()
		if !ok {
			return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonMissingDep, domi18n.Str("component", "HomeDir"))
		}
		out = strings.TrimRight(home.String(), `/\`) + "/" + out[2:]
	}
	return out, nil
}

func collectPreferredAlgorithms(entries []parsedEntry, ep netaddr.Endpoint) []string {
	revokedBlobs := collectRevokedBlobs(entries, ep)
	var algos []string
	for _, e := range entries {
		if e.matchesEndpoint(ep) {
			algos = appendEntryPreferredAlgos(algos, e, revokedBlobs)
		}
	}
	return algos
}

func collectRevokedBlobs(entries []parsedEntry, ep netaddr.Endpoint) [][]byte {
	var blobs [][]byte
	for _, e := range entries {
		if e.marker == markerRevoked && e.matchesEndpoint(ep) {
			blobs = append(blobs, e.wireBlob)
		}
	}
	return blobs
}

func appendEntryPreferredAlgos(algos []string, e parsedEntry, revokedBlobs [][]byte) []string {
	if isBlobRevoked(e.wireBlob, revokedBlobs) {
		return algos
	}
	switch e.marker {
	case markerCertAuthority:
		for _, certAlgo := range hostCertPreferredAlgorithms() {
			if !slices.Contains(algos, certAlgo) {
				algos = append(algos, certAlgo)
			}
		}
	case markerRegular:
		if !slices.Contains(algos, e.algorithm) {
			algos = append(algos, e.algorithm)
		}
	}
	return algos
}

func isBlobRevoked(blob []byte, revokedBlobs [][]byte) bool {
	for _, rb := range revokedBlobs {
		if keyBlobEqual(blob, rb) {
			return true
		}
	}
	return false
}

func (db *KnownHostsDB) nowFunc() func() time.Time {
	if db.clock != nil {
		return db.clock.Now
	}
	return func() time.Time { return time.Now().UTC() }
}

func (db *KnownHostsDB) evaluateHostTrust(req ports.HostTrustRequest, entries []parsedEntry) ports.HostTrustCheckSpec {
	if isHostCertificateAlgorithm(req.Presented().Algorithm()) {
		return evaluateHostCertTrust(req.Endpoint(), req.Presented(), entries, db.nowFunc())
	}
	ep := req.Endpoint()
	presented := req.Presented()
	spec := ports.HostTrustCheckSpec{
		Endpoint:  ep,
		Presented: presented,
		Status:    ports.HostTrustUnknown,
		Reason:    "unknown host key",
	}
	var trusted bool
	for _, e := range entries {
		if !e.matchesEndpoint(ep) {
			continue
		}
		if e.marker == markerRevoked && keyBlobEqual(e.wireBlob, presented.WireBlob()) {
			spec.Status = ports.HostTrustRevoked
			spec.Reason = "host key is explicitly marked @revoked"
			return spec
		}
		if e.marker != markerRegular {
			continue
		}
		if !slices.ContainsFunc(spec.ExpectedFingerprints, e.fingerprint.Equal) {
			spec.ExpectedFingerprints = append(spec.ExpectedFingerprints, e.fingerprint)
		}
		if keyBlobEqual(e.wireBlob, presented.WireBlob()) {
			trusted = true
		}
	}
	if trusted {
		spec.Status = ports.HostTrustTrusted
		spec.Reason = ""
	} else if len(spec.ExpectedFingerprints) > 0 {
		spec.Status = ports.HostTrustMismatch
		spec.Reason = "presented host key does not match known_hosts"
	}
	return spec
}

func hasActiveMatchingEntry(entries []parsedEntry, ep netaddr.Endpoint, key ports.PublicKeyInfo) bool {
	for _, e := range entries {
		if e.marker == markerRegular && e.matchesEndpoint(ep) && keyBlobEqual(e.wireBlob, key.WireBlob()) {
			return true
		}
	}
	return false
}

func appendKnownHostsLine(existing []byte, record string) []byte {
	var buf bytes.Buffer
	buf.Grow(len(existing) + len(record) + 2)
	buf.Write(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(record)
	buf.WriteByte('\n')
	return buf.Bytes()
}
