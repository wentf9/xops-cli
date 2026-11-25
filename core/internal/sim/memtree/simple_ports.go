package memtree

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
)

type simpleBase struct {
	mu          sync.Mutex
	initialized bool
	notInitErr  error
	faults      *FaultInjector
}

func newSimpleBase(notInitErr error) simpleBase {
	return simpleBase{initialized: true, notInitErr: notInitErr, faults: NewFaultInjector(nil)}
}
func (b *simpleBase) ok() bool { return b != nil && b.initialized }
func (b *simpleBase) Faults() *FaultInjector {
	if b.ok() {
		return b.faults
	}
	return nil
}
func (b *simpleBase) withLock(fn func()) {
	if b.ok() {
		b.mu.Lock()
		fn()
		b.mu.Unlock()
	}
}
func (b *simpleBase) check(ctx context.Context, op string, valid ...bool) error {
	if !b.ok() {
		return b.notInitErr
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if slices.Contains(valid, false) {
		return ports.ErrInvalidArgument
	}
	if op != "" {
		return b.faults.Check(op)
	}
	return nil
}

// EnvPort 实现 ports.EnvPort 的纯内存环境变量与本机身份元信息仿真器（零 os.Getenv）。
//
//xops:opaque
//xops:failclosed
type EnvPort struct {
	simpleBase
	env  map[string]string
	id   ports.LocalIdentityInfo
	hasI bool
}

// NewEnvPort 创建预置环境变量快照与可选本机身份信息的仿真环境端口。
func NewEnvPort(notInitErr error, env map[string]string, id ports.LocalIdentityInfo) *EnvPort {
	p := &EnvPort{simpleBase: newSimpleBase(notInitErr), env: maps.Clone(env)}
	if p.env == nil {
		p.env = make(map[string]string)
	}
	if id.IsValid() {
		p.id, p.hasI = id, true
	}
	return p
}
func (e *EnvPort) SetEnv(key, val string) {
	if key != "" {
		e.withLock(func() { e.env[key] = val })
	}
}
func (e *EnvPort) SetIdentity(id ports.LocalIdentityInfo) {
	e.withLock(func() { e.id, e.hasI = id, id.IsValid() })
}
func (e *EnvPort) LookupEnv(key string) (val string, ok bool) {
	if !e.ok() || key == "" {
		return "", false
	}
	e.withLock(func() { val, ok = e.env[key] })
	return val, ok
}
func (e *EnvPort) Environ() map[string]string {
	if !e.ok() {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return maps.Clone(e.env)
}
func (e *EnvPort) LookupLocalIdentity() (out ports.LocalIdentityInfo, err error) {
	if !e.ok() {
		return out, e.notInitErr
	}
	if fErr := e.faults.Check("env.identity"); fErr != nil {
		return out, fErr
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.hasI {
		return out, ports.ErrNotFound
	}
	return e.id, nil
}

// SSHFPLookup 实现 ports.SSHFPLookupPort 的确定性内存 DNS SSHFP 查询仿真器。
//
//xops:opaque
//xops:failclosed
type SSHFPLookup struct {
	simpleBase
	records map[string][]ports.SSHFPRecord
}

// NewSSHFPLookup 创建空白的 SSHFP 查询仿真器。
func NewSSHFPLookup(notInitErr error) *SSHFPLookup {
	return &SSHFPLookup{simpleBase: newSimpleBase(notInitErr), records: make(map[string][]ports.SSHFPRecord)}
}
func (s *SSHFPLookup) SetRecords(host netaddr.CanonicalHost, recs ...ports.SSHFPRecord) {
	if host.IsValid() {
		valid := slices.DeleteFunc(slices.Clone(recs), func(r ports.SSHFPRecord) bool { return !r.IsValid() })
		s.withLock(func() { s.records[host.String()] = valid })
	}
}
func (s *SSHFPLookup) LookupSSHFP(ctx context.Context, host netaddr.CanonicalHost) ([]ports.SSHFPRecord, error) {
	if err := s.check(ctx, "sshfp.lookup", host.IsValid()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records[host.String()]), nil
}

// TUNDevicePort 实现 ports.TUNDevicePort 的纯内存本机 TUN/TAP 虚拟网卡仿真器。
//
//xops:opaque
//xops:failclosed
type TUNDevicePort struct {
	simpleBase
	available bool
	nextUnit  uint32
}

// NewTUNDevicePort 创建默认可用的纯内存本机 TUN/TAP 设备仿真器。
func NewTUNDevicePort(notInitErr error) *TUNDevicePort {
	return &TUNDevicePort{simpleBase: newSimpleBase(notInitErr), available: true}
}
func (t *TUNDevicePort) SetAvailable(en bool) { t.withLock(func() { t.available = en }) }
func (t *TUNDevicePort) OpenLocalTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	if err := t.check(ctx, "tun.open", spec.IsValid()); err != nil {
		return nil, "", err
	}
	var iface string
	var avail bool
	t.withLock(func() {
		avail = t.available
		if !avail {
			return
		}
		unit := spec.LocalUnit()
		if unit == ports.TUNUnitAny {
			unit = t.nextUnit
			t.nextUnit++
		}
		prefix := "tun"
		if spec.Mode() == ports.TUNModeEthernet {
			prefix = "tap"
		}
		iface = fmt.Sprintf("%s%d", prefix, unit)
	})
	if !avail {
		return nil, "", ports.ErrPermissionDenied
	}
	return NewEchoConn("local:" + iface), iface, nil
}
