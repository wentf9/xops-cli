package engine

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
)

// muxActivityHub 将默认 sshnet/mux 控制套接字上的客户端活跃事件安全桥接至 session.Service.TouchControlMaster，
// 以驱动有限时长 ControlPersist 空闲计时器续期，并在停机或句柄失效时自动清理登记项（锁外调用避免死锁）。
type muxActivityHub struct {
	mu      sync.Mutex
	session *ucsess.Service
	bySock  map[string]plan.ManagedHandle[plan.KindMux]
}

func newMuxActivityHub() *muxActivityHub {
	return &muxActivityHub{bySock: make(map[string]plan.ManagedHandle[plan.KindMux])}
}
func (h *muxActivityHub) bind(svc *ucsess.Service) {
	if h != nil {
		h.mu.Lock()
		h.session = svc
		h.mu.Unlock()
	}
}
func (h *muxActivityHub) register(socketPath string, handle plan.ManagedHandle[plan.KindMux]) {
	key := normalizeMuxSocketKey(socketPath)
	if h == nil || key == "" || !handle.IsValid() {
		return
	}
	h.mu.Lock()
	h.bySock[key] = handle
	h.mu.Unlock()
}
func (h *muxActivityHub) unregisterHandle(handle plan.ManagedHandle[plan.KindMux]) {
	if h == nil || !handle.IsValid() {
		return
	}
	h.mu.Lock()
	for k, cur := range h.bySock {
		if cur.Equal(handle) {
			delete(h.bySock, k)
		}
	}
	h.mu.Unlock()
}
func (h *muxActivityHub) clear() {
	if h != nil {
		h.mu.Lock()
		clear(h.bySock)
		h.mu.Unlock()
	}
}
func (h *muxActivityHub) notify(ctx context.Context, socketAddr string) {
	key := normalizeMuxSocketKey(socketAddr)
	if h == nil || key == "" || ctx == nil || ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	svc, handle := h.session, h.bySock[key]
	h.mu.Unlock()
	if svc == nil || !handle.IsValid() {
		return
	}
	if err := svc.TouchControlMaster(ctx, handle); errors.Is(err, pool.ErrHandleNotFound) || errors.Is(err, pool.ErrHandleRevoked) {
		h.mu.Lock()
		if cur, ok := h.bySock[key]; ok && cur.Equal(handle) {
			delete(h.bySock, key)
		}
		h.mu.Unlock()
	}
}
func normalizeMuxSocketKey(raw string) string {
	s := strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(raw), `\\?\`), `\`, "/")
	if len(s) >= 2 && s[1] == ':' && s[0] >= 'A' && s[0] <= 'Z' {
		s = strings.ToLower(s[:1]) + s[1:]
	}
	return s
}
