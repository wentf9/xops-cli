package engine

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
)

// muxActivityHub 将默认 sshnet/mux 控制套接字上的客户端进入/活跃/离开与监听关闭事件
// 安全桥接至 session.Service.TouchControlMasterActivity，保活活跃会话并在监听退出时零泄漏清理索引。
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
func (h *muxActivityHub) register(socketPath string, handle plan.ManagedHandle[plan.KindMux], doneCh <-chan struct{}) {
	key := normalizeMuxSocketKey(socketPath)
	if h == nil || key == "" || !handle.IsValid() {
		return
	}
	if doneCh != nil {
		select {
		case <-doneCh:
			return
		default:
		}
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
func (h *muxActivityHub) notify(ctx context.Context, socketAddr string, kind mux.SocketActivityKind) {
	key := normalizeMuxSocketKey(socketAddr)
	if h == nil || key == "" {
		return
	}
	if kind == mux.SocketActivityClosed {
		h.mu.Lock()
		delete(h.bySock, key)
		h.mu.Unlock()
		return
	}
	if ctx == nil || ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	svc, handle := h.session, h.bySock[key]
	h.mu.Unlock()
	if svc == nil || !handle.IsValid() {
		return
	}
	delta := 0
	switch kind {
	case mux.SocketActivityClientEnter:
		delta = 1
	case mux.SocketActivityClientLeave:
		delta = -1
	}
	if err := svc.TouchControlMasterActivity(ctx, handle, delta); errors.Is(err, pool.ErrHandleNotFound) || errors.Is(err, pool.ErrHandleRevoked) {
		h.mu.Lock()
		if cur, ok := h.bySock[key]; ok && cur.Equal(handle) {
			delete(h.bySock, key)
		}
		h.mu.Unlock()
	}
}
func normalizeMuxSocketKey(raw string) string {
	s := strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(raw), `\\?\`), `\`, "/")
	for strings.HasPrefix(s, "./") {
		s = strings.TrimPrefix(s, "./")
	}
	if len(s) >= 2 && s[1] == ':' && s[0] >= 'A' && s[0] <= 'Z' {
		s = strings.ToLower(s[:1]) + s[1:]
	}
	return s
}
