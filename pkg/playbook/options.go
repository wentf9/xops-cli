package playbook

// EngineOption 用于配置 Engine
type EngineOption func(*Engine)

// WithEventListener 为 Engine 注入事件监听器（必须支持并发调用）
func WithEventListener(l EventListener) EngineOption {
	return func(e *Engine) {
		if l != nil {
			e.listener = l
		} else {
			e.listener = NopEventListener
		}
	}
}
