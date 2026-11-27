package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// fallbackTUI 返回 TUI 工作台哨兵、配置错误及嵌入错误参数的流类型标签规范英文兜底模板。
func fallbackTUI(id domi18n.MessageID) string {
	switch id {
	case KeyTUINilContext:
		return "tui: context must not be nil"
	case KeyTUIInvalidConfig:
		return "tui: invalid TUI configuration"
	case KeyTUIInvalidEvent:
		return "tui: received invalid or unsupported event variant"
	case KeyTUITerminalRestore:
		return "tui: failed to restore terminal state"
	case KeyTUITakeoverDisabled:
		return "tui: interactive session takeover callback is not configured"
	case KeyTUIConfigNoSource:
		return "Engine, Projection, SystemBus, and OperationStreams cannot all be empty"
	case KeyTUIConfigInvalidView:
		return "invalid InitialView ({view})"
	case KeyTUIConfigOutOfBounds:
		return "window size, buffer capacity, or sample limit is out of bounds"
	case KeyTUIConfigInvalidCLIOpts:
		return "invalid CLIOptions"
	case KeyTUIConfigNilOpStream:
		return "OperationStreams[{index}] must not be nil"
	case KeyTUIConfigMetricsInterval:
		return "MetricsInterval must be positive"
	case KeyTUIConfigInvalidLogTarget:
		return "invalid DefaultLogTarget"
	case KeyTUIEventEmpty:
		return "event is nil or failed validation"
	case KeyTUIEventUnsupportedType:
		return "unsupported event type {type}"
	case KeyTUINoHostForMetrics:
		return "no host selected for metrics stream"
	case KeyTUINoHostForLogs:
		return "no host selected for log stream"
	case KeyTUINoHostForTakeover:
		return "no host selected for interactive session"
	case KeyTUIActionQueueBusy:
		return "action queue busy; try again"
	case KeyTUIInventoryErr:
		return "inventory"
	case KeyTUIStreamErr:
		return "{kind} stream ({target})"
	case KeyTUITakeoverErr:
		return "session ({target})"
	case KeyTUIStreamKindMetrics:
		return "metrics"
	case KeyTUIStreamKindLogs:
		return "logs"
	default:
		return ""
	}
}
