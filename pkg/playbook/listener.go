package playbook

// EventListener 定义 Playbook 执行过程中的事件通知接口
type EventListener interface {
	OnTargetsResolved(count int)
	OnTagEmpty(tag string)
	OnStepRunning(host, stepName string)
	OnStepResult(host, stepName string, r StepResult)
}

// nopEventListener 提供默认空实现
type nopEventListener struct{}

func (nopEventListener) OnTargetsResolved(int)                   {}
func (nopEventListener) OnTagEmpty(string)                       {}
func (nopEventListener) OnStepRunning(string, string)            {}
func (nopEventListener) OnStepResult(string, string, StepResult) {}

// NopEventListener 是默认的空事件监听器
var NopEventListener EventListener = nopEventListener{}
