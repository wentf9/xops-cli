package playbook

import (
	"context"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// SetDispatchStepFnForTest allows tests to intercept step dispatch while exercising the real runStep retry loop.
func (e *Engine) SetDispatchStepFnForTest(fn func(context.Context, *ssh.Client, Step, bool, models.Node) StepResult) {
	e.dispatchStepFn = fn
}
