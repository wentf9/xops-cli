package cmd

import (
	"context"

	"github.com/wentf9/xops-cli/pkg/config"
)

func (o *SshOptions) withTestPendingNode(ctx context.Context, provider config.ConfigProvider, fn func(config.PendingLease) error) error {
	req, err := o.buildPendingEnsureOptions(ctx, provider)
	if err != nil {
		return err
	}
	return config.WithPendingNode(ctx, provider, req, fn)
}

func (o *ScpOptions) withTestPendingPath(ctx context.Context, provider config.ConfigProvider, p PathInfo, specificPassword string, fn func(config.PendingLease) error) error {
	req, err := o.buildScpEnsureOptions(provider, p, specificPassword)
	if err != nil {
		return err
	}
	return config.WithPendingNode(ctx, provider, req, fn)
}

func (o *ExecOptions) withTestPendingHostTasks(ctx context.Context, provider config.ConfigProvider, fn func([]execHostTask, []config.PendingLease, []error) error) error {
	tasks, hostErrs, err := o.planTasksFromHosts(ctx, provider)
	if err != nil {
		return err
	}
	return o.withPendingExecTasks(ctx, provider, tasks, func(mat []execHostTask, leases []config.PendingLease, matErrs []error) error {
		return fn(mat, leases, append(hostErrs, matErrs...))
	})
}

func (o *ExecOptions) withTestPendingTagTasks(ctx context.Context, provider config.ConfigProvider, fn func([]execHostTask, []config.PendingLease) error) error {
	tasks, err := o.planTasksFromTags(ctx, provider)
	if err != nil {
		return err
	}
	return o.withPendingExecTasks(ctx, provider, tasks, func(mat []execHostTask, leases []config.PendingLease, _ []error) error {
		return fn(mat, leases)
	})
}
