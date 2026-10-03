// Package sftp preserves the original import path for the shared XOps implementation.
package sftp

import (
	context "context"
	core "github.com/wentf9/xops-cli/core/sftp"
	ssh "github.com/wentf9/xops-cli/pkg/ssh"
)

type Option = core.Option

func WithConcurrentFiles(con int) Option { return core.WithConcurrentFiles(con) }

func WithThreadsPerFile(t int) Option { return core.WithThreadsPerFile(t) }

func WithChunkSize(size int) Option { return core.WithChunkSize(size) }

func WithResume(enable bool) Option { return core.WithResume(enable) }

func WithResumeMinSize(size int64) Option { return core.WithResumeMinSize(size) }

func WithForce(force bool) Option { return core.WithForce(force) }

type Client = core.Client

func NewClient(ctx context.Context, sshCli *ssh.Client, opts ...Option) (*Client, error) {
	return core.NewClient(ctx, sshCli, opts...)
}

const DefaultConcurrentFiles = core.DefaultConcurrentFiles

const DefaultThreadsPerFile = core.DefaultThreadsPerFile

const DefaultChunkSize = core.DefaultChunkSize

const DefaultResumeMinSize = core.DefaultResumeMinSize

const DefaultTempSuffix = core.DefaultTempSuffix

type TransferConfig = core.TransferConfig

func DefaultConfig() TransferConfig { return core.DefaultConfig() }

type ProgressCallback = core.ProgressCallback
