// Package ssh preserves the original import path for the shared XOps implementation.
package ssh

import (
	context "context"
	core "github.com/wentf9/xops-cli/core/ssh"
	logger "github.com/wentf9/xops-cli/pkg/logger"
	ssh "golang.org/x/crypto/ssh"
	io "io"
	os "os"
	sync "sync"
	time "time"
)

type AuthMethod = core.AuthMethod

type PasswordAuth = core.PasswordAuth

type KeyAuth = core.KeyAuth

type AutoAuthOptions = core.AutoAuthOptions

type Client = core.Client

type InteractiveIO = core.InteractiveIO

type RunConfig = core.RunConfig

type RunOption = core.RunOption

func WithLoginShell(login bool) RunOption { return core.WithLoginShell(login) }

func WithOutputMode(mode OutputMode) RunOption { return core.WithOutputMode(mode) }

func WithRingBuffer(maxBytes int) RunOption { return core.WithRingBuffer(maxBytes) }

func WithStream(writer io.Writer, prefix string) RunOption { return core.WithStream(writer, prefix) }

func WithOutFile(file *os.File) RunOption { return core.WithOutFile(file) }

func DefaultRunConfig() *RunConfig { return core.DefaultRunConfig() }

type Connector = core.Connector

var ErrConnectorClosed = core.ErrConnectorClosed

var ErrInteractionRequired = core.ErrInteractionRequired

const DefaultInteractionTimeout = core.DefaultInteractionTimeout

func NewConnector(provider ConnectionProvider, opts ...Option) *Connector {
	return core.NewConnector(provider, append([]core.Option{core.WithEnvironment(defaultEnvironment())}, opts...)...)
}

type PooledClient = core.PooledClient

type CredentialFailureReporter = core.CredentialFailureReporter

var ErrHostKeyMismatch = core.ErrHostKeyMismatch

var ErrPasswordRequired = core.ErrPasswordRequired

var ErrKeyPathRequired = core.ErrKeyPathRequired

var ErrAgentNotAvailable = core.ErrAgentNotAvailable

var ErrProxyCycle = core.ErrProxyCycle

type ConnectionError = core.ConnectionError

type HandshakeError = core.HandshakeError

type ProxyCycleError = core.ProxyCycleError

const DefaultPasswordPromptPattern = core.DefaultPasswordPromptPattern

type ExpectRule = core.ExpectRule

type Expect = core.Expect

type ExpectOption = core.ExpectOption

func WithExpectLogger(l logger.DebugLogger) ExpectOption { return core.WithExpectLogger(l) }

func NewExpect(writer io.Writer, rules ...ExpectRule) *Expect {
	return core.NewExpect(writer, rules...)
}

func NewExpectWithOptions(writer io.Writer, rules []ExpectRule, opts ...ExpectOption) *Expect {
	return core.NewExpectWithOptions(writer, rules, opts...)
}

func StaticRespond(s string) func() (string, error) { return core.StaticRespond(s) }

var ErrHandshakeClosed = core.ErrHandshakeClosed

const DefaultKeepAliveInterval = core.DefaultKeepAliveInterval

const DefaultKeepAliveTimeout = core.DefaultKeepAliveTimeout

func StartKeepAlive(ctx context.Context, client *ssh.Client, interval, timeout time.Duration, fallback func(err error)) <-chan struct{} {
	return core.StartKeepAlive(ctx, client, interval, timeout, fallback)
}

type DiskMetric = core.DiskMetric

type SystemMetrics = core.SystemMetrics

type CPUTicks = core.CPUTicks

type MetricsCollector = core.MetricsCollector

func NewMetricsCollector(c *Client) *MetricsCollector { return core.NewMetricsCollector(c) }

type Option = core.Option

func WithLogger(l logger.DebugLogger) Option { return core.WithLogger(l) }

func WithPasswordPromptPattern(pattern string) Option { return core.WithPasswordPromptPattern(pattern) }

func WithInteractionHandler(handler InteractionHandler) Option {
	return core.WithInteractionHandler(handler)
}

func WithSecretPrompter(prompter SecretPrompter) Option { return core.WithSecretPrompter(prompter) }

func WithHostKeyConfirmer(confirmer HostKeyConfirmer) Option {
	return core.WithHostKeyConfirmer(confirmer)
}

func WithInteractionTimeout(timeout time.Duration) Option {
	return core.WithInteractionTimeout(timeout)
}

func WithHandshakeTimeout(timeout time.Duration) Option { return core.WithHandshakeTimeout(timeout) }

func WithDialer(dialer Dialer) Option { return core.WithDialer(dialer) }

func WithSecretResolver(resolver SecretResolver) Option { return core.WithSecretResolver(resolver) }

func WithCredentialRecorder(recorder CredentialRecorder) Option {
	return core.WithCredentialRecorder(recorder)
}

func WithConnectionProvider(provider ConnectionProvider) Option {
	return core.WithConnectionProvider(provider)
}

type OutputMode = core.OutputMode

const OutputModeString = core.OutputModeString

const OutputModeRingBuffer = core.OutputModeRingBuffer

const OutputModeStream = core.OutputModeStream

const OutputModeFile = core.OutputModeFile

type LockedWriter = core.LockedWriter

func NewLockedWriter(mu *sync.Mutex, w io.Writer) *LockedWriter { return core.NewLockedWriter(mu, w) }

type SSHProxyDialer = core.SSHProxyDialer

type Forward = core.Forward

type ForwardOption = core.ForwardOption

func WithForwardConnectionLimit(limit int) ForwardOption {
	return core.WithForwardConnectionLimit(limit)
}

func WithForwardErrorHandler(handler func(error)) ForwardOption {
	return core.WithForwardErrorHandler(handler)
}

type Dialer = core.Dialer

type SudoMode = core.SudoMode

const SudoModeRoot = core.SudoModeRoot

const SudoModeSudo = core.SudoModeSudo

const SudoModeSudoer = core.SudoModeSudoer

const SudoModeSu = core.SudoModeSu

const SudoModeNone = core.SudoModeNone

const SudoModeAuto = core.SudoModeAuto

type ClientConfig = core.ClientConfig

type ConnectionConfig = core.ConnectionConfig

type AuthMaterial = core.AuthMaterial

type PrivilegeMaterial = core.PrivilegeMaterial

type ConnectionConfirmer = core.ConnectionConfirmer

type ConnectionProvider = core.ConnectionProvider

type SecretResolver = core.SecretResolver

type CredentialRecorder = core.CredentialRecorder

type ConfigStore = core.ConfigStore

type SecretKind = core.SecretKind

const SecretKindUnknown = core.SecretKindUnknown

const SecretKindLoginPassword = core.SecretKindLoginPassword

const SecretKindPrivateKeyPassphrase = core.SecretKindPrivateKeyPassphrase

const SecretKindSuPassword = core.SecretKindSuPassword

const SecretKindSudoPassword = core.SecretKindSudoPassword

var ErrSnapshotMismatch = core.ErrSnapshotMismatch

type SecretRequest = core.SecretRequest

type HostKeyConfirmation = core.HostKeyConfirmation

type SecretPrompter = core.SecretPrompter

type HostKeyConfirmer = core.HostKeyConfirmer

type InteractionHandler = core.InteractionHandler
