package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// fallbackCLI 返回 CLI 命令族与组合根 cmd/xops 全部错误/诊断键的规范英文兜底模板。
func fallbackCLI(id domi18n.MessageID) string {
	if text := fallbackCLISentinelsAndFlags(id); text != "" {
		return text
	}
	if text := fallbackCLIExitAndCommands(id); text != "" {
		return text
	}
	return fallbackCmdXops(id)
}

func fallbackCLISentinelsAndFlags(id domi18n.MessageID) string {
	switch id {
	case KeyCLIInvalidConfig:
		return "cli: invalid AppConfig"
	case KeyCLIAppNotInitialized:
		return "cli: App is not initialized"
	case KeyCLIUsage:
		return "cli: invalid command-line arguments"
	case KeyCLINotConfigured:
		return "cli: host capability callback is not configured"
	case KeyCLIUnsupportedRunner:
		return "cli: engine runner does not support this command capability"
	case KeyCLINilContext:
		return "cli: context must not be nil"
	case KeyCLINilEngineFactory:
		return "EngineFactory must not be nil"
	case KeyCLINilStdStreams:
		return "Stdout and Stderr must not be nil"
	case KeyCLIShutdownTimeoutPositive:
		return "ShutdownTimeout must be positive"
	case KeyCLINilSessionRunner:
		return "EngineFactory returned nil SessionRunner"
	case KeyCLICapabilityRequired:
		return "requires {capability} capability interface"
	case KeyCLIHookNotConfigured:
		return "host callback {hook} is not configured"
	case KeyCLIInputTooLarge:
		return "input exceeds maximum allowed size of {max} bytes"
	case KeyCLIUnknownCommand:
		return "unknown command {cmd} (run 'xops --help' for usage)"
	case KeyCLIUnknownSubcommand:
		return "unknown {cmd} subcommand {sub}"
	case KeyCLIHelpTooManyTopics:
		return "help accepts at most one topic, got {args}"
	case KeyCLIUnknownHelpTopic:
		return "unknown help topic {topic}"
	case KeyCLIVersionInvalidArg:
		return "version accepts only --json, --lang, or --help, got {arg}"
	case KeyCLIMissingShortValue:
		return "option -{flag} requires a value"
	case KeyCLIMissingLongValue:
		return "option --{flag} requires a value"
	case KeyCLIHelpNoValue:
		return "--help does not accept a value"
	case KeyCLIUnknownShortFlag:
		return "unknown short option -{flag}"
	case KeyCLIUnknownLongFlag:
		return "unknown option {flag}"
	case KeyCLIUnexpectedArg:
		return "unexpected argument {arg}"
	case KeyCLIEmptyConfigFile:
		return "-F config file path must not be empty"
	case KeyCLIInvalidBoolFlag:
		return "invalid boolean value {value} for --{flag}"
	case KeyCLIInvalidPositiveInt:
		return "{flag} requires a positive integer, got {value}"
	case KeyCLIInvalidNonNegInt:
		return "{flag} requires a non-negative integer, got {value}"
	case KeyCLIInvalidDuration:
		return "{flag} requires a positive duration (e.g. 30s, 5m), got {value}"
	case KeyCLIEmptyPerm:
		return "{flag} permission must not be empty"
	case KeyCLIInvalidOctalPerm:
		return "{flag} requires a valid octal permission (0001..0777), got {value}"
	case KeyCLIInvalidKeyValue:
		return "{flag} requires KEY=VALUE format, got {value}"
	case KeyCLIInvalidFlagValue:
		return "invalid {flag} value {value}"
	case KeyCLIInvalidFlagValueEnum:
		return "{flag} must be one of {allowed}, got {value}"
	case KeyCLIInvalidField:
		return "invalid {field} {value}"
	case KeyCLIInvalidLaunchProfile:
		return "invalid launch profile combination"
	case KeyCLIInvalidOptionLayer:
		return "CLI option layer validation failed"
	case KeyCLIMissingRequiredFlag:
		return "{cmd} requires {flag}"
	case KeyCLIMutuallyExclusiveFlags:
		return "{flag_a} and {flag_b} cannot be specified together"
	case KeyCLIExactlyOneFlagRequired:
		return "must specify exactly one of {flag_a} or {flag_b}"
	case KeyCLIArgCountExact:
		return "{cmd} requires exactly {count} argument(s): {usage}"
	case KeyCLIArgCountAtLeast:
		return "{cmd} requires at least {count} argument(s): {usage}"
	case KeyCLIInteractiveNoJSON:
		return "interactive {mode} does not support --json output"
	default:
		return ""
	}
}

func fallbackCLIExitAndCommands(id domi18n.MessageID) string {
	switch id {
	case KeyCLIExitInvalidOutcome:
		return "ssh execution failed: invalid execution outcome"
	case KeyCLIExitUnexpectedOutcome:
		return "unexpected execution outcome type {type}"
	case KeyCLIExitInvalidStatus:
		return "ssh execution finished with invalid exit status"
	case KeyCLIExitUnreadableCode:
		return "ssh execution finished with unreadable exit code"
	case KeyCLIExitUnexpectedStatus:
		return "unexpected exit status type {type}"
	case KeyCLIExitSignal:
		return "remote process terminated by signal {signal}"
	case KeyCLIExitSignalCore:
		return "remote process terminated by signal {signal} (core dumped)"
	case KeyCLIExitSignalMsg:
		return "remote process terminated by signal {signal}: {message}"
	case KeyCLIExitSignalCoreMsg:
		return "remote process terminated by signal {signal} (core dumped): {message}"
	case KeyCLIExitUnknown:
		return "remote process exited without exit status"
	case KeyCLIExitUnknownReason:
		return "remote process exited without exit status: {reason}"
	case KeyCLIExitNotStarted:
		return "ssh failed before start ({phase})"
	case KeyCLIExitNotStartedReason:
		return "ssh failed before start ({phase}): {reason}"
	case KeyCLIExitOutcomeUnknown:
		return "ssh outcome unknown ({phase}; do not blindly retry)"
	case KeyCLIExitOutcomeUnknownReason:
		return "ssh outcome unknown ({phase}; do not blindly retry): {reason}"
	case KeyCLIForwardEmpty:
		return "forward specification must not be empty"
	case KeyCLIForwardInvalidDir:
		return "unsupported forward direction {dir}"
	case KeyCLIForwardInvalidSpec:
		return "invalid forward specification {spec}"
	case KeyCLIForwardInvalidPort:
		return "invalid port {port}"
	case KeyCLITUNEmpty:
		return "-w TUN device specification must not be empty"
	case KeyCLITUNInvalidUnit:
		return "TUN device unit {value} must be 'any' or a non-negative integer"
	case KeyCLISSHMissingTarget:
		return "missing target host [user@]host"
	case KeyCLISSHFlagConflictCmd:
		return "{flag} cannot be combined with remote command arguments"
	case KeyCLISSHControlConflictBg:
		return "-O control mode cannot be combined with -f background mode"
	case KeyCLISSHBgRequiresForward:
		return "-f background mode requires -N, -M, or at least one forward (-L/-R/-D/-w)"
	case KeyCLISSHNoCmdRequiresForward:
		return "-N mode requires -M or at least one forward (-L/-R/-D/-w)"
	case KeyCLISSHStdioFwdUnsupported:
		return "-W host:port stdio forwarding is not yet supported; use -J ProxyJump or -O proxy"
	case KeyCLIMuxRequiresSingleForward:
		return "mux {action} requires exactly one forward specification (-L/-R/-D/-w)"
	case KeyCLITunnelRequiresForward:
		return "tunnel requires at least one forward specification (-L/-R/-D/-w)"
	case KeyCLIExecMissingTarget:
		return "exec requires a target host or selector (--all/--nodes/--tags)"
	case KeyCLIExecMissingCommand:
		return "exec requires a remote command"
	case KeyCLIExecBatchPrivUnsupported:
		return "batch exec does not support interactive --sudo/--su/--doas; use single target or playbook"
	case KeyCLIExecPlanFailed:
		return "failed to build command plan"
	case KeyCLIExecSelectorInvalid:
		return "invalid target selector"
	case KeyCLISCPEndpointMismatch:
		return "scp requires one local path and one [user@]host:<remote_path> endpoint"
	case KeyCLISCPDownloadSymlinkPolicy:
		return "scp download only allows --symlink-policy=reject or contained_relative"
	case KeyCLISCPRecursiveSymlinkPolicy:
		return "recursive upload (-r) only allows --symlink-policy=reject"
	case KeyCLISCPLocalRootRelative:
		return "local source must be a sandbox-relative path when --local-root is set"
	case KeyCLISCPRecursiveDotAbs:
		return "recursive upload of '.' requires an absolute working directory or explicit --local-root"
	case KeyCLISCPNoRemoteBase:
		return "remote path {path} has no filename component to infer local destination"
	case KeyCLISFTPRecoverUsage:
		return "sftp recover requires 0 arguments (recover all) or <target> <transfer_id>"
	case KeyCLIVaultIdentityExists:
		return "identity {id} already exists (pass --replace to overwrite)"
	case KeyCLIVaultNodeNotFound:
		return "node {id} not found"
	case KeyCLIPlaybookDecodeFailed:
		return "failed to parse playbook {source}"
	case KeyCLIPlaybookEmpty:
		return "playbook input is empty"
	case KeyCLIPlaybookMustBeObject:
		return "playbook top-level document must be an object, not an array"
	case KeyCLIPlaybookYAMLFailed:
		return "playbook YAML decode failed"
	case KeyCLIPlaybookYAMLDupKey:
		return "playbook YAML contains duplicate key {key}"
	case KeyCLIPlaybookYAMLNoAlias:
		return "playbook YAML aliases are not allowed"
	default:
		return ""
	}
}

func fallbackCmdXops(id domi18n.MessageID) string {
	switch id {
	case KeyCmdConfigDecodeFailed:
		return "failed to decode config field {field}"
	case KeyCmdConfigInvalidValue:
		return "invalid config {field} value {value}"
	case KeyCmdAuditLogInHomeDir:
		return "policy.guardrail.audit_log {path} cannot place audit root directly in home directory; use a path under state directory or a dedicated private directory"
	case KeyCmdEnvNotInitialized:
		return "homeAwareEnv is not initialized"
	case KeyCmdResolveDirFailed:
		return "failed to resolve {target}"
	case KeyCmdInvalidDirPath:
		return "invalid {target} path {path}"
	case KeyCmdOpenSSHConfigUnreadable:
		return "cannot read OpenSSH config file {path}"
	case KeyCmdTakeoverInvalidOutcome:
		return "interactive ssh takeover returned invalid outcome"
	case KeyCmdTakeoverNotStarted:
		return "interactive ssh takeover not started ({phase}/{code}): {reason}"
	case KeyCmdTakeoverOutcomeUnknown:
		return "interactive ssh takeover outcome unknown ({phase}/{code}): {reason}"
	case KeyCmdAuditReadFailed:
		return "failed to read audit log"
	case KeyCmdAuditLineInvalid:
		return "audit log line {line} is invalid"
	case KeyCmdFileTooLarge:
		return "file {path} exceeds maximum allowed size of {max} bytes"
	case KeyCmdFileSizeExceedsLimit:
		return "file {path} size {size} bytes exceeds limit {max} bytes"
	case KeyCmdShutdownStageFailed:
		return "shutdown {stage} failed"
	case KeyCmdVaultUnknownDefault:
		return "vault.default_store {store} is not a known default store"
	case KeyCmdVaultUnsupportedKind:
		return "unsupported vault store {name} kind {kind}"
	case KeyCmdInitComponentFailed:
		return "failed to initialize {component}"
	case KeyCmdLoadConfigFailed:
		return "failed to load config.yaml"
	case KeyCmdReconcileFailed:
		return "startup crash audit reconciliation failed"
	default:
		return ""
	}
}
