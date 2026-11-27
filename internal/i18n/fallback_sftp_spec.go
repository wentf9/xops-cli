package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// fallbackSFTPAndDaemons 返回 SFTP Shell、MCP 与 MuxDaemon 入口全部错误键的规范英文兜底模板。
func fallbackSFTPAndDaemons(id domi18n.MessageID) string {
	if text := fallbackSFTP(id); text != "" {
		return text
	}
	if text := fallbackMCP(id); text != "" {
		return text
	}
	return fallbackMuxDaemon(id)
}

func fallbackSFTP(id domi18n.MessageID) string {
	switch id {
	case KeySFTPNilContext:
		return "sftpshell: context must not be nil"
	case KeySFTPInvalidConfig:
		return "sftpshell: invalid SFTP Shell configuration"
	case KeySFTPNotInitialized:
		return "sftpshell: Shell is not initialized"
	case KeySFTPCommandCanceled:
		return "sftpshell: current command was canceled"
	case KeySFTPSyntax:
		return "sftpshell: invalid command syntax"
	case KeySFTPConfigNilEngine:
		return "Engine must not be nil"
	case KeySFTPConfigNilStdStreams:
		return "Stdout and Stderr must not be nil"
	case KeySFTPConfigTargetXOR:
		return "Target and TargetSpec are mutually exclusive and one is required"
	case KeySFTPConfigTargetConflict:
		return "pre-resolved Target is invalid or cannot be combined with CLIOptions"
	case KeySFTPConfigInvalidField:
		return "invalid {field}"
	case KeySFTPConfigScopedSymlink:
		return "SymlinkFollowOperatorSource is forbidden in ScopedLocalOnly mode"
	case KeySFTPConfigTimeoutPositive:
		return "CommandTimeout must be positive"
	case KeySFTPConfigStreamBufNeg:
		return "StreamBuffer must not be negative"
	case KeySFTPConfigDefaultLocalDir:
		return "failed to initialize default local directory"
	case KeySFTPInitialRemoteNotDir:
		return "initial remote path {path} is not a directory ({type})"
	case KeySFTPUnclosedQuote:
		return "unclosed quote or dangling escape"
	case KeySFTPEmptyRemotePath:
		return "remote path must not be empty"
	case KeySFTPEmptyLocalPath:
		return "local path must not be empty"
	case KeySFTPDisallowedLocalPrefix:
		return "local path {path} uses a forbidden UNC, device namespace, or root-relative backslash prefix"
	case KeySFTPDisallowedDriveRel:
		return "local path {path} is a forbidden drive-relative path"
	case KeySFTPDisallowedPOSIXBackslash:
		return "POSIX absolute path {path} must not contain backslashes"
	case KeySFTPLocalRelEscape:
		return "cannot traverse '..' above relative local directory {dir}"
	case KeySFTPScopedAbsForbidden:
		return "absolute local path {path} is forbidden in ScopedLocalOnly mode"
	case KeySFTPScopedEscape:
		return "local path cannot traverse '..' outside sandbox root"
	case KeySFTPInvalidLocalComponent:
		return "invalid local path component {component}"
	case KeySFTPScopedUploadRoot:
		return "ScopedLocalOnly upload source cannot be sandbox root '.'"
	case KeySFTPInvalidDownloadDest:
		return "invalid download destination path"
	case KeySFTPCannotInferLocalName:
		return "cannot infer local filename from remote path {path}; specify destination explicitly"
	case KeySFTPEmptyPerm:
		return "permission must not be empty"
	case KeySFTPInvalidPerm:
		return "invalid octal permission {value} (must be in 0001..0777)"
	case KeySFTPEmptyTimestamp:
		return "timestamp must not be empty"
	case KeySFTPInvalidTimestamp:
		return "cannot parse timestamp {value} (supports RFC3339, YYYY-MM-DDTHH:MM:SS, or Unix seconds)"
	case KeySFTPTimestampOutOfRange:
		return "timestamp {value} is outside RFC3339 year range [1,9999]"
	case KeySFTPLineTooLong:
		return "command line exceeds maximum length of {max} bytes (line discarded)"
	case KeySFTPUnknownCommand:
		return "unknown command {cmd} (type 'help' for available commands)"
	case KeySFTPNoArgsAllowed:
		return "{cmd} accepts no arguments"
	case KeySFTPUsage:
		return "usage: {usage}"
	case KeySFTPRemoteNotDir:
		return "remote path {path} is not a directory ({type})"
	case KeySFTPLocalNotDir:
		return "local path {path} is not a directory or does not exist"
	case KeySFTPLocalFSUnavailable:
		return "LocalFS is not configured; cannot list local directory"
	case KeySFTPUnknownOption:
		return "{cmd}: unknown option {option}"
	case KeySFTPListTooManyPaths:
		return "ls/lls accepts at most one path argument"
	case KeySFTPUnknownHelpTopic:
		return "unknown help topic {topic}"
	case KeySFTPMkdirMissingMode:
		return "mkdir -m requires a permission argument"
	default:
		return ""
	}
}

func fallbackMCP(id domi18n.MessageID) string {
	switch id {
	case KeyMCPNilContext:
		return "mcpcmd: context must not be nil"
	case KeyMCPInvalidConfig:
		return "mcpcmd: invalid MCP entry configuration"
	case KeyMCPInvalidTransport:
		return "mcpcmd: unsupported MCP transport mode"
	case KeyMCPInvalidTransportValue:
		return "unsupported transport {value} (only stdio or http is supported)"
	case KeyMCPCreateServerFailed:
		return "create mcp server failed"
	case KeyMCPNilServer:
		return "ServerFactory returned nil MCPServerContract"
	case KeyMCPPrepareFailed:
		return "mcp server prepare failed"
	case KeyMCPNoEngineOrFactory:
		return "Engine and ServerFactory cannot both be nil"
	case KeyMCPShutdownTimeoutPositive:
		return "ShutdownTimeout must be positive"
	case KeyMCPStdioNilStreams:
		return "stdio transport requires non-nil Stdin and Stdout"
	case KeyMCPStdioForbidsListener:
		return "stdio transport does not allow an HTTP Listener"
	case KeyMCPHTTPMissingEndpoint:
		return "http transport requires ListenAddr or Listener"
	default:
		return ""
	}
}

func fallbackMuxDaemon(id domi18n.MessageID) string {
	switch id {
	case KeyMuxDaemonNilContext:
		return "muxdaemon: context must not be nil"
	case KeyMuxDaemonInvalidConfig:
		return "muxdaemon: invalid muxdaemon configuration"
	case KeyMuxDaemonNilClient:
		return "Client must not be nil"
	case KeyMuxDaemonNilBackend:
		return "backend must not be nil"
	case KeyMuxDaemonMissingTarget:
		return "TargetSpec or Target must be specified"
	case KeyMuxDaemonInvalidForward:
		return "Forwards[{index}] is invalid"
	case KeyMuxDaemonShutdownTimeoutPositive:
		return "ShutdownTimeout must be positive"
	case KeyMuxDaemonInvalidSocketPath:
		return "invalid SocketPath"
	case KeyMuxDaemonInvalidControlPath:
		return "invalid ControlPath"
	case KeyMuxDaemonInvalidCLIOpts:
		return "CLIOptions validation failed"
	case KeyMuxDaemonNilDoneChan:
		return "{source}.Done() returned nil"
	case KeyMuxDaemonStopForwardFailed:
		return "stop forward {addr} failed"
	case KeyMuxDaemonStopMasterFailed:
		return "stop control master {socket} failed"
	default:
		return ""
	}
}
