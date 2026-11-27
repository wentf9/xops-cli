package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// fallbackHost 返回本地宿主适配器层（internal/host/**）全部错误与哨兵键的规范英文兜底模板。
// 每条返回文本须与 locales/en/host.yaml 中的对应词条保持 100% 逐字一致，由 catalog_test.go 强制锁死。
func fallbackHost(id domi18n.MessageID) string {
	if text := fallbackHostCommonAndAudit(id); text != "" {
		return text
	}
	if text := fallbackHostOpenSSH(id); text != "" {
		return text
	}
	if text := fallbackHostStore(id); text != "" {
		return text
	}
	if text := fallbackHostYAML(id); text != "" {
		return text
	}
	if text := fallbackHostSys(id); text != "" {
		return text
	}
	return fallbackHostVault(id)
}

func fallbackHostCommonAndAudit(id domi18n.MessageID) string {
	switch id {
	case KeyHostNotInitialized:
		return "{component} is not initialized"
	case KeyHostNilDependency:
		return "{field} must not be nil"
	case KeyHostInvalidField:
		return "{field} is invalid"
	case KeyHostInvalidSecretRef:
		return "invalid secret reference"
	case KeyHostInvalidSecretBox:
		return "invalid SecretBox"
	case KeyHostLimitOutOfRange:
		return "{field}={value} is out of allowed range (1..{max})"
	case KeyHostDurationMustBePositive:
		return "{field} must be a positive duration"
	case KeyHostValueMustBeNonNegative:
		return "{field} must not be negative"
	case KeyHostValueMustBeNonZero:
		return "{field} must not be zero"
	case KeyHostPathIsSymlink:
		return "path {path} is a symlink"
	case KeyHostPathNotDir:
		return "path {path} is not a directory"
	case KeyHostPathNotRegular:
		return "path {path} is not a regular file"
	case KeyHostSizeExceedsLimit:
		return "size exceeds maximum limit of {max} bytes"
	case KeyHostReadFailed:
		return "failed to read {path}"
	case KeyHostAuditCorruptLog:
		return "audit: audit log record is corrupt or malformed"
	case KeyHostAuditUnreconciledLock:
		return "process lock file {path} contains unreconciled entries; run crash reconciliation or use a new ProcessInstanceID"
	case KeyHostAuditLockIOFailed:
		return "process lock log I/O failed"
	case KeyHostAuditLockCompactFailed:
		return "failed to compact process lock after drain"
	case KeyHostAuditLineUnmarshalFailed:
		return "failed to unmarshal audit log line {line}"
	case KeyHostAuditAppendAbortedFailed:
		return "failed to append AbortedByCrash entry"
	default:
		return ""
	}
}

func fallbackHostOpenSSH(id domi18n.MessageID) string {
	switch id {
	case KeyHostOpenSSHIncludeCycle:
		return "openssh: include cycle detected"
	case KeyHostOpenSSHIncludeDepthExceeded:
		return "openssh: include nesting depth exceeded"
	case KeyHostOpenSSHInvalidConfig:
		return "openssh: invalid OpenSSH config file or directive"
	case KeyHostOpenSSHIncludeNeedsHome:
		return "expanding include path {pattern} requires a valid HomeDir"
	case KeyHostOpenSSHIncludeGlobNeedsFS:
		return "wildcard Include {pattern} requires ScopedFS"
	case KeyHostOpenSSHIncludeGlobDotDot:
		return "wildcard include path {pattern} must not contain '..' segments"
	case KeyHostOpenSSHInvalidGlob:
		return "invalid include wildcard pattern {pattern}"
	case KeyHostOpenSSHMatchMissingCriteria:
		return "Match directive is missing valid criteria"
	case KeyHostOpenSSHMatchModifierInvalid:
		return "Match {modifier} has invalid negation, assignment, duplication, or ordering"
	case KeyHostOpenSSHMatchCriterionMissingArg:
		return "Match criterion {keyword} is missing a valid argument"
	case KeyHostOpenSSHIncludeDepthAt:
		return "{path} (depth={depth})"
	case KeyHostOpenSSHIncludeCycleAt:
		return "include cycle at {path}"
	case KeyHostOpenSSHIncludeFilesExceeded:
		return "included file count exceeds limit of {max}"
	case KeyHostOpenSSHFileTooLarge:
		return "{path} exceeds maximum size of {max} bytes"
	case KeyHostOpenSSHLineError:
		return "{file}:{line}"
	case KeyHostOpenSSHInvalidClause:
		return "{file}:{line}: invalid {clause} directive"
	case KeyHostOpenSSHDirectiveMissingValue:
		return "directive {key} is missing a value"
	case KeyHostOpenSSHUnclosedQuote:
		return "unclosed quote"
	default:
		return ""
	}
}

func fallbackHostStore(id domi18n.MessageID) string {
	switch id {
	case KeyHostStoreUnsupportedSchema:
		return "store: unsupported config schema version (only version: 2 is supported)"
	case KeyHostStorePlaintextSecretForbidden:
		return "store: plaintext passwords or secrets are forbidden in config or import sources"
	case KeyHostStoreInvalidCSV:
		return "store: invalid CSV import format or record field"
	case KeyHostStoreCorruptJournalFrame:
		return "store: WAL record frame format or CRC32 check failed"
	case KeyHostStoreCSVEmpty:
		return "CSV input is empty or contains no data rows"
	case KeyHostStoreCSVTooManyRows:
		return "CSV row count exceeds limit of {max}"
	case KeyHostStoreCSVForbiddenColumn:
		return "forbidden plaintext secret column {column}"
	case KeyHostStoreCSVDupOrEmptyColumn:
		return "CSV header contains empty or duplicate column {column}"
	case KeyHostStoreCSVMissingReqColumns:
		return "CSV header must include name/alias, address/host, and user columns"
	case KeyHostStoreCSVUnknownColumn:
		return "unknown CSV column {column}"
	case KeyHostStoreCSVColumnCountMismatch:
		return "CSV row {row} has {got} columns, expected {want}"
	case KeyHostStoreCSVRowInvalidField:
		return "CSV row {row} has invalid {field}"
	case KeyHostStoreCSVInvalidPort:
		return "port {port} is outside valid range 1..65535"
	case KeyHostStoreCSVCertRequiresKey:
		return "cert_path requires key_path to be set"
	case KeyHostStoreOpenSSHNoNodes:
		return "no importable host nodes found in OpenSSH config stream"
	case KeyHostStoreRevisionOverflow:
		return "config revision reached uint64 maximum"
	case KeyHostStoreWALGenerationCorrupt:
		return "WAL generation {generation} is corrupt"
	case KeyHostStoreWALEmpty:
		return "WAL file for generation {generation} is empty"
	case KeyHostStoreWALTruncatedLine:
		return "WAL line {line} is missing trailing newline (possible truncated write)"
	case KeyHostStoreWALLineError:
		return "WAL line {line}"
	case KeyHostStoreWALMarshalFailed:
		return "failed to marshal canonical WAL journal record"
	case KeyHostStoreWALInvalidFrame:
		return "malformed WAL frame header or CRC32 format"
	case KeyHostStoreWALCRCMismatch:
		return "WAL CRC32 checksum mismatch"
	case KeyHostStoreWALPayloadFailed:
		return "WAL payload unmarshal, digest, or ownership verification failed"
	default:
		return ""
	}
}

func fallbackHostYAML(id domi18n.MessageID) string {
	switch id {
	case KeyHostYAMLUnsupportedSchema:
		return "yamlcodec: unsupported config schema version (only version: 2 is supported)"
	case KeyHostYAMLSectionKey:
		return "{section}.{key}"
	case KeyHostYAMLEmptyConfig:
		return "config file is empty"
	case KeyHostYAMLDecodeFailed:
		return "failed to decode YAML vNext document"
	case KeyHostYAMLInvalidVersion:
		return "unsupported schema version {version} (expected 2)"
	case KeyHostYAMLMultipleDocs:
		return "config file must contain a single YAML document"
	case KeyHostYAMLNodeOverrideInvalid:
		return "policy.guardrail.node_overrides rule must be a non-empty string or mapping"
	case KeyHostYAMLDuplicateField:
		return "{section} contains duplicate field {field}"
	case KeyHostYAMLUnknownField:
		return "{section} contains unknown field {field}"
	case KeyHostYAMLNodeOverrideFieldInvalid:
		return "node_overrides[{pattern}].{field} is invalid"
	case KeyHostYAMLInvalidFieldValue:
		return "{field}={value} is invalid"
	case KeyHostYAMLVaultStoreInvalid:
		return "vault.stores.{name} has invalid name or kind {kind}"
	case KeyHostYAMLVaultDefaultUndeclared:
		return "vault.default_store={store} is not declared in vault.stores"
	case KeyHostYAMLPassphraseBindingPair:
		return "passphrase_ref and key_fingerprint must be specified together"
	case KeyHostYAMLInvalidFieldCombo:
		return "invalid field combination for {kind}"
	case KeyHostYAMLLiteralPathRequired:
		return "literal_path requires a valid literal path"
	case KeyHostYAMLAlgoMissingTokens:
		return "algorithm policy {op} requires non-empty tokens"
	case KeyHostYAMLAlgoInvalidToken:
		return "algorithm token {token} contains invalid operator prefix, whitespace, or comma"
	case KeyHostYAMLPathItemInvalid:
		return "invalid state=set path entry {entry}"
	case KeyHostYAMLEnvPatternPrefix:
		return "env filter {field} pattern {pattern} must not start with '-'"
	default:
		return ""
	}
}

func fallbackHostSys(id domi18n.MessageID) string {
	switch id {
	case KeyHostSysOrphanedProcessGroup:
		return "sys: current process is in an orphaned process group or is a session leader; suspend is forbidden"
	case KeyHostSysInputCanceled:
		return "sys: terminal input read canceled by scope end"
	case KeyHostSysHostnameFailed:
		return "failed to query local hostname"
	case KeyHostSysSyscallFailed:
		return "{call} failed"
	case KeyHostSysTerminalStreamReq:
		return "interactive stream terminal requires In, Out, and SizeFn"
	case KeyHostSysTerminalSizeFailed:
		return "failed to query terminal window size"
	case KeyHostSysTerminalNonPosSize:
		return "Windows console returned non-positive size {cols}x{rows}"
	case KeyHostSysTerminalRawModeFailed:
		return "failed to configure raw terminal mode"
	case KeyHostSysCancelHandleFailed:
		return "failed to create cancel wakeup handle"
	case KeyHostAgentInvalidSignArgs:
		return "public key fingerprint and signing algorithm must both be valid"
	case KeyHostAgentDisabled:
		return "SSH agent is explicitly disabled"
	case KeyHostAgentEnvUnset:
		return "environment variable {env} is not set"
	case KeyHostAgentKeyNotFound:
		return "matching public key fingerprint not found in SSH agent"
	case KeyHostSSHFPDNSRcode:
		return "DNS server {server} returned error RCODE={rcode}"
	case KeyHostSSHFPNoServers:
		return "no usable DNS servers configured or discovered"
	case KeyHostSSHFPInvalidServerAddr:
		return "invalid DNS server address {addr}"
	case KeyHostSSHFPWinAdaptersFailed:
		return "failed to query Windows adapter DNS server list"
	case KeyHostSSHFPInvalidDNSName:
		return "invalid DNS query domain name or label length"
	case KeyHostSSHFPDNSHeaderMismatch:
		return "DNS response transaction ID or QR flag mismatch"
	case KeyHostSSHFPDNSBadQDCount:
		return "DNS response QDCOUNT={count} must equal 1"
	case KeyHostSSHFPDNSQuestionMismatch:
		return "DNS Question ({name}, {qtype}, {qclass}) does not match query"
	case KeyHostSSHFPDNSWireMalformed:
		return "malformed or truncated DNS wire packet"
	case KeyHostSSHFPCNAMELoop:
		return "DNS CNAME chain contains a loop"
	case KeyHostSSHFPCNAMETooDeep:
		return "DNS CNAME chain exceeds maximum hop limit of {max}"
	case KeyHostTUNDarwinL3Only:
		return "macOS native utun only supports L3 point-to-point tunnels"
	case KeyHostTUNPlatformUnsupported:
		return "native local TUN/TAP devices are not supported on this platform"
	case KeyHostTUNInvalidIPVersion:
		return "invalid utun L3 frame IP version byte ({byte})"
	default:
		return ""
	}
}

func fallbackHostVault(id domi18n.MessageID) string {
	switch id {
	case KeyHostVaultRouterEmpty:
		return "RouterVault requires at least one store backend or DefaultStore"
	case KeyHostVaultRouterInvalidStore:
		return "vault store {name} or its backend implementation is invalid"
	case KeyHostVaultStoreNotRegistered:
		return "vault store {name} is not registered"
	case KeyHostVaultHelperProtocol:
		return "vault/helper: invalid helper protocol frame"
	case KeyHostVaultHelperReadOnly:
		return "external credential helper is in read-only mode"
	case KeyHostVaultHelperNonZeroExit:
		return "external credential helper exited with non-zero status"
	case KeyHostVaultHelperBase64Failed:
		return "failed to decode Base64 secret payload from helper"
	case KeyHostVaultHelperBadResponse:
		return "external credential helper returned empty, oversized, or invalid JSON response"
	case KeyHostVaultKDFParamsInvalid:
		return "Argon2id parameters out of range (t={time}, m={memory_kib} KiB, p={threads})"
	case KeyHostVaultKDFSubprocessFailed:
		return "isolated KDF subprocess execution failed"
	case KeyHostVaultKeychainLoadFramework:
		return "failed to load {framework}"
	case KeyHostVaultKeychainResolveSymbol:
		return "failed to resolve macOS Keychain symbol {symbol}"
	case KeyHostVaultKeychainOSStatus:
		return "macOS Keychain returned OSStatus={status}"
	case KeyHostVaultOfflineMetaDecode:
		return "failed to decode offline vault metadata"
	case KeyHostVaultOfflineUnsupportedFmt:
		return "unsupported offline vault format version or KDF"
	case KeyHostVaultOfflineItemDecode:
		return "failed to decode offline vault item"
	case KeyHostVaultOfflineCorruptField:
		return "offline vault field {field} is corrupt or invalid"
	case KeyHostVaultOfflineAEADFailed:
		return "offline vault ciphertext authentication failed"
	case KeyHostVaultSSInvalidDHKey:
		return "Secret Service DH server public key length or subgroup is invalid"
	case KeyHostVaultSSInvalidCiphertext:
		return "Secret Service AES-CBC ciphertext, IV, or PKCS#7 padding is invalid"
	case KeyHostVaultSSDBusInvalidAddr:
		return "D-Bus session address must be a single valid local unix:path= address"
	case KeyHostVaultSSDBusAbstractDenied:
		return "security policy rejects D-Bus unix:abstract sockets without filesystem permissions"
	case KeyHostVaultSSDBusUnknownParam:
		return "unknown D-Bus address parameter {param}"
	case KeyHostVaultSSEnvRequired:
		return "EnvPort is required when BusAddress is not explicitly specified"
	case KeyHostVaultSSConnectFailed:
		return "failed to validate or connect to D-Bus session bus"
	case KeyHostVaultSSHandshakeFailed:
		return "D-Bus {step} handshake failed"
	case KeyHostVaultSSBadDBusValue:
		return "unexpected D-Bus response value type for {member}"
	case KeyHostVaultSSDBusCallFailed:
		return "Secret Service D-Bus call failed"
	case KeyHostVaultWinCredCallFailed:
		return "Windows Credential Manager call failed"
	default:
		return ""
	}
}
