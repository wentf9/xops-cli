package i18n

import (
	"slices"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// TestAllRootKeyConstantsBijection 镜像 core/domain/i18n/keys_bijection_test.go，
// 严格在 LayerInternalI18n 纯内存无 I/O 边界内校验本包声明的全部 604 个 Key* 常量与
// RootKeys() / RootErrorKeys() / rootcatalog 保持 100% 双向双射（零孤儿、零缺失、零重复、零影子兜底）。
func TestAllRootKeyConstantsBijection(t *testing.T) {
	declared := allDeclaredRootKeys()
	rootKeys := RootKeys()
	rootErrKeys := RootErrorKeys()

	if !slices.IsSorted(rootKeys) {
		t.Fatal("RootKeys() 必须保持严格字典序升序")
	}
	if !slices.IsSorted(rootErrKeys) {
		t.Fatal("RootErrorKeys() 必须保持严格字典序升序")
	}
	if len(declared) != len(rootKeys) {
		t.Fatalf("声明常量总数 (%d) 与 RootKeys() 总数 (%d) 不一致", len(declared), len(rootKeys))
	}

	rootSet := buildUniqueRootKeySet(t, "RootKeys()", rootKeys)
	errSet := buildUniqueRootKeySet(t, "RootErrorKeys()", rootErrKeys)
	seen := make(map[domi18n.MessageID]bool, len(declared))
	for _, id := range declared {
		if !id.IsValid() || seen[id] {
			t.Fatalf("声明常量包含非法或重复键: %q", id)
		}
		seen[id] = true
		assertDeclaredRootKeyInCatalog(t, id, rootSet, errSet)
	}
	assertRootKeySliceDefensiveCopies(t)
}

func buildUniqueRootKeySet(t *testing.T, label string, keys []domi18n.MessageID) map[domi18n.MessageID]bool {
	t.Helper()
	set := make(map[domi18n.MessageID]bool, len(keys))
	for _, id := range keys {
		if !id.IsValid() || set[id] {
			t.Fatalf("%s 包含非法或重复键: %q", label, id)
		}
		set[id] = true
	}
	return set
}

func assertDeclaredRootKeyInCatalog(t *testing.T, id domi18n.MessageID, rootSet, errSet map[domi18n.MessageID]bool) {
	t.Helper()
	if !rootSet[id] {
		t.Errorf("常量 %q 未在 rootcatalog.AllKeys() 中登记", id)
	}
	fb := rootFallback(id)
	if !errSet[id] {
		if fb != "" {
			t.Errorf("展示类常量 %q 不应在 rootcatalog.Lookup 中登记影子兜底: %q", id, fb)
		}
		return
	}
	if fb == "" {
		t.Errorf("错误/提示常量 %q 缺少 rootcatalog.Lookup 规范英文兜底", id)
		return
	}
	ph, err := domi18n.ExtractPlaceholders(fb)
	if err != nil {
		t.Errorf("常量 %q 兜底模板语法非法 %q: %v", id, fb, err)
	}
	if len(ph) > domi18n.MaxMessageParams {
		t.Errorf("常量 %q 占位符数 %d 超过 MaxMessageParams(%d)", id, len(ph), domi18n.MaxMessageParams)
	}
}

func assertRootKeySliceDefensiveCopies(t *testing.T) {
	t.Helper()
	all1 := RootKeys()
	origAll := all1[0]
	all1[0] = KeyCatalogCorrupt
	if all2 := RootKeys(); all2[0] != origAll {
		t.Fatalf("RootKeys() 必须返回独立副本: got=%q want=%q", all2[0], origAll)
	}
	err1 := RootErrorKeys()
	origErr := err1[0]
	err1[0] = KeyCatalogCorrupt
	if err2 := RootErrorKeys(); err2[0] != origErr {
		t.Fatalf("RootErrorKeys() 必须返回独立副本: got=%q want=%q", err2[0], origErr)
	}
}

func allDeclaredRootKeys() []domi18n.MessageID {
	return []domi18n.MessageID{
		KeyCLIHelpRoot, KeyCLIHelpVersion, KeyCLIHelpSSH, KeyCLIHelpExec,
		KeyCLIHelpTunnel, KeyCLIHelpMux, KeyCLIHelpSCP, KeyCLIHelpSFTP,
		KeyCLIHelpHosts, KeyCLIHelpVault, KeyCLIHelpConfig, KeyCLIHelpPlaybook,
		KeyCLIHelpDoctor, KeyCLIHelpAudit, KeyCLIHelpMCP, KeyCLIHelpTUI,
		KeyCLIVersionOutput, KeyCLIShutdownFailed, KeyCLIMarshalJSONFailed, KeyCLICleanupFailed,
		KeyCLICommandFailed, KeyCLIApprovalRequired, KeyCLIRefAsset, KeyCLIRefSecret,
		KeyCLIExitJoinDiag, KeyCLISSHMasterActive, KeyCLISSHForwardListening, KeyCLIExecBatchSummary,
		KeyCLIExecBatchNodeHeader, KeyCLIExecStatusOK, KeyCLIExecStatusFailed, KeyCLIExecStatusNotStarted,
		KeyCLIExecStatusCompleted, KeyCLIExecStatusUnknown, KeyCLISCPUploaded, KeyCLISCPDownloaded,
		KeyCLISFTPStat, KeyCLISFTPWrote, KeyCLISFTPPatch, KeyCLISFTPActionOK,
		KeyCLISFTPRenamed, KeyCLISFTPChmodOK, KeyCLISFTPRecoveredOne, KeyCLISFTPRecoverUncertainInspect,
		KeyCLISFTPRecoveredAll, KeyCLISFTPRecoverEntry, KeyCLISFTPRecoverError, KeyCLISFTPRecoverUncertainNoRetry,
		KeyCLIConfigNoFormats, KeyCLIConfigImportSummary, KeyCLIConfigImportLabelPlan, KeyCLIConfigImportLabelImport,
		KeyCLIConfigImportWarnLine, KeyCLIHostsResolved, KeyCLIHostsDAGValid, KeyCLIHostsFoundRefs,
		KeyCLIHostsMutationOK, KeyCLIHostsAllSummary, KeyCLIVaultStatus, KeyCLIVaultStatusDetail,
		KeyCLIVaultActionOK, KeyCLIVaultLocked, KeyCLIVaultDoctorSummary, KeyCLIVaultSagaResult,
		KeyCLIVaultSagaUncertain, KeyCLIVaultRefsSummary, KeyCLIVaultDeleted, KeyCLIVaultGCComplete,
		KeyCLIVaultEnrolled, KeyCLIAuditReconcileSummary, KeyCLIAuditEntriesSummary, KeyCLIDoctorVaultNoCap,
		KeyCLIDoctorVaultNotConfigured, KeyCLIDoctorSummary, KeyCLIDoctorInventory, KeyCLIDoctorVault,
		KeyCLIDoctorVaultNote, KeyCLIPlaybookValid, KeyCLIPlaybookSummary, KeyCLIPlaybookUnknownWarning,
		KeyCLIInvalidConfig, KeyCLIAppNotInitialized, KeyCLIUsage, KeyCLINotConfigured,
		KeyCLIUnsupportedRunner, KeyCLINilContext, KeyCLINilEngineFactory, KeyCLINilStdStreams,
		KeyCLIShutdownTimeoutPositive, KeyCLINilSessionRunner, KeyCLICapabilityRequired, KeyCLIHookNotConfigured,
		KeyCLIInputTooLarge, KeyCLIUnknownCommand, KeyCLIUnknownSubcommand, KeyCLIHelpTooManyTopics,
		KeyCLIUnknownHelpTopic, KeyCLIVersionInvalidArg, KeyCLIMissingShortValue, KeyCLIMissingLongValue,
		KeyCLIHelpNoValue, KeyCLIUnknownShortFlag, KeyCLIUnknownLongFlag, KeyCLIUnexpectedArg,
		KeyCLIEmptyConfigFile, KeyCLIInvalidBoolFlag, KeyCLIInvalidPositiveInt, KeyCLIInvalidNonNegInt,
		KeyCLIInvalidDuration, KeyCLIEmptyPerm, KeyCLIInvalidOctalPerm, KeyCLIInvalidKeyValue,
		KeyCLIInvalidFlagValue, KeyCLIInvalidFlagValueEnum, KeyCLIInvalidField, KeyCLIInvalidLaunchProfile,
		KeyCLIInvalidOptionLayer, KeyCLIMissingRequiredFlag, KeyCLIMutuallyExclusiveFlags, KeyCLIExactlyOneFlagRequired,
		KeyCLIArgCountExact, KeyCLIArgCountAtLeast, KeyCLIInteractiveNoJSON, KeyCLIExitInvalidOutcome,
		KeyCLIExitUnexpectedOutcome, KeyCLIExitInvalidStatus, KeyCLIExitUnreadableCode, KeyCLIExitUnexpectedStatus,
		KeyCLIExitSignal, KeyCLIExitSignalCore, KeyCLIExitSignalMsg, KeyCLIExitSignalCoreMsg,
		KeyCLIExitUnknown, KeyCLIExitUnknownReason, KeyCLIExitNotStarted, KeyCLIExitNotStartedReason,
		KeyCLIExitOutcomeUnknown, KeyCLIExitOutcomeUnknownReason, KeyCLIForwardEmpty, KeyCLIForwardInvalidDir,
		KeyCLIForwardInvalidSpec, KeyCLIForwardInvalidPort, KeyCLITUNEmpty, KeyCLITUNInvalidUnit,
		KeyCLISSHMissingTarget, KeyCLISSHFlagConflictCmd, KeyCLISSHControlConflictBg, KeyCLISSHBgRequiresForward,
		KeyCLISSHNoCmdRequiresForward, KeyCLISSHStdioFwdUnsupported, KeyCLIMuxRequiresSingleForward, KeyCLITunnelRequiresForward,
		KeyCLIExecMissingTarget, KeyCLIExecMissingCommand, KeyCLIExecBatchPrivUnsupported, KeyCLIExecPlanFailed,
		KeyCLIExecSelectorInvalid, KeyCLISCPEndpointMismatch, KeyCLISCPDownloadSymlinkPolicy, KeyCLISCPRecursiveSymlinkPolicy,
		KeyCLISCPLocalRootRelative, KeyCLISCPRecursiveDotAbs, KeyCLISCPNoRemoteBase, KeyCLISFTPRecoverUsage,
		KeyCLIVaultIdentityExists, KeyCLIVaultNodeNotFound, KeyCLIPlaybookDecodeFailed, KeyCLIPlaybookEmpty,
		KeyCLIPlaybookMustBeObject, KeyCLIPlaybookYAMLFailed, KeyCLIPlaybookYAMLDupKey, KeyCLIPlaybookYAMLNoAlias,
		KeyCmdConfigDecodeFailed, KeyCmdConfigInvalidValue, KeyCmdAuditLogInHomeDir, KeyCmdEnvNotInitialized,
		KeyCmdResolveDirFailed, KeyCmdInvalidDirPath, KeyCmdOpenSSHConfigUnreadable, KeyCmdTakeoverInvalidOutcome,
		KeyCmdTakeoverNotStarted, KeyCmdTakeoverOutcomeUnknown, KeyCmdAuditReadFailed, KeyCmdAuditLineInvalid,
		KeyCmdFileTooLarge, KeyCmdFileSizeExceedsLimit, KeyCmdShutdownStageFailed, KeyCmdVaultUnknownDefault,
		KeyCmdVaultUnsupportedKind, KeyCmdInitComponentFailed, KeyCmdLoadConfigFailed, KeyCmdReconcileFailed,
		KeyCLIFieldLocalFilePath, KeyCLIFieldControlSocketPath, KeyCLIFieldRemoteDestPath, KeyCLIFieldRemoteSourcePath,
		KeyCLIFieldLocalSourcePath, KeyCLIFieldLocalRelPath, KeyCLIFieldLocalDirName, KeyCLIFieldLocalDestPath,
		KeyCLIFieldLocalDestFilename, KeyCLIFieldLocalDestRelPath, KeyCLIFieldRemotePath, KeyCLIFieldOldPath,
		KeyCLIFieldNewPath, KeyCLIFieldTransferID, KeyCLIFieldTag, KeyCLIFieldAlias,
		KeyCLIFieldSecretRef, KeyCmdTargetAuditLogDir, KeyCmdTargetAuditLogFile, KeyCmdTargetLocalIdentity,
		KeyCmdTargetHomeDir, KeyCmdTargetDefaultStateDir, KeyCmdTargetDefaultSSHDir, KeyCmdTargetDefaultSSHConfig,
		KeyCmdTargetOpenSSHConfig, KeyCmdTargetInitialRemoteDir, KeyCmdTargetWorkingDir, KeyCmdTargetDefaultVaultDir,
		KeyCmdTargetVaultStore, KeyCmdCompInventoryStore, KeyCmdCompWALJournalStore, KeyCmdCompTerminalAdapter,
		KeyCmdCompInteractionAdapter, KeyCmdCompSSHFPLookupAdapter, KeyCmdCompOpenSSHImporter, KeyCmdCompCSVImporter,
		KeyCmdCompProcessInstanceID, KeyCmdCompAuditSink, KeyCmdCompAuditReconciler, KeyCmdCompDefaultOfflineVault,
		KeyCmdCompPlatformKeychainVault, KeyCmdCompRouterVault, KeyCmdCompConfiguredRouterVault, KeyCmdCompOfflineAEADVault,
		KeyCmdCompOSKeychainVault, KeyCmdCompExternalHelperVault, KeyHostNotInitialized, KeyHostNilDependency,
		KeyHostInvalidField, KeyHostInvalidSecretRef, KeyHostInvalidSecretBox, KeyHostLimitOutOfRange,
		KeyHostDurationMustBePositive, KeyHostValueMustBeNonNegative, KeyHostValueMustBeNonZero, KeyHostPathIsSymlink,
		KeyHostPathNotDir, KeyHostPathNotRegular, KeyHostSizeExceedsLimit, KeyHostReadFailed,
		KeyHostAuditCorruptLog, KeyHostAuditUnreconciledLock, KeyHostAuditLockIOFailed, KeyHostAuditLockCompactFailed,
		KeyHostAuditLineUnmarshalFailed, KeyHostAuditAppendAbortedFailed, KeyHostOpenSSHIncludeCycle, KeyHostOpenSSHIncludeDepthExceeded,
		KeyHostOpenSSHInvalidConfig, KeyHostOpenSSHIncludeNeedsHome, KeyHostOpenSSHIncludeGlobNeedsFS, KeyHostOpenSSHIncludeGlobDotDot,
		KeyHostOpenSSHInvalidGlob, KeyHostOpenSSHMatchMissingCriteria, KeyHostOpenSSHMatchModifierInvalid, KeyHostOpenSSHMatchCriterionMissingArg,
		KeyHostOpenSSHIncludeDepthAt, KeyHostOpenSSHIncludeCycleAt, KeyHostOpenSSHIncludeFilesExceeded, KeyHostOpenSSHFileTooLarge,
		KeyHostOpenSSHLineError, KeyHostOpenSSHInvalidClause, KeyHostOpenSSHDirectiveMissingValue, KeyHostOpenSSHUnclosedQuote,
		KeyHostStoreUnsupportedSchema, KeyHostStorePlaintextSecretForbidden, KeyHostStoreInvalidCSV, KeyHostStoreCorruptJournalFrame,
		KeyHostStoreCSVEmpty, KeyHostStoreCSVTooManyRows, KeyHostStoreCSVForbiddenColumn, KeyHostStoreCSVDupOrEmptyColumn,
		KeyHostStoreCSVMissingReqColumns, KeyHostStoreCSVUnknownColumn, KeyHostStoreCSVColumnCountMismatch, KeyHostStoreCSVRowInvalidField,
		KeyHostStoreCSVInvalidPort, KeyHostStoreCSVCertRequiresKey, KeyHostStoreOpenSSHNoNodes, KeyHostStoreRevisionOverflow,
		KeyHostStoreWALGenerationCorrupt, KeyHostStoreWALEmpty, KeyHostStoreWALTruncatedLine, KeyHostStoreWALLineError,
		KeyHostStoreWALMarshalFailed, KeyHostStoreWALInvalidFrame, KeyHostStoreWALCRCMismatch, KeyHostStoreWALPayloadFailed,
		KeyHostYAMLUnsupportedSchema, KeyHostYAMLSectionKey, KeyHostYAMLEmptyConfig, KeyHostYAMLDecodeFailed,
		KeyHostYAMLInvalidVersion, KeyHostYAMLMultipleDocs, KeyHostYAMLNodeOverrideInvalid, KeyHostYAMLDuplicateField,
		KeyHostYAMLUnknownField, KeyHostYAMLNodeOverrideFieldInvalid, KeyHostYAMLInvalidFieldValue, KeyHostYAMLVaultStoreInvalid,
		KeyHostYAMLVaultDefaultUndeclared, KeyHostYAMLPassphraseBindingPair, KeyHostYAMLInvalidFieldCombo, KeyHostYAMLLiteralPathRequired,
		KeyHostYAMLAlgoMissingTokens, KeyHostYAMLAlgoInvalidToken, KeyHostYAMLPathItemInvalid, KeyHostYAMLEnvPatternPrefix,
		KeyHostSysOrphanedProcessGroup, KeyHostSysInputCanceled, KeyHostSysHostnameFailed, KeyHostSysSyscallFailed,
		KeyHostSysTerminalStreamReq, KeyHostSysTerminalSizeFailed, KeyHostSysTerminalNonPosSize, KeyHostSysTerminalRawModeFailed,
		KeyHostSysCancelHandleFailed, KeyHostAgentInvalidSignArgs, KeyHostAgentDisabled, KeyHostAgentEnvUnset,
		KeyHostAgentKeyNotFound, KeyHostSSHFPDNSRcode, KeyHostSSHFPNoServers, KeyHostSSHFPInvalidServerAddr,
		KeyHostSSHFPWinAdaptersFailed, KeyHostSSHFPInvalidDNSName, KeyHostSSHFPDNSHeaderMismatch, KeyHostSSHFPDNSBadQDCount,
		KeyHostSSHFPDNSQuestionMismatch, KeyHostSSHFPDNSWireMalformed, KeyHostSSHFPCNAMELoop, KeyHostSSHFPCNAMETooDeep,
		KeyHostTUNDarwinL3Only, KeyHostTUNPlatformUnsupported, KeyHostTUNInvalidIPVersion, KeyHostVaultRouterEmpty,
		KeyHostVaultRouterInvalidStore, KeyHostVaultStoreNotRegistered, KeyHostVaultHelperProtocol, KeyHostVaultHelperReadOnly,
		KeyHostVaultHelperNonZeroExit, KeyHostVaultHelperBase64Failed, KeyHostVaultHelperBadResponse, KeyHostVaultKDFParamsInvalid,
		KeyHostVaultKDFSubprocessFailed, KeyHostVaultKeychainLoadFramework, KeyHostVaultKeychainResolveSymbol, KeyHostVaultKeychainOSStatus,
		KeyHostVaultOfflineMetaDecode, KeyHostVaultOfflineUnsupportedFmt, KeyHostVaultOfflineItemDecode, KeyHostVaultOfflineCorruptField,
		KeyHostVaultOfflineAEADFailed, KeyHostVaultSSInvalidDHKey, KeyHostVaultSSInvalidCiphertext, KeyHostVaultSSDBusInvalidAddr,
		KeyHostVaultSSDBusAbstractDenied, KeyHostVaultSSDBusUnknownParam, KeyHostVaultSSEnvRequired, KeyHostVaultSSConnectFailed,
		KeyHostVaultSSHandshakeFailed, KeyHostVaultSSBadDBusValue, KeyHostVaultSSDBusCallFailed, KeyHostVaultWinCredCallFailed,
		KeyInteractNilFileHandles, KeyInteractNilStreamHandles, KeyInteractInvalidRequest, KeyInteractEmptyText,
		KeyInteractEmptySecret, KeyInteractLineTooLong, KeyInteractUnixReadTermios, KeyInteractUnixDisableEcho,
		KeyInteractUnixWakePipe, KeyInteractWinReadConsole, KeyInteractWinDisableEcho, KeyInteractWinCancelEvent,
		KeyInteractVaultInitTitle, KeyInteractVaultUnlockTitle, KeyInteractVaultMasterPrompt, KeyInteractVaultConfirmTitle,
		KeyInteractVaultConfirmPrompt, KeyInteractVaultEnrollPassTitle, KeyInteractVaultEnrollPassPrompt, KeyInteractVaultNodePrivTitle,
		KeyInteractVaultNodePrivPrompt, KeyInteractVaultRotateTitle, KeyInteractVaultRotatePrompt, KeyInteractVaultEnrollKeyTitle,
		KeyInteractVaultEnrollKeyPrompt, KeyInteractRiskUnknown, KeyInteractRiskSafe, KeyInteractRiskModerate,
		KeyInteractRiskDangerous, KeyInteractApprovalBanner, KeyInteractApprovalDigestLabel, KeyCatalogCorrupt,
		KeyCatalogLoadFailed, KeyCatalogMissingLocale, KeyCatalogInvalidYAML, KeyCatalogInvalidKey,
		KeyCatalogDuplicateKey, KeyCatalogInvalidEntry, KeyCatalogInvalidEntryNode, KeyCatalogEmptyEntry,
		KeyCatalogUnknownField, KeyCatalogDuplicateField, KeyCatalogNonScalarField, KeyCatalogMissingOther,
		KeyCatalogInvalidTemplate, KeyCatalogPluralPlaceholderMismatch, KeyCatalogPlaceholderMismatch, KeyCatalogMissingKey,
		KeyStdContextCanceled, KeyStdDeadlineExceeded, KeyConcNurseryNotInitialized, KeyConcNurseryClosed,
		KeyConcNilTask, KeyConcTaskPanicked, KeyConcMutexNotInitialized, KeyConcNilContext,
		KeyConcPanic, KeySFTPNilContext, KeySFTPInvalidConfig, KeySFTPNotInitialized,
		KeySFTPCommandCanceled, KeySFTPSyntax, KeySFTPConfigNilEngine, KeySFTPConfigNilStdStreams,
		KeySFTPConfigTargetXOR, KeySFTPConfigTargetConflict, KeySFTPConfigInvalidField, KeySFTPConfigScopedSymlink,
		KeySFTPConfigTimeoutPositive, KeySFTPConfigStreamBufNeg, KeySFTPConfigDefaultLocalDir, KeySFTPInitialRemoteNotDir,
		KeySFTPUnclosedQuote, KeySFTPEmptyRemotePath, KeySFTPEmptyLocalPath, KeySFTPDisallowedLocalPrefix,
		KeySFTPDisallowedDriveRel, KeySFTPDisallowedPOSIXBackslash, KeySFTPLocalRelEscape, KeySFTPScopedAbsForbidden,
		KeySFTPScopedEscape, KeySFTPInvalidLocalComponent, KeySFTPScopedUploadRoot, KeySFTPInvalidDownloadDest,
		KeySFTPCannotInferLocalName, KeySFTPEmptyPerm, KeySFTPInvalidPerm, KeySFTPEmptyTimestamp,
		KeySFTPInvalidTimestamp, KeySFTPTimestampOutOfRange, KeySFTPLineTooLong, KeySFTPUnknownCommand,
		KeySFTPNoArgsAllowed, KeySFTPUsage, KeySFTPRemoteNotDir, KeySFTPLocalNotDir,
		KeySFTPLocalFSUnavailable, KeySFTPUnknownOption, KeySFTPListTooManyPaths, KeySFTPUnknownHelpTopic,
		KeySFTPMkdirMissingMode, KeySFTPMsgCanceled, KeySFTPMsgTimeout, KeySFTPMsgRemoteIsDirHint,
		KeySFTPMsgOutcomeUnknown, KeySFTPMsgApprovalRequired, KeySFTPOutputStat, KeySFTPOutputUploaded,
		KeySFTPOutputDownloaded, KeySFTPOutputWrote, KeySFTPOutputProgress, KeySFTPHelpSummary,
		KeySFTPHelpPut, KeySFTPHelpGet, KeySFTPHelpMV, KeySFTPHelpChmod,
		KeySFTPHelpChtimes, KeySFTPHelpWrite, KeySFTPHelpStat, KeySFTPHelpLstat,
		KeySFTPHelpGeneric, KeyMCPNilContext, KeyMCPInvalidConfig, KeyMCPInvalidTransport,
		KeyMCPInvalidTransportValue, KeyMCPCreateServerFailed, KeyMCPNilServer, KeyMCPPrepareFailed,
		KeyMCPNoEngineOrFactory, KeyMCPShutdownTimeoutPositive, KeyMCPStdioNilStreams, KeyMCPStdioForbidsListener,
		KeyMCPHTTPMissingEndpoint, KeyMuxDaemonNilContext, KeyMuxDaemonInvalidConfig, KeyMuxDaemonNilClient,
		KeyMuxDaemonNilBackend, KeyMuxDaemonMissingTarget, KeyMuxDaemonInvalidForward, KeyMuxDaemonShutdownTimeoutPositive,
		KeyMuxDaemonInvalidSocketPath, KeyMuxDaemonInvalidControlPath, KeyMuxDaemonInvalidCLIOpts, KeyMuxDaemonNilDoneChan,
		KeyMuxDaemonStopForwardFailed, KeyMuxDaemonStopMasterFailed, KeyTUINilContext, KeyTUIInvalidConfig,
		KeyTUIInvalidEvent, KeyTUITerminalRestore, KeyTUITakeoverDisabled, KeyTUIConfigNoSource,
		KeyTUIConfigInvalidView, KeyTUIConfigOutOfBounds, KeyTUIConfigInvalidCLIOpts, KeyTUIConfigNilOpStream,
		KeyTUIConfigMetricsInterval, KeyTUIConfigInvalidLogTarget, KeyTUIEventEmpty, KeyTUIEventUnsupportedType,
		KeyTUINoHostForMetrics, KeyTUINoHostForLogs, KeyTUINoHostForTakeover, KeyTUIActionQueueBusy,
		KeyTUIInventoryErr, KeyTUIStreamErr, KeyTUITakeoverErr, KeyTUIStreamKindMetrics,
		KeyTUIStreamKindLogs, KeyTUIWindowTitle, KeyTUIBrand, KeyTUIViewHosts,
		KeyTUIViewMetrics, KeyTUIViewLogs, KeyTUIViewOperations, KeyTUIViewHelp,
		KeyTUIViewInvalid, KeyTUIHeaderMeta, KeyTUIBannerHalted, KeyTUIBannerHaltedDefaultReason,
		KeyTUIBannerUnknownOutcome, KeyTUIFilterLabel, KeyTUIFilterEditing, KeyTUIHostsTitle,
		KeyTUIHostsEmpty, KeyTUIStreamIdle, KeyTUIStreamStreaming, KeyTUIMetricsTitle,
		KeyTUIMetricsEmpty, KeyTUIMetricsFrameSummary, KeyTUIMetricsDisks, KeyTUIMetricsTopProcesses,
		KeyTUILogsTitle, KeyTUILogsEmpty, KeyTUILogsTruncated, KeyTUIOpsTitle,
		KeyTUIOpsEmpty, KeyTUIOpStatusRunning, KeyTUIOpStatusOK, KeyTUIOpStatusFailed,
		KeyTUIOpStatusUnknown, KeyTUIHelpTitle, KeyTUIHelpBody, KeyTUIFooterErrPrefix,
		KeyTUIFooterHelp, KeyTUISortCPU, KeyTUISortMem, KeyTUILangNameEn,
		KeyTUILangNameZh, KeyTUIStatusReady, KeyTUIStatusLanguageSwitched, KeyTUIStatusMetricsUpdated,
		KeyTUIStatusGateHalted, KeyTUIStatusFilterMode, KeyTUIStatusFilterCleared, KeyTUIStatusFilterApplied,
		KeyTUIStatusRefreshingInventory, KeyTUIStatusInventoryFailed, KeyTUIStatusInventoryLoaded, KeyTUIStatusStartingMetrics,
		KeyTUIStatusStartingLogs, KeyTUIStatusStoppingStreams, KeyTUIStatusProcessSort, KeyTUIStatusStreamErr,
		KeyTUIStatusStreamActive, KeyTUIStatusStreamIdle, KeyTUIStatusTakeoverErr, KeyTUIStatusTakeoverDone,
	}
}
