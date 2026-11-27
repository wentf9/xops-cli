package i18n

import (
	"slices"
	"testing"
)

// TestAllCoreKeyConstantsBijection 断言本包声明的全部强类型 Key* 常量与 CoreKeys() / corecatalog
// 保持 100% 精确双射（零缺失、零孤儿、零重复且每个兜底模板均合法且参数数 <= MaxMessageParams）。
func TestAllCoreKeyConstantsBijection(t *testing.T) {
	declared := allDeclaredCoreKeys()
	coreKeys := CoreKeys()
	if !slices.IsSorted(coreKeys) {
		t.Fatal("CoreKeys() 必须保持严格字典序升序")
	}
	if len(declared) != len(coreKeys) {
		t.Fatalf("声明常量总数 (%d) 与 CoreKeys() 总数 (%d) 不一致", len(declared), len(coreKeys))
	}
	coreSet := buildUniqueKeySet(t, "CoreKeys()", coreKeys)
	seen := make(map[MessageID]bool, len(declared))
	for _, id := range declared {
		if !id.IsValid() || seen[id] {
			t.Fatalf("声明常量包含非法或重复键: %q", id)
		}
		seen[id] = true
		assertDeclaredKeyInCatalog(t, id, coreSet)
	}
}

func buildUniqueKeySet(t *testing.T, label string, keys []MessageID) map[MessageID]bool {
	t.Helper()
	set := make(map[MessageID]bool, len(keys))
	for _, id := range keys {
		if !id.IsValid() || set[id] {
			t.Fatalf("%s 包含非法或重复键: %q", label, id)
		}
		set[id] = true
	}
	return set
}

func assertDeclaredKeyInCatalog(t *testing.T, id MessageID, coreSet map[MessageID]bool) {
	t.Helper()
	if !coreSet[id] {
		t.Errorf("常量 %q 未在 corecatalog.AllKeys() 中登记", id)
	}
	fb := CanonicalFallback(id)
	if fb == "" {
		t.Errorf("常量 %q 缺少 CanonicalFallback", id)
		return
	}
	ph, err := ExtractPlaceholders(fb)
	if err != nil {
		t.Errorf("常量 %q 兜底模板语法非法 %q: %v", id, fb, err)
	}
	if len(ph) > MaxMessageParams {
		t.Errorf("常量 %q 占位符数 %d 超过 MaxMessageParams(%d)", id, len(ph), MaxMessageParams)
	}
}

func allDeclaredCoreKeys() []MessageID {
	return []MessageID{
		KeyLocaleInvalid, KeyLocaleInvalidValue, KeyParamInvalid, KeyParamInvalidKey,
		KeyParamInvalidKind, KeyParamInvalidValue, KeyParamDepthExceeded, KeyMessageInvalid,
		KeyMessageTooManyParams, KeyMessageDuplicateParam, KeyTemplateInvalid, KeyTemplateUnclosed,
		KeyTemplateUnescaped, KeyTemplateBadKey, KeyNilReceiver, KeyCommonNilContext,
		KeyCommonNotInitialized, KeyCommonInvalidArgument, KeyCommonLimitExceeded, KeyCommonNilCallback,
		KeyCommonNotFound, KeyCommonAlreadyExists, KeyCommonCanceled, KeyCommonTimeout,
		KeyCommonPermissionDeny, KeyCommonInternalError, KeyCommonErrorJoin, KeyCommonFieldRequired,
		KeyCommonFieldInvalid, KeyCommonFieldValueInvalid, KeyCommonFieldEmpty, KeyCommonFieldPositive,
		KeyCommonFieldNegative, KeyCommonFieldRange, KeyCommonFieldMaxExceeded, KeyCommonFieldNil,
		KeyCommonIndexInvalid, KeyCommonIndexValueInvalid, KeyCommonDuplicateItem, KeyCommonMismatch,
		KeyCommonStateForbidden, KeyCommonUnknownValue, KeyCommonValueInvalid, KeyCommonOpFailed,
		KeyCommonOpTargetFailed, KeyCommonPathForbidden, KeyCommonNotSupported, KeyCommonMissingDep,
		KeyCommonComponentClosed, KeyCommonCountLimit, KeyCommonSizeLimit, KeyCommonJSONNullForbidden,
		KeyCommonJSONTrailingData, KeyCommonJSONMissingField, KeyCommonJSONVariantInvalid, KeyCommonMutuallyExclusive,
		KeyCommonOneOfRequired, KeyCommonInvalidTextChars, KeyCommonInvalidUTF8, KeyCommonBase64DecodeFailed,
		KeyCommonZeroEntropy, KeyCommonPermInvalid, KeyCommonEitherMissingDep, KeyCommonUnsupportedVariant,
		KeyCommonIDGenFailed, KeyCommonPathTemplateFailed, keyCommonDetail, KeyInteractHostKeyTitle,
		KeyInteractHostKeyBody, KeyInteractSSHChallengeTitle, KeyInteractChallengeResponse, KeyInteractChallengeBannerResponse,
		KeyInteractKeyPassphraseTitle, KeyInteractKeyPassphraseBody, KeyInteractPrivilegeTitle, KeyInteractPrivilegeBody,
		KeyInteractMuxConfirmTitle, KeyInteractMuxStartBody, KeyInteractMuxReuseBody, KeyInteractMuxAttachBody,
		KeyAlgebraicEmptySlice, KeyAlgebraicInvalidDuration, KeyAlgebraicDurationOverflow, KeyAlgebraicNilReceiver,
		KeyAlgebraicNilCallback, KeyExecutionInvalidLaunchDialect, KeyExecutionInvalidInterpreter, KeyExecutionInvalidLoginMode,
		KeyExecutionInvalidLaunchProfile, KeyExecutionUnsupportedCombination, KeyExecutionNotPOSIXBourne, KeyExecutionInvalidPlanKind,
		KeyExecutionInvalidCommandPlan, KeyExecutionInvalidEnvVar, KeyExecutionInvalidShellQuote, KeyExecutionInvalidPhase,
		KeyExecutionInvalidExitStatus, KeyExecutionInvalidOutcome, KeyExecutionNilWriter, KeyExecutionNilReceiver,
		KeyExecutionScriptPTYForbidden, KeyExecutionScriptInterpreter, KeyExecutionProfileMismatch, KeyExecutionLoginUnsupported,
		KeyExecutionQuoteForbiddenChar, KeyFSMInvalidState, KeyFSMInvalidInput, KeyFSMIllegalTransition,
		KeyFSMInvalidContext, KeyFSMInvalidDurability, KeyFSMInvalidOutcome, KeyFSMInvalidJournal,
		KeyFSMCorruptJournal, KeyFSMTransferSizeExceeded, KeyFSMInvalidChunkOffset, KeyFSMInvalidApprovalEnvelope,
		KeyFSMInvalidEnsureStep, KeyFSMInvalidEnrollLease, KeyFSMNilWriter, KeyFSMNilReceiver,
		KeyFSMTerminalState, KeyFSMExpectedInput, KeyFSMJournalSplitBrain, KeyFSMJournalRollbackForbidden,
		KeyFSMJournalBothCorrupt, KeyFSMChunkRemainingExceeded, KeyFSMTimeBeforeStaged, KeyFSMLeaseNotExpired,
		KeyInventoryInvalidID, KeyInventoryInvalidKeySpec, KeyInventoryInvalidChallengeRule, KeyInventoryInvalidAuthMethod,
		KeyInventoryAuthCompositeTooDeep, KeyInventoryInvalidNodeOrigin, KeyInventoryInvalidHost, KeyInventoryInvalidIdentity,
		KeyInventoryInvalidNode, KeyInventoryInvalidGraph, KeyInventoryDuplicateAssetID, KeyInventoryMissingAssetRef,
		KeyInventoryMissingProxyHop, KeyInventoryProxyJumpCycle, KeyInventoryProxyJumpDepth, KeyInventoryUnknownSecretStore,
		KeyInventoryInvalidImportBundle, KeyInventoryNilWriter, KeyInventoryNilReceiver, KeyInventoryCycleDetected,
		KeyInventoryAliasConflict, KeyInventoryHopUnknown, KeyInventoryRegexCompileFailed, KeyInvNodeMissingAssetRef,
		KeyNetaddrInvalidHost, KeyNetaddrInvalidZone, KeyNetaddrInvalidPort, KeyNetaddrInvalidHostPort,
		KeyNetaddrInvalidEndpoint, KeyNetaddrNilReceiver, KeyNetaddrBracketsMalformed, KeyNetaddrHostPortFormat,
		KeyNetaddrPortFormat, KeyNetaddrHostnameInvalid, KeyNetaddrReasonLength, KeyNetaddrReasonEdgeDot,
		KeyNetaddrReasonNumericTLD, KeyNetaddrReasonLabelLength, KeyNetaddrReasonEdgeHyphen, KeyNetaddrReasonIllegalChar,
		KeyOptionInvalidOption, KeyOptionUnknownOption, KeyOptionInvalidOrigin, KeyOptionInvalidEndpoint,
		KeyOptionInvalidPathList, KeyOptionInvalidAlgoPolicy, KeyOptionEmptyAlgorithmList, KeyOptionInvalidProxyRoute,
		KeyOptionInvalidControlPolicy, KeyOptionInvalidEnvFilter, KeyOptionInvalidPercentInput, KeyOptionNilReceiver,
		KeyOptionQuotedSyntax, KeyOptionDurationInvalid, KeyOptionTemplateInvalid, KeyPathalgInvalidComponent,
		KeyPathalgInvalidRemoteName, KeyPathalgInvalidRemotePath, KeyPathalgInvalidLocalDest, KeyPathalgInvalidLocalDir,
		KeyPathalgInvalidLocalSource, KeyPathalgInvalidSymlinkPolicy, KeyPathalgUnsafeSymlink, KeyPathalgNameCollision,
		KeyPathalgInvalidUTF8, KeyPathalgInvalidProtectedRule, KeyPathalgInvalidGlob, KeyPathalgNilReceiver,
		KeyPathalgTraversalForbidden, KeyPathalgReservedName, KeyPathalgForbiddenChar, KeyPathalgGlobUnclosed,
		KeyPathalgGlobRangeInvalid, KeyPathalgReasonSepOrTraversal, KeyPathalgReasonEdgeSlash, KeyPathalgReasonDisallowedPfx,
		KeyPathalgReasonDriveRelative, KeyPathalgReasonBareDriveRoot, KeyPathalgReasonBareRoot, KeyPathalgReasonCurrentDir,
		KeyPathalgReasonMustBeAbs, KeyPathalgReasonAbsRelMismatch, KeyPathalgReasonUnresolvBase, KeyPathalgReasonEscapesRoot,
		KeyPathalgReasonNonRelOrChar, KeyPathalgReasonAncestorLink, KeyPathalgReasonChainEscapes, KeyPlanInvalidDigest,
		KeyPlanInvalidTransportPolicy, KeyPlanInvalidHopSpec, KeyPlanInvalidConnectionPlan, KeyPlanTamperedPlanDigest,
		KeyPlanInvalidHandleKind, KeyPlanInvalidHandleID, KeyPlanInvalidManagedHandle, KeyPlanNilEntropy,
		KeyPlanNilWriter, KeyPlanNilReceiver, KeyPlanHopIndexDiscontinuous, KeyPlanDigestVerifyFailed,
		KeyPlaybookUnsupportedVersion, KeyPlaybookInvalidPlaybookID, KeyPlaybookInvalidStepID, KeyPlaybookInvalidOnErrorPolicy,
		KeyPlaybookInvalidFileMode, KeyPlaybookInvalidTargetSelector, KeyPlaybookInvalidStepAction, KeyPlaybookInvalidEnsureCheck,
		KeyPlaybookNestedEnsureForbidden, KeyPlaybookInvalidStep, KeyPlaybookDuplicateStepID, KeyPlaybookInvalidPlaybook,
		KeyPlaybookTamperedDigest, KeyPlaybookInvalidVar, KeyPlaybookInvalidStepStatus, KeyPlaybookInvalidNodeStatus,
		KeyPlaybookInvalidStepRecord, KeyPlaybookOutcomeStatusMismatch, KeyPlaybookDuplicateStepRecord, KeyPlaybookUnknownStepID,
		KeyPlaybookEmptyReport, KeyPlaybookNilWriter, KeyPlaybookNilReceiver, KeyPlaybookSelectorOverlap,
		KeyPlaybookOctalModeInvalid, KeySecretInvalid, KeySecretWiped, KeySecretNilCallback,
		KeySecretInvalidRef, KeySecretNilReceiver, KeySecretRefFormat, KeySecurityInvalidVerdict,
		KeySecurityInvalidRiskLevel, KeySecurityInvalidDecision, KeySecurityInvalidCapability, KeySecurityInvalidGlob,
		KeySecurityInvalidNodeOverride, KeySecurityInvalidTraceID, KeySecurityInvalidOperationID, KeySecurityNilEntropy,
		KeySecurityInvalidDigest, KeySecurityInvalidBinding, KeySecurityInvalidEnvelope, KeySecurityInvalidScope,
		KeySecurityNilWriter, KeySecurityNilReceiver, KeySecurityEscalationReasons, KeyPortsNilContext,
		KeyPortsNilCallback, KeyPortsNilReceiver, KeyPortsInvalidArgument, KeyPortsUnsupported,
		KeyPortsClosed, KeyPortsNotFound, KeyPortsAlreadyExists, KeyPortsPermissionDenied,
		KeyPortsLimitExceeded, KeyPortsRevisionConflict, KeyPortsCorruptData, KeyPortsInvalidRevision,
		KeyPortsInvalidDurability, KeyPortsInvalidLockMode, KeyPortsInvalidReadLimits, KeyPortsLockBusy,
		KeyPortsNotRegularFile, KeyPortsSymlinkRejected, KeyPortsHandleExpired, KeyPortsVaultLocked,
		KeyPortsSecretNotFound, KeyPortsSecretVerifyFailed, KeyPortsHostKeyMismatch, KeyPortsHostKeyUnknown,
		KeyPortsHostKeyRevoked, KeyPortsSignerUnavailable, KeyPortsDialFailed, KeyPortsAuthFailed,
		KeyPortsMuxUnavailable, KeyPortsRemoteAnchorMismatch, KeyPortsRemoteIsDir, KeyPortsAuditWriteFailed,
		KeyPortsAuditPostWrite, KeyPortsAuditHalted, KeyPortsInvalidAuditEntry, KeyPortsInvalidProcInstID,
		KeyPortsInteractionUnavail, KeyPortsInteractionCanceled, KeyPortsEntropyShortRead, KeyPortsInvalidTTYSize,
		KeyPortsAuditPostWriteOp, KeyPortsPromptMsgInvalid, KeyPortsModTimeOutOfRange, KeyPortsDurabilitySpec,
		KeyPortsTUNSpecConflict, KeyEventsNilContext, KeyEventsNilReceiver, KeyEventsNilWriter,
		KeyEventsInvalidEvent, KeyEventsInvalidEventMeta, KeyEventsInvalidEventKind, KeyEventsInvalidEventClass,
		KeyEventsInvalidBackpressure, KeyEventsInvalidSeverity, KeyEventsInvalidOutputStream, KeyEventsInvalidAuditStage,
		KeyEventsInvalidPoolAction, KeyEventsInvalidDiagScope, KeyEventsInvalidFSMMachine, KeyEventsUnsupportedClass,
		KeyEventsOperationMismatch, KeyEventsInvalidStreamConfig, KeyEventsStreamNotInit, KeyEventsStreamClosed,
		KeyEventsInvalidFoldFunc, KeyEventsInvalidAuditConfig, KeyEventsNilAuditWriter, KeyEventsAuditDispNotInit,
		KeyEventsAuditHalted, KeyEventsAuditDispatchFailed, KeyEventsInvalidBusConfig, KeyEventsBusNotInit,
		KeyEventsBusClosed, KeyEventsBusSubscriberLimit, KeyEventsSubNotInit, KeyEventsClassMismatch,
		KeyEventsAuditConflict, KeyEventsOutcomeConflict, KeyEventsJSONObjectRequired, KeyEventsAuditHaltWriteFailed,
		KeyEventsAuditHaltReason, KeyOSFSSlotOccupied, KeyOSFSNotSocket, KeyOSFSInvalidControlPath,
		KeyOSFSControlPathTooLong, KeyOSFSUnauthorizedPeer, KeyOSFSUnsupportedPeerCred, KeyOSFSInsecurePermissions,
		KeyOSFSSameFileMismatch, KeyOSFSNotRegularFile, KeyOSFSNotDirectory, KeyOSFSSymlinkDetected,
		KeyOSFSNotUnixSocket, KeyOSFSPeerUIDMismatch, KeyOSFSPeerSIDMismatch, KeyOSFSNamedPipeInvalid,
		KeyOSFSDACLCheckFailed, KeyOSFSPathPlatformMismatch, KeyOSFSLockTargetReplaced, KeyOSFSAppendNewline,
		KeyOSFSStaleProbeFailed, KeyOSFSSyscallFailed, KeyOSFSOpenFailed, KeyOSFSRandomHexFailed,
		KeyOSFSSlotOccupiedAt, KeyOSFSRootAccessDenied, KeyActorNotInitialized, KeyActorAlreadyStarted,
		KeyActorStopped, KeyActorInvalidConfig, KeyActorNilContext, KeyTraceInvalidLeaseScope,
		KeyTraceNilContext, KeyTraceReentrantLease, KeyTraceReentrantDetail, KeyPoolNotInitialized,
		KeyPoolInvalidConfig, KeyPoolClosed, KeyPoolGateHalted, KeyPoolNilContext,
		KeyPoolNilCallback, KeyPoolInvalidPlan, KeyPoolEmptyPlanList, KeyPoolCapacityExceeded,
		KeyPoolParentEpochChanged, KeyPoolInvalidTransportConn, KeyPoolLeaseInvalid, KeyPoolLeaseExpired,
		KeyPoolLeaseRevoked, KeyPoolHopRetired, KeyPoolTeardownEscalated, KeyPoolInvalidResource,
		KeyPoolInvalidHandle, KeyPoolHandleNotFound, KeyPoolHandleRevoked, KeyPoolHandleGenMismatch,
		KeyPoolHandleBindMismatch, KeyPoolHandleTypeMismatch, KeyPoolHandleLimitExceeded, KeyPoolFastPathMiss,
		KeyGateNilContext, KeyGateNilAuthorizer, KeyGateNilCallback, KeyGateInvalidConfig,
		KeyGateInvalidPolicy, KeyGateInvalidProfile, KeyGateInvalidFallback, KeyGateInvalidRequest,
		KeyGateInvalidOutcome, KeyGateCapabilityMismatch, KeyGateNotInitialized, KeyGateHalted,
		KeyGateInvalidPermit, KeyGatePermitRevoked, KeyGateAuthorizationDenied, KeyGateApprovalRequired,
		KeyGateApprovalRejected, KeyGateApprovalExpired, KeyGateApprovalReplayed, KeyGateApprovalMismatch,
		KeyGateApprovalInvalidated, KeyGatePendingLimitExceeded, KeyGateScopeEscalated, KeyGateAuditStageFailed,
		KeyGateAuditPreWriteFailed, KeyGateAuditUnstageFailed, KeyGateReconcilerUnavail, KeyGateOperationPanicked,
		KeyGateOperationAborted, KeyGateExecutionOutcome, KeyGateOpPanickedDetail, KeyGateApprovalChallenge,
		KeyGateApprovalPendingMiss, KeyGateApprovalRound2Diff, KeyGateAbstractCapability, KeyGateInvalidClockTime,
		KeyGateUnknownApprovalPhase, KeyGateProtectedPathCheckFailed, KeyGateApprovalDigestMismatch, KeyGateRound2CanonRequired,
		KeyGateCanonBindingInvalid, KeyGateReasonNilDecision, KeyGateReasonEmptyDecisions, KeyGateReasonUnknownRisk,
		KeyGateReasonInvalidThreshold, KeyGateReasonRiskMeetsThreshold, KeyGateReasonRiskBelowThreshold, KeyGateReasonInvalidOverrides,
		KeyGateReasonNodeOverrideAllow, KeyGateReasonNodeOverrideUnkRisk, KeyGateReasonNodeOverrideAppr, KeyGateReasonNodeOverrideDeny,
		KeyGateReasonLexVerdictDenied, KeyGateReasonLexGuardrailDenied, KeyGateReasonInvalidLexDecision, KeyGateReasonRound2CanonFailed,
		KeyGateReasonCanonBindingDrifted, KeyGateReasonRound2EscFailed, KeyGateReasonEffVerdictDenied, KeyGateReasonCanonGuardrailDeny,
		KeyGateReasonCanonScopeEscalated, KeyGateReasonInvalidCanonDecision, KeyGateReasonUserRejected, KeyGateReasonTokenExpOrMismatch,
		KeyGateReasonTokenDigestMismatch, KeyGateReasonRound2ProbeFailed, KeyGateReasonPostChallengeDrift, KeyGateReasonInvalidProfile,
		KeyGateReasonVerdictDenied, KeyGateReasonDirectOperatorAllow, KeyGateReasonUnexpectedDecision, KeyGateReasonProtectedPath,
		KeyGateReasonGuardrailDenied, KeyGateReasonCanonicalDenied, KeyGateReasonApprovalRequired, KeyGateReasonScopeEscalated,
		KeyGateReasonTokenInvalidated, KeyGateReasonAuthDenied, KeyGateReasonGateHalted, KeyGateReasonPrivEscApproval,
		KeyGateReasonPreEscBaseline, KeyGateReasonInvalidAuditEvent, KeyPrivHandshakeEnded, KeyProbeFailed,
		KeyDialParentRequired, KeyDialNoAuthMethods, KeyDialEmptyAlgoIntersect, KeyDialChallengeUnmatched,
		KeyDialChallengeCmdFailed, KeyDialTOTPInvalid, KeyDialTCPFailed, KeyDialDirectTCPIPFailed,
		KeyDialReadPasswordFailed, KeyDialLoginPasswordUnavail, KeyDialProxyCmdExpandFailed, KeyDialProxyCmdParseFailed,
		KeyDialProxyCmdStartFailed, KeyDialProxyCmdUnclosedQuote, KeyDialHostKeyRecordFailed, KeyDialUnknownHostTrustStatus,
		KeyDialSubsystemUnsupported, KeyKeySignerPassphraseReq, KeyKeySignerFPMismatch, KeyKeySignerNoKeysFound,
		KeyKeySignerNotFound, KeyKeySignerInvalidCert, KeyKeySignerReadKeyFailed, KeyKeySignerParseKeyFailed,
		KeyKeySignerDecryptKeyFailed, KeyKeySignerReadCertFailed, KeyKeySignerParseCertFailed, KeyKeySignerResolveHomeFailed,
		KeyKeySignerParsePubKeyFailed, KeyKeySignerSignFailed, KeyForwardNonLoopback, KeyForwardSOCKS5Header,
		KeyForwardSOCKS5NoAuth, KeyForwardSOCKS5CmdReject, KeyForwardDirUnsupported, KeyForwardListenTCPFailed,
		KeyForwardListenSOCKS5Failed, KeyForwardSOCKS5ATYP, KeyForwardBindAddrInvalid, KeyForwardBindPortInvalid,
		KeyForwardTargetAddrInvalid, KeyForwardSOCKS5DomainInvalid, KeyHostKeyCertTOFU, KeyHostKeyLineMalformed,
		KeyHostKeyReasonBadMarker, KeyHostKeyReasonMissingHost, KeyHostKeyReasonMissingAlg, KeyHostKeyReasonMissingKey,
		KeyHostKeyReasonBadKeyBase64, KeyHostKeyReasonMalformedHash, KeyHostKeyReasonBadHashSalt, KeyHostKeyReasonBadHashDigest,
		KeyMuxExtNotNegotiated, KeyMuxProtoVersion, KeyMuxUnexpectedFrame, KeyMuxFrameTruncated,
		KeyMuxPTYSizeInvalid, KeyMuxRemoteError, KeyMuxControlActionUnsup, KeyMuxTUNDynamicUnsup,
		KeyMuxHandshakeFailed, KeyMuxAliveCheckFailed, KeyMuxSessionCheckFailed, KeyMuxRawSubsysUnsup,
		KeyMuxPacketTooLarge, KeyPrivDialectPOSIXOnly, KeyPrivHandshakeTimeout, KeyPrivPasswordRequired,
		KeyPrivAuthRejected, KeyPrivTokenGenFailed, KeyPrivBuildCmdFailed, KeyPrivQuoteArgFailed,
		KeyPrivMethodUnsupported, KeyPrivWritePasswordFailed, KeyProbeNoDialect, KeyProbeNoInterpreter,
		KeyProbeFrameInvalid, KeyProbeStage2DialectUnsup, KeyProbeStage2EnumFailed, KeyProbeOutputLimit,
		KeyProbeSessionStartFailed, KeyProbeSessionExecFailed, KeySFTPStatusCode, KeySFTPStatusCodeDetail,
		KeySFTPProtoVersion, KeySFTPUnexpectedPacket, KeySFTPPacketTruncated, KeySFTPNotSymlink,
		KeySFTPTempSuffixFailed, KeySFTPDirNotEmpty, KeySFTPDirEntriesLimit, KeySFTPRemoteSizeLimit,
		KeyUCAutoNilContext, KeyUCAutoInvalidConfig, KeyUCAutoNotInitialized, KeyUCAutoInvalidRequest,
		KeyUCAutoNoTargets, KeyUCAutoOpReadUnavail, KeyUCAutoScopedFSUnavail, KeyUCAutoInvUnavail,
		KeyUCAutoTemplateRender, KeyUCAutoBatchFailed, KeyUCAutoPlaybookFailed, KeyUCAutoPlaybookAborted,
		KeyUCAutoUncertainOutcome, KeyUCAutoUncertainDurable, KeyUCAutoUnsupportedAction, KeyUCAutoSymlinkDenied,
		KeyUCAutoSandboxAbsForbid, KeyUCAutoSnapshotMissing, KeyUCAutoRemoteExists, KeyUCAutoBatchCounts,
		KeyUCAutoNodeStreamFailed, KeyUCAutoSandboxFollowUnsup, KeyUCAutoLocalSourceLimit, KeyUCAutoTemplateSizeLimit,
		KeyUCAutoResolveTargetFailed, KeyUCAutoDupTargetNode, KeyUCAutoRemoteCanonHops, KeyUCCredNilContext,
		KeyUCCredNilCallback, KeyUCCredInvalidConfig, KeyUCCredNotInitialized, KeyUCCredInvalidRequest,
		KeyUCCredInvalidSecretBox, KeyUCCredVaultCtrlUnavail, KeyUCCredStoreUnavail, KeyUCCredInteractUnavail,
		KeyUCCredPassphraseDiff, KeyUCCredSecretReferenced, KeyUCCredSagaRolledBack, KeyUCCredUncertainDurable,
		KeyUCCredSagaUncertain, KeyUCCredSecretRefDetail, KeyUCCredStoreUnknown, KeyUCCredRefNotInGraph,
		KeyUCCredSagaStepLimit, KeyUCCredOldSecretGCFailed, KeyUCCredSagaEffectCount, KeyUCCredGenItemFailed,
		KeyUCDoctorVaultUnavailable, KeyUCDoctorVaultStatusFailed, KeyUCDoctorVaultLockedSkip, KeyUCDoctorVaultUninit,
		KeyUCDoctorVaultStateInvalid, KeyUCDoctorStoreLoadGraph, KeyUCDoctorUnknownStore, KeyUCDoctorSecretNotFound,
		KeyUCDoctorVaultLockedProbe, KeyUCDoctorSecretProbeFailed, KeyUCDoctorPendingSecretPin, KeyUCDoctorStoreLoadSnap,
		KeyUCDoctorProxyDAGInvalid, KeyUCDoctorUnusedHost, KeyUCDoctorUnusedIdentity, KeyUCDoctorOpenSSHReadFailed,
		KeyUCDoctorOpenSSHAliasShadow, KeyUCDoctorOpenSSHJumpInvalid, KeyUCDoctorKeySignerUnavail, KeyUCDoctorUnknownAuthMethod,
		KeyUCDoctorPrivKeyInspectFail, KeyUCDoctorPrivKeyFPMismatch, KeyUCInvNilContext, KeyUCInvInvalidConfig,
		KeyUCInvNotInitialized, KeyUCInvInvalidTarget, KeyUCInvUnsupportedOrigin, KeyUCInvMissingUsername,
		KeyUCInvNoAuthMethod, KeyUCInvProxyJumpCycle, KeyUCInvProxyJumpDepth, KeyUCInvNilCallback,
		KeyUCInvInvalidRequest, KeyUCInvStoreUnavail, KeyUCInvGateUnavail, KeyUCInvVaultUnavail,
		KeyUCInvKeySignerUnavail, KeyUCInvInteractUnavail, KeyUCInvClockUnavail, KeyUCInvAssetNotFound,
		KeyUCInvAssetExists, KeyUCInvAssetReferenced, KeyUCInvSecretReferenced, KeyUCInvUnknownImportFmt,
		KeyUCInvImportConflict, KeyUCInvCommitNotApplied, KeyUCInvUncertainDurable, KeyUCInvCommitUnknown,
		KeyUCInvLeaseExpired, KeyUCInvEnrollAborted, KeyUCInvEnrollUncertain, KeyUCInvKeyFPMismatch,
		KeyUCInvAssetRefDetail, KeyUCInvSecretRefDetail, KeyUCInvTemplateToken, KeyUCInvEnvVarMissing,
		KeyUCInvImportConflicts, KeyUCInvFPMismatchDetail, KeyUCInvHopCycleDetail, KeyUCInvNodeNotFound,
		KeyUCInvUsernameHint, KeyUCInvTargetMalformed, KeyUCInvEnvVarPlaceholder, KeyUCInvUnknownImportFmtVal,
		KeyUCInvImportBundleInvalid, KeyUCInvOriginUnsupported, KeyUCInvNodeOriginMismatch, KeyUCInvProxyDepthLimit,
		KeyUCInvPlanHopsLimit, KeyUCInvInitCredSvcFailed, KeyUCInvQueryStoresFailed, KeyUCInvDupImportFormat,
		KeyUCInvJumpHopInvalid, KeyUCInvJumpUserInvalid, KeyUCInvJumpHostInvalid, KeyUCInvTargetReasonBadChars,
		KeyUCInvTargetReasonBadAt, KeyUCInvTargetReasonMissingHost, KeyUCInvTargetReasonBadBrackets, KeyUCInvTargetReasonNotIPv6HP,
		KeyUCInvTargetReasonMalBrackets, KeyUCInvTargetReasonNotIPv6Brkt, KeyUCInvTargetReasonBadSuffix, KeyUCObsNilContext,
		KeyUCObsInvalidConfig, KeyUCObsNotInitialized, KeyUCObsInvalidRequest, KeyUCObsPOSIXRequired,
		KeyUCObsInvalidLogTarget, KeyUCObsInvalidGUIInput, KeyUCObsScreenshotInvalid, KeyUCObsScopedFSUnavail,
		KeyUCObsForwarderUnavail, KeyUCObsProjectionClosed, KeyUCObsUncertainOutcome, KeyUCObsSymlinkDenied,
		KeyUCObsLogLimitReached, KeyUCObsCoordsRange, KeyUCObsImageDimensions, KeyUCObsImageFormat,
		KeyUCObsScreenshotMarker, KeyUCObsNonLoopback, KeyUCObsJPEGEncodeFailed, KeyUCObsImageDecodeFailed,
		KeyUCObsProbeShellFailed, KeyUCObsVNCUnixSocketUnsup, KeyUCSessNilContext, KeyUCSessInvalidConfig, KeyUCSessNotInitialized,
		KeyUCSessInvalidRequest, KeyUCSessInvalidReqTTY, KeyUCSessPortUnavailable, KeyUCSessInvalidProbe,
		KeyUCSessEscScopeChanged, KeyUCSessPTYClosed, KeyUCSessMuxDisabled, KeyUCSessMuxUnavailable,
		KeyUCSessMuxPersistExp, KeyUCSessEscalationDrift, KeyUCSessMuxDisabledInfo, KeyUCSessMuxAskNeedsTTY,
		KeyUCSessMuxRejected, KeyUCSessControlTilde, KeyUCSessReasonLexDenied, KeyUCTransferNilContext,
		KeyUCTransferInvalidCfg, KeyUCTransferNotInit, KeyUCTransferInvalidReq, KeyUCTransferOpReadUnav,
		KeyUCTransferScopedUnav, KeyUCTransferJournalUnav, KeyUCTransferPatchConf, KeyUCTransferPatchNoHit,
		KeyUCTransferPatchAmbig, KeyUCTransferUncertain, KeyUCTransferCorruptJrn, KeyUCTransferNotFound,
		KeyUCTransferHandleDiff, KeyUCTransferSymlinkDeny, KeyUCTransferRemoteUnsup, KeyUCTransferDigestDiff,
		KeyUCTransferTerminal, KeyUCTransferDualActive, KeyUCTransferGenRollback, KeyUCTransferGenUncert,
		KeyUCTransferPatchMulti, KeyUCTransferPatchNoHitIdx, KeyUCTransferSymlinkPol, KeyUCTransferRemoteDrift,
		KeyUCTransferRemoteCycle, KeyUCTransferRemoteAbs, KeyUCTransferRemoteHops, KeyUCTransferRemoteType, KeyUCTransferRecursiveUploadUnsup,
		KeyUCTransferReasonExistsNonDir, KeyUCTransferReasonTargetIsDir, KeyUCTransferReasonNoClobber, KeyUCTransferReasonRecursiveReq,
		KeyUCTransferReasonNotRegular, KeyUCTransferReasonAlreadyExist, KeyUCTransferReasonLinkOverDir, KeyMCPInvalidConfig,
		KeyMCPServerNotInit, KeyMCPServerClosed, KeyMCPNonLoopback, KeyMCPMessageTooLarge,
		KeyMCPStartupReconcile, KeyMCPStartupRecovery, KeyMCPProtoParseJSON, KeyMCPProtoInvalidRPC,
		KeyMCPProtoInvalidReqID, KeyMCPProtoInvalidMsg, KeyMCPProtoInvalidAppr, KeyMCPProtoInvalidSchema,
		KeyMCPProtoInvalidParams, KeyMCPProtoToolNotFound, KeyMCPProtoOutcomeUnk, KeyMCPProtoOutcomeUnkDetail,
		KeyMCPProtoOutcomeUnkReason, KeyMCPToolsInvalidConfig, KeyMCPToolsNotInit, KeyMCPToolsSvcUnavail,
		KeyMCPToolsHandleNotFnd, KeyMCPHTTPHeaderMissing, KeyMCPHTTPHeaderReject, KeyMCPHTTPSessionMiss,
		KeyMCPCorruptJournalLim, KeyMCPProtoIDType, KeyMCPNonLoopbackBind, KeyMCPNonLoopbackHost,
		KeyMCPInvalidListenAddr, KeyMCPProtoMarshalFailed, KeyMCPProtoSchemaCanonFailed, KeyMCPUnknownTool,
		KeyMCPUnknownToolAction, KeyMCPBatchExecStdinUnsup, KeyMCPHTTPListenFailed, KeyMCPHTTPReadBodyFailed,
		KeyMCPTransferPathInvalid, KeyEngineNilContext, KeyEngineInvalidConfig, KeyEngineNotInitialized,
		KeyEngineClosed, KeyEngineHalted, KeyEngineInvalidRequest, KeyEngineInvalidProfile,
		KeyEngineInvalidFallback, KeyEngineInvalidReqTTY, KeyEngineReconcilerUnav, KeyEngineVaultUnavail,
		KeyEngineMCPNotInit, KeyEngineProjNotInit, KeyEngineApprovalReq, KeyEngineApprovalReject,
		KeyEngineAuthDenied, KeyEngineScopeEscalated, KeyEngineNotFound, KeyEngineAlreadyExists,
		KeyEngineRevisionConf, KeyEngineStillReferenced, KeyEngineImportConflict, KeyEngineUncertainDur,
		KeyEngineOutcomeUnknown, KeyEngineVaultLocked, KeyEngineSecretNotFound, KeyEngineAuthFailed,
		KeyEngineHostKeyUnknown, KeyEngineHostKeyMismatch, KeyEngineHostKeyRevoked, KeyEngineDialFailed,
		KeyEngineMuxDisabled, KeyEngineMuxUnavailable, KeyEngineHandleNotFound, KeyEngineHandleRevoked,
		KeyEngineInteractUnav, KeyEngineInteractCancel, KeyEngineAnchorMismatch, KeyEngineRemoteIsDir,
		KeyEngineNotRegularFile, KeyEnginePatchConflict, KeyEngineDigestMismatch, KeyEngineSymlinkReject,
		KeyEngineCorruptData, KeyEngineLimitExceeded, KeyEngineUnsupported, KeyEngineInitCompFailed,
		KeyEngineHostKeyUnobs, KeyEngineKHDirMissing, KeyEngineHostKeyObserverUnsup,
	}
}
