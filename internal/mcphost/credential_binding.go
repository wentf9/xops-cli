package mcphost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	maxMCPCertBindingBytes = 256 * 1024
	maxMCPKeyBindingBytes  = 1024 * 1024
)

type certificateFileBinding struct {
	Path        string
	Missing     bool
	NonRegular  bool
	Truncated   bool
	RawSHA256   string
	CertType    uint32
	Serial      uint64
	ValidAfter  uint64
	ValidBefore uint64
	KeySHA256   string
}

type keyFileBinding struct {
	Path       string
	Missing    bool
	NonRegular bool
	Unreadable bool
	Truncated  bool
	SHA256     string
}

type resolvedIdentityAgentBinding struct {
	Socket   string
	Disabled bool
	Invalid  bool
}

// Read-only providers intentionally lack credential-write CAS tokens. Bind
// their credential dependencies separately instead of inventing writable tokens
// or persisting secrets in the connection plan. The provider is the same frozen
// view used to capture all hops; no secret-store reads are performed here.
func credentialVersion(provider config.ConfigProvider, plan ssh.ConnectionPlan) (string, error) {
	copied := plan
	copied.Hops = slices.Clone(plan.Hops)
	for i := range copied.Hops {
		copied.Hops[i] = copied.Hops[i].Clone()
	}
	return bindPlanCredentials(provider, &copied)
}

// bindPlanCredentials computes the deterministic credential dependency version
// for plan and populates every hop's EnforceAdmittedCertificates /
// AdmittedCertificates (including pre-read RawBytes for valid regular certs)
// and EnforceAdmittedKeyDigests / AdmittedKeyDigests (digests only; private key
// bytes are never retained in ConnectionPlan).
func bindPlanCredentials(provider config.ConfigProvider, plan *ssh.ConnectionPlan) (string, error) {
	if plan == nil {
		return "", errors.New("connection plan is required")
	}
	type dependency struct {
		NodeID, IdentityRef    string
		Identity               models.Identity
		KeyPaths               []string
		IdentityFiles          []string
		KeyFileBindings        []keyFileBinding
		CertificateFiles       []string
		CertificateBindings    []certificateFileBinding
		IdentityAgent          string
		ResolvedIdentityAgents []resolvedIdentityAgentBinding
		SudoMode               models.SudoMode
		SuPassword             string
		PrivilegePasswordRef   *credential.Ref
	}
	dependencies := make([]dependency, 0, len(plan.Hops))
	stores := make(map[string]*config.StoreConfig)
	configuration := provider.Snapshot()
	env := sshenv.Discover()
	prevHopIDs := make([]string, 0, len(plan.Hops))
	for i := range plan.Hops {
		hop := &plan.Hops[i]
		snapshot, err := provider.ResolveConnection(hop.NodeID)
		if err != nil {
			return "", fmt.Errorf("resolve MCP credential dependencies for %q: %w", hop.NodeID, err)
		}
		var identityFiles []string
		var certificateFiles []string
		var identityAgent string
		identitiesOnly := false
		if hop.Options != nil {
			identityFiles = hop.Options.IdentityFiles()
			certificateFiles = hop.Options.CertificateFiles()
			identityAgent = hop.Options.IdentityAgent()
			identitiesOnly = hop.Options.IdentitiesOnly()
		}
		if snapshot.Node.SSHOptions != nil {
			if len(identityFiles) == 0 {
				identityFiles = snapshot.Node.SSHOptions.IdentityFiles()
			}
			if len(certificateFiles) == 0 {
				certificateFiles = snapshot.Node.SSHOptions.CertificateFiles()
			}
			if identityAgent == "" {
				identityAgent = snapshot.Node.SSHOptions.IdentityAgent()
			}
			if hop.Options == nil || hop.Options.Get(ssh.OptionIdentitiesOnly) == "" {
				identitiesOnly = snapshot.Node.SSHOptions.IdentitiesOnly()
			}
		}
		cumulativeJump := strings.Join(prevHopIDs, ",")
		targets := buildHopBindingTargets(env, *hop, snapshot.Identity.KeyPath, snapshot.Node.ProxyJump, cumulativeJump)
		prevHopIDs = append(prevHopIDs, hop.NodeID)
		certBindings, admittedCerts := collectHopCertificateBindings(
			env,
			*hop,
			snapshot.Identity.KeyPath,
			identityFiles,
			certificateFiles,
			identitiesOnly,
			targets,
		)
		keyBindings, admittedKeys := collectHopKeyBindings(
			env,
			*hop,
			snapshot.Identity.KeyPath,
			identityFiles,
			identitiesOnly,
			targets,
		)
		hop.EnforceAdmittedCertificates = true
		hop.AdmittedCertificates = admittedCerts
		hop.EnforceAdmittedKeyDigests = true
		hop.AdmittedKeyDigests = admittedKeys

		var resolvedAgents []resolvedIdentityAgentBinding
		if identityAgent != "" {
			resolvedAgents = resolveHopIdentityAgentBindings(identityAgent, env, targets)
		} else if !identitiesOnly {
			resolvedAgents = resolveHopIdentityAgentBindings("", env, targets)
		}
		dependencies = append(dependencies, dependency{
			NodeID: hop.NodeID, IdentityRef: snapshot.Node.IdentityRef, Identity: snapshot.Identity,
			KeyPaths: append([]string(nil), hop.KeyPaths...), IdentityFiles: identityFiles,
			KeyFileBindings:  keyBindings,
			CertificateFiles: certificateFiles, CertificateBindings: certBindings,
			IdentityAgent: identityAgent, ResolvedIdentityAgents: resolvedAgents,
			SudoMode: snapshot.Node.SudoMode, SuPassword: snapshot.Node.SuPwd, PrivilegePasswordRef: snapshot.Node.PrivilegePasswordRef,
		})
		for _, ref := range hopCredentialRefs(snapshot) {
			if ref == nil || ref.IsEmpty() {
				continue
			}
			stores[ref.StoreID] = nil
			if configuration != nil && configuration.Credential != nil {
				if source, ok := configuration.Credential.Stores[ref.StoreID]; ok {
					stores[ref.StoreID] = &source
				}
			}
		}
	}
	// YAML preserves arbitrary bytes in legacy values, unlike JSON strings.
	// Only the digest survives; display fields and unrelated stores are excluded.
	data, err := yaml.Marshal(struct {
		Dependencies []dependency
		Stores       map[string]*config.StoreConfig
	}{dependencies, stores})
	if err != nil {
		return "", fmt.Errorf("encode MCP credential dependencies: %w", err)
	}
	defer clear(data)
	digest := sha256.Sum256(data)
	return "credentials-v1:" + hex.EncodeToString(digest[:]), nil
}

func resolveHopIdentityAgentBindings(
	identityAgent string,
	env ssh.Environment,
	targets []ssh.TargetContext,
) []resolvedIdentityAgentBinding {
	var resolved []resolvedIdentityAgentBinding
	for _, target := range targets {
		sock, disabled, err := ssh.ResolveIdentityAgent(identityAgent, env, target)
		entry := resolvedIdentityAgentBinding{
			Socket:   sock,
			Disabled: disabled,
			Invalid:  err != nil,
		}
		if !slices.Contains(resolved, entry) {
			resolved = append(resolved, entry)
		}
	}
	return resolved
}

func expandMCPBindingPath(raw string, env ssh.Environment, target ssh.TargetContext) string {
	expanded, err := ssh.ExpandIdentityPath(raw, env, target)
	if err != nil {
		return ""
	}
	return expanded
}

func inspectCertificateBinding(certPath string, includeMissing bool) (certificateFileBinding, bool) {
	binding, _, ok := inspectCertificateBindingWithRaw(certPath, includeMissing)
	return binding, ok
}

func inspectCertificateBindingWithRaw(certPath string, includeMissing bool) (certificateFileBinding, ssh.AdmittedCertificate, bool) {
	cleanPath := filepath.Clean(filepath.FromSlash(certPath))
	// OpenSSH follows symlinks for user certificate files (e.g. rotated certs);
	// fsx.OpenRegular opens handle-first without blocking on FIFOs/pipes and
	// rejects non-regular targets with fsx.ErrNonRegular. MaxInt64 lets the
	// bounded LimitReader below compute a truncated digest for oversized files.
	rf, err := fsx.OpenRegular(certPath, fsx.Limits{MaxBytes: math.MaxInt64}, fsx.FollowSymlinks())
	if errors.Is(err, fsx.ErrNonRegular) {
		if includeMissing {
			return certificateFileBinding{Path: certPath, NonRegular: true},
				ssh.AdmittedCertificate{Path: cleanPath, NonRegular: true}, true
		}
		return certificateFileBinding{}, ssh.AdmittedCertificate{}, false
	}
	if err != nil || rf == nil {
		if includeMissing {
			return certificateFileBinding{Path: certPath, Missing: true},
				ssh.AdmittedCertificate{Path: cleanPath, Missing: true}, true
		}
		return certificateFileBinding{}, ssh.AdmittedCertificate{}, false
	}
	defer func() { _ = rf.Close() }()

	data, err := io.ReadAll(io.LimitReader(rf, maxMCPCertBindingBytes+1))
	if err != nil {
		if includeMissing {
			return certificateFileBinding{Path: certPath, Missing: true},
				ssh.AdmittedCertificate{Path: cleanPath, Missing: true}, true
		}
		return certificateFileBinding{}, ssh.AdmittedCertificate{}, false
	}
	truncated := len(data) > maxMCPCertBindingBytes
	if truncated {
		data = data[:maxMCPCertBindingBytes]
	}
	rawSum := sha256.Sum256(data)
	rawHex := hex.EncodeToString(rawSum[:])
	binding := certificateFileBinding{
		Path:      certPath,
		Truncated: truncated,
		RawSHA256: rawHex,
	}
	if pub, _, _, _, parseErr := cryptoSSH.ParseAuthorizedKey(data); parseErr == nil {
		if cert, ok := pub.(*cryptoSSH.Certificate); ok {
			binding.CertType = cert.CertType
			binding.Serial = cert.Serial
			binding.ValidAfter = cert.ValidAfter
			binding.ValidBefore = cert.ValidBefore
			if cert.Key != nil {
				keySum := sha256.Sum256(cert.Key.Marshal())
				binding.KeySHA256 = hex.EncodeToString(keySum[:])
			}
		}
	}
	if truncated {
		// Oversized files exceed core/ssh maxUserCertFileBytes (256 KiB).
		// Leave SHA256 empty and RawBytes nil so handshake always fails closed.
		return binding, ssh.AdmittedCertificate{Path: cleanPath}, true
	}
	admitted := ssh.AdmittedCertificate{
		Path:   cleanPath,
		SHA256: rawHex,
	}
	if len(data) > 0 {
		admitted.RawBytes = data
	}
	return binding, admitted, true
}

func inspectKeyFileBinding(keyPath string, includeMissing bool) (keyFileBinding, ssh.AdmittedKeyDigest, bool) {
	cleanPath := filepath.Clean(filepath.FromSlash(keyPath))
	// OpenSSH follows symlinks for user private keys; fsx.OpenRegular opens
	// handle-first without Stat-then-Open or FIFO blocking, while MaxInt64 lets
	// LimitReader below record a truncated digest on oversized regular files.
	rf, err := fsx.OpenRegular(keyPath, fsx.Limits{MaxBytes: math.MaxInt64}, fsx.FollowSymlinks())
	if errors.Is(err, fsx.ErrNonRegular) {
		if includeMissing {
			return keyFileBinding{Path: cleanPath, NonRegular: true},
				ssh.AdmittedKeyDigest{Path: cleanPath, NonRegular: true}, true
		}
		return keyFileBinding{}, ssh.AdmittedKeyDigest{}, false
	}
	if err != nil || rf == nil {
		if !includeMissing {
			return keyFileBinding{}, ssh.AdmittedKeyDigest{}, false
		}
		if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
			return keyFileBinding{Path: cleanPath, Missing: true},
				ssh.AdmittedKeyDigest{Path: cleanPath, Missing: true}, true
		}
		// Existing but unreadable file (e.g. EACCES): record non-missing with empty
		// SHA-256 so handshake fails closed with ErrSnapshotMismatch instead of
		// silently treating it as absent.
		return keyFileBinding{Path: cleanPath, Unreadable: true},
			ssh.AdmittedKeyDigest{Path: cleanPath}, true
	}
	defer func() { _ = rf.Close() }()

	hasher := sha256.New()
	var scratch [32 * 1024]byte
	defer clear(scratch[:])
	n, readErr := io.CopyBuffer(hasher, io.LimitReader(rf, maxMCPKeyBindingBytes+1), scratch[:])
	if readErr != nil {
		if !includeMissing {
			return keyFileBinding{}, ssh.AdmittedKeyDigest{}, false
		}
		return keyFileBinding{Path: cleanPath, Unreadable: true},
			ssh.AdmittedKeyDigest{Path: cleanPath}, true
	}
	sumHex := hex.EncodeToString(hasher.Sum(nil))
	if n > maxMCPKeyBindingBytes {
		// Exceeds core/ssh maxKeyFileBytes (1 MiB): keep bounded digest for version
		// invalidation, and leave AdmittedKeyDigest.SHA256 empty to fail closed.
		return keyFileBinding{Path: cleanPath, Truncated: true, SHA256: sumHex},
			ssh.AdmittedKeyDigest{Path: cleanPath}, true
	}
	return keyFileBinding{Path: cleanPath, SHA256: sumHex},
		ssh.AdmittedKeyDigest{Path: cleanPath, SHA256: sumHex}, true
}

func buildHopBindingTarget(env ssh.Environment, hop ssh.ConnectionConfig, identityKeyPath string) ssh.TargetContext {
	port := hop.Port
	if port <= 0 {
		port = 22
	}
	user := hop.User
	if user == "" {
		user = env.LocalUser
	}
	originalHost := strings.TrimSpace(hop.OriginalHost)
	if originalHost == "" {
		originalHost = hop.NodeID
	}
	if cleanOrig, ok := config.OpenSSHOriginalHost(originalHost); ok {
		originalHost = cleanOrig
	}
	keyPath := hop.KeyPath
	if keyPath == "" {
		keyPath = identityKeyPath
	}
	return ssh.TargetContext{
		Host:         hop.Address,
		Port:         port,
		User:         user,
		OriginalHost: originalHost,
		JumpHost:     ssh.NormalizeProxyJump(hop.ProxyJump),
		KeyPath:      keyPath,
	}
}

func buildHopBindingTargets(
	env ssh.Environment,
	hop ssh.ConnectionConfig,
	identityKeyPath string,
	nodeProxyJump string,
	extraJumps ...string,
) []ssh.TargetContext {
	base := buildHopBindingTarget(env, hop, identityKeyPath)
	targets := []ssh.TargetContext{base}
	seenJumps := []string{base.JumpHost}

	addAltJump := func(raw string) {
		if !ssh.HasActiveProxyJump(raw) {
			return
		}
		jump := ssh.NormalizeProxyJump(raw)
		if jump == "" || slices.Contains(seenJumps, jump) {
			return
		}
		seenJumps = append(seenJumps, jump)
		alt := base
		alt.JumpHost = jump
		targets = append(targets, alt)
	}
	addAltJump(nodeProxyJump)
	if hop.HasOriginalProxyJump {
		addAltJump(hop.OriginalProxyJump)
	}
	for _, extra := range extraJumps {
		addAltJump(extra)
	}
	return targets
}

func rawHopExplicitKeys(hop ssh.ConnectionConfig, identityKeyPath string, identityFiles []string) []string {
	var explicitKeys []string
	explicitKeys = append(explicitKeys, hop.KeyPaths...)
	if hop.KeyPath != "" {
		explicitKeys = append(explicitKeys, hop.KeyPath)
	}
	if identityKeyPath != "" && identityKeyPath != hop.KeyPath {
		explicitKeys = append(explicitKeys, identityKeyPath)
	}
	explicitKeys = append(explicitKeys, identityFiles...)
	return explicitKeys
}

func expandTargetCandidateKeys(
	rawExplicitKeys []string,
	env ssh.Environment,
	target ssh.TargetContext,
	identitiesOnly bool,
) (explicitPaths []string, defaultPaths []string) {
	hasExplicit := false
	seenExplicit := make(map[string]struct{}, len(rawExplicitKeys))
	for _, raw := range rawExplicitKeys {
		if hasControlOrLineSep(raw) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasExplicit = true
		if ssh.IsNoneValue(trimmed) {
			break
		}
		expanded := expandMCPBindingPath(raw, env, target)
		if expanded == "" {
			continue
		}
		if _, dup := seenExplicit[expanded]; dup {
			continue
		}
		seenExplicit[expanded] = struct{}{}
		explicitPaths = append(explicitPaths, expanded)
	}
	if !identitiesOnly || !hasExplicit {
		seenDefault := make(map[string]struct{}, len(env.DefaultKeyPaths))
		for _, rawDefault := range env.DefaultKeyPaths {
			expanded := expandMCPBindingPath(rawDefault, env, target)
			if expanded == "" {
				continue
			}
			if _, dup := seenExplicit[expanded]; dup {
				continue
			}
			if _, dup := seenDefault[expanded]; dup {
				continue
			}
			seenDefault[expanded] = struct{}{}
			defaultPaths = append(defaultPaths, expanded)
		}
	}
	return explicitPaths, defaultPaths
}

func collectHopCertificateBindings(
	env ssh.Environment,
	hop ssh.ConnectionConfig,
	identityKeyPath string,
	identityFiles []string,
	certificateFiles []string,
	identitiesOnly bool,
	targets []ssh.TargetContext,
) ([]certificateFileBinding, []ssh.AdmittedCertificate) {
	var bindings []certificateFileBinding
	var admitted []ssh.AdmittedCertificate
	seen := make(map[string]struct{})

	hasExplicitCerts := false
	for _, raw := range certificateFiles {
		if hasControlOrLineSep(raw) {
			continue
		}
		if strings.TrimSpace(raw) != "" {
			hasExplicitCerts = true
			break
		}
	}
	if hasExplicitCerts {
		for _, target := range targets {
			for _, raw := range certificateFiles {
				if hasControlOrLineSep(raw) {
					continue
				}
				trimmed := strings.TrimSpace(raw)
				if trimmed == "" {
					continue
				}
				if ssh.IsNoneValue(trimmed) {
					break
				}
				expanded := expandMCPBindingPath(raw, env, target)
				if expanded == "" {
					continue
				}
				if _, dup := seen[expanded]; dup {
					continue
				}
				seen[expanded] = struct{}{}
				if b, a, ok := inspectCertificateBindingWithRaw(expanded, true); ok {
					bindings = append(bindings, b)
					admitted = append(admitted, a)
				}
			}
		}
		return bindings, admitted
	}

	rawExplicitKeys := rawHopExplicitKeys(hop, identityKeyPath, identityFiles)
	for _, target := range targets {
		explicitPaths, defaultPaths := expandTargetCandidateKeys(rawExplicitKeys, env, target, identitiesOnly)
		for _, expandedKey := range append(explicitPaths, defaultPaths...) {
			sidecarPath := strings.TrimSuffix(expandedKey, ".pub") + "-cert.pub"
			if _, dup := seen[sidecarPath]; dup {
				continue
			}
			seen[sidecarPath] = struct{}{}
			if b, a, ok := inspectCertificateBindingWithRaw(sidecarPath, false); ok {
				bindings = append(bindings, b)
				admitted = append(admitted, a)
			}
		}
	}
	return bindings, admitted
}

func collectHopKeyBindings(
	env ssh.Environment,
	hop ssh.ConnectionConfig,
	identityKeyPath string,
	identityFiles []string,
	identitiesOnly bool,
	targets []ssh.TargetContext,
) ([]keyFileBinding, []ssh.AdmittedKeyDigest) {
	var bindings []keyFileBinding
	var admitted []ssh.AdmittedKeyDigest
	seen := make(map[string]struct{})
	var nonPubCandidates []string

	rawExplicitKeys := rawHopExplicitKeys(hop, identityKeyPath, identityFiles)
	for _, target := range targets {
		explicitPaths, defaultPaths := expandTargetCandidateKeys(rawExplicitKeys, env, target, identitiesOnly)
		for _, expandedKey := range append(explicitPaths, defaultPaths...) {
			cleanKey := filepath.Clean(filepath.FromSlash(expandedKey))
			if _, dup := seen[cleanKey]; dup {
				continue
			}
			seen[cleanKey] = struct{}{}
			if b, a, ok := inspectKeyFileBinding(cleanKey, true); ok {
				bindings = append(bindings, b)
				admitted = append(admitted, a)
			}
			if !strings.HasSuffix(cleanKey, ".pub") {
				nonPubCandidates = append(nonPubCandidates, cleanKey)
			}
		}
	}

	// Also bind existing companion .pub files (used by core/ssh for lazy encrypted-key
	// probing and IdentitiesOnly agent matching) without masking explicit .pub entries.
	for _, keyPath := range nonPubCandidates {
		pubPath := keyPath + ".pub"
		if _, dup := seen[pubPath]; dup {
			continue
		}
		seen[pubPath] = struct{}{}
		if b, a, ok := inspectKeyFileBinding(pubPath, false); ok {
			bindings = append(bindings, b)
			admitted = append(admitted, a)
		}
	}
	return bindings, admitted
}

func hopCredentialRefs(snapshot config.ConnectionSnapshot) []*credential.Ref {
	refs := []*credential.Ref{
		snapshot.Identity.LoginPasswordRef,
		snapshot.Identity.PassphraseRef,
		snapshot.Node.PrivilegePasswordRef,
	}
	if snapshot.Identity.OTP != nil {
		refs = append(refs, snapshot.Identity.OTP.TOTPSecretRef)
	}
	if snapshot.Identity.KeyboardInteractive != nil {
		for i := range snapshot.Identity.KeyboardInteractive.Rules {
			refs = append(refs, snapshot.Identity.KeyboardInteractive.Rules[i].SecretRef)
		}
	}
	return refs
}
