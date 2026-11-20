package mcphost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const maxMCPCertBindingBytes = 256 * 1024

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
	type dependency struct {
		NodeID, IdentityRef    string
		Identity               models.Identity
		KeyPaths               []string
		IdentityFiles          []string
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
	for _, hop := range plan.Hops {
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
		targets := buildHopBindingTargets(env, hop, snapshot.Identity.KeyPath, snapshot.Node.ProxyJump, cumulativeJump)
		prevHopIDs = append(prevHopIDs, hop.NodeID)
		certBindings := collectHopCertificateBindings(
			env,
			hop,
			snapshot.Identity.KeyPath,
			identityFiles,
			certificateFiles,
			identitiesOnly,
			targets,
		)
		var resolvedAgents []resolvedIdentityAgentBinding
		if identityAgent != "" {
			resolvedAgents = resolveHopIdentityAgentBindings(identityAgent, env, targets)
		}
		dependencies = append(dependencies, dependency{
			NodeID: hop.NodeID, IdentityRef: snapshot.Node.IdentityRef, Identity: snapshot.Identity,
			KeyPaths: append([]string(nil), hop.KeyPaths...), IdentityFiles: identityFiles,
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
	f, _, nonRegular, err := openRegularCertFile(certPath)
	if nonRegular {
		if includeMissing {
			return certificateFileBinding{Path: certPath, NonRegular: true}, true
		}
		return certificateFileBinding{}, false
	}
	if err != nil || f == nil {
		if includeMissing {
			return certificateFileBinding{Path: certPath, Missing: true}, true
		}
		return certificateFileBinding{}, false
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxMCPCertBindingBytes+1))
	if err != nil {
		if includeMissing {
			return certificateFileBinding{Path: certPath, Missing: true}, true
		}
		return certificateFileBinding{}, false
	}
	truncated := len(data) > maxMCPCertBindingBytes
	if truncated {
		data = data[:maxMCPCertBindingBytes]
	}
	rawSum := sha256.Sum256(data)
	binding := certificateFileBinding{
		Path:      certPath,
		Truncated: truncated,
		RawSHA256: hex.EncodeToString(rawSum[:]),
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
	return binding, true
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

func collectHopCertificateBindings(
	env ssh.Environment,
	hop ssh.ConnectionConfig,
	identityKeyPath string,
	identityFiles []string,
	certificateFiles []string,
	identitiesOnly bool,
	targets []ssh.TargetContext,
) []certificateFileBinding {
	var bindings []certificateFileBinding
	seen := make(map[string]struct{})
	if len(certificateFiles) > 0 {
		for _, target := range targets {
			for _, raw := range certificateFiles {
				expanded := expandMCPBindingPath(raw, env, target)
				if expanded == "" {
					continue
				}
				if _, dup := seen[expanded]; dup {
					continue
				}
				seen[expanded] = struct{}{}
				if b, ok := inspectCertificateBinding(expanded, true); ok {
					bindings = append(bindings, b)
				}
			}
		}
		return bindings
	}

	var explicitKeys []string
	explicitKeys = append(explicitKeys, hop.KeyPaths...)
	if hop.KeyPath != "" {
		explicitKeys = append(explicitKeys, hop.KeyPath)
	}
	if identityKeyPath != "" {
		explicitKeys = append(explicitKeys, identityKeyPath)
	}
	explicitKeys = append(explicitKeys, identityFiles...)

	for _, target := range targets {
		hasExplicitCandidate := false
		for _, rawKey := range explicitKeys {
			if expandMCPBindingPath(rawKey, env, target) != "" {
				hasExplicitCandidate = true
				break
			}
		}
		candidateKeys := explicitKeys
		if !identitiesOnly || !hasExplicitCandidate {
			candidateKeys = append(append([]string(nil), explicitKeys...), env.DefaultKeyPaths...)
		}
		for _, rawKey := range candidateKeys {
			expandedKey := expandMCPBindingPath(rawKey, env, target)
			if expandedKey == "" {
				continue
			}
			sidecarPath := strings.TrimSuffix(expandedKey, ".pub") + "-cert.pub"
			if _, dup := seen[sidecarPath]; dup {
				continue
			}
			seen[sidecarPath] = struct{}{}
			if b, ok := inspectCertificateBinding(sidecarPath, false); ok {
				bindings = append(bindings, b)
			}
		}
	}
	return bindings
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
