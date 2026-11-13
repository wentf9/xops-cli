package mcphost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type certificateFileBinding struct {
	Path        string
	Missing     bool
	RawSHA256   string
	CertType    uint32
	Serial      uint64
	ValidAfter  uint64
	ValidBefore uint64
	KeySHA256   string
}

// Read-only providers intentionally lack credential-write CAS tokens. Bind
// their credential dependencies separately instead of inventing writable tokens
// or persisting secrets in the connection plan. The provider is the same frozen
// view used to capture all hops; no secret-store reads are performed here.
func credentialVersion(provider config.ConfigProvider, plan ssh.ConnectionPlan) (string, error) {
	type dependency struct {
		NodeID, IdentityRef  string
		Identity             models.Identity
		KeyPaths             []string
		IdentityFiles        []string
		CertificateFiles     []string
		CertificateBindings  []certificateFileBinding
		IdentityAgent        string
		SudoMode             models.SudoMode
		SuPassword           string
		PrivilegePasswordRef *credential.Ref
	}
	dependencies := make([]dependency, 0, len(plan.Hops))
	stores := make(map[string]*config.StoreConfig)
	configuration := provider.Snapshot()
	env := sshenv.Discover()
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
			if hop.Options == nil {
				identitiesOnly = snapshot.Node.SSHOptions.IdentitiesOnly()
			}
		}
		certBindings := collectHopCertificateBindings(env, hop, snapshot.Identity.KeyPath, identityFiles, certificateFiles, identitiesOnly)
		dependencies = append(dependencies, dependency{
			NodeID: hop.NodeID, IdentityRef: snapshot.Node.IdentityRef, Identity: snapshot.Identity,
			KeyPaths: append([]string(nil), hop.KeyPaths...), IdentityFiles: identityFiles,
			CertificateFiles: certificateFiles, CertificateBindings: certBindings, IdentityAgent: identityAgent,
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

func expandMCPBindingPath(raw string, env ssh.Environment, target ssh.TargetContext) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return ""
	}
	expanded, err := ssh.ExpandControlPath(trimmed, env, target)
	if err != nil {
		if env.ResolveKeyPath != nil {
			expanded = env.ResolveKeyPath(trimmed)
		} else {
			expanded = trimmed
		}
	} else if env.ResolveKeyPath != nil {
		expanded = env.ResolveKeyPath(expanded)
	}
	if expanded == "" || strings.EqualFold(expanded, "none") {
		return ""
	}
	return filepath.Clean(filepath.FromSlash(expanded))
}

func inspectCertificateBinding(certPath string, includeMissing bool) (certificateFileBinding, bool) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		if includeMissing {
			return certificateFileBinding{Path: certPath, Missing: true}, true
		}
		return certificateFileBinding{}, false
	}
	rawSum := sha256.Sum256(data)
	binding := certificateFileBinding{
		Path:      certPath,
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

func collectHopCertificateBindings(
	env ssh.Environment,
	hop ssh.ConnectionConfig,
	identityKeyPath string,
	identityFiles []string,
	certificateFiles []string,
	identitiesOnly bool,
) []certificateFileBinding {
	port := hop.Port
	if port <= 0 {
		port = 22
	}
	user := hop.User
	if user == "" {
		user = env.LocalUser
	}
	target := ssh.TargetContext{
		Host:         hop.Address,
		Port:         port,
		User:         user,
		OriginalHost: hop.NodeID,
		JumpHost:     hop.ProxyJump,
	}

	var bindings []certificateFileBinding
	seen := make(map[string]struct{})
	if len(certificateFiles) > 0 {
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
		return bindings
	}

	var candidateKeys []string
	candidateKeys = append(candidateKeys, hop.KeyPaths...)
	if hop.KeyPath != "" {
		candidateKeys = append(candidateKeys, hop.KeyPath)
	}
	if identityKeyPath != "" {
		candidateKeys = append(candidateKeys, identityKeyPath)
	}
	candidateKeys = append(candidateKeys, identityFiles...)
	hasExplicitCandidate := false
	for _, rawKey := range candidateKeys {
		if expandMCPBindingPath(rawKey, env, target) != "" {
			hasExplicitCandidate = true
			break
		}
	}
	if !identitiesOnly || !hasExplicitCandidate {
		candidateKeys = append(candidateKeys, env.DefaultKeyPaths...)
	}

	for _, rawKey := range candidateKeys {
		expandedKey := expandMCPBindingPath(rawKey, env, target)
		if expandedKey == "" {
			continue
		}
		sidecarPath := expandedKey + "-cert.pub"
		if _, dup := seen[sidecarPath]; dup {
			continue
		}
		seen[sidecarPath] = struct{}{}
		if b, ok := inspectCertificateBinding(sidecarPath, false); ok {
			bindings = append(bindings, b)
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
