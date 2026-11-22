package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

// DoctorSeverity indicates the severity of a configuration diagnostic finding.
type DoctorSeverity string

const (
	DoctorSeverityError DoctorSeverity = "ERROR"
	DoctorSeverityWarn  DoctorSeverity = "WARN"
)

// DoctorIssue describes one invariant violation discovered in a configuration file.
type DoctorIssue struct {
	Code       string
	Entity     string
	Severity   DoctorSeverity
	Message    string
	Fixable    bool
	FixSummary string
}

// DoctorFix records one explicit repair applied by FixConfigFile.
type DoctorFix struct {
	Code    string
	Entity  string
	Summary string
}

// DoctorReport summarizes configuration diagnostics and any applied repairs.
type DoctorReport struct {
	Path   string
	Exists bool
	Issues []DoctorIssue
	Fixes  []DoctorFix
}

// HasErrors reports whether any error-severity issue remains unresolved.
func (r *DoctorReport) HasErrors() bool {
	if r == nil {
		return false
	}
	for _, issue := range r.Issues {
		if issue.Severity == DoctorSeverityError {
			return true
		}
	}
	return false
}

// HasFixableIssues reports whether at least one remaining issue supports --fix.
func (r *DoctorReport) HasFixableIssues() bool {
	if r == nil {
		return false
	}
	for _, issue := range r.Issues {
		if issue.Fixable {
			return true
		}
	}
	return false
}

// Healthy reports whether the configuration has no diagnostic issues.
func (r *DoctorReport) Healthy() bool {
	return r == nil || len(r.Issues) == 0
}

// DiagnoseConfigFile inspects path in strictly read-only mode and reports all
// schema, alias, TargetRef, and ProxyJump graph violations without modifying disk.
func DiagnoseConfigFile(path string) (*DoctorReport, error) {
	report := &DoctorReport{Path: path}
	data, exists, err := readDoctorFile(path)
	if err != nil {
		return nil, err
	}
	report.Exists = exists
	if !exists {
		return report, nil
	}
	v2, preIssues := parseV2ForDoctor(data)
	if len(preIssues) > 0 {
		report.Issues = append(report.Issues, preIssues...)
		return report, nil
	}
	report.Issues = diagnoseV2Issues(v2)
	return report, nil
}

// FixConfigFile diagnoses path, applies explicit safe repairs for fixable issues
// (invalid/duplicate aliases, invalid/self/cyclic ProxyJump hops), and persists
// the repaired configuration through Repository.commit full-graph validation.
// If any non-fixable issue remains, the file on disk is left untouched.
func FixConfigFile(ctx context.Context, path, keyPath string) (*DoctorReport, error) {
	if ctx == nil {
		return nil, fmt.Errorf("config doctor context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report := &DoctorReport{Path: path}
	data, exists, err := readDoctorFile(path)
	if err != nil {
		return nil, err
	}
	report.Exists = exists
	if !exists {
		return report, nil
	}
	initialVersion := sha256.Sum256(data)

	v2, preIssues := parseV2ForDoctor(data)
	if len(preIssues) > 0 {
		report.Issues = preIssues
		return report, fmt.Errorf("configuration has %d unfixable issue(s)", len(preIssues))
	}
	initialIssues := diagnoseV2Issues(v2)
	if len(initialIssues) == 0 {
		return report, nil
	}

	repairedV2, fixes := repairV2(v2)
	remaining := diagnoseV2Issues(repairedV2)
	report.Fixes = fixes
	report.Issues = remaining
	if len(remaining) > 0 {
		return report, fmt.Errorf("configuration still has %d unfixable issue(s); file was not modified", len(remaining))
	}
	if len(fixes) == 0 {
		return report, nil
	}

	repairedCfg, err := FromV2(repairedV2)
	if err != nil {
		report.Issues = append(report.Issues, DoctorIssue{
			Code:     "schema_validation",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		})
		return report, fmt.Errorf("repaired configuration failed validation: %w", err)
	}

	store := NewDefaultStore(path, keyPath)
	repo, err := NewRepositoryWithoutOpenSSH(repairedCfg, store)
	if err != nil {
		return report, fmt.Errorf("initialize repository for repaired configuration: %w", err)
	}
	if err := repo.commitDoctorRepairContext(ctx, initialVersion, repairedCfg); err != nil {
		return report, fmt.Errorf("persist repaired configuration: %w", err)
	}
	return report, nil
}

func (r *Repository) commitDoctorRepairContext(ctx context.Context, expectedVersion Version, repaired *Configuration) (retErr error) {
	if err := r.lockCommit(ctx); err != nil {
		return err
	}
	defer r.commitMu.Unlock()

	updated, lookup, aliases, err := prepareConfiguration(repaired, func(*Configuration) error { return nil })
	if err != nil {
		return err
	}

	ds, ok := r.store.(*defaultStore)
	if !ok {
		result, err := r.persist(updated)
		if err != nil && !result.Applied {
			return err
		}
		r.publish(updated, lookup, aliases)
		return err
	}

	if err := ds.gate.acquire(ctx); err != nil {
		return fmt.Errorf("acquire in-process configuration lock for doctor repair: %w", err)
	}
	defer ds.gate.release()
	lock, err := acquireConfigLock(ctx, ds.Path)
	if err != nil {
		return fmt.Errorf("acquire configuration lock for doctor repair: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release configuration lock after doctor repair: %w", closeErr))
		}
	}()

	currentVersion, err := configurationVersion(ds.Path)
	if err != nil {
		return err
	}
	if currentVersion != expectedVersion {
		return fmt.Errorf("configuration changed while doctor repair was running: %w", ErrConfigConflict)
	}

	persisted, err := ds.saveLocked(updated)
	if err != nil && !persisted.Applied {
		return err
	}
	r.publish(updated, lookup, aliases)
	if err != nil {
		r.hasUndurableWrite.Store(true)
		return &DurabilityError{Err: err}
	}
	if !persisted.Durable {
		r.hasUndurableWrite.Store(true)
		return &DurabilityError{Err: fmt.Errorf("configuration store returned an incomplete durability result")}
	}
	r.hasUndurableWrite.Store(false)
	return nil
}

func readDoctorFile(path string) ([]byte, bool, error) {
	data, err := fsx.ReadAllBounded(path, fsx.Limits{MaxBytes: maxConfigFileBytes}, fsx.FollowSymlinks())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read configuration file %s: %w", path, err)
	}
	return data, true, nil
}

func parseV2ForDoctor(data []byte) (*ConfigurationV2, []DoctorIssue) {
	version, err := DetectSchemaVersion(data)
	if err != nil {
		return nil, []DoctorIssue{{
			Code:     "yaml_parse",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		}}
	}
	if err := ValidateRuntimeSchema(version); err != nil {
		return nil, []DoctorIssue{{
			Code:     "schema_version",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		}}
	}
	if err := checkForbiddenPlaintextFields(data); err != nil {
		return nil, []DoctorIssue{{
			Code:     "forbidden_plaintext",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		}}
	}
	var cfg ConfigurationV2
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, []DoctorIssue{{
			Code:     "yaml_decode",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		}}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, []DoctorIssue{{
			Code:     "yaml_trailing_document",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  "trailing YAML documents are not allowed",
		}}
	}
	return &cfg, nil
}

// DiagnoseV2 inspects a parsed ConfigurationV2 and returns all diagnostic findings.
func DiagnoseV2(v2 *ConfigurationV2) *DoctorReport {
	return &DoctorReport{
		Exists: true,
		Issues: diagnoseV2Issues(v2),
	}
}

func diagnoseV2Issues(v2 *ConfigurationV2) []DoctorIssue {
	if v2 == nil {
		return []DoctorIssue{{
			Code:     "schema_validation",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  "configuration is nil",
		}}
	}
	var issues []DoctorIssue
	issues = append(issues, diagnoseV2Aliases(v2)...)
	issues = append(issues, diagnoseV2ProxyJumps(v2)...)

	// Validate the in-memory repaired configuration so unfixable schema errors
	// that coexist with fixable alias/ProxyJump issues are always surfaced
	// during read-only diagnosis instead of being masked.
	validationTarget := v2
	if len(issues) > 0 {
		validationTarget, _ = repairV2(v2)
	}
	if err := ValidateV2(validationTarget); err != nil {
		issues = append(issues, DoctorIssue{
			Code:     "schema_validation",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		})
	} else if _, err := FromV2(validationTarget); err != nil {
		issues = append(issues, DoctorIssue{
			Code:     "schema_validation",
			Entity:   "config",
			Severity: DoctorSeverityError,
			Message:  err.Error(),
		})
	}
	return issues
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func diagnoseV2Aliases(v2 *ConfigurationV2) []DoctorIssue {
	var issues []DoctorIssue
	for _, hostName := range sortedMapKeys(v2.Hosts) {
		host := v2.Hosts[hostName]
		for _, alias := range host.Alias {
			if err := ValidateNodeAlias(alias); err != nil {
				issues = append(issues, DoctorIssue{
					Code:       "invalid_host_alias",
					Entity:     "host:" + hostName,
					Severity:   DoctorSeverityError,
					Message:    err.Error(),
					Fixable:    true,
					FixSummary: fmt.Sprintf("remove invalid alias %q from host %q", alias, hostName),
				})
			}
		}
	}

	nodeNames := sortedMapKeys(v2.Nodes)
	nodeAliasOwners := make(map[string]string)
	for _, nodeName := range nodeNames {
		node := v2.Nodes[nodeName]
		for _, alias := range node.Alias {
			if err := ValidateNodeAlias(alias); err != nil {
				issues = append(issues, DoctorIssue{
					Code:       "invalid_node_alias",
					Entity:     "node:" + nodeName,
					Severity:   DoctorSeverityError,
					Message:    err.Error(),
					Fixable:    true,
					FixSummary: fmt.Sprintf("remove invalid alias %q from node %q", alias, nodeName),
				})
				continue
			}
			if alias == "" {
				continue
			}
			if owner, exists := nodeAliasOwners[alias]; exists && owner != nodeName {
				issues = append(issues, DoctorIssue{
					Code:       "duplicate_alias",
					Entity:     "node:" + nodeName,
					Severity:   DoctorSeverityError,
					Message:    fmt.Sprintf("alias %q is already assigned to node %q", alias, owner),
					Fixable:    true,
					FixSummary: fmt.Sprintf("remove duplicate alias %q from node %q", alias, nodeName),
				})
				continue
			}
			nodeAliasOwners[alias] = nodeName
		}
	}
	return append(issues, diagnoseV2HostAliasConflicts(v2, nodeNames, nodeAliasOwners)...)
}

func diagnoseV2HostAliasConflicts(v2 *ConfigurationV2, nodeNames []string, nodeAliasOwners map[string]string) []DoctorIssue {
	var issues []DoctorIssue
	hostAliasHostRef := make(map[string]string)
	hostAliasNode := make(map[string]string)
	reported := make(map[string]struct{})
	for _, nodeName := range nodeNames {
		node := v2.Nodes[nodeName]
		host, ok := v2.Hosts[node.HostRef]
		if !ok {
			continue
		}
		for _, alias := range host.Alias {
			if alias == "" || ValidateNodeAlias(alias) != nil {
				continue
			}
			key := node.HostRef + "\x00" + alias
			if ownerNode, exists := nodeAliasOwners[alias]; exists && v2.Nodes[ownerNode].HostRef != node.HostRef {
				if _, seen := reported[key]; !seen {
					reported[key] = struct{}{}
					issues = append(issues, DoctorIssue{
						Code:       "duplicate_alias",
						Entity:     "host:" + node.HostRef,
						Severity:   DoctorSeverityError,
						Message:    fmt.Sprintf("host alias %q conflicts with node %q", alias, ownerNode),
						Fixable:    true,
						FixSummary: fmt.Sprintf("remove conflicting alias %q from host %q", alias, node.HostRef),
					})
				}
				continue
			}
			if existingHostRef, exists := hostAliasHostRef[alias]; exists && existingHostRef != node.HostRef {
				if _, seen := reported[key]; !seen {
					reported[key] = struct{}{}
					issues = append(issues, DoctorIssue{
						Code:       "duplicate_alias",
						Entity:     "host:" + node.HostRef,
						Severity:   DoctorSeverityError,
						Message:    fmt.Sprintf("host alias %q is already assigned to node %q", alias, hostAliasNode[alias]),
						Fixable:    true,
						FixSummary: fmt.Sprintf("remove duplicate alias %q from host %q", alias, node.HostRef),
					})
				}
				continue
			}
			if _, exists := hostAliasHostRef[alias]; !exists {
				hostAliasHostRef[alias] = node.HostRef
				hostAliasNode[alias] = nodeName
			}
		}
	}
	return issues
}

type jumpEdge struct {
	target string
	hop    string
}

func diagnoseV2ProxyJumps(v2 *ConfigurationV2) []DoctorIssue {
	cfg := configurationFromV2Unchecked(v2)
	lookup, aliases, _ := buildIndexes(cfg, false)
	nodeIDs := cfg.Nodes.Keys()
	slices.Sort(nodeIDs)

	var issues []DoctorIssue
	adj := make(map[string][]jumpEdge, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok || !ssh.HasActiveProxyJump(node.ProxyJump) {
			continue
		}
		edges, nodeIssues := diagnoseNodeProxyJumpHops(cfg, lookup, aliases, nodeID, node)
		issues = append(issues, nodeIssues...)
		adj[nodeID] = edges
	}
	for _, cyc := range findProxyJumpCycleEdges(nodeIDs, adj) {
		issues = append(issues, DoctorIssue{
			Code:       "proxy_jump_cycle",
			Entity:     "node:" + cyc.from,
			Severity:   DoctorSeverityError,
			Message:    fmt.Sprintf("proxy_jump cycle detected: %s", strings.Join(cyc.path, " -> ")),
			Fixable:    true,
			FixSummary: fmt.Sprintf("remove cyclic proxy_jump hop %q from node %q", cyc.hop, cyc.from),
		})
	}
	return issues
}

func diagnoseNodeProxyJumpHops(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	nodeID string,
	node models.Node,
) ([]jumpEdge, []DoctorIssue) {
	var edges []jumpEdge
	var issues []DoctorIssue
	for rawHop := range strings.SplitSeq(strings.TrimSpace(node.ProxyJump), ",") {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		ref, err := ParseTargetRef(hop)
		if err != nil {
			issues = append(issues, DoctorIssue{
				Code:       "proxy_jump_invalid",
				Entity:     "node:" + nodeID,
				Severity:   DoctorSeverityError,
				Message:    fmt.Sprintf("proxy_jump hop %q invalid: %v", hop, err),
				Fixable:    true,
				FixSummary: fmt.Sprintf("remove invalid proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		if err := ref.Validate(); err != nil {
			issues = append(issues, DoctorIssue{
				Code:       "proxy_jump_invalid",
				Entity:     "node:" + nodeID,
				Severity:   DoctorSeverityError,
				Message:    fmt.Sprintf("proxy_jump hop %q invalid: %v", hop, err),
				Fixable:    true,
				FixSummary: fmt.Sprintf("remove invalid proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		if hopReferencesSelf(cfg, nodeID, node, hop, ref) {
			issues = append(issues, DoctorIssue{
				Code:       "proxy_jump_self",
				Entity:     "node:" + nodeID,
				Severity:   DoctorSeverityError,
				Message:    fmt.Sprintf("proxy_jump hop %q references node %q itself", hop, nodeID),
				Fixable:    true,
				FixSummary: fmt.Sprintf("remove self-referencing proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		if ref.OpenSSH {
			continue
		}
		for _, targetID := range resolveLocalJumpTargets(cfg, lookup, aliases, hop, ref) {
			if targetID == nodeID {
				issues = append(issues, DoctorIssue{
					Code:       "proxy_jump_self",
					Entity:     "node:" + nodeID,
					Severity:   DoctorSeverityError,
					Message:    fmt.Sprintf("proxy_jump hop %q resolves to node %q itself", hop, nodeID),
					Fixable:    true,
					FixSummary: fmt.Sprintf("remove self-referencing proxy_jump hop %q from node %q", hop, nodeID),
				})
				continue
			}
			edges = append(edges, jumpEdge{target: targetID, hop: hop})
		}
	}
	return edges, issues
}

type cycleBackEdge struct {
	from string
	hop  string
	path []string
}

func findProxyJumpCycleEdges(nodeIDs []string, adj map[string][]jumpEdge) []cycleBackEdge {
	const (
		stateUnvisited = 0
		stateVisiting  = 1
		stateVisited   = 2
	)
	state := make(map[string]uint8, len(nodeIDs))
	var stack []string
	var found []cycleBackEdge
	seenEdge := make(map[string]struct{})

	var dfs func(u string)
	dfs = func(u string) {
		state[u] = stateVisiting
		stack = append(stack, u)
		for _, edge := range adj[u] {
			switch state[edge.target] {
			case stateVisiting:
				key := u + "\x00" + edge.hop
				if _, dup := seenEdge[key]; !dup {
					seenEdge[key] = struct{}{}
					start := slices.Index(stack, edge.target)
					path := append(slices.Clone(stack[start:]), edge.target)
					found = append(found, cycleBackEdge{from: u, hop: edge.hop, path: path})
				}
			case stateUnvisited:
				dfs(edge.target)
			}
		}
		stack = stack[:len(stack)-1]
		state[u] = stateVisited
	}

	for _, id := range nodeIDs {
		if state[id] == stateUnvisited {
			dfs(id)
		}
	}
	return found
}

func cloneV2ForRepair(v2 *ConfigurationV2) *ConfigurationV2 {
	out := &ConfigurationV2{
		SchemaVersion:         v2.SchemaVersion,
		Credential:            *v2.Credential.Clone(),
		Identities:            make(map[string]IdentityV2, len(v2.Identities)),
		Hosts:                 make(map[string]models.Host, len(v2.Hosts)),
		Nodes:                 make(map[string]NodeV2, len(v2.Nodes)),
		Guardrail:             cloneGuardrail(v2.Guardrail),
		MCP:                   v2.MCP.Clone(),
		PasswordPromptPattern: v2.PasswordPromptPattern,
		Execution:             v2.Execution.Clone(),
		SSHOptions:            v2.SSHOptions.Clone(),
	}
	for k, h := range v2.Hosts {
		out.Hosts[k] = cloneHost(h)
	}
	for k, id := range v2.Identities {
		id.LoginPasswordRef = id.LoginPasswordRef.Clone()
		id.PassphraseRef = id.PassphraseRef.Clone()
		id.OTP = id.OTP.Clone()
		id.KeyboardInteractive = id.KeyboardInteractive.Clone()
		out.Identities[k] = id
	}
	for k, n := range v2.Nodes {
		n.Alias = slices.Clone(n.Alias)
		n.Tags = slices.Clone(n.Tags)
		n.PrivilegePasswordRef = n.PrivilegePasswordRef.Clone()
		n.Execution = n.Execution.Clone()
		n.SSHOptions = n.SSHOptions.Clone()
		out.Nodes[k] = n
	}
	return out
}

func repairV2(v2 *ConfigurationV2) (*ConfigurationV2, []DoctorFix) {
	repaired := cloneV2ForRepair(v2)
	var fixes []DoctorFix
	fixes = append(fixes, repairV2Aliases(repaired)...)
	fixes = append(fixes, repairV2ProxyJumps(repaired)...)
	return repaired, fixes
}

func repairV2Aliases(v2 *ConfigurationV2) []DoctorFix {
	var fixes []DoctorFix
	for _, hostName := range sortedMapKeys(v2.Hosts) {
		host := v2.Hosts[hostName]
		cleaned := make([]string, 0, len(host.Alias))
		for _, alias := range host.Alias {
			if ValidateNodeAlias(alias) != nil {
				fixes = append(fixes, DoctorFix{
					Code:    "invalid_host_alias",
					Entity:  "host:" + hostName,
					Summary: fmt.Sprintf("removed invalid alias %q from host %q", alias, hostName),
				})
				continue
			}
			cleaned = append(cleaned, alias)
		}
		host.Alias = cleaned
		v2.Hosts[hostName] = host
	}

	nodeNames := sortedMapKeys(v2.Nodes)
	nodeAliasOwners := make(map[string]string)
	for _, nodeName := range nodeNames {
		node := v2.Nodes[nodeName]
		cleaned := make([]string, 0, len(node.Alias))
		for _, alias := range node.Alias {
			if ValidateNodeAlias(alias) != nil {
				fixes = append(fixes, DoctorFix{
					Code:    "invalid_node_alias",
					Entity:  "node:" + nodeName,
					Summary: fmt.Sprintf("removed invalid alias %q from node %q", alias, nodeName),
				})
				continue
			}
			if alias != "" {
				if owner, exists := nodeAliasOwners[alias]; exists && owner != nodeName {
					fixes = append(fixes, DoctorFix{
						Code:    "duplicate_alias",
						Entity:  "node:" + nodeName,
						Summary: fmt.Sprintf("removed duplicate alias %q from node %q (kept on %q)", alias, nodeName, owner),
					})
					continue
				}
				nodeAliasOwners[alias] = nodeName
			}
			cleaned = append(cleaned, alias)
		}
		node.Alias = cleaned
		v2.Nodes[nodeName] = node
	}
	return append(fixes, repairV2HostAliasConflicts(v2, nodeNames, nodeAliasOwners)...)
}

func repairV2HostAliasConflicts(v2 *ConfigurationV2, nodeNames []string, nodeAliasOwners map[string]string) []DoctorFix {
	var fixes []DoctorFix
	hostAliasHostRef := make(map[string]string)
	for _, nodeName := range nodeNames {
		node := v2.Nodes[nodeName]
		host, ok := v2.Hosts[node.HostRef]
		if !ok {
			continue
		}
		cleaned := make([]string, 0, len(host.Alias))
		changed := false
		for _, alias := range host.Alias {
			if alias == "" {
				cleaned = append(cleaned, alias)
				continue
			}
			if ownerNode, exists := nodeAliasOwners[alias]; exists && v2.Nodes[ownerNode].HostRef != node.HostRef {
				fixes = append(fixes, DoctorFix{
					Code:    "duplicate_alias",
					Entity:  "host:" + node.HostRef,
					Summary: fmt.Sprintf("removed conflicting alias %q from host %q", alias, node.HostRef),
				})
				changed = true
				continue
			}
			if existingHostRef, exists := hostAliasHostRef[alias]; exists && existingHostRef != node.HostRef {
				fixes = append(fixes, DoctorFix{
					Code:    "duplicate_alias",
					Entity:  "host:" + node.HostRef,
					Summary: fmt.Sprintf("removed duplicate alias %q from host %q", alias, node.HostRef),
				})
				changed = true
				continue
			}
			hostAliasHostRef[alias] = node.HostRef
			cleaned = append(cleaned, alias)
		}
		if changed {
			host.Alias = cleaned
			v2.Hosts[node.HostRef] = host
		}
	}
	return fixes
}

func repairV2ProxyJumps(v2 *ConfigurationV2) []DoctorFix {
	var fixes []DoctorFix
	cfg := configurationFromV2Unchecked(v2)
	lookup, aliases, _ := buildIndexes(cfg, false)
	for _, nodeID := range sortedMapKeys(v2.Nodes) {
		nodeV2 := v2.Nodes[nodeID]
		if !ssh.HasActiveProxyJump(nodeV2.ProxyJump) {
			continue
		}
		nodeModel, _ := cfg.Nodes.Get(nodeID)
		kept, nodeFixes := filterValidNonSelfJumpHops(cfg, lookup, aliases, nodeID, nodeModel)
		if len(nodeFixes) > 0 {
			nodeV2.ProxyJump = strings.Join(kept, ",")
			v2.Nodes[nodeID] = nodeV2
			fixes = append(fixes, nodeFixes...)
		}
	}

	// Iteratively break any remaining cycles deterministically.
	for {
		cfg = configurationFromV2Unchecked(v2)
		lookup, aliases, _ = buildIndexes(cfg, false)
		nodeIDs := sortedMapKeys(v2.Nodes)
		adj := make(map[string][]jumpEdge, len(nodeIDs))
		for _, nodeID := range nodeIDs {
			node, ok := cfg.Nodes.Get(nodeID)
			if !ok || !ssh.HasActiveProxyJump(node.ProxyJump) {
				continue
			}
			edges, _ := diagnoseNodeProxyJumpHops(cfg, lookup, aliases, nodeID, node)
			adj[nodeID] = edges
		}
		cycles := findProxyJumpCycleEdges(nodeIDs, adj)
		if len(cycles) == 0 {
			break
		}
		cyc := cycles[0]
		nodeV2 := v2.Nodes[cyc.from]
		updatedChain, removed := removeJumpHopFromChain(nodeV2.ProxyJump, cyc.hop)
		if !removed {
			break
		}
		nodeV2.ProxyJump = updatedChain
		v2.Nodes[cyc.from] = nodeV2
		fixes = append(fixes, DoctorFix{
			Code:    "proxy_jump_cycle",
			Entity:  "node:" + cyc.from,
			Summary: fmt.Sprintf("removed cyclic proxy_jump hop %q from node %q (%s)", cyc.hop, cyc.from, strings.Join(cyc.path, " -> ")),
		})
	}
	return fixes
}

func filterValidNonSelfJumpHops(
	cfg *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	nodeID string,
	node models.Node,
) ([]string, []DoctorFix) {
	var kept []string
	var fixes []DoctorFix
	for rawHop := range strings.SplitSeq(strings.TrimSpace(node.ProxyJump), ",") {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		ref, err := ParseTargetRef(hop)
		if err != nil || ref.Validate() != nil {
			fixes = append(fixes, DoctorFix{
				Code:    "proxy_jump_invalid",
				Entity:  "node:" + nodeID,
				Summary: fmt.Sprintf("removed invalid proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		if hopReferencesSelf(cfg, nodeID, node, hop, ref) {
			fixes = append(fixes, DoctorFix{
				Code:    "proxy_jump_self",
				Entity:  "node:" + nodeID,
				Summary: fmt.Sprintf("removed self-referencing proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		if !ref.OpenSSH && slices.Contains(resolveLocalJumpTargets(cfg, lookup, aliases, hop, ref), nodeID) {
			fixes = append(fixes, DoctorFix{
				Code:    "proxy_jump_self",
				Entity:  "node:" + nodeID,
				Summary: fmt.Sprintf("removed self-referencing proxy_jump hop %q from node %q", hop, nodeID),
			})
			continue
		}
		kept = append(kept, hop)
	}
	return kept, fixes
}

func removeJumpHopFromChain(chain, targetHop string) (string, bool) {
	var kept []string
	removed := false
	for rawHop := range strings.SplitSeq(strings.TrimSpace(chain), ",") {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		if !removed && hop == targetHop {
			removed = true
			continue
		}
		kept = append(kept, hop)
	}
	return strings.Join(kept, ","), removed
}
