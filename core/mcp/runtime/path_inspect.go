package runtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
)

const twoPhaseAuditMetadataKey = "io.xops.audit"

type preAuthorizedOp struct {
	ctx  context.Context
	op   *operation
	opID string
}

type localPathInspection struct {
	canonicalPath string
	extraPaths    []string
	isDir         bool
	isSymlink     bool
}

func mergeUniquePaths(groups ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, group := range groups {
		for _, p := range group {
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func sameResolvedRisk(lexical, effective guardrail.RiskInput) bool {
	return slices.Equal(lexical.Paths, effective.Paths) &&
		slices.Equal(lexical.RecursivePaths, effective.RecursivePaths)
}

func stripApprovalRoundTripParams(req *mcp.CallToolRequest) *mcp.CallToolRequest {
	if req == nil {
		return nil
	}
	cloned := *req
	if req.Params != nil {
		params := *req.Params
		params.RequestState = ""
		params.InputResponses = nil
		cloned.Params = &params
	}
	return &cloned
}

// inspectRemotePath resolves canonical remote path metadata under an Inspect
// permit without reading or mutating remote file data.
func (r *Runtime) inspectRemotePath(
	ctx context.Context,
	view ports.OperationSnapshot,
	binding ports.Binding,
	nodeID string,
	remotePath string,
) (_ remotefile.PathInspection, retErr error) {
	permit, err := r.enter(ctx, view, binding, ports.Inspect, "")
	if err != nil {
		return remotefile.PathInspection{}, err
	}
	defer func() { retErr = errors.Join(retErr, permit.Close()) }()
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Inspect)
	if err != nil {
		return remotefile.PathInspection{}, err
	}
	defer cancel()
	if inspector, ok := r.backend.(ports.PathInspector); ok {
		return inspector.InspectPath(work, permit, nodeID, ports.PathInspectRequest{Path: remotePath})
	}
	files, err := r.backend.OpenFiles(work, permit, nodeID)
	if err != nil {
		return remotefile.PathInspection{}, err
	}
	defer joinCloseError(&retErr, files, "sftp inspection client")
	return remotefile.InspectPath(work, files, remotePath)
}

func resolveNearestLocalCanonicalPath(cleanPath string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err == nil {
		return filepath.Clean(resolved), true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("resolve local path %q: %w", cleanPath, err)
	}
	var suffix []string
	cur := cleanPath
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			if rootResolved, rootErr := filepath.EvalSymlinks(cur); rootErr == nil {
				return joinLocalSuffix(filepath.Clean(rootResolved), suffix), false, nil
			}
			return cleanPath, false, nil
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
		if ancResolved, ancErr := filepath.EvalSymlinks(cur); ancErr == nil {
			return joinLocalSuffix(filepath.Clean(ancResolved), suffix), false, nil
		} else if !errors.Is(ancErr, os.ErrNotExist) {
			return "", false, fmt.Errorf("resolve local ancestor %q: %w", cur, ancErr)
		}
	}
}

func joinLocalSuffix(base string, reversedSuffix []string) string {
	parts := make([]string, 0, len(reversedSuffix)+1)
	parts = append(parts, base)
	for i := len(reversedSuffix) - 1; i >= 0; i-- {
		parts = append(parts, reversedSuffix[i])
	}
	return filepath.Clean(filepath.Join(parts...))
}

func canonicalizeLocalPath(cleanPath string) (localPathInspection, error) {
	res := localPathInspection{}
	linfo, lstatErr := os.Lstat(cleanPath)
	if lstatErr == nil {
		res.isSymlink = linfo.Mode()&os.ModeSymlink != 0
	} else if !errors.Is(lstatErr, os.ErrNotExist) {
		return localPathInspection{}, fmt.Errorf("inspect local path %q: %w", cleanPath, lstatErr)
	}

	if st, statErr := os.Stat(cleanPath); statErr == nil {
		res.isDir = st.IsDir()
	} else if !errors.Is(statErr, os.ErrNotExist) && !res.isSymlink {
		return localPathInspection{}, fmt.Errorf("stat local path %q: %w", cleanPath, statErr)
	}

	var parentCanon string
	if parent := filepath.Dir(cleanPath); parent != cleanPath {
		var parentErr error
		parentCanon, _, parentErr = resolveNearestLocalCanonicalPath(parent)
		if parentErr != nil {
			return localPathInspection{}, parentErr
		}
	}

	canon, exact, canonErr := resolveNearestLocalCanonicalPath(cleanPath)
	if canonErr != nil {
		return localPathInspection{}, canonErr
	}
	res.canonicalPath = canon

	if parentCanon != "" {
		parentJoined := filepath.Clean(filepath.Join(parentCanon, filepath.Base(cleanPath)))
		if parentJoined != res.canonicalPath {
			res.extraPaths = append(res.extraPaths, parentJoined)
		}
	}

	if res.isSymlink && !exact {
		if linkTarget, rlErr := os.Readlink(cleanPath); rlErr == nil && linkTarget != "" {
			candidate := linkTarget
			if !filepath.IsAbs(candidate) {
				baseDir := parentCanon
				if baseDir == "" {
					baseDir = filepath.Dir(cleanPath)
				}
				candidate = filepath.Join(baseDir, candidate)
			}
			candidate = filepath.Clean(candidate)
			resolvedTarget, _, targetErr := resolveNearestLocalCanonicalPath(candidate)
			if targetErr != nil {
				return localPathInspection{}, targetErr
			}
			if resolvedTarget != "" && resolvedTarget != res.canonicalPath {
				res.extraPaths = append(res.extraPaths, resolvedTarget)
			}
		}
	}

	return res, nil
}

// collectLocalPushSymlinkTargets walks a local directory using os.Lstat
// semantics (without following directory symlinks) and resolves every local
// symlink target via filepath.EvalSymlinks (or nearest ancestor for dangling
// symlinks) so ProtectedPaths cannot be bypassed via symlinks nested inside a
// pushed directory.
func collectLocalPushSymlinkTargets(rootDir string) ([]string, error) {
	var targets []string
	seen := make(map[string]struct{})
	err := filepath.WalkDir(rootDir, func(entryPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		resolved, evalErr := filepath.EvalSymlinks(entryPath)
		if evalErr == nil {
			clean := filepath.Clean(resolved)
			if _, ok := seen[clean]; !ok {
				seen[clean] = struct{}{}
				targets = append(targets, clean)
			}
			return nil
		}
		if !errors.Is(evalErr, os.ErrNotExist) {
			return fmt.Errorf("resolve symlink %q inside pushed directory: %w", entryPath, evalErr)
		}
		linkTarget, rlErr := os.Readlink(entryPath)
		if rlErr != nil {
			return fmt.Errorf("read symlink %q inside pushed directory: %w", entryPath, rlErr)
		}
		if linkTarget == "" {
			return nil
		}
		candidate := linkTarget
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(filepath.Dir(entryPath), candidate)
		}
		resolvedTarget, _, targetErr := resolveNearestLocalCanonicalPath(filepath.Clean(candidate))
		if targetErr != nil {
			return targetErr
		}
		if resolvedTarget != "" {
			if _, ok := seen[resolvedTarget]; !ok {
				seen[resolvedTarget] = struct{}{}
				targets = append(targets, resolvedTarget)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(targets)
	return targets, nil
}

func (r *Runtime) authorizeLexicalPrecheck(
	ctx context.Context,
	req *mcp.CallToolRequest,
	view ports.OperationSnapshot,
	tool string,
	lexicalRI guardrail.RiskInput,
	boundLex any,
) (context.Context, *operation, *preAuthorizedOp, *mcp.CallToolResult, error) {
	lexCtx, lexOp, err := r.operationContext(ctx, view, tool, boundLex)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	decision := r.guardrail.EvaluateContext(lexCtx, lexicalRI)
	if decision == guardrail.Deny || (decision == guardrail.NeedApproval && !hasApprovalRoundTripParams(req)) {
		opID, pending, authErr := r.guardrail.Authorize(lexCtx, req, lexicalRI, boundLex)
		if authErr != nil || pending != nil {
			return lexCtx, lexOp, nil, pending, authErr
		}
		return lexCtx, lexOp, &preAuthorizedOp{ctx: lexCtx, op: lexOp, opID: opID}, nil, nil
	}
	if hasApprovalRoundTripParams(req) {
		matchedLex, matchErr := r.guardrail.HasMatchingPendingApproval(lexCtx, req, lexicalRI, boundLex)
		if matchErr != nil {
			return lexCtx, lexOp, nil, nil, matchErr
		}
		if matchedLex {
			opID, pending, authErr := r.guardrail.Authorize(lexCtx, req, lexicalRI, boundLex)
			if authErr != nil || pending != nil {
				return lexCtx, lexOp, nil, pending, authErr
			}
			return lexCtx, lexOp, &preAuthorizedOp{ctx: lexCtx, op: lexOp, opID: opID}, nil, nil
		}
	}
	return lexCtx, lexOp, nil, nil, nil
}

func (r *Runtime) authorizeCanonicalScope(
	ctx context.Context,
	req *mcp.CallToolRequest,
	view ports.OperationSnapshot,
	tool string,
	lexicalRI guardrail.RiskInput,
	preAuth *preAuthorizedOp,
	effectiveRI guardrail.RiskInput,
	boundEff any,
) (context.Context, *operation, string, *mcp.CallToolResult, error) {
	if preAuth != nil && sameResolvedRisk(lexicalRI, effectiveRI) {
		return preAuth.ctx, preAuth.op, preAuth.opID, nil, nil
	}
	effCtx, effOp, err := r.operationContext(ctx, view, tool, boundEff)
	if err != nil {
		return nil, nil, "", nil, err
	}
	authReq := req
	if preAuth != nil {
		authReq = stripApprovalRoundTripParams(req)
	}
	opID, pending, effErr := r.guardrail.Authorize(effCtx, authReq, effectiveRI, boundEff)
	if effErr != nil || pending != nil {
		return nil, nil, "", pending, effErr
	}
	return effCtx, effOp, opID, nil, nil
}

func (r *Runtime) recordTwoPhaseOutcome(
	opCtx context.Context,
	opID string,
	effectiveRI guardrail.RiskInput,
	result *mcp.CallToolResult,
	execErr error,
) (*mcp.CallToolResult, error) {
	outcome := "executed"
	if execErr != nil {
		outcome = "error"
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(opCtx), 5*time.Second)
	defer cancel()
	postAuditErr := r.guardrail.RecordAuthorizedContext(auditCtx, opID, effectiveRI, outcome, execErr)
	if postAuditErr == nil {
		return result, execErr
	}
	if execErr != nil {
		return result, errors.Join(execErr, fmt.Errorf("post-execution audit log failed: %w", postAuditErr))
	}
	if result == nil {
		result = &mcp.CallToolResult{}
	}
	if result.Meta == nil {
		result.Meta = make(mcp.Meta)
	}
	result.Meta[twoPhaseAuditMetadataKey] = map[string]any{
		"operation_id": opID,
		"executed":     true,
		"audit_failed": true,
		"retryable":    false,
	}
	result.Content = append(result.Content, &mcp.TextContent{
		Text: fmt.Sprintf("[WARNING: AUDIT_FAILED] Operation %s executed successfully, but post-execution audit log failed: %v. (DO NOT RETRY)", opID, postAuditErr),
	})
	return result, nil
}
