package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

var TemplateFile string
var Tag string

// ImportOptions controls verification independently from explicit persistence.
type ImportOptions struct {
	SkipVerify          bool
	SaveOnVerifyFailure bool
	Output              io.Writer
	Tag                 string
	NoProbe             bool
	Execution           *ssh.ExecutionConfig // Applied only to newly enrolled nodes.
}

func NewCmdInventoryLoad() *cobra.Command {
	cmd := &cobra.Command{
		Use: "import [csv_file]", Aliases: []string{"load"},
		Short: i18n.T("inventory_load_short"), Long: i18n.T("inventory_load_long"),
		Args: cobra.MaximumNArgs(1), RunE: RunInventoryLoad,
	}
	cmd.Flags().StringVarP(&TemplateFile, "template", "T", "", i18n.T("flag_inv_template"))
	cmd.Flags().StringVarP(&Tag, "tag", "t", "", i18n.T("flag_inv_load_tag"))
	RegisterImportVerificationFlags(cmd)
	return cmd
}

// RegisterImportVerificationFlags also keeps legacy import aliases consistent.
func RegisterImportVerificationFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("skip-verify", false, i18n.T("flag_skip_verify"))
	cmd.Flags().Bool("save-on-verify-failure", false, i18n.T("flag_save_on_verify_failure"))
	cmd.MarkFlagsMutuallyExclusive("skip-verify", "save-on-verify-failure")
	registerEnrollmentProbeFlags(cmd)
}

func RunInventoryLoad(cmd *cobra.Command, args []string) error {
	if TemplateFile != "" {
		if err := os.WriteFile(TemplateFile, []byte(i18n.T("inventory_template_header")), 0644); err != nil {
			return fmt.Errorf("export template %q failed: %w", TemplateFile, err)
		}
		var out io.Writer = os.Stdout
		if cmd != nil {
			out = cmd.OutOrStdout()
		}
		if _, err := fmt.Fprintln(out, i18n.Tf("template_export_success", map[string]any{"Path": TemplateFile})); err != nil {
			return fmt.Errorf("write template export result: %w", err)
		}
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("%s", i18n.Tf("inventory_load_args_error", map[string]any{"Count": len(args)}))
	}
	hosts, err := utils.ReadCSVFile(args[0])
	if err != nil {
		return fmt.Errorf("read CSV file %q failed: %w", args[0], err)
	}
	skip, err := cmd.Flags().GetBool("skip-verify")
	if err != nil {
		return fmt.Errorf("read skip verification option: %w", err)
	}
	keep, err := cmd.Flags().GetBool("save-on-verify-failure")
	if err != nil {
		return fmt.Errorf("read save-on-failure option: %w", err)
	}
	probe, execution, err := enrollmentProbeOptions(cmd)
	if err != nil {
		return err
	}
	return ExecuteLoadHostWithOptions(cmd.Context(), hosts, ImportOptions{SkipVerify: skip, SaveOnVerifyFailure: keep, Output: cmd.OutOrStdout(), Tag: Tag, NoProbe: !probe, Execution: execution})
}

// ExecuteLoadHost imports only authenticated nodes by default.
func ExecuteLoadHost(hosts []utils.HostInfo) error {
	return ExecuteLoadHostContext(context.Background(), hosts)
}

func ExecuteLoadHostContext(ctx context.Context, hosts []utils.HostInfo) error {
	return ExecuteLoadHostWithOptions(ctx, hosts, ImportOptions{Tag: Tag})
}

func ExecuteLoadHostWithOptions(ctx context.Context, hosts []utils.HostInfo, opts ImportOptions) error {
	if err := opts.Execution.Validate(); err != nil {
		return err
	}
	if opts.SkipVerify && opts.SaveOnVerifyFailure {
		return fmt.Errorf("--skip-verify and --save-on-verify-failure are mutually exclusive")
	}
	_, repo, _, err := utils.GetConfigStore()
	if err != nil {
		return fmt.Errorf("load import configuration: %w", err)
	}
	return executeImport(credential.WithoutInteraction(ctx), repo, hosts, opts, verifyInventoryNode)
}

type importDraft struct {
	nodeID string
	bundle config.ConnectionSnapshot
	ref    config.NodeRef
	addr   utils.HostInfo
}

type importResult struct {
	nodeID, status string
	err            error
	warning        error
}

type importRow struct {
	index int
	addr  utils.HostInfo
}

// Group before scheduling so rows for one endpoint retain CSV order without
// occupying workers while waiting for another row of the same endpoint.
// Saved-node IDs also group distinct selectors that resolve to the same node.
func groupImportRows(repo *config.Repository, hosts []utils.HostInfo, results []importResult) [][]importRow {
	var groups [][]importRow
	byNode := make(map[string]int)
	for index, addr := range hosts {
		normalized, err := normalizeImportAddress(addr)
		if err != nil {
			results[index] = importResult{nodeID: addr.Host, status: "inventory_not_saved", err: err}
			continue
		}
		endpoint := config.FormatNodeID(normalized.User, normalized.Host, normalized.Port)
		nodeID, err := resolveImportNode(repo, normalized)
		if err != nil {
			results[index] = importResult{nodeID: endpoint, status: "inventory_not_saved", err: fmt.Errorf("resolve imported endpoint: %w", err)}
			continue
		}
		if nodeID == "" {
			nodeID = endpoint
		}
		group, exists := byNode[nodeID]
		if !exists {
			group = len(groups)
			byNode[nodeID] = group
			groups = append(groups, nil)
		}
		groups[group] = append(groups[group], importRow{index: index, addr: normalized})
	}
	return groups
}

func executeImport(ctx context.Context, repo *config.Repository, hosts []utils.HostInfo, opts ImportOptions, verify inventoryVerifier) error {
	results := make([]importResult, len(hosts))
	groups := groupImportRows(repo, hosts, results)
	wp := pkgutils.NewWorkerPool(uint(min(len(groups), 16)))
	for _, rows := range groups {
		wp.Execute(func() {
			for _, row := range rows {
				// Prepare only after the preceding row has finished verifying
				// and saving, so its aliases and current version are visible.
				results[row.index] = importOne(ctx, repo, row.addr, opts, verify)
			}
		})
	}
	wp.Wait()
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	var errs []error
	for _, result := range results {
		if result.warning != nil {
			if _, err := fmt.Fprintln(out, probeWarning(result.nodeID, result.warning)); err != nil {
				errs = append(errs, fmt.Errorf("write import probe warning: %w", err))
			}
		}
		message := i18n.Tf(result.status, map[string]any{"Node": result.nodeID, "Error": result.err})
		if _, err := fmt.Fprintln(out, message); err != nil {
			errs = append(errs, fmt.Errorf("write import result: %w", err))
		}
		if result.err != nil {
			errs = append(errs, fmt.Errorf("[%s] %s: %w", result.nodeID, message, result.err))
		}
	}
	return errors.Join(errs...)
}

func importOne(ctx context.Context, repo *config.Repository, addr utils.HostInfo, opts ImportOptions, verify inventoryVerifier) importResult {
	result := importResult{nodeID: addr.Host, status: "inventory_not_saved"}
	draft, err := prepareImport(repo, addr, opts.Tag)
	if err != nil {
		result.err = err
		return result
	}
	result.nodeID = draft.nodeID
	if draft.ref.ID == "" {
		draft.bundle.Node.Execution = opts.Execution.Clone()
	}
	var verifyErr error
	if !opts.SkipVerify {
		check := inventoryVerification{ConnectionSnapshot: draft.verificationBundle(), Probe: !opts.NoProbe && draft.ref.ID == ""}
		verifyErr = verify(ctx, repo, draft.nodeID, &check)
		if verifyErr != nil && (!opts.SaveOnVerifyFailure || ctx.Err() != nil) {
			result.status, result.err = "inventory_verify_not_saved", verifyErr
			return result
		}
		if verifyErr == nil && draft.ref.ID == "" {
			draft.bundle.Node.Execution, result.warning = enrollmentExecution(opts.Execution, &check)
		}
	}
	if err := draft.save(ctx, repo); err != nil {
		result.err = errors.Join(verifyErr, err)
		var durabilityErr *config.DurabilityError
		var cleanupErr *credential.CleanupError
		if errors.As(err, &durabilityErr) || errors.As(err, &cleanupErr) {
			result.status = "inventory_save_incomplete"
		}
		return result
	}
	switch {
	case opts.SkipVerify:
		result.status = "inventory_saved_unverified"
	case verifyErr != nil:
		result.status, result.err = "inventory_verify_failed_saved", verifyErr
	default:
		result.status = "inventory_verified_saved"
	}
	return result
}

func normalizeImportAddress(addr utils.HostInfo) (utils.HostInfo, error) {
	addr.Host, addr.User = strings.TrimSpace(addr.Host), strings.TrimSpace(addr.User)
	if addr.Host == "" {
		return utils.HostInfo{}, fmt.Errorf("import host is empty")
	}
	if addr.User == "" {
		var err error
		addr.User, err = utils.GetCurrentUser()
		if err != nil {
			return utils.HostInfo{}, fmt.Errorf("get import user: %w", err)
		}
	}
	if addr.Port == 0 {
		addr.Port = 22
	}
	return addr, nil
}

// resolveImportNode preserves legacy IPv6 IDs and lookup entries, which used
// user@address:port without brackets. Both grouping and preparation must use
// this lookup so alternate IPv6 spellings update the same saved node in order.
func resolveImportNode(repo *config.Repository, addr utils.HostInfo) (string, error) {
	nodeID, err := repo.ResolveSelector(config.FormatNodeID(addr.User, addr.Host, addr.Port))
	if err != nil || nodeID != "" {
		return nodeID, err
	}
	host := strings.TrimPrefix(strings.TrimSuffix(addr.Host, "]"), "[")
	if !strings.Contains(host, ":") {
		return "", nil
	}
	return repo.ResolveSelector(fmt.Sprintf("%s@%s:%d", addr.User, host, addr.Port))
}

func prepareImport(repo *config.Repository, addr utils.HostInfo, tag string) (*importDraft, error) {
	addr, err := normalizeImportAddress(addr)
	if err != nil {
		return nil, err
	}
	canonicalID := config.FormatNodeID(addr.User, addr.Host, addr.Port)
	nodeID, err := resolveImportNode(repo, addr)
	if err != nil {
		return nil, fmt.Errorf("resolve imported endpoint: %w", err)
	}
	draft := &importDraft{nodeID: nodeID, addr: addr}
	if nodeID != "" {
		view := repo.View()
		draft.ref = view.NodeRefs[nodeID]
		if draft.ref.ID == "" {
			return nil, fmt.Errorf("import target %q is not a saved node", nodeID)
		}
		node, _ := view.Configuration.Nodes.Get(nodeID)
		host, _ := view.Configuration.Hosts.Get(node.HostRef)
		identity, _ := view.Configuration.Identities.Get(node.IdentityRef)
		draft.bundle = config.ConnectionSnapshot{Node: node, Host: host, Identity: identity}
	} else {
		draft.nodeID = canonicalID
		draft.bundle = config.ConnectionSnapshot{
			Node: models.Node{HostRef: config.FormatHostPort(addr.Host, addr.Port), IdentityRef: "node:" + canonicalID + ":identity", SudoMode: models.SudoModeAuto},
			Host: models.Host{Address: addr.Host, Port: addr.Port}, Identity: models.Identity{User: addr.User, AuthType: "auto"},
		}
	}
	if addr.Alias != "" {
		if existing := repo.FindAlias(addr.Alias); existing != "" && existing != draft.nodeID {
			return nil, fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": addr.Alias, "Node": existing}))
		}
		draft.bundle.Node.Alias, _ = appendUnique(draft.bundle.Node.Alias, addr.Alias)
	}
	draft.bundle.Node.Tags, _ = appendUnique(draft.bundle.Node.Tags, tag)
	return draft, nil
}

func (d *importDraft) verificationBundle() config.ConnectionSnapshot {
	bundle := d.bundle
	if d.addr.Password != "" {
		bundle.Identity.Password, bundle.Identity.AuthType = d.addr.Password, "password"
		bundle.Identity.LoginPasswordRef = nil
	} else if d.addr.KeyPath != "" || d.addr.Passphrase != "" {
		if d.addr.KeyPath != "" {
			bundle.Identity.KeyPath = utils.ToAbsolutePath(d.addr.KeyPath)
		}
		bundle.Identity.Passphrase, bundle.Identity.AuthType = d.addr.Passphrase, "key"
		bundle.Identity.PassphraseRef = nil
	}
	return bundle
}

func (d *importDraft) save(ctx context.Context, repo *config.Repository) error {
	node, host, identity := d.bundle.Node, d.bundle.Host, d.bundle.Identity
	if repo.Snapshot().SchemaVersion == 2 && d.ref.ID == "" && d.addr.KeyPath != "" && d.addr.Passphrase == "" && d.addr.Password == "" {
		identity.KeyPath, identity.AuthType = utils.ToAbsolutePath(d.addr.KeyPath), "key"
		write, err := utils.PrepareInventoryCredential(repo, credential.Target{NodeID: d.nodeID}, identity, "", "", d.addr.KeyPath, nil)
		if err != nil {
			return err
		}
		defer write.Clear()
		mutation, err := repo.CreateNodeContext(ctx, d.nodeID, node, host, identity)
		if err != nil {
			return err
		}
		return write.Save(ctx, mutation.AuthVersion)
	}
	if repo.Snapshot().SchemaVersion == 2 && (d.addr.Password != "" || d.addr.Passphrase != "" || d.addr.KeyPath != "") {
		updater := repo.NodeCredentialCreate(d.nodeID, node, host, identity)
		if d.ref.ID != "" {
			updater = repo.NodeCredentialEdit(d.ref, d.nodeID, node, host, identity)
		}
		write, err := utils.PrepareInventoryCredential(repo, credential.Target{NodeID: d.nodeID}, identity, d.addr.Password, d.addr.Passphrase, d.addr.KeyPath, updater)
		if err != nil {
			return err
		}
		defer write.Clear()
		version := ""
		if d.ref.ID != "" {
			version = string(d.ref.Version[:])
		}
		return write.Save(credential.WithoutInteraction(ctx), version)
	}
	updateLegacyImportAuth(&identity, d.addr)
	if d.ref.ID != "" {
		return repo.ReplaceNodeAtRefContext(ctx, d.ref, d.nodeID, node, host, identity)
	}
	_, err := repo.CreateNodeContext(ctx, d.nodeID, node, host, identity)
	return err
}

// updateLegacyImportAuth is retained only for the v1 release compatibility window.
func updateLegacyImportAuth(identity *models.Identity, addr utils.HostInfo) bool {
	if addr.Password != "" {
		changed := identity.Password != addr.Password || identity.AuthType != "password"
		identity.Password, identity.AuthType = addr.Password, "password"
		return changed
	}
	if addr.KeyPath != "" {
		path := utils.ToAbsolutePath(addr.KeyPath)
		changed := identity.KeyPath != path || identity.Passphrase != addr.Passphrase || identity.AuthType != "key"
		identity.KeyPath, identity.Passphrase, identity.AuthType = path, addr.Passphrase, "key"
		return changed
	}
	return false
}

func appendUnique(slice []string, val string) ([]string, bool) {
	if val == "" {
		return slice, false
	}
	for _, item := range slice {
		if item == val {
			return slice, false
		}
	}
	return append(slice, val), true
}
