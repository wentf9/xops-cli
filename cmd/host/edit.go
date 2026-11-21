package host

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

type editFlags struct {
	address, user, password, keyPath, keyPass, jump, identityAlias string
	port                                                           uint16
	alias, tags, addTags, rmTags                                   []string
}

func NewCmdInventoryEdit() *cobra.Command {
	flags := &editFlags{}
	secretInput := &utils.InventorySecretInput{}

	cmd := &cobra.Command{
		Use:     "edit [node_id] [[user@]host[:port]]",
		Aliases: []string{"ed", "set", "update"},
		Short:   i18n.T("inventory_edit_short"),
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryEdit(cmd, args, flags, secretInput)
		},
	}

	cmd.Flags().StringVarP(&flags.address, "address", "H", "", i18n.T("flag_inv_edit_address"))
	cmd.Flags().Uint16VarP(&flags.port, "port", "p", 0, i18n.T("flag_inv_edit_port"))
	cmd.Flags().StringVarP(&flags.user, "user", "u", "", i18n.T("flag_inv_edit_user"))
	cmd.Flags().StringVarP(&flags.keyPath, "key", "k", "", i18n.T("flag_inv_edit_key"))
	cmd.Flags().StringVarP(&flags.identityAlias, "identity", "I", "", i18n.T("flag_inv_identity"))
	cmd.Flags().StringSliceVarP(&flags.alias, "alias", "a", []string{}, i18n.T("flag_inv_edit_alias"))
	cmd.Flags().StringSliceVarP(&flags.tags, "tags", "t", []string{}, i18n.T("flag_inv_tags"))
	cmd.Flags().StringSliceVar(&flags.addTags, "add-tag", []string{}, i18n.T("flag_inv_edit_add_tag"))
	cmd.Flags().StringSliceVar(&flags.rmTags, "rm-tag", []string{}, i18n.T("flag_inv_edit_rm_tag"))
	cmd.Flags().StringVarP(&flags.jump, "jump", "j", "", i18n.T("flag_inv_edit_jump"))
	secretInput.RegisterFlags(cmd)
	cmd.MarkFlagsMutuallyExclusive("tags", "add-tag")
	cmd.MarkFlagsMutuallyExclusive("tags", "rm-tag")
	cmd.MarkFlagsMutuallyExclusive("identity", "user")
	cmd.MarkFlagsMutuallyExclusive("identity", "key")
	cmd.MarkFlagsMutuallyExclusive("identity", "password-stdin", "passphrase-stdin", "ask-pass", "ask-passphrase")
	return cmd
}

func runInventoryEdit(cmd *cobra.Command, args []string, flags *editFlags, secretInput *utils.InventorySecretInput) error {
	var err error
	flags.password, flags.keyPass, err = secretInput.Read(cmd)
	if err != nil {
		return err
	}
	portChanged := cmd.Flags().Changed("port")
	if portChanged && flags.port == 0 {
		return fmt.Errorf("%s", i18n.T("scp_err_port_zero"))
	}
	if err := applyEditTargetArgs(args[1:], flags, portChanged); err != nil {
		return err
	}
	if flags.keyPath != "" && flags.keyPass == "" && flags.password == "" && !secretInput.UsesStdin() {
		flags.keyPass, err = utils.PromptPassphraseIfEncryptedKey(flags.keyPath, flags.keyPass)
		if err != nil {
			return err
		}
	}

	_, repository, _, err := utils.GetConfigStore()
	if err != nil {
		return err
	}
	view := repository.View()
	oldName, node, host, identity, err := resolveNodeForEdit(repository, view, args[0])
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("alias") {
		if err := validateEditNodeAliases(repository, oldName, flags.alias); err != nil {
			return err
		}
	}

	oldAliases := slices.Clone(node.Alias)
	updated, nameChanged := applyNodeUpdates(cmd, repository, oldName, &host, &identity, &node, flags)
	if err := applyEditedIdentityTemplate(view, flags.identityAlias, &node, &identity, &updated, &nameChanged); err != nil {
		return err
	}

	newName, err := validateEditedNodeName(repository, oldName, nameChanged, identity.User, host.Address, host.Port)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("jump") {
		resolvedJump, err := validateEditProxyJump(repository, oldName, newName, oldAliases, node.Alias, flags.jump)
		if err != nil {
			return err
		}
		node.ProxyJump = resolvedJump
	}
	return commitEditedNode(cmd, repository, view.NodeRefs[oldName], oldName, newName, node, host, identity, flags, updated)
}

func applyEditedIdentityTemplate(
	view config.ConfigView,
	identityAlias string,
	node *models.Node,
	identity *models.Identity,
	updated, nameChanged *bool,
) error {
	if identityAlias == "" {
		return nil
	}
	tpl, ok := view.Configuration.Identities.Get(identityAlias)
	if !ok {
		return fmt.Errorf("认证模板 %s 不存在", identityAlias)
	}
	if node.IdentityRef != identityAlias {
		if identity.User != tpl.User {
			*nameChanged = true
		}
		node.IdentityRef = identityAlias
		*identity = tpl
		*updated = true
	}
	return nil
}

func resolveNodeForEdit(repository *config.Repository, view config.ConfigView, query string) (string, models.Node, models.Host, models.Identity, error) {
	oldName, err := repository.ResolveSelector(query)
	if err != nil {
		return "", models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("resolve node %q for editing failed: %w", query, err)
	}
	if oldName == "" || view.NodeRefs[oldName].ID == "" {
		return "", models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("节点 %s 不存在", query)
	}
	node, host, identity, err := repository.Resolve(oldName)
	if err != nil {
		return "", models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("resolve node %q for editing failed: %w", oldName, err)
	}
	return oldName, node, host, identity, nil
}

func validateEditedNodeName(repository *config.Repository, oldName string, nameChanged bool, user, address string, port uint16) (string, error) {
	if !nameChanged {
		return oldName, nil
	}
	newName := config.FormatNodeID(user, address, port)
	if newName != oldName {
		if _, exists := repository.GetNode(newName); exists {
			return "", fmt.Errorf("node %q already exists", newName)
		}
	}
	return newName, nil
}

func commitEditedNode(cmd *cobra.Command, repository *config.Repository, ref config.NodeRef, oldName, newName string, node models.Node, host models.Host, identity models.Identity, flags *editFlags, updated bool) error {
	write, err := utils.PrepareInventoryCredential(repository, credential.Target{NodeID: newName}, identity, flags.password, flags.keyPass, flags.keyPath, repository.NodeCredentialEdit(ref, newName, node, host, identity))
	if err != nil {
		return err
	}
	defer write.Clear()

	if !updated && write == nil {
		logger.PrintWarn(i18n.T("node_no_changes"))
		return nil
	}
	if write != nil {
		if err := write.Save(cmd.Context(), string(ref.Version[:])); err != nil {
			return err
		}
	} else if flags.identityAlias != "" {
		service, err := utils.GetCredentialService(repository, repository.Snapshot())
		if err != nil {
			return err
		}
		if err := repository.ReplaceNodeWithCredentialsContext(cmd.Context(), ref, newName, node, host, identity, service); err != nil {
			return fmt.Errorf("update node %q failed: %w", oldName, err)
		}
	} else if err := repository.ReplaceNodeAtRefContext(cmd.Context(), ref, newName, node, host, identity); err != nil {
		return fmt.Errorf("update node %q failed: %w", oldName, err)
	}
	logger.PrintSuccess(i18n.Tf("node_update_success", map[string]any{"Name": newName}))
	return nil
}

func applyEditTargetArgs(extraArgs []string, flags *editFlags, portChanged bool) error {
	if flags.address != "" {
		raw := flags.address
		flags.address = ""
		if err := mergeTargetAddressSpec(raw, &flags.address, &flags.user, &flags.port, &portChanged); err != nil {
			return err
		}
	}
	if len(extraArgs) == 0 {
		return nil
	}
	return mergeTargetAddressSpec(extraArgs[0], &flags.address, &flags.user, &flags.port, &portChanged)
}

type aliasResolver interface {
	FindAlias(string) string
}

func validateEditNodeAliases(provider aliasResolver, oldName string, aliases []string) error {
	for _, a := range aliases {
		if err := config.ValidateNodeAlias(a); err != nil {
			return err
		}
		if existingNode := provider.FindAlias(a); existingNode != "" && existingNode != oldName {
			return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": a, "Node": existingNode}))
		}
	}
	return nil
}

func applyNodeUpdates(cmd *cobra.Command, provider aliasResolver, oldName string, host *models.Host, identity *models.Identity, node *models.Node, flags *editFlags) (updated, nameChanged bool) {
	if flags.address != "" {
		host.Address, updated, nameChanged = flags.address, true, true
	}
	if flags.port != 0 {
		host.Port, updated, nameChanged = flags.port, true, true
	}
	if flags.user != "" {
		identity.User, updated, nameChanged = flags.user, true, true
	}
	// Secret replacements commit authentication metadata with the new ref.
	if flags.keyPath != "" && flags.keyPass == "" && flags.password == "" {
		identity.KeyPath, identity.AuthType, updated = utils.ToAbsolutePath(flags.keyPath), "key", true
	}

	if cmd.Flags().Changed("alias") {
		filtered := make([]string, 0, len(flags.alias))
		for _, a := range flags.alias {
			if err := config.ValidateNodeAlias(a); err != nil {
				continue
			}
			if existingNode := provider.FindAlias(a); existingNode != "" && existingNode != oldName {
				continue
			}
			filtered = append(filtered, a)
		}
		node.Alias, updated = filtered, true
	}
	if cmd.Flags().Changed("jump") {
		node.ProxyJump, updated = flags.jump, true
	}
	if applyNodeTagUpdates(cmd, node, flags) {
		updated = true
	}
	return updated, nameChanged
}

func validateEditProxyJump(
	repository *config.Repository,
	oldName, newName string,
	oldAliases, newAliases []string,
	rawJump string,
) (string, error) {
	if !ssh.HasActiveProxyJump(rawJump) {
		return "", nil
	}
	selfIDs := buildSelfJumpIdentitySet(oldName, newName, oldAliases, newAliases)
	for _, hop := range splitActiveJumpHops(rawJump) {
		if _, isSelf := selfIDs[hop]; isSelf {
			return "", fmt.Errorf("jump host %q cannot reference the edited node %q", rawJump, newName)
		}
	}
	resolvedJump, err := repository.ResolveProxyJumpChain(rawJump)
	if err != nil {
		return "", fmt.Errorf("resolve jump host for edited node: %w", err)
	}
	queue := splitActiveJumpHops(resolvedJump)
	visited := make(map[string]struct{}, len(queue))
	for len(queue) > 0 {
		hop := queue[0]
		queue = queue[1:]
		if hopMatchesSelfIdentity(repository, hop, selfIDs) {
			return "", fmt.Errorf("jump host %q creates a proxy jump cycle with node %q", rawJump, newName)
		}
		if _, seen := visited[hop]; seen {
			continue
		}
		visited[hop] = struct{}{}
		queue = append(queue, resolveNextJumpHops(repository, hop)...)
	}
	return resolvedJump, nil
}

func buildSelfJumpIdentitySet(oldName, newName string, oldAliases, newAliases []string) map[string]struct{} {
	selfIDs := make(map[string]struct{}, 2+len(oldAliases)+len(newAliases))
	addSelf := func(id string) {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			selfIDs[trimmed] = struct{}{}
		}
	}
	addSelf(oldName)
	addSelf(newName)
	for _, a := range oldAliases {
		addSelf(a)
	}
	for _, a := range newAliases {
		addSelf(a)
	}
	return selfIDs
}

func hopMatchesSelfIdentity(repository *config.Repository, hop string, selfIDs map[string]struct{}) bool {
	if _, isSelf := selfIDs[hop]; isSelf {
		return true
	}
	if config.IsOpenSSHNodeID(hop) {
		return false
	}
	sel, err := repository.ResolveSelector(hop)
	if err != nil || sel == "" {
		return false
	}
	_, isSelf := selfIDs[sel]
	return isSelf
}

func resolveNextJumpHops(repository *config.Repository, hop string) []string {
	var nextJump string
	if n, ok := repository.GetNode(hop); ok {
		nextJump = n.ProxyJump
	} else if snap, snapErr := repository.ResolveConnection(hop); snapErr == nil {
		nextJump = snap.Node.ProxyJump
	}
	if !ssh.HasActiveProxyJump(nextJump) {
		return nil
	}
	resolvedNext, nextErr := repository.ResolveProxyJumpChain(nextJump)
	if nextErr != nil {
		resolvedNext = nextJump
	}
	return splitActiveJumpHops(resolvedNext)
}

func splitActiveJumpHops(chain string) []string {
	var hops []string
	for part := range strings.SplitSeq(chain, ",") {
		hop := strings.TrimSpace(part)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		hops = append(hops, hop)
	}
	return hops
}

func applyNodeTagUpdates(cmd *cobra.Command, node *models.Node, flags *editFlags) bool {
	if cmd.Flags().Changed("tags") {
		node.Tags = normalizeTagList(flags.tags)
		return true
	}
	updated := false
	if len(flags.addTags) > 0 {
		for _, tag := range normalizeTagList(flags.addTags) {
			node.Tags, _ = appendUnique(node.Tags, tag)
		}
		updated = true
	}
	if len(flags.rmTags) > 0 {
		rmSet := normalizeTagList(flags.rmTags)
		filtered := make([]string, 0, len(node.Tags))
		for _, existing := range node.Tags {
			if !slices.Contains(rmSet, existing) {
				filtered = append(filtered, existing)
			}
		}
		node.Tags = filtered
		updated = true
	}
	return updated
}

func normalizeTagList(raw []string) []string {
	var out []string
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" && !slices.Contains(out, trimmed) {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name> [name2...]",
		Aliases: []string{"rm", "del", "remove"},
		Short:   i18n.T("inventory_delete_short"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var queries []string
			for _, arg := range args {
				for _, part := range strings.Split(arg, ",") {
					trimmed := strings.TrimSpace(part)
					if trimmed != "" {
						queries = append(queries, trimmed)
					}
				}
			}
			if len(queries) == 0 {
				return fmt.Errorf("必须指定要删除的节点")
			}

			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			view := repository.View()
			var refs []config.NodeRef
			var names []string
			seen := make(map[string]struct{})
			for _, query := range queries {
				name, resolveErr := repository.ResolveSelector(query)
				if resolveErr != nil {
					return fmt.Errorf("resolve node %q for deletion failed: %w", query, resolveErr)
				}
				ref, hasRef := view.NodeRefs[name]
				if name == "" || !hasRef {
					return fmt.Errorf("节点 %s 不存在", query)
				}
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					refs = append(refs, ref)
					names = append(names, name)
				}
			}

			service, err := utils.GetCredentialService(repository, view.Configuration)
			if err != nil {
				return err
			}
			if err := repository.DeleteNodesWithCredentialsContext(cmd.Context(), refs, service); err != nil {
				return fmt.Errorf("delete node %q failed: %w", strings.Join(names, ", "), err)
			}
			for _, name := range names {
				logger.PrintSuccess(i18n.Tf("node_delete_success", map[string]any{"Name": name}))
			}
			return nil
		},
	}
}
