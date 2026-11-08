package host

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

type addFlags struct {
	address       string
	port          uint16
	user          string
	keyPath       string
	identityAlias string
	alias         []string
	tags          []string
	jump          string
	skipVerify    bool
}

func NewCmdInventoryAdd() *cobra.Command {
	return newCmdInventoryAdd(verifyInventoryNode)
}

func newCmdInventoryAdd(verify inventoryVerifier) *cobra.Command {
	flags := &addFlags{}
	secretInput := &utils.InventorySecretInput{}

	cmd := &cobra.Command{
		Use:     "add [[alias] [user@]host[:port]]",
		Aliases: []string{"new", "create"},
		Short:   i18n.T("inventory_add_short"),
		Long:    i18n.T("inventory_add_long"),
		Args:    cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryAdd(cmd, args, flags, secretInput, verify)
		},
	}

	cmd.Flags().StringVarP(&flags.address, "address", "H", "", i18n.T("flag_inv_address"))
	cmd.Flags().Uint16VarP(&flags.port, "port", "p", 22, i18n.T("flag_inv_port"))
	cmd.Flags().StringVarP(&flags.user, "user", "u", "", i18n.T("flag_inv_user"))
	cmd.Flags().StringVarP(&flags.keyPath, "key", "k", "", i18n.T("flag_inv_key"))
	cmd.Flags().StringVarP(&flags.identityAlias, "identity", "I", "", i18n.T("flag_inv_identity"))
	cmd.Flags().StringSliceVarP(&flags.alias, "alias", "a", []string{}, i18n.T("flag_inv_alias"))
	cmd.Flags().StringSliceVarP(&flags.tags, "tags", "t", []string{}, i18n.T("flag_inv_tags"))
	cmd.Flags().StringVarP(&flags.jump, "jump", "j", "", i18n.T("flag_inv_jump"))
	cmd.Flags().BoolVar(&flags.skipVerify, "skip-verify", false, i18n.T("flag_skip_verify"))
	registerEnrollmentProbeFlags(cmd)

	secretInput.RegisterFlags(cmd)
	cmd.MarkFlagsMutuallyExclusive("identity", "password-stdin", "passphrase-stdin", "ask-pass", "ask-passphrase")
	return cmd
}

func runInventoryAdd(cmd *cobra.Command, args []string, flags *addFlags, secretInput *utils.InventorySecretInput, verify inventoryVerifier) error {
	probe, execution, err := enrollmentProbeOptions(cmd)
	if err != nil {
		return err
	}
	password, keyPass, err := secretInput.Read(cmd)
	if err != nil {
		return err
	}

	portChanged := cmd.Flags().Changed("port")
	if err := resolveAddTargetAndAlias(args, flags, secretInput.UsesStdin(), portChanged); err != nil {
		return err
	}

	_, repository, cfg, err := utils.GetConfigStore()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}
	if flags.port == 0 {
		flags.port = 22
	}
	if keyPass != "" && flags.keyPath == "" {
		return fmt.Errorf("private-key path is required for a passphrase (--key)")
	}
	if flags.keyPath != "" && keyPass == "" && password == "" && !secretInput.UsesStdin() {
		keyPass, err = utils.PromptPassphraseIfEncryptedKey(flags.keyPath, keyPass)
		if err != nil {
			return err
		}
	}

	identity, identityRef, password, err := resolveAddedIdentity(cfg, flags, password)
	if err != nil {
		return err
	}

	name := config.FormatNodeID(identity.User, flags.address, flags.port)
	if _, ok := repository.GetNode(name); ok {
		return fmt.Errorf("节点 %s 已存在", name)
	}
	if err := validateNewNodeAliases(repository, flags.alias); err != nil {
		return err
	}

	hostObj := models.Host{Address: flags.address, Port: flags.port}
	resolvedJump, err := repository.ResolveProxyJumpChain(flags.jump)
	if err != nil {
		return fmt.Errorf("resolve jump host for new node: %w", err)
	}
	node := models.Node{
		HostRef:     config.FormatHostPort(flags.address, flags.port),
		IdentityRef: identityRef,
		Alias:       flags.alias,
		Tags:        normalizeTagList(flags.tags),
		ProxyJump:   resolvedJump,
		SudoMode:    models.SudoModeAuto,
		Execution:   execution,
	}

	if !flags.skipVerify {
		bundle := inventoryVerification{ConnectionSnapshot: config.ConnectionSnapshot{Node: node, Host: hostObj, Identity: identity}, Probe: probe}
		auth := utils.HostInfo{Password: password, KeyPath: flags.keyPath, Passphrase: keyPass}
		node.Execution, err = verifyAndProbeAddedNode(cmd, repository, name, &bundle, auth, verify)
		if err != nil {
			return err
		}
	}
	return commitAddedNode(cmd, repository, name, node, hostObj, identity, password, keyPass, flags.keyPath)
}

func commitAddedNode(cmd *cobra.Command, repository *config.Repository, name string, node models.Node, hostObj models.Host, identity models.Identity, password, keyPass, keyPath string) error {
	write, err := utils.PrepareInventoryCredential(repository, credential.Target{NodeID: name}, identity, password, keyPass, keyPath, nil)
	if err != nil {
		return err
	}
	defer write.Clear()
	mutation, err := repository.CreateNodeContext(cmd.Context(), name, node, hostObj, identity)
	if err != nil {
		return fmt.Errorf("create node %q failed: %w", name, err)
	}
	if err := write.Save(cmd.Context(), mutation.AuthVersion); err != nil {
		return err
	}
	logger.PrintSuccess(i18n.Tf("node_add_success", map[string]any{"Name": name}))
	return nil
}

func resolveAddTargetAndAlias(args []string, flags *addFlags, usesStdin, portChanged bool) error {
	if err := applyAddTargetArgs(args, &flags.alias, &flags.address, &flags.user, &flags.port, portChanged); err != nil {
		return err
	}
	if flags.address == "" && !usesStdin && utils.IsInteractiveTerminal() {
		if err := promptInteractiveHostAdd(flags, portChanged); err != nil {
			return err
		}
	}
	if flags.address == "" {
		return fmt.Errorf("必须指定主机地址 (--address)")
	}
	return nil
}

func promptInteractiveHostAdd(flags *addFlags, portChanged bool) error {
	targetStr, err := utils.ReadLineFromTerminal(i18n.T("prompt_enter_host_target"))
	if err != nil || targetStr == "" {
		return err
	}
	if err := applyAddTargetArgs([]string{targetStr}, &flags.alias, &flags.address, &flags.user, &flags.port, portChanged); err != nil {
		return err
	}
	if len(flags.alias) == 0 {
		aliasStr, aliasErr := utils.ReadLineFromTerminal(i18n.T("prompt_enter_host_alias"))
		if aliasErr != nil {
			return aliasErr
		}
		for _, part := range strings.Split(aliasStr, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				flags.alias = append(flags.alias, trimmed)
			}
		}
	}
	return nil
}

func resolveAddedIdentity(cfg *config.Configuration, flags *addFlags, password string) (models.Identity, string, string, error) {
	if flags.identityAlias != "" {
		identity, ok := cfg.Identities.Get(flags.identityAlias)
		if !ok {
			return models.Identity{}, "", "", fmt.Errorf("认证模板 %s 不存在", flags.identityAlias)
		}
		return identity, flags.identityAlias, password, nil
	}
	identity, newPassword, err := newInventoryIdentity(flags.user, password, flags.keyPath, flags.skipVerify)
	if err != nil {
		return models.Identity{}, "", "", err
	}
	return identity, fmt.Sprintf("%s@%s", identity.User, flags.address), newPassword, nil
}

func applyAddTargetArgs(args []string, alias *[]string, address, user *string, port *uint16, portChanged bool) error {
	if *address != "" && (strings.Contains(*address, "@") || strings.Contains(*address, ":")) {
		raw := *address
		*address = ""
		if err := mergeTargetAddressSpec(raw, address, user, port, &portChanged); err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return nil
	}
	targetArg := args[0]
	if len(args) == 2 {
		posAlias := strings.TrimSpace(args[0])
		if posAlias == "" || strings.ContainsAny(posAlias, "@:") {
			return fmt.Errorf("%s", i18n.T("ssh_err_alias_invalid"))
		}
		if !slices.Contains(*alias, posAlias) {
			*alias = append(*alias, posAlias)
		}
		targetArg = args[1]
	}
	return mergeTargetAddressSpec(targetArg, address, user, port, &portChanged)
}

func mergeTargetAddressSpec(spec string, address, user *string, port *uint16, portChanged *bool) error {
	posUser, posHost, posPort, err := utils.ParseAddr(spec)
	if err != nil {
		return err
	}
	if *address != "" && *address != posHost {
		return fmt.Errorf("conflicting host addresses %q and %q", *address, posHost)
	}
	*address = posHost
	if posUser != "" {
		if *user != "" && *user != posUser {
			return fmt.Errorf("conflicting usernames %q and %q", *user, posUser)
		}
		*user = posUser
	}
	if posPort != 0 {
		if *portChanged && *port != posPort {
			return fmt.Errorf("conflicting ports %d and %d", *port, posPort)
		}
		*port = posPort
		*portChanged = true
	}
	return nil
}

func validateNewNodeAliases(repo *config.Repository, aliases []string) error {
	for _, alias := range aliases {
		if existing := repo.FindAlias(alias); existing != "" {
			return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": alias, "Node": existing}))
		}
	}
	return nil
}

// newInventoryIdentity keeps prompted and stdin credentials outside the model.
func newInventoryIdentity(user, password, keyPath string, skipVerify bool) (models.Identity, string, error) {
	if user == "" {
		var err error
		user, err = utils.GetCurrentUser()
		if err != nil {
			return models.Identity{}, "", fmt.Errorf("get current user failed: %w", err)
		}
	}
	identity := models.Identity{User: user}
	switch {
	case keyPath != "":
		identity.KeyPath, identity.AuthType = utils.ToAbsolutePath(keyPath), "key"
	case password != "":
		identity.AuthType = "password"
	case skipVerify:
		identity.AuthType = "auto"
	default:
		pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
		if err != nil {
			return models.Identity{}, "", err
		}
		password, identity.AuthType = pass, "password"
	}
	return identity, password, nil
}
