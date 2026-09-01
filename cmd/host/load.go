package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

var TemplateFile string
var Tag string

func NewCmdInventoryLoad() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "import [csv_file]",
		Aliases: []string{"load"},
		Short:   i18n.T("inventory_load_short"),
		Long:    i18n.T("inventory_load_long"),
		Args:    cobra.MaximumNArgs(1),
		RunE:    RunInventoryLoad,
	}

	cmd.Flags().StringVarP(&TemplateFile, "template", "T", "", i18n.T("flag_inv_template"))
	cmd.Flags().StringVarP(&Tag, "tag", "t", "", i18n.T("flag_inv_load_tag"))
	return cmd
}

func RunInventoryLoad(cmdObj *cobra.Command, args []string) error {
	// 如果指定了导出模板
	if TemplateFile != "" {
		header := i18n.T("inventory_template_header")
		err := os.WriteFile(TemplateFile, []byte(header), 0644)
		if err != nil {
			return fmt.Errorf("export template %q failed: %w", TemplateFile, err)
		}
		logger.PrintSuccess(i18n.Tf("template_export_success", map[string]any{"Path": TemplateFile}))
		return nil
	}

	if len(args) != 1 {
		return fmt.Errorf("%s", i18n.Tf("inventory_load_args_error", map[string]any{"Count": len(args)}))
	}
	csvFile := args[0]
	hosts, err := utils.ReadCSVFile(csvFile)
	if err != nil {
		return fmt.Errorf("read CSV file %q failed: %w", csvFile, err)
	}

	return ExecuteLoadHostContext(cmdObj.Context(), hosts)
}

// ExecuteLoadHost imports hosts using a background context for compatibility.
func ExecuteLoadHost(hosts []utils.HostInfo) error {
	return ExecuteLoadHostContext(context.Background(), hosts)
}

// ExecuteLoadHostContext imports hosts and propagates caller cancellation to
// every connection attempt.
func ExecuteLoadHostContext(ctx context.Context, hosts []utils.HostInfo) (retErr error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}
	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}
	connector := adapter.NewNonInteractiveConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	// 批量导入时默认接受新的主机密钥，避免并发时大量询问
	connector.AcceptNewHostKey.Store(true)
	defer func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close SSH connector failed: %w", closeErr))
		}
	}()

	wp := pkgutils.NewWorkerPool(uint(len(hosts)))
	var nodeMu sync.Mutex
	var errMu sync.Mutex
	var loadErrs []error

	for _, host := range hosts {
		h := host // capture
		wp.Execute(func() {
			nodeMu.Lock()
			nodeID, _, err := getOrCreateNode(ctx, provider, h)
			nodeMu.Unlock()

			if err != nil {
				errMu.Lock()
				loadErrs = append(loadErrs, fmt.Errorf("[%s] %w", h.Host, err))
				errMu.Unlock()
				return
			}

			// 验证连接 (单次尝试最长 15 秒，避免网络卡死或死锁无限期阻塞)
			connectCtx, cancelConnect := context.WithTimeout(ctx, 15*time.Second)
			defer cancelConnect()
			client, err := connector.Connect(connectCtx, nodeID)
			if err != nil {
				errMu.Lock()
				loadErrs = append(loadErrs, fmt.Errorf("[%s] verify failed: %w", h.Host, err))
				errMu.Unlock()
				return
			}
			if closeErr := client.Close(); closeErr != nil {
				errMu.Lock()
				loadErrs = append(loadErrs, fmt.Errorf("close verification connection to %q failed: %w", h.Host, closeErr))
				errMu.Unlock()
				return
			}

			logger.PrintSuccess(i18n.Tf("load_verify_success", map[string]any{"Host": h.Host}))
		})
	}

	wp.Wait()
	return errors.Join(loadErrs...)
}

func getOrCreateNode(ctx context.Context, provider *config.Repository, addr utils.HostInfo) (string, bool, error) {
	host := strings.TrimSpace(addr.Host)
	user := strings.TrimSpace(addr.User)
	port := addr.Port

	if user == "" {
		var userErr error
		user, userErr = utils.GetCurrentUser()
		if userErr != nil {
			return "", false, fmt.Errorf("get current user failed: %w", userErr)
		}
	}
	if port == 0 {
		port = 22
	}

	nodeID, err := provider.ResolveSelector(fmt.Sprintf("%s@%s:%d", user, host, port))
	if err != nil {
		return "", false, fmt.Errorf("resolve host selector: %w", err)
	}
	if nodeID == "" {
		nodeID, err = provider.ResolveSelector(host)
		if err != nil {
			return "", false, fmt.Errorf("resolve host selector: %w", err)
		}
	}

	if nodeID != "" {
		updated, updateErr := updateNodeFromHostInfo(ctx, nodeID, provider, addr)
		return nodeID, updated, updateErr
	}

	// 创建新节点
	nodeID = fmt.Sprintf("%s@%s:%d", user, host, port)

	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		SudoMode:    models.SudoModeAuto,
	}

	if addr.Alias != "" {
		// 检查别名是否已被其他节点使用
		if existingNode := provider.FindAlias(addr.Alias); existingNode != "" && existingNode != nodeID {
			return "", false, fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": addr.Alias, "Node": existingNode}))
		}
		node.Alias = []string{addr.Alias}
	}

	// 如果指定了全局标签
	if Tag != "" {
		node.Tags = []string{Tag}
	}

	identity := models.Identity{
		User: user,
	}

	if addr.Password != "" {
		identity.Password = addr.Password
		identity.AuthType = "password"
	} else if addr.KeyPath != "" {
		identity.KeyPath = utils.ToAbsolutePath(addr.KeyPath)
		identity.Passphrase = addr.Passphrase
		identity.AuthType = "key"
	}

	if _, err := provider.CreateNodeContext(ctx, nodeID, node, models.Host{Address: host, Port: port}, identity); err != nil {
		return "", false, fmt.Errorf("create imported node %q failed: %w", nodeID, err)
	}

	return nodeID, true, nil
}

func updateNodeFromHostInfo(ctx context.Context, nodeID string, provider *config.Repository, addr utils.HostInfo) (bool, error) {
	ref, ok := provider.View().NodeRefs[nodeID]
	if !ok {
		return false, fmt.Errorf("resolve imported node %q reference: %w", nodeID, config.ErrNodeNotFound)
	}
	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve imported node %q for update failed: %w", nodeID, err)
	}
	updated := false

	// 更新密码或密钥
	if addr.Password != "" {
		if identity.Password != addr.Password || identity.AuthType != "password" {
			identity.Password = addr.Password
			identity.AuthType = "password"
			updated = true
		}
	} else if addr.KeyPath != "" {
		absKeyPath := utils.ToAbsolutePath(addr.KeyPath)
		if identity.KeyPath != absKeyPath || identity.Passphrase != addr.Passphrase || identity.AuthType != "key" {
			identity.KeyPath = absKeyPath
			identity.Passphrase = addr.Passphrase
			identity.AuthType = "key"
			updated = true
		}
	}

	// 更新别名
	if addr.Alias != "" {
		// 检查别名是否已被其他节点使用
		if existingNode := provider.FindAlias(addr.Alias); existingNode != "" && existingNode != nodeID {
			logger.PrintWarn(i18n.Tf("alias_err_exists", map[string]any{"Alias": addr.Alias, "Node": existingNode}))
		} else {
			aliases, changed := appendUnique(node.Alias, addr.Alias)
			if changed {
				node.Alias = aliases
				updated = true
			}
		}
	}

	// 更新标签
	if Tag != "" {
		tags, changed := appendUnique(node.Tags, Tag)
		if changed {
			node.Tags = tags
			updated = true
		}
	}

	if updated {
		if err := provider.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity); err != nil {
			return false, fmt.Errorf("update imported node %q failed: %w", nodeID, err)
		}
	}

	return updated, nil
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
