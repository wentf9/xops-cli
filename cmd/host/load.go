package host

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
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
		Use:   "load [csv_file]",
		Short: i18n.T("inventory_load_short"),
		Long:  i18n.T("inventory_load_long"),
		RunE:  RunInventoryLoad,
	}

	cmd.Flags().StringVarP(&TemplateFile, "template", "T", "", i18n.T("flag_inv_template"))
	cmd.Flags().StringVarP(&Tag, "tag", "t", "", i18n.T("flag_inv_load_tag"))
	return cmd
}

func RunInventoryLoad(cmdObj *cobra.Command, args []string) error {
	// 如果指定了导出模板
	if TemplateFile != "" {
		header := "主机,端口,别名,用户,密码,私钥,私钥密码\n"
		err := os.WriteFile(TemplateFile, []byte(header), 0644)
		if err != nil {
			return fmt.Errorf("导出模板失败: %w", err)
		}
		logger.PrintSuccess(i18n.Tf("template_export_success", map[string]any{"Path": TemplateFile}))
		return nil
	}

	if len(args) != 1 {
		return fmt.Errorf("期望一个参数 (CSV文件路径), 但提供了 %d 个 (或使用 -T 导出模板)", len(args))
	}
	csvFile := args[0]
	hosts, err := utils.ReadCSVFile(csvFile)
	if err != nil {
		return fmt.Errorf("读取CSV文件失败: %w", err)
	}

	return ExecuteLoadHost(hosts)
}

func ExecuteLoadHost(hosts []utils.HostInfo) error {
	configPath, keyPath := utils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(len(hosts)))

	for _, host := range hosts {
		h := host // capture
		wp.Execute(func() {
			nodeID, _, err := getOrCreateNode(provider, h)
			if err != nil {
				logger.PrintError(i18n.Tf("load_config_generate_failed", map[string]any{"Host": h.Host, "Error": err}))
				return
			}

			// 验证连接
			client, err := connector.Connect(ctx, nodeID)
			if err != nil {
				logger.PrintError(i18n.Tf("load_verify_failed", map[string]any{"Host": h.Host, "Error": err}))
				return
			}
			_ = client.Close()

			logger.PrintSuccess(i18n.Tf("load_verify_success", map[string]any{"Host": h.Host}))

		})
	}

	wp.Wait()
	return configStore.Save(cfg)
}

func getOrCreateNode(provider config.ConfigProvider, addr utils.HostInfo) (string, bool, error) {
	host := strings.TrimSpace(addr.Host)
	user := strings.TrimSpace(addr.User)
	port := addr.Port

	if user == "" {
		user = utils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	nodeID := provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	if nodeID == "" {
		nodeID = provider.Find(host)
	}

	if nodeID != "" {
		updated := updateNodeFromHostInfo(nodeID, provider, addr)
		return nodeID, updated, nil
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
			logger.PrintError(i18n.Tf("alias_err_exists", map[string]any{"Alias": addr.Alias, "Node": existingNode}))
			return nodeID, false, nil
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

	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)

	return nodeID, true, nil
}

func updateNodeFromHostInfo(nodeID string, provider config.ConfigProvider, addr utils.HostInfo) bool {
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)
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
		provider.AddNode(nodeID, node)
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
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
