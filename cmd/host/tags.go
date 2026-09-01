package host

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func NewCmdInventoryTagAdd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [tag_name] [node1,node2...]",
		Short: i18n.T("inventory_tag_add_short"),
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")
			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			nodeIDs := make([]string, 0, len(nodeNames))
			for _, query := range nodeNames {
				name, resolveErr := repository.ResolveSelector(strings.TrimSpace(query))
				if resolveErr != nil {
					return fmt.Errorf("resolve node %q for tag addition failed: %w", query, resolveErr)
				}
				if name == "" {
					continue
				}
				nodeIDs = append(nodeIDs, name)
			}
			updatedCount, err := repository.UpdateNodeTagsContext(cmd.Context(), nodeIDs, []string{tagName}, true)
			if err != nil {
				return fmt.Errorf("add tag to selected nodes failed: %w", err)
			}
			if updatedCount > 0 {
				logger.PrintSuccess(i18n.Tf("tag_add_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
			}
			return nil
		},
	}
}

func NewCmdInventoryTagRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [tag_name] [node1,node2...]",
		Short: i18n.T("inventory_tag_remove_short"),
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")
			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			nodeIDs := make([]string, 0, len(nodeNames))
			for _, query := range nodeNames {
				name, resolveErr := repository.ResolveSelector(strings.TrimSpace(query))
				if resolveErr != nil {
					return fmt.Errorf("resolve node %q for tag removal failed: %w", query, resolveErr)
				}
				if name == "" {
					continue
				}
				nodeIDs = append(nodeIDs, name)
			}
			updatedCount, err := repository.UpdateNodeTagsContext(cmd.Context(), nodeIDs, []string{tagName}, false)
			if err != nil {
				return fmt.Errorf("remove tag from selected nodes failed: %w", err)
			}
			if updatedCount > 0 {
				logger.PrintSuccess(i18n.Tf("tag_remove_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
			}
			return nil
		},
	}
}
