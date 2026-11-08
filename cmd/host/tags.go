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
		Use:     "add [tag_name] [node1] [node2...]",
		Aliases: []string{"a"},
		Short:   i18n.T("inventory_tag_add_short"),
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryTagMutation(cmd, args, true)
		},
	}
}

func NewCmdInventoryTagRemove() *cobra.Command {
	return &cobra.Command{
		Use:     "remove [tag_name] [node1] [node2...]",
		Aliases: []string{"rm", "del", "delete"},
		Short:   i18n.T("inventory_tag_remove_short"),
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryTagMutation(cmd, args, false)
		},
	}
}

func runInventoryTagMutation(cmd *cobra.Command, args []string, isAdd bool) error {
	tagName := strings.TrimSpace(args[0])
	if tagName == "" {
		return fmt.Errorf("标签名称不能为空")
	}

	var nodeNames []string
	for _, arg := range args[1:] {
		for _, part := range strings.Split(arg, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				nodeNames = append(nodeNames, trimmed)
			}
		}
	}

	_, repository, _, err := utils.GetConfigStore()
	if err != nil {
		return err
	}

	nodeIDs := make([]string, 0, len(nodeNames))
	actionLabel := "addition"
	if !isAdd {
		actionLabel = "removal"
	}
	for _, query := range nodeNames {
		name, resolveErr := repository.ResolveSelector(query)
		if resolveErr != nil {
			return fmt.Errorf("resolve node %q for tag %s failed: %w", query, actionLabel, resolveErr)
		}
		if name == "" {
			continue
		}
		nodeIDs = append(nodeIDs, name)
	}

	updatedCount, err := repository.UpdateNodeTagsContext(cmd.Context(), nodeIDs, []string{tagName}, isAdd)
	if err != nil {
		if isAdd {
			return fmt.Errorf("add tag to selected nodes failed: %w", err)
		}
		return fmt.Errorf("remove tag from selected nodes failed: %w", err)
	}
	if updatedCount > 0 {
		if isAdd {
			logger.PrintSuccess(i18n.Tf("tag_add_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
		} else {
			logger.PrintSuccess(i18n.Tf("tag_remove_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
		}
	}
	return nil
}
