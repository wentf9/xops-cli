package host

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdInventoryList() *cobra.Command {
	var tagFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: i18n.T("inventory_list_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("load config failed: %w", err)
			}

			var nodes map[string]models.Node
			if tagFilter != "" {
				nodes = provider.GetNodesByTag(tagFilter)
			} else {
				nodes = provider.ListNodes()
			}

			if len(nodes) == 0 {
				if tagFilter != "" {
					logger.PrintWarn(i18n.Tf("node_no_tag_match", map[string]any{"Tag": tagFilter}))
				} else {
					logger.PrintWarn(i18n.T("node_no_stored"))
				}
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, i18n.T("node_list_header")); err != nil {
				return fmt.Errorf("write node list header failed: %w", err)
			}

			keys := make([]string, 0, len(nodes))
			for k := range nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, nodeID := range keys {
				node, host, identity, resolveErr := provider.Resolve(nodeID)
				if resolveErr != nil {
					return fmt.Errorf("resolve node %q for listing failed: %w", nodeID, resolveErr)
				}

				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					nodeID,
					strings.Join(node.Alias, ", "),
					fmt.Sprintf("%s:%d", host.Address, host.Port),
					identity.User,
					identity.AuthType,
					node.ProxyJump,
					strings.Join(node.Tags, ", "),
				); err != nil {
					return fmt.Errorf("write node %q failed: %w", nodeID, err)
				}
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("flush node list failed: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&tagFilter, "tag", "t", "", i18n.T("flag_inv_tag_filter"))
	return cmd
}

func NewCmdInventoryTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: i18n.T("inventory_tags_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("load config failed: %w", err)
			}

			nodes := provider.ListNodes()
			tagMap := make(map[string]int)
			for _, node := range nodes {
				for _, tag := range node.Tags {
					tagMap[tag]++
				}
			}

			if len(tagMap) == 0 {
				logger.PrintWarn(i18n.T("tags_no_stored"))
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, i18n.T("tags_list_header")); err != nil {
				return fmt.Errorf("write tag list header failed: %w", err)
			}

			tags := make([]string, 0, len(tagMap))
			for t := range tagMap {
				tags = append(tags, t)
			}
			sort.Strings(tags)

			for _, t := range tags {
				if _, err := fmt.Fprintf(w, "%s\t%d\n", t, tagMap[t]); err != nil {
					return fmt.Errorf("write tag %q failed: %w", t, err)
				}
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("flush tag list failed: %w", err)
			}
			return nil
		},
	}
}
