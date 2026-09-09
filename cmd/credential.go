package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/pkg/credential"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

// NewCmdCredential 创建凭据管理根命令
func NewCmdCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred"},
		Short:   i18n.T("credential_short"),
		Long:    i18n.T("credential_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdCredentialStore())
	cmd.AddCommand(newCmdCredentialDoctor())
	cmd.AddCommand(newCmdCredentialGC())

	return cmd
}

func newCmdCredentialStore() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "store",
		Short: i18n.T("credential_store_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdCredentialStoreList())
	return cmd
}

func newCmdCredentialStoreList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("credential_store_list_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			credCfg := cfg.Credential
			if credCfg == nil {
				credCfg = &config.CredentialConfig{
					DefaultStore:     "none",
					RememberPrompted: utils.RememberPolicyAsk,
					Stores: map[string]config.StoreConfig{
						"none": {Type: config.StoreTypeNone},
					},
				}
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, "STORE\tTYPE\tDEFAULT\tREAD-ONLY\tTIMEOUT\tCACHE-TTL"); err != nil {
				return fmt.Errorf("write store list header failed: %w", err)
			}

			names := make([]string, 0, len(credCfg.Stores))
			for name := range credCfg.Stores {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				st := credCfg.Stores[name]
				isDefault := "no"
				if name == credCfg.DefaultStore {
					isDefault = "yes"
				}
				readOnly := "false"
				if st.ReadOnly {
					readOnly = "true"
				}

				timeoutStr := st.Timeout.String()
				if st.Timeout == 0 {
					timeoutStr = "default(5s)"
				}
				cacheTTLStr := st.CacheTTL.String()

				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					name, st.Type, isDefault, readOnly, timeoutStr, cacheTTLStr,
				); err != nil {
					return fmt.Errorf("write store list row failed: %w", err)
				}
			}

			return w.Flush()
		},
	}
}

// DoctorCheckItem 表示单项检查结果
type DoctorCheckItem struct {
	Name    string
	Status  string // "OK", "WARN", "FAIL"
	Message string
}

func newCmdCredentialDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: i18n.T("credential_doctor_short"),
		Long:  i18n.T("credential_doctor_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			items := runDoctorChecks(cmd.Context())

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, "CHECK\tSTATUS\tDETAILS"); err != nil {
				return fmt.Errorf("write doctor header failed: %w", err)
			}

			hasFail := false
			for _, it := range items {
				if it.Status == "FAIL" {
					hasFail = true
				}
				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", it.Name, it.Status, it.Message); err != nil {
					return fmt.Errorf("write doctor row failed: %w", err)
				}
			}
			if err := w.Flush(); err != nil {
				return err
			}

			if hasFail {
				return fmt.Errorf("credential doctor detected issues with system or configured stores")
			}
			logger.PrintSuccess(i18n.T("credential_doctor_healthy"))
			return nil
		},
	}
}

func runDoctorChecks(ctx context.Context) []DoctorCheckItem {
	var items []DoctorCheckItem

	// 1. 操作系统检测
	osItem := DoctorCheckItem{
		Name:    "Platform",
		Status:  "OK",
		Message: fmt.Sprintf("%s (%s)", runtime.GOOS, runtime.GOARCH),
	}
	items = append(items, osItem)

	// 2. 平台密钥库与辅助工具检测
	switch runtime.GOOS {
	case "darwin":
		if p, err := exec.LookPath("security"); err == nil {
			items = append(items, DoctorCheckItem{
				Name:    "OS Keychain Helper",
				Status:  "OK",
				Message: fmt.Sprintf("found %s (native Keychain available)", p),
			})
		} else {
			items = append(items, DoctorCheckItem{
				Name:    "OS Keychain Helper",
				Status:  "FAIL",
				Message: "macOS 'security' command not found in PATH",
			})
		}
	case "windows":
		items = append(items, DoctorCheckItem{
			Name:    "OS Credential Manager",
			Status:  "OK",
			Message: "Windows Credential Manager API available",
		})
	case "linux":
		dbusVal := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
		if dbusVal != "" {
			items = append(items, DoctorCheckItem{
				Name:    "Linux Secret Service D-Bus",
				Status:  "OK",
				Message: fmt.Sprintf("D-Bus session bus detected: %s", dbusVal),
			})
		} else {
			items = append(items, DoctorCheckItem{
				Name:    "Linux Secret Service D-Bus",
				Status:  "WARN",
				Message: "DBUS_SESSION_BUS_ADDRESS not set; headless environments recommend pass or helper store",
			})
		}
	}

	// 3. 检查 pass 工具可用性
	if p, err := exec.LookPath("pass"); err == nil {
		items = append(items, DoctorCheckItem{
			Name:    "Pass (Passwordstore)",
			Status:  "OK",
			Message: fmt.Sprintf("found %s", p),
		})
	}

	// 4. 检查已配置的 Store 状态
	items = append(items, checkConfiguredStores(ctx)...)
	return items
}

func checkConfiguredStores(ctx context.Context) []DoctorCheckItem {
	var items []DoctorCheckItem
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil {
		items = append(items, DoctorCheckItem{
			Name:    "Config Store",
			Status:  "FAIL",
			Message: fmt.Sprintf("load config failed: %v", err),
		})
		return items
	}

	credCfg := cfg.Credential
	if credCfg == nil {
		items = append(items, DoctorCheckItem{
			Name:    "Configured Stores",
			Status:  "OK",
			Message: "no credential stores configured; persistence is disabled (none)",
		})
		return items
	}

	for storeID, storeCfg := range credCfg.Stores {
		st, buildErr := config.BuildStore(storeID, storeCfg)
		if buildErr != nil {
			items = append(items, DoctorCheckItem{
				Name:    fmt.Sprintf("Store: %s", storeID),
				Status:  "FAIL",
				Message: buildErr.Error(),
			})
			continue
		}
		if storeCfg.Type == config.StoreTypeNone {
			items = append(items, DoctorCheckItem{Name: fmt.Sprintf("Store: %s", storeID), Status: "OK", Message: "persistence disabled (none)"})
			continue
		}
		probeCtx, cancel := context.WithTimeout(credential.WithoutInteraction(ctx), 5*time.Second)
		secret, probeErr := st.Get(probeCtx, credential.Ref{StoreID: storeID, ItemID: "doctor-" + credential.GenerateItemID()})
		clear(secret.Value)
		cancel()
		if probeErr != nil && !errors.Is(probeErr, credential.ErrCredentialNotFound) {
			items = append(items, DoctorCheckItem{Name: fmt.Sprintf("Store: %s", storeID), Status: "FAIL", Message: probeErr.Error()})
			continue
		}
		items = append(items, DoctorCheckItem{
			Name:    fmt.Sprintf("Store: %s", storeID),
			Status:  "OK",
			Message: fmt.Sprintf("type=%s, non-interactive read probe passed; write access not tested", storeCfg.Type),
		})
	}
	return items
}

func newCmdCredentialGC() *cobra.Command {
	return &cobra.Command{
		Use:   "gc",
		Short: i18n.T("credential_gc_short"),
		Long:  i18n.T("credential_gc_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, repo, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			svc, err := utils.GetCredentialService(repo, cfg)
			if err != nil {
				return fmt.Errorf("initialize credential service: %w", err)
			}

			results, err := svc.GC(cmd.Context())
			if err != nil {
				return fmt.Errorf("credential garbage collection failed: %w", err)
			}

			if len(results) == 0 {
				logger.PrintInfo(i18n.T("credential_gc_no_pending"))
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, "ENTRY\tOP\tSTAGE\tACTION\tSTATUS"); err != nil {
				return fmt.Errorf("write gc header failed: %w", err)
			}

			for _, r := range results {
				status := "OK"
				if r.Err != nil {
					status = fmt.Sprintf("ERR: %v", r.Err)
				}
				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					r.EntryID, r.Op, r.Stage, r.Action, status,
				); err != nil {
					return fmt.Errorf("write gc row failed: %w", err)
				}
			}

			if err := w.Flush(); err != nil {
				return err
			}

			logger.PrintSuccessf(i18n.T("credential_gc_completed"), len(results))
			return nil
		},
	}
}
