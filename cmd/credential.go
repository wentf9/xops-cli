package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/internal/credentialfile"
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
	"github.com/wentf9/xops-cli/pkg/models"
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
	cmd.AddCommand(newCmdCredentialMigrate())
	cmd.AddCommand(newCmdCredentialFinalizeMigration())

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
	for _, op := range []string{"init", "probe", "inspect", "rewrap", "reencrypt", "resume", "restore", "clone", "prune"} {
		cmd.AddCommand(newOfflineStoreCommand(op))
	}
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
			hasWarn := false
			for _, it := range items {
				if it.Status == "WARN" {
					hasWarn = true
				}
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
			if hasWarn {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.T("credential_doctor_warnings"))
				return err
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
				Message: fmt.Sprintf("D-Bus address configured (service availability not yet verified): %s", dbusVal),
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
		items = append(items, checkUnconfiguredSystemStore(ctx))
		return items
	}

	_, hasSystem := credCfg.Stores["system"]
	if !hasSystem {
		items = append(items, checkUnconfiguredSystemStore(ctx))
	}
	for storeID, storeCfg := range credCfg.Stores {
		if storeCfg.Type == config.StoreTypeEncryptedFile {
			items = append(items, checkOfflineDoctor(ctx, storeID, storeCfg, cfg))
			continue
		}
		items = append(items, checkDoctorStore(ctx, storeID, storeCfg))
	}
	return items
}

// checkUnconfiguredSystemStore also checks the implicit migration destination.
// An optional backend failure is a warning; configured backend failures are fatal.
func checkUnconfiguredSystemStore(ctx context.Context) DoctorCheckItem {
	item := checkDoctorStore(ctx, "system", config.StoreConfig{Type: config.StoreTypeSystem})
	item.Name = "Unconfigured system store (migration destination)"
	if item.Status == "FAIL" {
		item.Status = "WARN"
	}
	return item
}

func checkDoctorStore(ctx context.Context, storeID string, cfg config.StoreConfig) DoctorCheckItem {
	item := DoctorCheckItem{Name: "Store: " + storeID, Status: "FAIL"}
	st, err := config.BuildStore(storeID, cfg)
	if err != nil {
		item.Message = err.Error()
		return item
	}
	if cfg.Type == config.StoreTypeNone {
		item.Status = "OK"
		item.Message = "persistence disabled (none)"
		return item
	}
	timeout := 5 * time.Second
	if cfg.Timeout > 0 && cfg.Timeout < timeout {
		timeout = cfg.Timeout
	}
	probeCtx, cancel := context.WithTimeout(credential.WithoutInteraction(ctx), timeout)
	defer cancel()
	secret, err := st.Get(probeCtx, credential.Ref{StoreID: storeID, ItemID: "doctor-" + credential.GenerateItemID()})
	clear(secret.Value)
	if err != nil && !errors.Is(err, credential.ErrCredentialNotFound) {
		item.Message = err.Error()
		return item
	}
	item.Status = "OK"
	item.Message = fmt.Sprintf("type=%s, non-interactive read probe passed; write access not tested", cfg.Type)
	return item
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

			var cleanupErr error
			for _, r := range results {
				status := "OK"
				if r.Err != nil {
					cleanupErr = errors.Join(cleanupErr, r.Err)
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

			if cleanupErr != nil {
				return fmt.Errorf("credential garbage collection remains incomplete: %w", cleanupErr)
			}
			logger.PrintSuccessf(i18n.T("credential_gc_completed"), len(results))
			return nil
		},
	}
}

func checkOfflineDoctor(ctx context.Context, id string, cfg config.StoreConfig, configuration *config.Configuration) DoctorCheckItem {
	item := DoctorCheckItem{Name: "Store: " + id, Status: "FAIL"}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		item.Message = err.Error()
		return item
	}
	cfg, err = config.ResolveFileStore(cfg, path)
	if err != nil {
		item.Message = err.Error()
		return item
	}
	work, cancel := context.WithTimeout(credential.WithoutInteraction(ctx), cfg.Timeout)
	defer cancel()
	if cfg.Unlock == "key-file" && !cfg.ReadOnly && !storeHasReferences(configuration, id) {
		layout, layoutErr := credentialfile.InspectLayout(work, cfg.Path, cfg.KeyFile)
		if layoutErr != nil {
			item.Message = fmt.Sprintf("inspect offline layout: %v", layoutErr)
			return item
		}
		if !layout.Vault && !layout.Key {
			item.Status = "WARN"
			item.Message = "encrypted-file not initialized; first successful credential save prepares the store; no unlock or write probe performed"
			return item
		}
	}
	s, err := credentialfile.Open(work, cfg.Path, id, credentialfile.Options{ReadOnly: true})
	if err == nil {
		_, err = s.Inspect(work, false)
		err = errors.Join(err, s.Close())
	}
	if err != nil {
		item.Message = fmt.Sprintf("%s: %v", offlineErrorCode(err), err)
		return item
	}
	item.Status = "WARN"
	item.Message = "encrypted-file metadata available; locked/unverified, no unlock or write probe performed; use credential store probe for filesystem capability checks"
	return item
}

func storeHasReferences(cfg *config.Configuration, id string) bool {
	if cfg == nil {
		return true
	}
	found := false
	if cfg.Identities != nil {
		cfg.Identities.IterCb(func(_ string, identity models.Identity) bool {
			for _, ref := range []*credential.Ref{identity.LoginPasswordRef, identity.PassphraseRef} {
				if ref != nil && ref.StoreID == id {
					found = true
					return false
				}
			}
			return true
		})
	}
	if cfg.Nodes != nil {
		cfg.Nodes.IterCb(func(_ string, node models.Node) bool {
			if node.PrivilegePasswordRef != nil && node.PrivilegePasswordRef.StoreID == id {
				found = true
				return false
			}
			return true
		})
	}
	return found
}
