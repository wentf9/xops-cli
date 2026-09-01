package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/executor"
	"github.com/wentf9/xops-cli/pkg/firewall"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"

	"github.com/spf13/cobra"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type FirewallOptions struct {
	SshOptions
	HostFile   string
	Protocol   string
	Reload     bool
	Remove     bool
	Zone       string
	Action     firewall.Action
	TaskCount  int
	StatusOnly bool
	Exclude    []string
}

func NewFirewallOptions() *FirewallOptions {
	return &FirewallOptions{
		SshOptions: *NewSshOptions(),
		Protocol:   "tcp",
		Action:     firewall.ActionAllow,
		TaskCount:  1,
	}
}

func newCmdFirewall() *cobra.Command {
	fwOptions := NewFirewallOptions()

	cmd := &cobra.Command{
		Use:   "firewall",
		Short: i18n.T("firewall_short"),
		Long:  i18n.T("firewall_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newFirewallListCmd(fwOptions))
	cmd.AddCommand(newFirewallPortCmd(fwOptions))
	cmd.AddCommand(newFirewallServiceCmd(fwOptions))
	cmd.AddCommand(newFirewallRuleCmd(fwOptions))
	cmd.AddCommand(newFirewallReloadCmd(fwOptions))
	cmd.AddCommand(newFirewallStatusCmd(fwOptions))

	cmd.PersistentFlags().StringVarP(&fwOptions.Host, "host", "H", "", i18n.T("flag_fw_host"))
	cmd.PersistentFlags().StringVarP(&fwOptions.HostFile, "ifile", "I", "", i18n.T("flag_fw_ifile"))
	cmd.PersistentFlags().StringSliceVarP(&fwOptions.Tags, "tag", "t", []string{}, i18n.T("flag_fw_tags"))
	cmd.PersistentFlags().StringSliceVar(&fwOptions.Exclude, "exclude", nil, i18n.T("flag_exclude"))
	cmd.PersistentFlags().StringVarP(&fwOptions.User, "user", "u", "", i18n.T("flag_fw_user"))
	cmd.PersistentFlags().StringVarP(&fwOptions.Password, "password", "w", "", i18n.T("flag_fw_password"))
	cmd.PersistentFlags().IntVar(&fwOptions.TaskCount, "task", 1, i18n.T("flag_fw_task"))

	cmd.PersistentFlags().StringVar(&fwOptions.Protocol, "proto", "tcp", i18n.T("flag_fw_proto"))
	cmd.PersistentFlags().BoolVarP(&fwOptions.Remove, "remove", "r", false, i18n.T("flag_fw_remove"))
	cmd.PersistentFlags().BoolVar(&fwOptions.Reload, "reload", false, i18n.T("flag_fw_reload"))
	cmd.PersistentFlags().StringVarP(&fwOptions.Zone, "zone", "z", "", i18n.T("flag_fw_zone"))

	return cmd
}

func (o *FirewallOptions) RunOnHosts(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	// 如果没有指定主机，默认本地模式
	if o.Host == "" && o.HostFile == "" && len(o.Tags) == 0 {
		return o.runLocalFirewall(ctx, action)
	}
	// 远程模式
	return o.runRemoteFirewalls(ctx, action)
}

func (o *FirewallOptions) runLocalFirewall(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s", i18n.Tf("fw_err_os_not_supported", map[string]any{"OS": runtime.GOOS}))
	}
	pwd, _, pwdErr := cmdutils.GetLocalSudoPassword()
	if pwdErr != nil {
		return fmt.Errorf("load local sudo password failed: %w", pwdErr)
	}
	exec := executor.NewLocalExecutor(pwd)
	fw, err := firewall.DetectFirewall(ctx, exec)
	if err != nil {
		if o.StatusOnly {
			printStatusOnly(nil, "LOCAL", "", "", err)
		}
		return fmt.Errorf("detect firewall failed: %w", err)
	}
	out, err := action(fw)
	if o.StatusOnly {
		printStatusOnly(nil, "LOCAL", fw.Name(), out, err)
	} else {
		if err == nil {
			printFwSuccess(nil, "LOCAL", fw.Name(), out)
		}
	}
	if err != nil {
		return err
	}
	if o.Reload {
		if _, reloadErr := fw.Reload(ctx); reloadErr != nil {
			return reloadErr
		}
	}
	return nil
}

func (o *FirewallOptions) resolveTargetHosts(provider config.ConfigProvider) ([]string, error) {
	var hosts []string
	if o.Host != "" {
		hosts = append(hosts, strings.Split(o.Host, ",")...)
	}
	if o.HostFile != "" {
		data, err := os.ReadFile(o.HostFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("err_read_ifile"), err)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				hosts = append(hosts, line)
			}
		}
	}
	if len(o.Tags) > 0 {
		for _, tag := range o.Tags {
			nodes := provider.GetNodesByTag(tag)
			if len(nodes) == 0 {
				return nil, fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": tag}))
			}
			for nodeID := range nodes {
				hosts = append(hosts, nodeID)
			}
		}
	}

	uniqueHosts := make(map[string]bool)
	var finalHosts []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !uniqueHosts[h] {
			uniqueHosts[h] = true
			finalHosts = append(finalHosts, h)
		}
	}

	if len(o.Exclude) > 0 {
		excludes, err := cmdutils.ResolveExcludes(provider, cmdutils.ParseExcludeFlag(o.Exclude))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("fw_err_exclude"), err)
		}
		filtered := finalHosts[:0]
		for _, h := range finalHosts {
			_, _, _, nodeID, resolveErr := o.resolveNodeID(h, provider)
			if resolveErr != nil {
				return nil, fmt.Errorf("resolve excluded firewall node %q failed: %w", h, resolveErr)
			}
			if nodeID != "" {
				if _, excluded := excludes[nodeID]; excluded {
					continue
				}
			}
			filtered = append(filtered, h)
		}
		finalHosts = filtered
	}

	if len(finalHosts) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("err_no_nodes_found"))
	}
	return finalHosts, nil
}

func (o *FirewallOptions) runRemoteFirewalls(ctx context.Context, action func(fw firewall.Firewall) (string, error)) (retErr error) {
	configPath, keyPath, pathErr := cmdutils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return err
	}
	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&retErr, connector)
	}()

	finalHosts, err := o.resolveTargetHosts(provider)
	if err != nil {
		return err
	}

	var (
		stdoutMu sync.Mutex
		errMu    sync.Mutex
		fwErrs   []error
	)
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))
	for _, h := range finalHosts {
		o.executeOnSingleHost(ctx, h, provider, connector, wp, action, &stdoutMu, &errMu, &fwErrs)
	}

	wp.Wait()
	return errors.Join(fwErrs...)
}

func (o *FirewallOptions) resolveNodeID(rawHost string, provider config.ConfigProvider) (string, string, uint16, string, error) {
	nodeID, resolveErr := provider.ResolveSelector(rawHost)
	if resolveErr != nil {
		return "", "", 0, "", fmt.Errorf("resolve firewall host %q failed: %w", rawHost, resolveErr)
	}
	u, hs, p, err := cmdutils.ParseAddr(rawHost)
	if err != nil {
		if nodeID != "" {
			return u, hs, p, nodeID, nil
		}
		return "", "", 0, "", fmt.Errorf("invalid host address %q: %w", rawHost, err)
	}
	if nodeID == "" {
		if u == "" {
			u = o.User
			if u == "" {
				var userErr error
				u, userErr = cmdutils.GetCurrentUser()
				if userErr != nil {
					return "", "", 0, "", fmt.Errorf("get current user failed: %w", userErr)
				}
			}
		}
		if p == 0 {
			p = o.Port
			if p == 0 {
				p = 22
			}
		}
		nodeID, resolveErr = provider.ResolveSelector(fmt.Sprintf("%s@%s:%d", u, hs, p))
		if resolveErr != nil {
			return "", "", 0, "", fmt.Errorf("resolve firewall address %q failed: %w", rawHost, resolveErr)
		}
	}
	return u, hs, p, nodeID, nil
}

func (o *FirewallOptions) executeOnSingleHost(ctx context.Context, h string, provider config.ConfigProvider, connector *ssh.Connector, wp pkgutils.WorkerPool, action func(fw firewall.Firewall) (string, error), stdoutMu *sync.Mutex, errMu *sync.Mutex, fwErrs *[]error) {
	wp.Execute(func() {
		rawHost := strings.TrimSpace(h)
		if rawHost == "" {
			return
		}

		_, _, _, nodeID, resolveErr := o.resolveNodeID(rawHost, provider)
		if resolveErr != nil {
			if o.StatusOnly {
				printStatusOnly(stdoutMu, rawHost, "", "", resolveErr)
			}
			errMu.Lock()
			*fwErrs = append(*fwErrs, fmt.Errorf("[%s] %w", rawHost, resolveErr))
			errMu.Unlock()
			return
		}
		if nodeID == "" {
			err := fmt.Errorf("%s", i18n.T("fw_err_node_not_found"))
			if o.StatusOnly {
				printStatusOnly(stdoutMu, rawHost, "", "", err)
			}
			errMu.Lock()
			*fwErrs = append(*fwErrs, fmt.Errorf("[%s] %w", rawHost, err))
			errMu.Unlock()
			return
		}

		client, err := connector.Connect(ctx, nodeID)
		if err != nil {
			if o.StatusOnly {
				printStatusOnly(stdoutMu, rawHost, "", "", err)
			}
			errMu.Lock()
			*fwErrs = append(*fwErrs, fmt.Errorf("[%s] %w", rawHost, err))
			errMu.Unlock()
			return
		}

		exec := executor.NewSSHExecutor(client, ssh.WithLoginShell(false))
		fw, err := firewall.DetectFirewall(ctx, exec)
		if err != nil {
			if o.StatusOnly {
				printStatusOnly(stdoutMu, rawHost, "", "", err)
			}
			errMu.Lock()
			*fwErrs = append(*fwErrs, fmt.Errorf("[%s] %w", rawHost, err))
			errMu.Unlock()
			return
		}

		out, err := action(fw)
		if o.StatusOnly {
			printStatusOnly(stdoutMu, rawHost, fw.Name(), out, err)
		} else {
			if err == nil {
				printFwSuccess(stdoutMu, rawHost, fw.Name(), out)
			}
		}
		if err != nil {
			errMu.Lock()
			*fwErrs = append(*fwErrs, fmt.Errorf("[%s] %w", rawHost, err))
			errMu.Unlock()
		}

		if o.Reload {
			if _, reloadErr := fw.Reload(ctx); reloadErr != nil {
				errMu.Lock()
				*fwErrs = append(*fwErrs, fmt.Errorf("[%s] reload failed: %w", rawHost, reloadErr))
				errMu.Unlock()
			}
		}
	})
}

func newFirewallListCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("firewall_list_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				return fw.ListRules(cmd.Context())
			})
		},
	}
}

func newFirewallPortCmd(fwOptions *FirewallOptions) *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "port [ports]",
		Short: i18n.T("firewall_port_short"),
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear {
				return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
					return fw.ClearPorts(cmd.Context())
				})
			}
			if len(args) < 1 {
				return fmt.Errorf("accepts at least 1 arg(s), received %d", len(args))
			}
			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				var allPorts []string
				for _, arg := range args {
					allPorts = append(allPorts, strings.Split(arg, ",")...)
				}

				for _, p := range allPorts {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
					rule := firewall.Rule{
						Port:     p,
						Protocol: firewall.Protocol(fwOptions.Protocol),
						Action:   fwOptions.Action,
					}
					var out string
					var err error
					if fwOptions.Remove {
						out, err = fw.RemoveRule(cmd.Context(), rule)
					} else {
						out, err = fw.AddRule(cmd.Context(), rule)
					}
					finalOut.WriteString(out)
					if err != nil {
						return finalOut.String(), err
					}
				}
				return finalOut.String(), nil
			})
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, i18n.T("flag_fw_clear"))
	return cmd
}

func newFirewallServiceCmd(fwOptions *FirewallOptions) *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "service [services]",
		Short: i18n.T("firewall_service_short"),
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear {
				return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
					return fw.ClearServices(cmd.Context())
				})
			}
			if len(args) < 1 {
				return fmt.Errorf("accepts at least 1 arg(s), received %d", len(args))
			}
			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				var allServices []string
				for _, arg := range args {
					allServices = append(allServices, strings.Split(arg, ",")...)
				}

				for _, s := range allServices {
					s = strings.TrimSpace(s)
					if s == "" {
						continue
					}
					rule := firewall.Rule{
						Service: s,
						Action:  fwOptions.Action,
					}
					var out string
					var err error
					if fwOptions.Remove {
						out, err = fw.RemoveRule(cmd.Context(), rule)
					} else {
						out, err = fw.AddRule(cmd.Context(), rule)
					}
					finalOut.WriteString(out)
					if err != nil {
						return finalOut.String(), err
					}
				}
				return finalOut.String(), nil
			})
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, i18n.T("flag_fw_clear"))
	return cmd
}

func newFirewallRuleCmd(fwOptions *FirewallOptions) *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "rule [port] [source_ip]",
		Short: i18n.T("firewall_rule_short"),
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear {
				return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
					return fw.ClearRules(cmd.Context())
				})
			}
			if len(args) < 1 || len(args) > 2 {
				return fmt.Errorf("accepts between 1 and 2 arg(s), received %d", len(args))
			}
			var portStr, sourceStr string
			if len(args) == 1 {
				sourceStr = args[0]
			} else {
				portStr = args[0]
				sourceStr = args[1]
			}

			reject, err := cmd.Flags().GetBool("reject")
			if err != nil {
				return fmt.Errorf("read firewall reject flag failed: %w", err)
			}
			drop, err := cmd.Flags().GetBool("drop")
			if err != nil {
				return fmt.Errorf("read firewall drop flag failed: %w", err)
			}
			action := firewall.ActionAllow
			if reject {
				action = firewall.ActionReject
			} else if drop {
				action = firewall.ActionDrop
			}

			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				sources := strings.Split(sourceStr, ",")
				var ports []string
				if portStr != "" {
					ports = strings.Split(portStr, ",")
				} else {
					ports = []string{""}
				}

				for _, src := range sources {
					src = strings.TrimSpace(src)
					if src == "" {
						continue
					}
					for _, p := range ports {
						p = strings.TrimSpace(p)
						rule := firewall.Rule{
							Port:     p,
							Source:   src,
							Protocol: firewall.Protocol(fwOptions.Protocol),
							Action:   action,
						}
						var out string
						var err error
						if fwOptions.Remove {
							out, err = fw.RemoveRule(cmd.Context(), rule)
						} else {
							out, err = fw.AddRule(cmd.Context(), rule)
						}
						finalOut.WriteString(out)
						if err != nil {
							return finalOut.String(), err
						}
					}
				}
				return finalOut.String(), nil
			})
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, i18n.T("flag_fw_clear"))
	cmd.Flags().Bool("reject", false, "使用 REJECT")
	cmd.Flags().Bool("drop", false, "使用 DROP")
	return cmd
}

func newFirewallReloadCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: i18n.T("firewall_reload_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				return fw.Reload(cmd.Context())
			})
		},
	}
}

func newFirewallStatusCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: i18n.T("firewall_status_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			fwOptions.StatusOnly = true
			return fwOptions.RunOnHosts(cmd.Context(), func(fw firewall.Firewall) (string, error) {
				open, err := fw.IsOpen(cmd.Context())
				if err != nil {
					return "", err
				}
				if open {
					return "running", nil
				}
				return "not running", nil
			})
		},
	}
}

func printFwSuccess(mu *sync.Mutex, host string, fwName string, out string) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}

	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s]", host))
		successLabel := i18n.T("fw_result_success")
		resultPart := logger.Green(fmt.Sprintf("%s (%s)", successLabel, fwName))
		var outPart string
		if out != "" {
			outPart = "\n" + out
		}
		fmt.Printf("%s %s%s\n", hostPart, resultPart, outPart)
	} else {
		logger.PrintSuccess(i18n.Tf("fw_action_success", map[string]any{"Host": host, "FwName": fwName, "Output": out}))
	}
}

func printStatusOnly(mu *sync.Mutex, host string, fwName string, status string, err error) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}

	var statusStr string
	if err != nil {
		statusStr = fmt.Sprintf("error: %v", err)
	} else {
		if status == "running" {
			statusStr = i18n.T("fw_status_running")
		} else {
			statusStr = i18n.T("fw_status_not_running")
		}
	}

	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s]", host))
		var statusPart string
		if err != nil {
			statusPart = logger.Red(statusStr)
		} else if status == "running" {
			statusPart = logger.Green(statusStr)
		} else {
			statusPart = logger.Yellow(statusStr)
		}
		var typePart string
		if fwName != "" {
			typePart = fmt.Sprintf(" (%s)", fwName)
		}
		fmt.Printf("%s %s%s\n", hostPart, statusPart, typePart)
	} else {
		var typePart string
		if fwName != "" {
			typePart = fmt.Sprintf(" (%s)", fwName)
		}
		fmt.Printf("[%s] %s%s\n", host, statusStr, typePart)
	}
}
