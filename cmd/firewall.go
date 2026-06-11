package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
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
	HostFile  string
	Protocol  string
	Reload    bool
	Remove    bool
	Zone      string
	Action    firewall.Action
	TaskCount int
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
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	cmd.AddCommand(newFirewallListCmd(fwOptions))
	cmd.AddCommand(newFirewallPortCmd(fwOptions))
	cmd.AddCommand(newFirewallServiceCmd(fwOptions))
	cmd.AddCommand(newFirewallRuleCmd(fwOptions))
	cmd.AddCommand(newFirewallReloadCmd(fwOptions))

	cmd.PersistentFlags().StringVarP(&fwOptions.Host, "host", "H", "", i18n.T("flag_fw_host"))
	cmd.PersistentFlags().StringVarP(&fwOptions.HostFile, "ifile", "I", "", i18n.T("flag_fw_ifile"))
	cmd.PersistentFlags().StringSliceVarP(&fwOptions.Tags, "tags", "t", []string{}, i18n.T("flag_fw_tags"))
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
	pwd := cmdutils.GetLocalSudoPassword()
	exec := executor.NewLocalExecutor(pwd)
	fw, err := firewall.DetectFirewall(ctx, exec)
	if err != nil {
		return err
	}
	out, err := action(fw)
	if err != nil {
		printFwActionFailed(nil, "LOCAL", err, out)
	} else {
		printFwSuccess(nil, "LOCAL", fw.Name(), out)
	}
	if o.Reload {
		if _, err := fw.Reload(ctx); err != nil {
			printFwError(nil, "LOCAL", err, "fw_label_reload_failed", "fw_local_reload_failed")
		}
	}
	return nil
}

func (o *FirewallOptions) runRemoteFirewalls(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return err
	}
	provider := config.NewProvider(cfg)
	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	var hosts []string
	if o.Host != "" {
		hosts = append(hosts, strings.Split(o.Host, ",")...)
	}
	if o.HostFile != "" {
		data, err := os.ReadFile(o.HostFile)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("err_read_ifile"), err)
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

	var stdoutMu sync.Mutex
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))
	for _, h := range finalHosts {
		o.executeOnSingleHost(ctx, h, provider, connector, wp, action, &stdoutMu)
	}

	wp.Wait()
	if err := configStore.Save(cfg); err != nil {
		logger.PrintError(i18n.Tf("save_config_failed", map[string]any{"Error": err}))
	}
	return nil
}

func (o *FirewallOptions) executeOnSingleHost(ctx context.Context, h string, provider config.ConfigProvider, connector *ssh.Connector, wp pkgutils.WorkerPool, action func(fw firewall.Firewall) (string, error), stdoutMu *sync.Mutex) {
	wp.Execute(func() {
		rawHost := strings.TrimSpace(h)
		if rawHost == "" {
			return
		}

		nodeID := provider.Find(rawHost)
		u, hs, p := cmdutils.ParseAddr(rawHost)
		if nodeID == "" {
			if u == "" {
				u = o.User
				if u == "" {
					u = cmdutils.GetCurrentUser()
				}
			}
			if p == 0 {
				p = o.Port
				if p == 0 {
					p = 22
				}
			}
			nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", u, hs, p))
		}

		if nodeID == "" {
			printFwNodeNotFound(stdoutMu, u, hs, p)
			return
		}

		client, err := connector.Connect(ctx, nodeID)
		if err != nil {
			printFwError(stdoutMu, rawHost, err, "fw_label_connect_failed", "fw_connect_failed")
			return
		}

		exec := executor.NewSSHExecutor(client, ssh.WithLoginShell(false))
		fw, err := firewall.DetectFirewall(ctx, exec)
		if err != nil {
			printFwError(stdoutMu, rawHost, err, "fw_label_detect_failed", "fw_detect_failed")
			return
		}

		out, err := action(fw)
		if err != nil {
			printFwActionFailed(stdoutMu, rawHost, err, out)
		} else {
			printFwSuccess(stdoutMu, rawHost, fw.Name(), out)
		}

		if o.Reload {
			if _, err := fw.Reload(ctx); err != nil {
				printFwError(stdoutMu, rawHost, err, "fw_label_reload_failed", "fw_reload_failed")
			}
		}
	})
}

func newFirewallListCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("firewall_list_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				return fw.ListRules(context.Background())
			})
		},
	}
}

func newFirewallPortCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "port <ports>",
		Short: i18n.T("firewall_port_short"),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
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
						out, err = fw.RemoveRule(context.Background(), rule)
					} else {
						out, err = fw.AddRule(context.Background(), rule)
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
}

func newFirewallServiceCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "service <services>",
		Short: i18n.T("firewall_service_short"),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
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
						out, err = fw.RemoveRule(context.Background(), rule)
					} else {
						out, err = fw.AddRule(context.Background(), rule)
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
}

func newFirewallRuleCmd(fwOptions *FirewallOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule [port] <source_ip>",
		Short: i18n.T("firewall_rule_short"),
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var portStr, sourceStr string
			if len(args) == 1 {
				sourceStr = args[0]
			} else {
				portStr = args[0]
				sourceStr = args[1]
			}

			reject, _ := cmd.Flags().GetBool("reject")
			drop, _ := cmd.Flags().GetBool("drop")
			action := firewall.ActionAllow
			if reject {
				action = firewall.ActionReject
			} else if drop {
				action = firewall.ActionDrop
			}

			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
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
							out, err = fw.RemoveRule(context.Background(), rule)
						} else {
							out, err = fw.AddRule(context.Background(), rule)
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
	cmd.Flags().Bool("reject", false, "使用 REJECT")
	cmd.Flags().Bool("drop", false, "使用 DROP")
	return cmd
}

func newFirewallReloadCmd(fwOptions *FirewallOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: i18n.T("firewall_reload_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				return fw.Reload(context.Background())
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

func printFwActionFailed(mu *sync.Mutex, host string, err error, out string) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}

	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s]", host))
		failedLabel := i18n.T("fw_result_failed")
		errorLabel := i18n.T("fw_label_error")
		outputLabel := i18n.T("fw_label_output")
		resultPart := logger.Red(failedLabel)
		errPart := logger.Red(fmt.Sprintf("%s: %v", errorLabel, err))
		var outPart string
		if out != "" {
			outPart = fmt.Sprintf("\n%s:\n%s", logger.Yellow(outputLabel), out)
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s%s\n", hostPart, resultPart, errPart, outPart)
	} else {
		logger.PrintError(i18n.Tf("fw_action_failed", map[string]any{"Host": host, "Error": err, "Output": out}))
	}
}

func printFwNodeNotFound(mu *sync.Mutex, u string, hs string, p uint16) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}

	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s@%s:%d]", u, hs, p))
		failedLabel := i18n.T("fw_result_failed")
		errText := i18n.T("fw_err_node_not_found")
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", hostPart, logger.Red(failedLabel), logger.Red(errText))
	} else {
		logger.PrintError(i18n.Tf("fw_node_not_found", map[string]any{"User": u, "Host": hs, "Port": p}))
	}
}

func printFwError(mu *sync.Mutex, host string, err error, labelKey string, fallbackTfKey string) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}

	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s]", host))
		failedLabel := i18n.T("fw_result_failed")
		errLabel := i18n.T(labelKey)
		fmt.Fprintf(os.Stderr, "%s %s: %s: %s\n", hostPart, logger.Red(failedLabel), logger.Red(errLabel), logger.Red(err.Error()))
	} else {
		logger.PrintError(i18n.Tf(fallbackTfKey, map[string]any{"Host": host, "Error": err}))
	}
}
