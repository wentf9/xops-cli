package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func newCmdDns() *cobra.Command {
	return &cobra.Command{
		Use:   "dns domain1 domain2 ...",
		Short: i18n.T("dns_short"),
		Long:  i18n.T("dns_long"),

		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				wg      sync.WaitGroup
				errMu   sync.Mutex
				dnsErrs []error
			)
			for _, domain := range args {
				wg.Add(1)
				go func(d string) {
					defer wg.Done()
					lookupCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
					defer cancel()
					resolved, err := net.DefaultResolver.LookupIPAddr(lookupCtx, d)
					if err != nil {
						errMu.Lock()
						dnsErrs = append(dnsErrs, fmt.Errorf("resolve %q failed: %w", d, err))
						errMu.Unlock()
						return
					}
					for _, address := range resolved {
						logger.PrintInfo(i18n.Tf("dns_resolve_info", map[string]any{"Domain": d, "IP": address.String()}))
					}
				}(domain)
			}
			wg.Wait()
			return errors.Join(dnsErrs...)
		},
	}
}
