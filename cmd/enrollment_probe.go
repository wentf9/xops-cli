package cmd

import (
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func enrollmentProbeOption() adapter.Option {
	return adapter.WithEnrollmentProbing(func(nodeID string, err error) {
		logger.PrintWarn(i18n.Tf("inventory_probe_warning", map[string]any{"Node": nodeID, "Error": err}))
	})
}
