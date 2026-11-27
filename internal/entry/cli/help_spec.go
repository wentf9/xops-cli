package cli

import (
	"io"

	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdasset"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdtransfer"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func writeRootHelp(w io.Writer, loc *i18n.Localizer) {
	_, _ = io.WriteString(w, clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpRoot))
}

func writeVersionHelp(w io.Writer, loc *i18n.Localizer) {
	_, _ = io.WriteString(w, clikit.EnsureLocalizer(loc).T(i18n.KeyCLIHelpVersion))
}

func lookupHelpTopic(loc *i18n.Localizer, topic string) (string, bool) {
	eff := clikit.EnsureLocalizer(loc)
	switch topic {
	case "ssh":
		return cmdssh.SSHHelpText(eff), true
	case "exec":
		return cmdssh.ExecHelpText(eff), true
	case "tunnel", "forward":
		return cmdssh.TunnelHelpText(eff), true
	case "mux":
		return cmdssh.MuxHelpText(eff), true
	case "scp":
		return cmdtransfer.SCPHelpText(eff), true
	case "sftp":
		return cmdtransfer.SFTPHelpText(eff), true
	case "hosts", "host", "inventory":
		return cmdasset.HostsHelpText(eff), true
	case "creds", "cred", "vault":
		return cmdasset.VaultHelpText(eff), true
	case "config":
		return cmdasset.ConfigHelpText(eff), true
	case "playbook", "play":
		return cmdops.PlaybookHelpText(eff), true
	case "doctor":
		return cmdops.DoctorHelpText(eff), true
	case "audit":
		return cmdops.AuditHelpText(eff), true
	case "mcp":
		return cmdops.MCPHelpText(eff), true
	case "tui":
		return cmdops.TUIHelpText(eff), true
	case "version":
		return eff.T(i18n.KeyCLIHelpVersion), true
	default:
		return "", false
	}
}
