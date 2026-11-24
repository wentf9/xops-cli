package main

import (
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/sys"
)

func main() {
	_ = conc.Nursery{}
	_ = osfs.LocalFS{}
	_ = sys.HostSys{}
	_ = engine.Engine{}
	_ = cli.CLI{}
}
