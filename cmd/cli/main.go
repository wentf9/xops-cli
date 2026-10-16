package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/wentf9/xops-cli/cmd"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func main() {
	if code, handled := sshenv.ServeConsoleOutputRelay(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) > 1 && os.Args[1] == kdfhelper.PrivateArgument {
		if len(os.Args) != 2 {
			os.Exit(1)
		}
		os.Exit(kdfhelper.ServeFiles(os.Stdin, os.Stdout))
	}
	// 提前解析 --lang 参数，在命令构造前设置语言
	// 解决 Cobra --help 跳过 PersistentPreRun 导致语言设置不生效的问题
	lang := parseLangFromArgs(os.Args[1:])
	if err := i18n.Init(lang); err != nil {
		if _, writeErr := fmt.Fprintf(os.Stderr, "init i18n failed: %v\n", err); writeErr != nil {
			logger.PrintError(fmt.Sprintf("init i18n failed: %v", err))
		}
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		reportError(err)
		os.Exit(1)
	}
}

// Standard streams can share a sink, so failed standard-stream output must not be
// reported to them again, even when the original failure was on stdout.
// Preserve the nonzero exit status and leave all other error reporting intact.
func reportError(err error) {
	if !cmd.HasStandardOutputError(err) {
		logger.PrintError(err.Error())
	}
}

// parseLangFromArgs 从命令行参数中提取 --lang 值
func parseLangFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "--lang" && i+1 < len(args) {
			return args[i+1]
		}
		if after, ok := strings.CutPrefix(arg, "--lang="); ok {
			return after
		}
	}
	return ""
}
