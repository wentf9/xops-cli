package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/wentf9/xops-cli/cmd"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func main() {
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
		logger.PrintError(err.Error())
		os.Exit(1)
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
