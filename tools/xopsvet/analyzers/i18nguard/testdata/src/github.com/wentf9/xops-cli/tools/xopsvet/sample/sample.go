package sample

import (
	"errors"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

func VetDiag() error {
	_ = "分析器诊断中文允许"
	_ = domi18n.MessageID("vet.raw")
	return errors.New("vet err")
}
