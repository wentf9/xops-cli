package good_test

import (
	"testing"

	"github.com/wentf9/xops-cli/core/domain/good"
	"golang.org/x/text/unicode/norm"
)

func TestGoodExternal(t *testing.T) {
	_ = norm.NFC.String("ok")
	if good.UseAllAllowedStdlibs() == 0 {
		t.Fatal("zero")
	}
}
