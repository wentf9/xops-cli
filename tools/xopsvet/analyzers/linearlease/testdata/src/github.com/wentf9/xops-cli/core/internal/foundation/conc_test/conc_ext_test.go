package conc_test

import "testing"

func TestExternalTestBareGoDenied(t *testing.T) {
	go func() {}() // want "core/internal/foundation/conc 之外禁止使用裸 go 语句"
}
