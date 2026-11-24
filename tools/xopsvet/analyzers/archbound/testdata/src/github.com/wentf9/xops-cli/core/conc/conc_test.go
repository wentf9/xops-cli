package conc

import (
	"testing"

	"go.uber.org/goleak"
)

func TestConcAllowsGoleak(t *testing.T) {
	goleak.VerifyNone(t)
}
