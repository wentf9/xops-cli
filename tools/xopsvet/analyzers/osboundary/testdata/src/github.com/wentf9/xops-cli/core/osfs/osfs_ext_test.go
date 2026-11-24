package osfs_test

import (
	"os"
	"testing"
)

func TestExternalTestNotWhitelisted(t *testing.T) {
	_, _ = os.Open("x") // want "core/osfs 之外禁止直接调用裸 OS"
}
