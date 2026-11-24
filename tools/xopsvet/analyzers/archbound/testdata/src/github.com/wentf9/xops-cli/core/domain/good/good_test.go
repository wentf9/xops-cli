package good

import "testing"

func TestGoodInternal(t *testing.T) {
	if UseAllAllowedStdlibs() == 0 {
		t.Fatal("zero")
	}
}
