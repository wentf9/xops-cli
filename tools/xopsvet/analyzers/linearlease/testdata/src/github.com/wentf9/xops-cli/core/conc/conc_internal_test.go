package conc

import "testing"

func TestConcInternalBareGoAllowed(t *testing.T) {
	done := make(chan struct{})
	go func() {
		close(done)
	}()
	<-done
}
