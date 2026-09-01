package ssh

import (
	"fmt"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"sync"
	"testing"
)

func TestConnector_CloseAll_Idempotent(t *testing.T) {
	c := &Connector{
		clients:   concurrent.NewMap[string, *PooledClient](concurrent.HashString),
		closeDone: make(chan struct{}),
	}
	c.closeErr = fmt.Errorf("initial close error")
	c.closed = true
	close(c.closeDone)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.CloseAll()
			if err == nil || err.Error() != "initial close error" {
				t.Errorf("expected 'initial close error', got %v", err)
			}
		}()
	}
	wg.Wait()
}
