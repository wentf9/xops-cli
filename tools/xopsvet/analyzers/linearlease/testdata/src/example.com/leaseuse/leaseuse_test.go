package leaseuse

import "testing"

func TestLeaseUseBareGoInTest(t *testing.T) {
	go func() {}() // want "禁止使用裸 go 语句"
}
