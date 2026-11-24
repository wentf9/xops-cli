package conc

import "context"

type Nursery struct{}

func NewNursery(ctx context.Context) *Nursery {
	_ = ctx
	return &Nursery{}
}
