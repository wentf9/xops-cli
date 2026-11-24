package sentinelpkg

import (
	"context"
	"errors"
)

var ErrShared = errors.New("shared")

type FieldHolder struct {
	ErrField error
}

type OverridingCtx struct {
	context.Context
}

func (OverridingCtx) Value(any) any {
	return nil
}

func NewOverriding() OverridingCtx {
	return OverridingCtx{}
}
