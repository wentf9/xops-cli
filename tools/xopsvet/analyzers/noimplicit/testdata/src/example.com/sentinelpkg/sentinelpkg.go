package sentinelpkg

import (
	"context"
	"errors"
)

var ErrShared = errors.New("shared")
var SharedFailure = errors.New("non sentinel") // want "禁止声明可变包级 var"

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
