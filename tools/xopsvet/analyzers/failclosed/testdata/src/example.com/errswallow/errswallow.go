package errswallow

import (
	"errors"
	"strconv"
)

type MyErr struct{ msg string }

func (e *MyErr) Error() string { return e.msg }

var errSentinel = errors.New("sentinel")

func produceErr() error {
	return errors.New("boom")
}

// 合法纯分类谓词（不产生新局部 error）
func isSentinel(err error) bool {
	return errors.Is(err, errSentinel)
}

func asMyErr(err error) (*MyErr, bool) {
	return errors.AsType[*MyErr](err)
}

func asAnyErr(err error) (error, bool) {
	return errors.AsType[error](err)
}

func asLegacyErr(err error) bool {
	var target *MyErr
	return errors.As(err, &target)
}

// 嵌套闭包的正确隔离：外层 bool 函数未吞噬 error，内层 FuncLit 返回 error 允许
func outerWithNestedErrorCallback(items []string) bool {
	cb := func(s string) error {
		_, err := strconv.Atoi(s)
		return err
	}
	_ = cb
	return len(items) > 0
}

// 非法：在 bool 函数内吞噬新产生的局部 error
func swallowAtoiToBool(s string) bool {
	_, err := strconv.Atoi(s) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	return err == nil
}

func swallowPairToCommaOK(s string) (int, bool) {
	v, err := strconv.Atoi(s) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	return v, err == nil
}

func swallowInsideErrorsIs() bool {
	return errors.Is(produceErr(), errSentinel) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
}

func swallowChanError(ch <-chan error) bool {
	err := <-ch // want "failclosed: 返回 bool 的函数禁止吞噬从 channel 接收的局部 error"
	return err == nil
}

func swallowInNestedBoolFuncLit() {
	fn := func(s string) bool {
		_, err := strconv.Atoi(s) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
		return err == nil
	}
	_ = fn("1")
}

// Challenge 7 & 8: defer/go/IIFE 匿名闭包、range <-chan error、具名 MyBool 及非末尾 (bool, string) 返回值。
type MyBool bool

func sortLike(items []string, cmp func(a, b string) int) {
	if len(items) > 1 {
		_ = cmp(items[0], items[1])
	}
}

func validOuterCallbackIsolated(items []string) bool {
	sortLike(items, func(a, b string) int {
		_, err := strconv.Atoi(a)
		_ = err
		return 0
	})
	return len(items) > 0
}

func validDeferPureIs(err error) bool {
	defer func() {
		_ = errors.Is(err, errSentinel)
	}()
	return err != nil
}

func swallowInDeferVoidFuncLit() bool {
	defer func() {
		_ = produceErr() // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	}()
	return true
}

func swallowInImmediateVoidFuncLit() bool {
	func() {
		_ = produceErr() // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	}()
	return true
}

func swallowInGoVoidFuncLit() bool {
	go func() {
		_ = produceErr() // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	}()
	return true
}

func swallowRangeChanError(ch <-chan error) bool {
	for err := range ch { // want "failclosed: 返回 bool 的函数禁止在 range chan error 中吞噬局部 error"
		if err != nil {
			return false
		}
	}
	return true
}

func swallowNamedBool(s string) MyBool {
	_, err := strconv.Atoi(s) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	return err == nil
}

func swallowBoolNotLast(s string) (bool, string) {
	_, err := strconv.Atoi(s) // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	return err == nil, s
}

// Challenger 2 - Challenge 4: 局部闭包变量绑定无返回 FuncLit 并调用时仍应检测吞噬 error。
func swallowInLocalVoidClosureVar() bool {
	fn := func() {
		_ = produceErr() // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	}
	fn()
	return true
}

func swallowInDeferLocalVoidClosureVar() bool {
	var fn = func() {
		_ = produceErr() // want "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error"
	}
	defer fn()
	return true
}

func validLocalVoidClosureVarPureIs(err error) bool {
	fn := func() {
		_ = errors.Is(err, errSentinel)
	}
	fn()
	return err != nil
}
