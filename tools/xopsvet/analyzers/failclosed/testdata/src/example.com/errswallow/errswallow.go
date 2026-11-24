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
