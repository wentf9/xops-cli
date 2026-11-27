package clikit

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// BuildLaunchProfile 依据 core/domain/execution 的组合约束矩阵，将部分指定的
// (--dialect / --interpreter / --login) 补全为合法且确定性的 execution.LaunchProfile。
// 三者均未指定时返回 DefaultServerLaunchProfile；任何不合法显式组合均失败关闭返回 ErrUsage。
func BuildLaunchProfile(
	dialectOpt algebraic.Option[execution.LaunchDialect],
	interp execution.Interpreter,
	login execution.LoginMode,
) (prof execution.LaunchProfile, err error) {
	if dialectOpt.IsNone() && !interp.IsValid() && !login.IsValid() {
		return execution.DefaultServerLaunchProfile(), nil
	}
	resolvedDialect, resolvedInterp := inferDialectAndInterpreter(dialectOpt, interp, login)
	resolvedLogin := inferLoginMode(resolvedInterp, login)
	built, pErr := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect:     resolvedDialect,
		Interpreter: resolvedInterp,
		Login:       resolvedLogin,
	})
	if pErr != nil {
		return prof, i18n.WrapS(ErrUsage, pErr, i18n.KeyCLIInvalidLaunchProfile)
	}
	return built, nil
}

// BuildOptionalLaunchProfile 当三者均未指定时返回 None，否则按 BuildLaunchProfile 矩阵推导并校验。
func BuildOptionalLaunchProfile(
	dialectOpt algebraic.Option[execution.LaunchDialect],
	interp execution.Interpreter,
	login execution.LoginMode,
) (algebraic.Option[execution.LaunchProfile], error) {
	if dialectOpt.IsNone() && !interp.IsValid() && !login.IsValid() {
		return algebraic.None[execution.LaunchProfile](), nil
	}
	prof, err := BuildLaunchProfile(dialectOpt, interp, login)
	if err != nil {
		return algebraic.None[execution.LaunchProfile](), err
	}
	return algebraic.Some(prof), nil
}

func inferDialectAndInterpreter(
	dialectOpt algebraic.Option[execution.LaunchDialect],
	interp execution.Interpreter,
	login execution.LoginMode,
) (algebraic.Option[execution.LaunchDialect], execution.Interpreter) {
	if !interp.IsValid() {
		if d, ok := dialectOpt.Get(); ok {
			return dialectOpt, defaultInterpreterForDialect(d)
		}
		// 仅指定 --login 时：inherit 对应 server 直通；login 需 bash（sh 不支持 login=login）；disabled 用 sh。
		switch login {
		case execution.LoginModeInherit:
			return algebraic.None[execution.LaunchDialect](), execution.InterpreterServer
		case execution.LoginModeLogin:
			return algebraic.Some(execution.DialectPOSIX), execution.InterpreterBash
		default:
			return algebraic.Some(execution.DialectPOSIX), execution.InterpreterSH
		}
	}
	if dialectOpt.IsNone() {
		if d, ok := defaultDialectForInterpreter(interp); ok {
			return algebraic.Some(d), interp
		}
	}
	return dialectOpt, interp
}

func defaultInterpreterForDialect(d execution.LaunchDialect) execution.Interpreter {
	switch d {
	case execution.DialectPOSIX:
		return execution.InterpreterSH
	case execution.DialectPowerShell:
		return execution.InterpreterPowerShell
	case execution.DialectCmd:
		return execution.InterpreterCmd
	default:
		// DialectRaw 仅允许 server 直通解释器。
		return execution.InterpreterServer
	}
}

func defaultDialectForInterpreter(interp execution.Interpreter) (execution.LaunchDialect, bool) {
	switch interp {
	case execution.InterpreterSH, execution.InterpreterBash, execution.InterpreterZsh:
		return execution.DialectPOSIX, true
	case execution.InterpreterPowerShell, execution.InterpreterPwsh:
		return execution.DialectPowerShell, true
	case execution.InterpreterCmd:
		return execution.DialectCmd, true
	default:
		return execution.DialectUnknown, false
	}
}

func inferLoginMode(interp execution.Interpreter, login execution.LoginMode) execution.LoginMode {
	if login.IsValid() {
		return login
	}
	if interp == execution.InterpreterServer {
		return execution.LoginModeInherit
	}
	return execution.LoginModeDisabled
}
