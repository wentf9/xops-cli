//go:build ignore

// verify.go 是 XOps v2 全仓库四端统一 CI/验证单一事实源（SSOT），
// 供 Makefile、GitHub Actions、Forgejo Local CI 与 scripts/local-ci/run.sh 共同调用。
//
// 调用约定：
//   - 外层统一直接执行 `go run ./scripts/ci/verify.go ...`，严禁在外层硬设 `GOWORK=off`；
//   - 本程序按模块在子进程显式管控 `GOWORK`：`tools/xopsvet/` 与 `core/` 强制 `GOWORK=off`，
//     根 CLI 模块默认清除继承的 `GOWORK` 以走 `go.work`（仅传入 `--gowork-off` 时关闭）。
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

// replaceDirectiveRE 匹配 go.mod 中禁止出现的 replace 指令（单行或块形式），不误伤注释行。
var replaceDirectiveRE = regexp.MustCompile(`(?m)^\s*replace(?:\s|\()`)

type options struct {
	stage, pkg, dstSeeds               string
	verbose, skipLint, goworkOff, test bool
}

type cmdStep struct {
	name string
	args []string
}

func lintArgs() []string {
	return []string{"run", "--max-issues-per-linter=0", "--max-same-issues=0", "./..."}
}

func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "[verify] ERROR: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	repoRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("获取工作目录失败: %w", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		return errors.New("请在仓库根目录执行 verify.go（未找到 go.mod）")
	}
	if err := runSelfCheck(repoRoot, opts.goworkOff); err != nil {
		return err
	}
	if err := checkNoReplaceDirectives(repoRoot); err != nil {
		return err
	}
	if opts.test {
		if err := runInternalSelfTest(); err != nil {
			return err
		}
		fmt.Println("[verify] self-test PASS")
		return nil
	}
	return executeStage(repoRoot, opts)
}

func parseOptions(args []string) (options, error) {
	defaultSeeds := strings.TrimSpace(os.Getenv("XOPS_DST_SEEDS"))
	if defaultSeeds == "" {
		defaultSeeds = "10000"
	}
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var opts options
	fs.StringVar(&opts.stage, "stage", "all", "执行阶段: xopsvet|core|root|cross|dst|all")
	fs.StringVar(&opts.pkg, "pkg", "./...", "传递给 core/root go test 的包匹配模式")
	fs.BoolVar(&opts.verbose, "verbose", false, "向 go test 透传 -v 输出详细用例日志")
	fs.BoolVar(&opts.skipLint, "skip-lint", false, "跳过 golangci-lint（适配外部 lint Action 或无 lint Runner）")
	fs.BoolVar(&opts.goworkOff, "gowork-off", false, "对根 CLI 模块也强制 GOWORK=off（正式发版锁 core/v1.0.0 Tag 验收）")
	fs.BoolVar(&opts.test, "self-test", false, "仅执行 verify.go 自检、replace 守卫与内部不变量测试")
	fs.StringVar(&opts.dstSeeds, "dst-seeds", defaultSeeds, "传递给 --stage=dst 的 XOPS_DST_SEEDS 种子数")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if err := validateStage(opts.stage); err != nil {
		return options{}, err
	}
	if strings.TrimSpace(opts.pkg) == "" {
		opts.pkg = "./..."
	}
	return opts, nil
}

func validateStage(stage string) error {
	valid := []string{"xopsvet", "core", "root", "cross", "dst", "all"}
	if !slices.Contains(valid, stage) {
		return fmt.Errorf("未知 --stage=%q，合法值: %s", stage, strings.Join(valid, "|"))
	}
	return nil
}

// runSelfCheck 对 verify.go 自身执行 gofmt 与根默认环境 go vet 自检，防脚本自身腐化。
func runSelfCheck(repoRoot string, goworkOff bool) error {
	const scriptRel = "./scripts/ci/verify.go"
	fmt.Printf("[verify] self-check: gofmt & go vet %s\n", scriptRel)
	out, err := captureCmd(repoRoot, buildEnv(goworkOff), "gofmt", "-l", scriptRel)
	if err != nil {
		return fmt.Errorf("gofmt 自检失败: %w", err)
	}
	if unformatted := strings.TrimSpace(out); unformatted != "" {
		return fmt.Errorf("scripts/ci/verify.go 未经 gofmt 格式化（请运行 gofmt -w scripts/ci/verify.go）: %s", unformatted)
	}
	if err := runCmd(repoRoot, buildEnv(goworkOff), "go", "vet", scriptRel); err != nil {
		return fmt.Errorf("go vet 自检 scripts/ci/verify.go 失败: %w", err)
	}
	return nil
}

// checkNoReplaceDirectives 强制全仓 3 个 go.mod 零 replace 指令（ADR-001）。
func checkNoReplaceDirectives(repoRoot string) error {
	for _, rel := range []string{"go.mod", filepath.Join("core", "go.mod"), filepath.Join("tools", "xopsvet", "go.mod")} {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", rel, err)
		}
		if hasReplaceDirective(data) {
			return fmt.Errorf("禁止在 %s 中声明 replace 指令（请通过 go.work 或正式 Tag 管理依赖）", filepath.ToSlash(rel))
		}
	}
	return nil
}

func hasReplaceDirective(goModContent []byte) bool { return replaceDirectiveRE.Match(goModContent) }

func executeStage(repoRoot string, opts options) error {
	switch opts.stage {
	case "xopsvet":
		return runXopsvetStage(repoRoot, opts)
	case "core":
		return runCoreStage(repoRoot, opts, opts.pkg)
	case "root":
		return runRootStage(repoRoot, opts, opts.pkg)
	case "cross":
		return runCrossStage(repoRoot, opts)
	case "dst":
		return runDSTStage(repoRoot, opts)
	case "all":
		if err := runXopsvetStage(repoRoot, opts); err != nil {
			return err
		}
		corePkg, rootPkg, err := resolveAllStagePkgs(repoRoot, opts.pkg)
		if err != nil {
			return err
		}
		if corePkg != "" {
			if err := runCoreStage(repoRoot, opts, corePkg); err != nil {
				return err
			}
		}
		if rootPkg != "" {
			return runRootStage(repoRoot, opts, rootPkg)
		}
		return nil
	default:
		return validateStage(opts.stage)
	}
}

// resolveAllStagePkgs 在 --stage=all 配合定向 --pkg 时，仅对包含该包路径的活跃模块透传 --pkg。
func resolveAllStagePkgs(repoRoot, pkg string) (corePkg, rootPkg string, err error) {
	if pkg == "./..." {
		return "./...", "./...", nil
	}
	cleanDir := filepath.FromSlash(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(pkg, "/..."), "..."), "./"))
	if hasGoFiles(filepath.Join(repoRoot, "core")) && pathExists(filepath.Join(repoRoot, "core", cleanDir)) {
		corePkg = pkg
	}
	if hasRootGoFiles(repoRoot) && pathExists(filepath.Join(repoRoot, cleanDir)) {
		rootPkg = pkg
	}
	if corePkg == "" && rootPkg == "" {
		return "", "", fmt.Errorf("--stage=all 下的 --pkg=%q 在 core/ 与根模块中均未匹配到目录", pkg)
	}
	return corePkg, rootPkg, nil
}

func runXopsvetStage(repoRoot string, opts options) error {
	xopsDir := filepath.Join(repoRoot, "tools", "xopsvet")
	if !hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet")) {
		fmt.Println("[verify] skip xopsvet: tools/xopsvet/cmd/xopsvet 尚无 Go 源码")
		return nil
	}
	vettool := vettoolPath(repoRoot)
	if err := os.MkdirAll(filepath.Dir(vettool), 0o755); err != nil {
		return fmt.Errorf("创建 bin 目录失败: %w", err)
	}
	fmt.Println("[verify] === Stage: xopsvet (GOWORK=off) ===")
	steps := []cmdStep{
		{name: "go", args: goTestArgs(opts.verbose, "./...")},
		{name: "go", args: []string{"build", "-o", vettool, "./cmd/xopsvet"}},
		{name: "go", args: []string{"vet", "-vettool=" + vettool, "./..."}},
	}
	if !opts.skipLint {
		steps = append(steps, cmdStep{name: "golangci-lint", args: lintArgs()})
	}
	return runSteps(xopsDir, buildEnv(true), steps)
}

func ensureVettool(repoRoot string) (string, bool, error) {
	xopsDir := filepath.Join(repoRoot, "tools", "xopsvet")
	if !hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet")) {
		return "", false, nil
	}
	vettool := vettoolPath(repoRoot)
	if pathExists(vettool) {
		return vettool, true, nil
	}
	if err := os.MkdirAll(filepath.Dir(vettool), 0o755); err != nil {
		return "", false, fmt.Errorf("创建 bin 目录失败: %w", err)
	}
	fmt.Printf("[verify] building xopsvet -> %s\n", vettool)
	if err := runCmd(xopsDir, buildEnv(true), "go", "build", "-o", vettool, "./cmd/xopsvet"); err != nil {
		return "", false, err
	}
	return vettool, true, nil
}

func runCoreStage(repoRoot string, opts options, pkg string) error {
	coreDir := filepath.Join(repoRoot, "core")
	if !hasGoFiles(coreDir) {
		fmt.Println("[verify] skip core: core/ 尚无 Go 源码")
		return nil
	}
	return runModuleVerify(repoRoot, coreDir, "core (GOWORK=off)", pkg, true, opts)
}

func runRootStage(repoRoot string, opts options, pkg string) error {
	if !hasRootGoFiles(repoRoot) {
		fmt.Println("[verify] skip root: 根 CLI 模块（cmd/xops 与 internal/）尚无 Go 源码")
		return nil
	}
	label := "root (go.work)"
	if opts.goworkOff {
		label = "root (GOWORK=off)"
	}
	return runModuleVerify(repoRoot, repoRoot, label, pkg, opts.goworkOff, opts)
}

func runModuleVerify(repoRoot, modDir, label, pkg string, goworkOff bool, opts options) error {
	vettool, hasVet, err := ensureVettool(repoRoot)
	if err != nil {
		return err
	}
	fmt.Printf("[verify] === Stage: %s, pkg=%s ===\n", label, pkg)
	steps := []cmdStep{{name: "go", args: []string{"build", "./..."}}}
	if hasVet {
		steps = append(steps, cmdStep{name: "go", args: []string{"vet", "-vettool=" + vettool, "./..."}})
	}
	if !opts.skipLint {
		steps = append(steps, cmdStep{name: "golangci-lint", args: lintArgs()})
	}
	steps = append(steps, cmdStep{name: "go", args: goTestArgs(opts.verbose, pkg)})
	return runSteps(modDir, buildEnv(goworkOff), steps)
}

func runCrossStage(repoRoot string, opts options) error {
	xopsDir := filepath.Join(repoRoot, "tools", "xopsvet")
	coreDir := filepath.Join(repoRoot, "core")
	hasXops := hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet"))
	hasCore := hasGoFiles(coreDir)
	hasRoot := hasRootGoFiles(repoRoot)

	fmt.Println("[verify] === Stage: cross (Windows & macOS cross-build & cross-lint) ===")
	for _, goos := range []string{"windows", "darwin"} {
		extra := []string{"GOOS=" + goos, "GOARCH=amd64"}
		offEnv := buildEnv(true, extra...)
		if hasXops {
			if err := runCmd(xopsDir, offEnv, "go", "build", "./..."); err != nil {
				return err
			}
		}
		if hasCore {
			if err := runCrossModule(coreDir, offEnv, opts.skipLint); err != nil {
				return err
			}
		}
		if hasRoot {
			if err := runCrossModule(repoRoot, buildEnv(opts.goworkOff, extra...), opts.skipLint); err != nil {
				return err
			}
		}
	}
	return nil
}

func runCrossModule(dir string, env []string, skipLint bool) error {
	steps := []cmdStep{{name: "go", args: []string{"build", "./..."}}}
	if !skipLint {
		steps = append(steps, cmdStep{name: "golangci-lint", args: lintArgs()})
	}
	return runSteps(dir, env, steps)
}

func runDSTStage(repoRoot string, opts options) error {
	if !hasMatchingFiles(filepath.Join(repoRoot, "core", "internal", "pool"), "_test.go") {
		fmt.Println("[verify] skip dst: core/internal/pool 尚无 DST 测试")
		return nil
	}
	args := goTestArgs(opts.verbose, "./...")
	args = slices.Insert(args, len(args)-1, "-run", "^TestDST_")
	fmt.Printf("[verify] === Stage: dst (GOWORK=off, XOPS_DST_SEEDS=%s) ===\n", opts.dstSeeds)
	return runCmd(filepath.Join(repoRoot, "core"), buildEnv(true, "XOPS_DST_SEEDS="+opts.dstSeeds), "go", args...)
}

func goTestArgs(verbose bool, pkg string) []string {
	args := []string{"test"}
	if verbose {
		args = append(args, "-v")
	}
	return append(args, "-race", "-shuffle=on", "-count=1", pkg)
}

func vettoolPath(repoRoot string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(repoRoot, "bin", "xopsvet.exe")
	}
	return filepath.Join(repoRoot, "bin", "xopsvet")
}

// buildEnv 基于当前进程环境构造子进程环境：按模块显式设置或剔除 GOWORK，并覆盖 extra 键值。
func buildEnv(goworkOff bool, extra ...string) []string {
	return buildEnvFrom(os.Environ(), goworkOff, extra...)
}

func buildEnvFrom(base []string, goworkOff bool, extra ...string) []string {
	overrideKeys := make([]string, 0, len(extra)+1)
	overrideKeys = append(overrideKeys, "GOWORK")
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok {
			overrideKeys = append(overrideKeys, k)
		}
	}
	out := make([]string, 0, len(base)+len(extra)+1)
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || slices.ContainsFunc(overrideKeys, func(key string) bool { return strings.EqualFold(key, k) }) {
			continue
		}
		out = append(out, kv)
	}
	if goworkOff {
		out = append(out, "GOWORK=off")
	}
	return append(out, extra...)
}

func runSteps(dir string, env []string, steps []cmdStep) error {
	for _, s := range steps {
		if err := runCmd(dir, env, s.name, s.args...); err != nil {
			return err
		}
	}
	return nil
}

func runCmd(dir string, env []string, name string, args ...string) error {
	fmt.Printf("[verify] (%s) %s %s\n", filepath.ToSlash(dir), name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, os.Stdout, os.Stderr
	return cmd.Run()
}

func captureCmd(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func hasRootGoFiles(repoRoot string) bool {
	return hasGoFiles(filepath.Join(repoRoot, "cmd", "xops")) || hasGoFiles(filepath.Join(repoRoot, "internal"))
}

func hasGoFiles(dir string) bool { return hasMatchingFiles(dir, ".go") }

func hasMatchingFiles(dir, suffix string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func pathExists(p string) bool { _, err := os.Stat(p); return err == nil }

// runInternalSelfTest 验证 verify.go 自身的核心环境隔离与正则守卫不变量。
func runInternalSelfTest() error {
	if hasReplaceDirective([]byte("module example.com/m\n\ngo 1.27.0\n// replace a => b\n")) {
		return errors.New("replace 正则误报了注释行")
	}
	if !hasReplaceDirective([]byte("module example.com/m\nreplace a => ./a\n")) ||
		!hasReplaceDirective([]byte("module example.com/m\n\treplace (\n\t\ta => ./a\n\t)\n")) {
		return errors.New("replace 正则漏报了 replace 指令")
	}
	rootEnv := buildEnvFrom([]string{"PATH=/usr/bin", "GOWORK=off", "GOOS=linux"}, false)
	if slices.ContainsFunc(rootEnv, func(kv string) bool { k, _, _ := strings.Cut(kv, "="); return strings.EqualFold(k, "GOWORK") }) {
		return fmt.Errorf("goworkOff=false 未清除继承的 GOWORK: %v", rootEnv)
	}
	coreEnv := buildEnvFrom([]string{"PATH=/usr/bin", "gowork=/tmp/go.work"}, true, "GOOS=windows")
	if !slices.Contains(coreEnv, "GOWORK=off") || !slices.Contains(coreEnv, "GOOS=windows") {
		return fmt.Errorf("goworkOff=true 未正确注入 GOWORK/GOOS: %v", coreEnv)
	}
	if validateStage("invalid-stage") == nil {
		return errors.New("validateStage 未拒绝非法阶段名")
	}
	return nil
}
