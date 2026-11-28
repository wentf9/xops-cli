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

// replaceDirectiveRE 匹配 go.mod/go.work 中禁止出现的 replace 指令（单行或块形式），不误伤注释行。
var replaceDirectiveRE = regexp.MustCompile(`(?m)^\s*replace(?:\s|\()`)

type options struct {
	stage, pkg, dstSeeds               string
	verbose, skipLint, goworkOff, test bool
}

type verifyRunner struct {
	repoRoot     string
	opts         options
	vettoolBuilt bool
}

type cmdStep struct {
	name string
	args []string
}

var golangciLintArgs = []string{"run", "--max-issues-per-linter=0", "--max-same-issues=0", "./..."}

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
		if err := runInternalSelfTest(repoRoot); err != nil {
			return err
		}
		fmt.Println("[verify] self-test PASS")
		return nil
	}
	return (&verifyRunner{repoRoot: repoRoot, opts: opts}).executeStage()
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var opts options
	fs.StringVar(&opts.stage, "stage", "all", "执行阶段: xopsvet|core|root|cross|dst|all")
	fs.StringVar(&opts.pkg, "pkg", "./...", "传递给 core/root go test 的包匹配模式")
	fs.BoolVar(&opts.verbose, "verbose", false, "向 go test 透传 -v 输出详细用例日志")
	fs.BoolVar(&opts.skipLint, "skip-lint", false, "跳过 golangci-lint（适配外部 lint Action 或无 lint Runner）")
	fs.BoolVar(&opts.goworkOff, "gowork-off", false, "对根 CLI 模块也强制 GOWORK=off（正式发版锁 core/v1.x.y Tag 验收）")
	fs.BoolVar(&opts.test, "self-test", false, "仅执行 verify.go 自检、replace 守卫与内部不变量测试")
	fs.StringVar(&opts.dstSeeds, "dst-seeds", strings.TrimSpace(os.Getenv("XOPS_DST_SEEDS")), "传递给 --stage=dst 的 XOPS_DST_SEEDS 种子数")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("存在未识别的位置参数: %v", fs.Args())
	}
	if err := validateStage(opts.stage); err != nil {
		return options{}, err
	}
	if strings.TrimSpace(opts.pkg) == "" {
		opts.pkg = "./..."
	}
	if strings.TrimSpace(opts.dstSeeds) == "" {
		opts.dstSeeds = "10000"
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

func runSelfCheck(repoRoot string, goworkOff bool) error {
	const scriptRel = "./scripts/ci/verify.go"
	fmt.Printf("[verify] self-check: gofmt & go vet %s\n", scriptRel)
	env := buildEnv(goworkOff)
	out, err := captureCmd(repoRoot, env, "gofmt", "-l", scriptRel)
	if err != nil {
		return fmt.Errorf("gofmt 自检失败: %w", err)
	}
	if s := strings.TrimSpace(out); s != "" {
		return fmt.Errorf("scripts/ci/verify.go 未经 gofmt 格式化: %s", s)
	}
	return runCmd(repoRoot, env, "go", "vet", scriptRel)
}

// checkNoReplaceDirectives 强制全仓 3 个 go.mod 与 go.work 零 replace 指令（ADR-001）。
func checkNoReplaceDirectives(repoRoot string) error {
	for _, rel := range []string{"go.mod", "go.work", filepath.Join("core", "go.mod"), filepath.Join("tools", "xopsvet", "go.mod")} {
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

func hasReplaceDirective(content []byte) bool { return replaceDirectiveRE.Match(content) }

func (r *verifyRunner) executeStage() error {
	switch r.opts.stage {
	case "xopsvet":
		return r.runXopsvetStage()
	case "core":
		return r.runCoreStage(r.opts.pkg)
	case "root":
		return r.runRootStage(r.opts.pkg)
	case "cross":
		return r.runCrossStage()
	case "dst":
		return r.runDSTStage()
	case "all":
		if err := r.runXopsvetStage(); err != nil {
			return err
		}
		corePkg, rootPkg, err := resolveAllStagePkgs(r.repoRoot, r.opts.pkg)
		if err != nil {
			return err
		}
		if corePkg != "" {
			if err := r.runCoreStage(corePkg); err != nil {
				return err
			}
		}
		if rootPkg != "" {
			return r.runRootStage(rootPkg)
		}
		return nil
	default:
		return validateStage(r.opts.stage)
	}
}

// resolveAllStagePkgs 在 --stage=all 配合定向 --pkg 时规范化并精确路由至含 .go 源码的模块（CI-2）。
func resolveAllStagePkgs(repoRoot, pkg string) (corePkg, rootPkg string, err error) {
	norm := strings.TrimSpace(filepath.ToSlash(pkg))
	if norm == "" || norm == "./..." || norm == "..." {
		return "./...", "./...", nil
	}
	if slices.Contains(strings.Split(norm, "/"), "..") {
		return "", "", fmt.Errorf("--pkg=%q 禁止包含路径穿越段 '..'", pkg)
	}
	if !strings.HasPrefix(norm, "./") && norm != "." {
		norm = "./" + strings.TrimPrefix(norm, "/")
	}
	if norm == "./core" || norm == "./core/..." || strings.HasPrefix(norm, "./core/") {
		sub := "." + strings.TrimPrefix(norm, "./core")
		if hasGoFiles(filepath.Join(repoRoot, "core", pkgDirRel(sub))) {
			return sub, "", nil
		}
		return "", "", fmt.Errorf("--pkg=%q 指向 core/ 但未找到 Go 源码目录", pkg)
	}
	rel := pkgDirRel(norm)
	if hasGoFiles(filepath.Join(repoRoot, "core", rel)) {
		corePkg = norm
	}
	if hasRootGoFiles(repoRoot) && hasGoFiles(filepath.Join(repoRoot, rel)) {
		rootPkg = norm
	}
	if corePkg == "" && rootPkg == "" {
		return "", "", fmt.Errorf("--stage=all 下的 --pkg=%q 在 core/ 与根模块中均未匹配到含 .go 文件的目录", pkg)
	}
	return corePkg, rootPkg, nil
}

func pkgDirRel(pkg string) string {
	s := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(pkg, "/..."), "..."), "./")
	if s == "." {
		return ""
	}
	return filepath.FromSlash(s)
}

func (r *verifyRunner) runXopsvetStage() error {
	xopsDir := filepath.Join(r.repoRoot, "tools", "xopsvet")
	if !hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet")) {
		fmt.Println("[verify] skip xopsvet: tools/xopsvet/cmd/xopsvet 尚无 Go 源码")
		return nil
	}
	vettool := vettoolPath(r.repoRoot)
	if err := os.MkdirAll(filepath.Dir(vettool), 0o755); err != nil {
		return err
	}
	fmt.Println("[verify] === Stage: xopsvet (GOWORK=off) ===")
	steps := []cmdStep{
		{"go", goTestArgs(r.opts.verbose, "./...")},
		{"go", []string{"build", "-o", vettool, "./cmd/xopsvet"}},
		{"go", []string{"vet", "-vettool=" + vettool, "./..."}},
	}
	if !r.opts.skipLint {
		steps = append(steps, cmdStep{"golangci-lint", golangciLintArgs})
	}
	if err := runSteps(xopsDir, buildEnv(true), steps); err != nil {
		return err
	}
	r.vettoolBuilt = true
	return nil
}

// ensureVettool 仅复用本次进程内新构建的 xopsvet 二进制，杜绝复用历史过期产物导致假绿（CI-1）。
func (r *verifyRunner) ensureVettool() (string, bool, error) {
	xopsDir := filepath.Join(r.repoRoot, "tools", "xopsvet")
	if !hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet")) {
		return "", false, nil
	}
	vettool := vettoolPath(r.repoRoot)
	if r.vettoolBuilt && pathExists(vettool) {
		return vettool, true, nil
	}
	if err := os.MkdirAll(filepath.Dir(vettool), 0o755); err != nil {
		return "", false, err
	}
	fmt.Printf("[verify] building xopsvet -> %s\n", vettool)
	if err := runCmd(xopsDir, buildEnv(true), "go", "build", "-o", vettool, "./cmd/xopsvet"); err != nil {
		return "", false, err
	}
	r.vettoolBuilt = true
	return vettool, true, nil
}

func (r *verifyRunner) runCoreStage(pkg string) error {
	dir := filepath.Join(r.repoRoot, "core")
	return r.runModuleStage(dir, "core (GOWORK=off)", pkg, true, hasGoFiles(dir), "core/ 尚无 Go 源码")
}

func (r *verifyRunner) runRootStage(pkg string) error {
	label := "root (go.work)"
	if r.opts.goworkOff {
		label = "root (GOWORK=off)"
	}
	return r.runModuleStage(r.repoRoot, label, pkg, r.opts.goworkOff, hasRootGoFiles(r.repoRoot), "根 CLI 模块（cmd/xops 与 internal/）尚无 Go 源码")
}

func (r *verifyRunner) runModuleStage(modDir, label, pkg string, goworkOff, present bool, skipMsg string) error {
	if !present {
		fmt.Println("[verify] skip:", skipMsg)
		return nil
	}
	vettool, hasVet, err := r.ensureVettool()
	if err != nil {
		return err
	}
	fmt.Printf("[verify] === Stage: %s, pkg=%s ===\n", label, pkg)
	steps := []cmdStep{{"go", []string{"build", "./..."}}}
	if hasVet {
		steps = append(steps, cmdStep{"go", []string{"vet", "-vettool=" + vettool, "./..."}})
	}
	if !r.opts.skipLint {
		steps = append(steps, cmdStep{"golangci-lint", golangciLintArgs})
	}
	return runSteps(modDir, buildEnv(goworkOff), append(steps, cmdStep{"go", goTestArgs(r.opts.verbose, pkg)}))
}

func (r *verifyRunner) runCrossStage() error {
	xopsDir, coreDir := filepath.Join(r.repoRoot, "tools", "xopsvet"), filepath.Join(r.repoRoot, "core")
	vettool, hasVet, err := r.ensureVettool()
	if err != nil {
		return err
	}
	fmt.Println("[verify] === Stage: cross (Windows & macOS cross-build, cross-vet & cross-lint, CGO_ENABLED=0) ===")
	for _, goos := range []string{"windows", "darwin"} {
		extra := []string{"GOOS=" + goos, "GOARCH=amd64", "CGO_ENABLED=0"}
		offEnv := buildEnv(true, extra...)
		for _, t := range []struct {
			on, vet, lint bool
			dir           string
			env           []string
		}{
			{hasGoFiles(filepath.Join(xopsDir, "cmd", "xopsvet")), false, false, xopsDir, offEnv},
			{hasGoFiles(coreDir), hasVet, !r.opts.skipLint, coreDir, offEnv},
			{hasRootGoFiles(r.repoRoot), hasVet, !r.opts.skipLint, r.repoRoot, buildEnv(r.opts.goworkOff, extra...)},
		} {
			if !t.on {
				continue
			}
			if err := runSteps(t.dir, t.env, crossTargetSteps(vettool, t.vet, t.lint)); err != nil {
				return err
			}
		}
	}
	return nil
}

// crossTargetSteps 构造跨平台目标模块的校验步骤：必跑编译，按需追加宿主机 xopsvet 跨平台静态检查与 golangci-lint。
func crossTargetSteps(vettool string, runVet, runLint bool) []cmdStep {
	steps := []cmdStep{{"go", []string{"build", "./..."}}}
	if runVet && vettool != "" {
		steps = append(steps, cmdStep{"go", []string{"vet", "-vettool=" + vettool, "./..."}})
	}
	if runLint {
		steps = append(steps, cmdStep{"golangci-lint", golangciLintArgs})
	}
	return steps
}

func (r *verifyRunner) runDSTStage() error {
	if !hasMatchingFiles(filepath.Join(r.repoRoot, "core", "internal", "pool"), "_test.go") {
		fmt.Println("[verify] skip dst: core/internal/pool 尚无 DST 测试")
		return nil
	}
	base := goTestArgs(r.opts.verbose, "./...")
	fmt.Printf("[verify] === Stage: dst (GOWORK=off, XOPS_DST_SEEDS=%s) ===\n", r.opts.dstSeeds)
	return runCmd(filepath.Join(r.repoRoot, "core"), buildEnv(true, "XOPS_DST_SEEDS="+r.opts.dstSeeds), "go", slices.Insert(base, len(base)-1, "-run", "^TestDST_")...)
}

func goTestArgs(verbose bool, pkg string) []string {
	if verbose {
		return []string{"test", "-v", "-race", "-shuffle=on", "-count=1", pkg}
	}
	return []string{"test", "-race", "-shuffle=on", "-count=1", pkg}
}

func vettoolPath(repoRoot string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(repoRoot, "bin", "xopsvet.exe")
	}
	return filepath.Join(repoRoot, "bin", "xopsvet")
}

func buildEnv(goworkOff bool, extra ...string) []string {
	return buildEnvFrom(os.Environ(), goworkOff, extra...)
}

func buildEnvFrom(base []string, goworkOff bool, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra)+1)
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || strings.EqualFold(k, "GOWORK") || slices.ContainsFunc(extra, func(e string) bool { ek, _, ok := strings.Cut(e, "="); return ok && strings.EqualFold(ek, k) }) {
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

func hasRootGoFiles(root string) bool {
	return hasGoFiles(filepath.Join(root, "cmd", "xops")) || hasGoFiles(filepath.Join(root, "internal"))
}
func hasGoFiles(dir string) bool { return hasMatchingFiles(dir, ".go") }
func pathExists(p string) bool   { _, err := os.Stat(p); return err == nil }

func hasMatchingFiles(dir, suffix string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && (d.Name() == "testdata" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func runInternalSelfTest(repoRoot string) error {
	rEnv := buildEnvFrom([]string{"PATH=/usr/bin", "GOWORK=off"}, false)
	cEnv := buildEnvFrom([]string{"PATH=/usr/bin", "gowork=/tmp/go.work"}, true, "GOOS=windows", "CGO_ENABLED=0")
	_, exErr := parseOptions([]string{"--stage=all", "extra-arg"})
	emOpt, emErr := parseOptions([]string{"--dst-seeds="})
	_, _, trErr := resolveAllStagePkgs(repoRoot, "../outside")
	c1, r1, e1 := resolveAllStagePkgs(repoRoot, "./core/conc/...")
	c2, r2, e2 := resolveAllStagePkgs(repoRoot, "conc")
	xsFull := crossTargetSteps("/tmp/xopsvet", true, true)
	xsNoLint := crossTargetSteps("/tmp/xopsvet", true, false)
	xsBuildOnly := crossTargetSteps("/tmp/xopsvet", false, false)
	for i, ok := range []bool{
		!hasReplaceDirective([]byte("module m\n// replace a => b\n")) && hasReplaceDirective([]byte("module m\nreplace a => ./a\n")) && hasReplaceDirective([]byte("module m\n\treplace (\n\t\ta => ./a\n\t)\n")),
		!slices.ContainsFunc(rEnv, func(kv string) bool { k, _, _ := strings.Cut(kv, "="); return strings.EqualFold(k, "GOWORK") }),
		slices.Contains(cEnv, "GOWORK=off") && slices.Contains(cEnv, "CGO_ENABLED=0"),
		exErr != nil, emErr == nil && emOpt.dstSeeds == "10000", trErr != nil,
		e1 == nil && c1 == "./conc/..." && r1 == "", e2 == nil && c2 == "./conc" && r2 == "",
		len(xsFull) == 3 && slices.Equal(xsFull[1].args, []string{"vet", "-vettool=/tmp/xopsvet", "./..."}) && xsFull[2].name == "golangci-lint",
		len(xsNoLint) == 2 && slices.Equal(xsNoLint[1].args, []string{"vet", "-vettool=/tmp/xopsvet", "./..."}),
		len(xsBuildOnly) == 1 && slices.Equal(xsBuildOnly[0].args, []string{"build", "./..."}),
	} {
		if !ok {
			return fmt.Errorf("内部自检 #%d 失败", i+1)
		}
	}
	return nil
}
