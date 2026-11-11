package cmd

import (
	"bytes"
	"fmt"
	"path"
	"strings"
)

type windowsAskpassEnv struct {
	getenv        func(string) string
	isRegularFile func(string) bool
	readHeader    func(string) ([]byte, error)
	absPath       func(string) string
}

// parseShebangLine parses a POSIX "#!" interpreter header line (matching kernel
// binfmt_script and /usr/bin/env semantics) from the beginning of a script file.
func parseShebangLine(header []byte) (interp string, args []string, ok bool) {
	if len(header) < 2 || header[0] != '#' || header[1] != '!' {
		return "", nil, false
	}
	line := header[2:]
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	trimmed := strings.TrimSpace(strings.TrimRight(string(line), "\r"))
	if trimmed == "" {
		return "", nil, false
	}

	var rest string
	if splitIdx := strings.IndexAny(trimmed, " \t"); splitIdx >= 0 {
		interp = trimmed[:splitIdx]
		rest = strings.TrimSpace(trimmed[splitIdx+1:])
	} else {
		interp = trimmed
	}

	base := path.Base(strings.ReplaceAll(interp, `\`, "/"))
	if strings.EqualFold(base, "env") || strings.EqualFold(base, "env.exe") {
		return parseEnvShebangArgs(rest)
	}
	if rest != "" {
		args = []string{rest}
	}
	return interp, args, true
}

func parseEnvShebangArgs(rest string) (interp string, args []string, ok bool) {
	fields := strings.Fields(rest)
	if len(fields) > 0 && fields[0] == "-S" {
		fields = fields[1:]
	}
	for len(fields) > 0 && strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "-") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", nil, false
	}
	if len(fields) > 1 {
		args = fields[1:]
	}
	return fields[0], args, true
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func winCleanSlashes(p string) string {
	return strings.ReplaceAll(p, "/", `\`)
}

func winBase(p string) string {
	cleaned := strings.TrimRight(winCleanSlashes(p), `\`)
	if cleaned == "" {
		return `\`
	}
	if idx := strings.LastIndexAny(cleaned, `\:`); idx >= 0 {
		return cleaned[idx+1:]
	}
	return cleaned
}

func winDir(p string) string {
	cleaned := strings.TrimRight(winCleanSlashes(p), `\`)
	idx := strings.LastIndexByte(cleaned, '\\')
	if idx < 0 {
		return "."
	}
	if idx == 2 && len(cleaned) >= 3 && isASCIIAlpha(cleaned[0]) && cleaned[1] == ':' {
		return cleaned[:3]
	}
	if idx == 0 {
		return `\`
	}
	return cleaned[:idx]
}

func winJoin(base, rel string) string {
	b := strings.TrimRight(winCleanSlashes(base), `\`)
	r := strings.TrimLeft(winCleanSlashes(rel), `\`)
	if b == "" {
		return r
	}
	if r == "" {
		return b
	}
	return b + `\` + r
}

func winExt(p string) string {
	base := winBase(p)
	idx := strings.LastIndexByte(base, '.')
	if idx < 0 {
		return ""
	}
	return base[idx:]
}

func isWindowsAbsPath(p string) bool {
	if len(p) >= 3 && isASCIIAlpha(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return len(p) >= 2 && ((p[0] == '\\' && p[1] == '\\') || (p[0] == '/' && p[1] == '/'))
}

func isBareCommandName(p string) bool {
	return !strings.ContainsAny(p, `/\:`)
}

func unquoteWindowsArg(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		return strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	return trimmed
}

func splitWindowsPathList(pathEnv string) []string {
	if pathEnv == "" {
		return nil
	}
	var dirs []string
	for entry := range strings.SplitSeq(pathEnv, ";") {
		dir := unquoteWindowsArg(entry)
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func parseWindowsPathExt(pathExtEnv string) []string {
	if strings.TrimSpace(pathExtEnv) == "" {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	var exts []string
	for entry := range strings.SplitSeq(strings.ToLower(pathExtEnv), ";") {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if e[0] != '.' {
			e = "." + e
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	return exts
}

// isWindowsWSLStubBash reports whether candidate points to a Windows System32/Sysnative
// or WindowsApps WSL bash.exe launcher stub rather than a Win32 POSIX shell (Git/MSYS2/Cygwin).
func isWindowsWSLStubBash(candidate, systemRoot, localAppData string) bool {
	norm := strings.ToLower(winCleanSlashes(candidate))
	if winBase(norm) != "bash.exe" {
		return false
	}
	if strings.HasSuffix(norm, `\microsoft\windowsapps\bash.exe`) ||
		strings.HasSuffix(norm, `\windows\system32\bash.exe`) ||
		strings.HasSuffix(norm, `\windows\sysnative\bash.exe`) ||
		strings.HasSuffix(norm, `\windows\syswow64\bash.exe`) {
		return true
	}
	if sysRoot := strings.ToLower(strings.TrimRight(winCleanSlashes(strings.TrimSpace(systemRoot)), `\`)); sysRoot != "" {
		for _, sub := range []string{`\system32\bash.exe`, `\sysnative\bash.exe`, `\syswow64\bash.exe`} {
			if norm == sysRoot+sub {
				return true
			}
		}
	}
	if appData := strings.ToLower(strings.TrimRight(winCleanSlashes(strings.TrimSpace(localAppData)), `\`)); appData != "" {
		if norm == appData+`\microsoft\windowsapps\bash.exe` {
			return true
		}
	}
	return false
}

func appendUniqueWinRoot(roots []string, seen map[string]struct{}, candidate string) []string {
	cleaned := strings.TrimRight(winCleanSlashes(strings.TrimSpace(candidate)), `\`)
	if len(cleaned) <= 3 {
		return roots
	}
	key := strings.ToLower(cleaned)
	if _, exists := seen[key]; exists {
		return roots
	}
	seen[key] = struct{}{}
	return append(roots, cleaned)
}

func discoverWindowsPosixRoots(env windowsAskpassEnv) []string {
	var roots []string
	seen := make(map[string]struct{})

	for _, dir := range splitWindowsPathList(env.getenv("PATH")) {
		if !isWindowsAbsPath(dir) {
			continue
		}
		gitCandidate := winJoin(dir, "git.exe")
		if env.isRegularFile(gitCandidate) {
			parent := winDir(dir)
			roots = appendUniqueWinRoot(roots, seen, parent)
			roots = appendUniqueWinRoot(roots, seen, winDir(parent))
		}
	}

	for _, envKey := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if base := strings.TrimSpace(env.getenv(envKey)); base != "" {
			roots = appendUniqueWinRoot(roots, seen, winJoin(base, "Git"))
		}
	}
	if localAppData := strings.TrimSpace(env.getenv("LOCALAPPDATA")); localAppData != "" {
		roots = appendUniqueWinRoot(roots, seen, winJoin(localAppData, `Programs\Git`))
	}
	sysDrive := strings.TrimSpace(env.getenv("SystemDrive"))
	if sysDrive == "" {
		sysDrive = "C:"
	}
	roots = appendUniqueWinRoot(roots, seen, sysDrive+`\msys64`)
	roots = appendUniqueWinRoot(roots, seen, sysDrive+`\cygwin64`)
	return roots
}

func findWindowsPosixShell(shellName string, env windowsAskpassEnv) (string, bool) {
	binName := "sh.exe"
	if strings.EqualFold(shellName, "bash") {
		binName = "bash.exe"
	}
	sysRoot := env.getenv("SystemRoot")
	localAppData := env.getenv("LOCALAPPDATA")

	for _, dir := range splitWindowsPathList(env.getenv("PATH")) {
		if !isWindowsAbsPath(dir) {
			continue
		}
		candidate := winJoin(dir, binName)
		if env.isRegularFile(candidate) && !isWindowsWSLStubBash(candidate, sysRoot, localAppData) {
			return candidate, true
		}
	}

	for _, root := range discoverWindowsPosixRoots(env) {
		for _, sub := range []string{`bin\` + binName, `usr\bin\` + binName} {
			candidate := winJoin(root, sub)
			if env.isRegularFile(candidate) && !isWindowsWSLStubBash(candidate, sysRoot, localAppData) {
				return candidate, true
			}
		}
	}
	return "", false
}

func resolveWindowsBinaryInPath(name string, env windowsAskpassEnv) (string, bool) {
	exts := parseWindowsPathExt(env.getenv("PATHEXT"))
	for _, dir := range splitWindowsPathList(env.getenv("PATH")) {
		if !isWindowsAbsPath(dir) {
			continue
		}
		if found, ok := matchWindowsPeOrBatch(winJoin(dir, name), exts, env.isRegularFile); ok {
			return found, true
		}
	}
	return "", false
}

func findWindowsPowerShell(preferred string, env windowsAskpassEnv) (string, bool) {
	if strings.EqualFold(preferred, "pwsh") {
		if p, ok := resolveWindowsBinaryInPath("pwsh", env); ok {
			return p, true
		}
	}
	if p, ok := resolveWindowsBinaryInPath("powershell", env); ok {
		return p, true
	}
	sysRoot := strings.TrimSpace(env.getenv("SystemRoot"))
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	builtinPS := winJoin(sysRoot, `System32\WindowsPowerShell\v1.0\powershell.exe`)
	if env.isRegularFile(builtinPS) {
		return builtinPS, true
	}
	if !strings.EqualFold(preferred, "pwsh") {
		if p, ok := resolveWindowsBinaryInPath("pwsh", env); ok {
			return p, true
		}
	}
	return "", false
}

func matchWindowsPeOrBatch(candidate string, exts []string, isRegularFile func(string) bool) (string, bool) {
	if winExt(candidate) != "" && isRegularFile(candidate) {
		return candidate, true
	}
	for _, ext := range exts {
		if f := candidate + ext; isRegularFile(f) {
			return f, true
		}
	}
	return "", false
}

func matchWindowsExecutableOrScript(candidate string, exts []string, isRegularFile func(string) bool) (string, bool) {
	if winExt(candidate) != "" {
		if isRegularFile(candidate) {
			return candidate, true
		}
		for _, ext := range exts {
			if f := candidate + ext; isRegularFile(f) {
				return f, true
			}
		}
		return "", false
	}
	for _, ext := range exts {
		if f := candidate + ext; isRegularFile(f) {
			return f, true
		}
	}
	if isRegularFile(candidate) {
		return candidate, true
	}
	return "", false
}

func explicitWindowsAskpassCandidates(prog string, env windowsAskpassEnv) []string {
	if strings.HasPrefix(prog, "/") && !strings.HasPrefix(prog, "//") {
		candidates := []string{winCleanSlashes(prog)}
		if len(prog) >= 3 && isASCIIAlpha(prog[1]) && prog[2] == '/' {
			candidates = append(candidates, strings.ToUpper(string(prog[1]))+":"+winCleanSlashes(prog[2:]))
		}
		for _, root := range discoverWindowsPosixRoots(env) {
			candidates = append(candidates, winJoin(root, prog[1:]))
		}
		return candidates
	}
	return []string{winCleanSlashes(prog)}
}

func resolveWindowsAskpassFile(askpassProg string, env windowsAskpassEnv) (string, bool) {
	prog := unquoteWindowsArg(askpassProg)
	if prog == "" {
		return "", false
	}
	exts := parseWindowsPathExt(env.getenv("PATHEXT"))
	if isBareCommandName(prog) {
		for _, dir := range splitWindowsPathList(env.getenv("PATH")) {
			if !isWindowsAbsPath(dir) {
				continue
			}
			if found, ok := matchWindowsExecutableOrScript(winJoin(dir, prog), exts, env.isRegularFile); ok {
				return found, true
			}
		}
		return "", false
	}

	for _, candidate := range explicitWindowsAskpassCandidates(prog, env) {
		if found, ok := matchWindowsExecutableOrScript(candidate, exts, env.isRegularFile); ok {
			if env.absPath != nil {
				found = env.absPath(found)
			}
			return found, true
		}
	}
	return "", false
}

func resolveWindowsShebangInterpreter(interp string, shebangArgs []string, targetPath, prompt string, env windowsAskpassEnv) (string, []string, error) {
	interpBase := strings.ToLower(winBase(interp))
	interpName := strings.TrimSuffix(interpBase, ".exe")

	switch interpName {
	case "sh", "ash", "dash":
		shExe, ok := findWindowsPosixShell("sh", env)
		if !ok {
			return "", nil, fmt.Errorf("posix sh interpreter not found for askpass script %q", targetPath)
		}
		return shExe, append(append([]string{}, shebangArgs...), targetPath, prompt), nil
	case "bash":
		bashExe, ok := findWindowsPosixShell("bash", env)
		if !ok {
			return "", nil, fmt.Errorf("bash interpreter not found for askpass script %q", targetPath)
		}
		return bashExe, append(append([]string{}, shebangArgs...), targetPath, prompt), nil
	case "pwsh", "powershell":
		psExe, ok := findWindowsPowerShell(interpName, env)
		if !ok {
			return "", nil, fmt.Errorf("powershell interpreter not found for askpass script %q", targetPath)
		}
		if len(shebangArgs) == 0 {
			return psExe, []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", targetPath, prompt}, nil
		}
		return psExe, append(append([]string{}, shebangArgs...), targetPath, prompt), nil
	default:
		if !isBareCommandName(interp) && isWindowsAbsPath(interp) {
			exts := parseWindowsPathExt(env.getenv("PATHEXT"))
			if found, ok := matchWindowsPeOrBatch(winCleanSlashes(interp), exts, env.isRegularFile); ok {
				return found, append(append([]string{}, shebangArgs...), targetPath, prompt), nil
			}
		}
		if found, ok := resolveWindowsBinaryInPath(interpName, env); ok {
			return found, append(append([]string{}, shebangArgs...), targetPath, prompt), nil
		}
		return "", nil, fmt.Errorf("interpreter %q not found for askpass script %q", interp, targetPath)
	}
}

func planWindowsAskpassCommand(askpassProg, prompt string, env windowsAskpassEnv) (string, []string, error) {
	targetPath, ok := resolveWindowsAskpassFile(askpassProg, env)
	if !ok {
		return "", nil, fmt.Errorf("askpass program not found: %s", askpassProg)
	}
	header, err := env.readHeader(targetPath)
	if err != nil {
		return "", nil, fmt.Errorf("read askpass header %q: %w", targetPath, err)
	}
	// Native Win32 PE executable ("MZ" header).
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return targetPath, []string{prompt}, nil
	}
	// Script with "#!" shebang (such as #!/bin/sh, #!/usr/bin/env bash, git-gui--askpass).
	if interp, shebangArgs, hasShebang := parseShebangLine(header); hasShebang {
		return resolveWindowsShebangInterpreter(interp, shebangArgs, targetPath, prompt, env)
	}

	switch strings.ToLower(winExt(targetPath)) {
	case ".bat", ".cmd":
		return targetPath, []string{prompt}, nil
	case ".sh":
		shExe, found := findWindowsPosixShell("sh", env)
		if !found {
			return "", nil, fmt.Errorf("posix sh interpreter not found for askpass script %q", targetPath)
		}
		return shExe, []string{targetPath, prompt}, nil
	case ".ps1":
		psExe, found := findWindowsPowerShell("", env)
		if !found {
			return "", nil, fmt.Errorf("powershell interpreter not found for askpass script %q", targetPath)
		}
		return psExe, []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", targetPath, prompt}, nil
	default:
		return "", nil, fmt.Errorf("unsupported askpass file format on Windows: %s", targetPath)
	}
}

func findWindowsSystemAskpass(env windowsAskpassEnv) string {
	if found, ok := resolveWindowsAskpassFile("ssh-askpass", env); ok {
		return found
	}
	for _, root := range discoverWindowsPosixRoots(env) {
		for _, rel := range []string{
			`mingw64\libexec\git-core\git-gui--askpass.exe`,
			`mingw64\libexec\git-core\git-gui--askpass`,
			`mingw32\libexec\git-core\git-gui--askpass.exe`,
			`mingw32\libexec\git-core\git-gui--askpass`,
			`usr\lib\ssh\ssh-askpass.exe`,
			`usr\lib\ssh\ssh-askpass`,
		} {
			candidate := winJoin(root, rel)
			if env.isRegularFile(candidate) {
				return candidate
			}
		}
	}
	for _, envKey := range []string{"ProgramFiles", "SystemRoot"} {
		base := strings.TrimSpace(env.getenv(envKey))
		if base == "" {
			continue
		}
		sub := `OpenSSH\ssh-askpass.exe`
		if strings.EqualFold(envKey, "SystemRoot") {
			sub = `System32\OpenSSH\ssh-askpass.exe`
		}
		candidate := winJoin(base, sub)
		if env.isRegularFile(candidate) {
			return candidate
		}
	}
	return ""
}
