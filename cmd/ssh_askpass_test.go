package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseShebangLine(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantInterp string
		wantArgs   []string
		wantOK     bool
	}{
		{
			name:       "standard_sh",
			header:     "#!/bin/sh\necho yes\n",
			wantInterp: "/bin/sh",
			wantOK:     true,
		},
		{
			name:       "crlf_sh_with_flag",
			header:     "#! /bin/sh -e \r\necho yes\r\n",
			wantInterp: "/bin/sh",
			wantArgs:   []string{"-e"},
			wantOK:     true,
		},
		{
			name:       "env_bash",
			header:     "#!/usr/bin/env bash\necho yes\n",
			wantInterp: "bash",
			wantOK:     true,
		},
		{
			name:       "env_split_string",
			header:     "#!/usr/bin/env -S FOO=1 bash -e\necho yes\n",
			wantInterp: "bash",
			wantArgs:   []string{"-e"},
			wantOK:     true,
		},
		{
			name:   "pe_binary_header",
			header: "MZ\x90\x00",
			wantOK: false,
		},
		{
			name:   "batch_script",
			header: "@echo off\r\necho yes\r\n",
			wantOK: false,
		},
		{
			name:   "empty_shebang",
			header: "#!  \r\n",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			interp, args, ok := parseShebangLine([]byte(tc.header))
			if ok != tc.wantOK {
				t.Fatalf("parseShebangLine(%q) ok = %v, want %v", tc.header, ok, tc.wantOK)
			}
			if interp != tc.wantInterp {
				t.Fatalf("parseShebangLine(%q) interp = %q, want %q", tc.header, interp, tc.wantInterp)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("parseShebangLine(%q) args = %v, want %v", tc.header, args, tc.wantArgs)
			}
		})
	}
}

func TestAskpassCommandEnv_CaseInsensitiveOverride(t *testing.T) {
	base := []string{
		"=C:=C:\\Users\\runner",
		"PATH=C:\\Windows\\System32",
		"ssh_askpass_prompt=none",
		"SSH_ASKPASS_PROMPT=other",
	}
	got := askpassCommandEnv(base)
	var promptEntries []string
	for _, kv := range got {
		if strings.HasPrefix(strings.ToUpper(kv), "SSH_ASKPASS_PROMPT=") {
			promptEntries = append(promptEntries, kv)
		}
	}
	if len(promptEntries) != 1 || promptEntries[0] != "SSH_ASKPASS_PROMPT=confirm" {
		t.Fatalf("expected single SSH_ASKPASS_PROMPT=confirm entry, got %v (full=%v)", promptEntries, got)
	}
}

type fakeWinFS struct {
	env   map[string]string
	files map[string]string
}

func (f *fakeWinFS) askpassEnv() windowsAskpassEnv {
	normKey := func(p string) string {
		return strings.ToLower(winCleanSlashes(p))
	}
	normalizedFiles := make(map[string]string, len(f.files))
	for k, v := range f.files {
		normalizedFiles[normKey(k)] = v
	}
	return windowsAskpassEnv{
		getenv: func(key string) string {
			for k, v := range f.env {
				if strings.EqualFold(k, key) {
					return v
				}
			}
			return ""
		},
		isRegularFile: func(p string) bool {
			_, ok := normalizedFiles[normKey(p)]
			return ok
		},
		readHeader: func(p string) ([]byte, error) {
			content, ok := normalizedFiles[normKey(p)]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		},
		absPath: winCleanSlashes,
	}
}

func newTestWindowsAskpassEnv() windowsAskpassEnv {
	fs := &fakeWinFS{
		env: map[string]string{
			"PATH":         `.;C:\Windows\System32;C:\Users\runner\AppData\Local\Microsoft\WindowsApps;C:\Program Files\Git\cmd`,
			"PATHEXT":      ".COM;.EXE;.BAT;.CMD",
			"SystemRoot":   `C:\Windows`,
			"ProgramFiles": `C:\Program Files`,
			"LOCALAPPDATA": `C:\Users\runner\AppData\Local`,
		},
		files: map[string]string{
			`C:\Windows\System32\bash.exe`:                                       "MZ-wsl-stub",
			`C:\Users\runner\AppData\Local\Microsoft\WindowsApps\bash.exe`:       "MZ-store-wsl-stub",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`:          "MZ-powershell",
			`C:\Program Files\Git\cmd\git.exe`:                                   "MZ-git",
			`C:\Program Files\Git\bin\sh.exe`:                                    "MZ-git-sh",
			`C:\Program Files\Git\bin\bash.exe`:                                  "MZ-git-bash",
			`C:\Program Files\Git\usr\lib\ssh\ssh-askpass`:                       "#!/bin/sh\necho yes\n",
			`C:\Program Files\Git\mingw64\libexec\git-core\git-gui--askpass`:     "#!/bin/sh\nexec wish\n",
			`C:\Program Files\Git\mingw64\libexec\git-core\git-gui--askpass.exe`: "MZ-gui-askpass",
			`C:\Users\runner\Temp\approve.sh`:                                    "#!/bin/sh\nif [ \"$SSH_ASKPASS_PROMPT\" != \"confirm\" ]; then exit 2; fi\necho yes\n",
			`C:\Users\runner\Temp\env-bash.sh`:                                   "#!/usr/bin/env bash\necho yes\n",
			`C:\Users\alice\bin\my-askpass`:                                      "#!/bin/sh -e\necho yes\n",
			`C:\Users\runner\Temp\approve.bat`:                                   "@echo off\r\necho yes\r\n",
			`C:\Users\runner\Temp\approve.ps1`:                                   "Write-Output 'yes'\r\n",
			`C:\Users\runner\Temp\native-askpass.exe`:                            "MZ-native",
			`C:\Users\runner\Temp\plain.txt`:                                     "not executable",
			`.\evil-cwd-askpass.exe`:                                             "MZ-evil",
		},
	}
	return fs.askpassEnv()
}

func TestPlanWindowsAskpassCommand(t *testing.T) {
	const prompt = "Allow connection sharing new session on this master? (yes/no) "
	env := newTestWindowsAskpassEnv()

	tests := []struct {
		name     string
		prog     string
		wantExe  string
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "sh_script_discovers_git_for_windows_sh",
			prog:     `C:\Users\runner\Temp\approve.sh`,
			wantExe:  `C:\Program Files\Git\bin\sh.exe`,
			wantArgs: []string{`C:\Users\runner\Temp\approve.sh`, prompt},
		},
		{
			name:     "env_bash_skips_wsl_stubs",
			prog:     `C:\Users\runner\Temp\env-bash.sh`,
			wantExe:  `C:\Program Files\Git\bin\bash.exe`,
			wantArgs: []string{`C:\Users\runner\Temp\env-bash.sh`, prompt},
		},
		{
			name:     "msys_drive_path_and_extensionless_shebang",
			prog:     `/c/Users/alice/bin/my-askpass`,
			wantExe:  `C:\Program Files\Git\bin\sh.exe`,
			wantArgs: []string{"-e", `C:\Users\alice\bin\my-askpass`, prompt},
		},
		{
			name:     "msys_root_path_and_extensionless_git_ssh_askpass",
			prog:     `/usr/lib/ssh/ssh-askpass`,
			wantExe:  `C:\Program Files\Git\bin\sh.exe`,
			wantArgs: []string{`C:\Program Files\Git\usr\lib\ssh\ssh-askpass`, prompt},
		},
		{
			name:     "extensionless_prefers_pathext_exe_sibling",
			prog:     `C:\Program Files\Git\mingw64\libexec\git-core\git-gui--askpass`,
			wantExe:  `C:\Program Files\Git\mingw64\libexec\git-core\git-gui--askpass.exe`,
			wantArgs: []string{prompt},
		},
		{
			name:     "quoted_batch_script",
			prog:     `"C:\Users\runner\Temp\approve.bat"`,
			wantExe:  `C:\Users\runner\Temp\approve.bat`,
			wantArgs: []string{prompt},
		},
		{
			name:     "powershell_script",
			prog:     `C:\Users\runner\Temp\approve.ps1`,
			wantExe:  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			wantArgs: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", `C:\Users\runner\Temp\approve.ps1`, prompt},
		},
		{
			name:     "native_pe_executable",
			prog:     `C:\Users\runner\Temp\native-askpass.exe`,
			wantExe:  `C:\Users\runner\Temp\native-askpass.exe`,
			wantArgs: []string{prompt},
		},
		{
			name:    "rejects_relative_cwd_bare_lookup",
			prog:    `evil-cwd-askpass`,
			wantErr: true,
		},
		{
			name:    "rejects_unknown_non_executable_file",
			prog:    `C:\Users\runner\Temp\plain.txt`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exe, args, err := planWindowsAskpassCommand(tc.prog, prompt, env)
			if (err != nil) != tc.wantErr {
				t.Fatalf("planWindowsAskpassCommand(%q) err = %v, wantErr %v", tc.prog, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if exe != tc.wantExe {
				t.Fatalf("planWindowsAskpassCommand(%q) exe = %q, want %q", tc.prog, exe, tc.wantExe)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("planWindowsAskpassCommand(%q) args = %v, want %v", tc.prog, args, tc.wantArgs)
			}
		})
	}

	if got := findWindowsSystemAskpass(env); got != `C:\Program Files\Git\mingw64\libexec\git-core\git-gui--askpass.exe` {
		t.Fatalf("findWindowsSystemAskpass = %q", got)
	}
}

func TestConfirmSessionWithAskpass_NativeScripts(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	handler := newCLIInteractionHandlerWithStreams(strings.NewReader("yes\n"), os.Stderr)
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	batApprove := filepath.Join(dir, "approve.bat")
	if err := os.WriteFile(batApprove, []byte("@echo off\r\nif not \"%SSH_ASKPASS_PROMPT%\"==\"confirm\" exit /b 2\r\necho yes\r\n"), 0o700); err != nil {
		t.Fatalf("write approve.bat: %v", err)
	}
	t.Setenv("SSH_ASKPASS", batApprove)
	if ok, err := handler.ConfirmSession(ctx, "new session"); err != nil || !ok {
		t.Fatalf("expected .bat askpass approval, got ok=%v err=%v", ok, err)
	}

	extlessApprove := filepath.Join(dir, "custom-ssh-askpass")
	if err := os.WriteFile(extlessApprove, []byte("#!/bin/sh\nif [ \"$SSH_ASKPASS_PROMPT\" != \"confirm\" ]; then exit 2; fi\necho yes\n"), 0o700); err != nil {
		t.Fatalf("write extensionless askpass: %v", err)
	}
	t.Setenv("SSH_ASKPASS", extlessApprove)
	if ok, err := handler.ConfirmSession(ctx, "new session"); err != nil || !ok {
		t.Fatalf("expected extensionless #!/bin/sh askpass approval on Windows, got ok=%v err=%v", ok, err)
	}

	psApprove := filepath.Join(dir, "approve.ps1")
	if err := os.WriteFile(psApprove, []byte("if ($env:SSH_ASKPASS_PROMPT -ne 'confirm') { exit 2 }\r\nWrite-Output 'yes'\r\n"), 0o700); err != nil {
		t.Fatalf("write approve.ps1: %v", err)
	}
	t.Setenv("SSH_ASKPASS", psApprove)
	if ok, err := handler.ConfirmSession(ctx, "new session"); err != nil || !ok {
		t.Fatalf("expected .ps1 askpass approval on Windows, got ok=%v err=%v", ok, err)
	}
}
