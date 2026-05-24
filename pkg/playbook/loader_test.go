package playbook_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/playbook"
)

// writeTempPlaybook 将内容写入临时文件并返回路径。
func writeTempPlaybook(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp playbook: %v", err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	yaml := `
name: test-playbook
targets:
  tags: [web]
steps:
  - name: check hostname
    shell: hostname
`
	path := writeTempPlaybook(t, yaml)
	pb, err := playbook.Load(path, nil)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if pb.Name != "test-playbook" {
		t.Errorf("Name = %q, want %q", pb.Name, "test-playbook")
	}
	if len(pb.Steps) != 1 {
		t.Errorf("Steps count = %d, want 1", len(pb.Steps))
	}
}

func TestLoad_VarRender(t *testing.T) {
	yaml := `
name: var-test
targets:
  tags: [web]
vars:
  app_dir: /opt/app
steps:
  - name: list app
    shell: "ls {{ .app_dir }}"
`
	path := writeTempPlaybook(t, yaml)

	// 测试：extraVars 覆盖 Playbook.Vars
	pb, err := playbook.Load(path, map[string]string{"app_dir": "/srv/myapp"})
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	got := pb.Steps[0].Shell
	want := "ls /srv/myapp"
	if got != want {
		t.Errorf("Shell = %q, want %q", got, want)
	}
}

func TestLoad_VarRenderFallback(t *testing.T) {
	yaml := `
name: var-fallback
targets:
  nodes: [web-1]
vars:
  env: prod
steps:
  - name: check env
    shell: "echo {{ .env }}"
`
	path := writeTempPlaybook(t, yaml)
	pb, err := playbook.Load(path, nil)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if pb.Steps[0].Shell != "echo prod" {
		t.Errorf("Shell = %q, want 'echo prod'", pb.Steps[0].Shell)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := playbook.Load("/nonexistent/path/to/playbook.yaml", nil)
	if err == nil {
		t.Fatal("Load() expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempPlaybook(t, "invalid: [yaml: content")
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for invalid YAML, got nil")
	}
}

func TestValidate_EmptySteps(t *testing.T) {
	yaml := `
name: empty-steps
targets:
  tags: [web]
steps: []
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for empty steps")
	}
}

func TestValidate_NoTargets(t *testing.T) {
	yaml := `
name: no-targets
targets: {}
steps:
  - name: test
    shell: echo hello
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for missing targets")
	}
}

func TestValidate_StepNoType(t *testing.T) {
	yaml := `
name: bad-step
targets:
  tags: [web]
steps:
  - name: missing-type
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for step with no type")
	}
}

func TestValidate_StepMultipleTypes(t *testing.T) {
	yaml := `
name: multi-type
targets:
  tags: [web]
steps:
  - name: bad
    shell: echo hello
    script: ./deploy.sh
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for step with multiple types")
	}
}

func TestValidate_CopyMissingSrc(t *testing.T) {
	yaml := `
name: bad-copy
targets:
  tags: [web]
steps:
  - name: copy missing src
    copy:
      dest: /tmp/file.txt
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for copy with missing src")
	}
}

func TestValidate_EnsureMissingAction(t *testing.T) {
	yaml := `
name: bad-ensure
targets:
  tags: [web]
steps:
  - name: ensure missing action
    ensure:
      check: "nginx -v"
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for ensure with missing action")
	}
}

func TestValidate_InvalidOnError(t *testing.T) {
	yaml := `
name: bad-onerror
targets:
  tags: [web]
settings:
  on_error: invalid_value
steps:
  - name: test
    shell: echo hello
`
	path := writeTempPlaybook(t, yaml)
	_, err := playbook.Load(path, nil)
	if err == nil {
		t.Fatal("Load() expected error for invalid on_error")
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	yaml := `
name: duration-test
targets:
  tags: [web]
settings:
  timeout: 30s
steps:
  - name: test
    shell: echo hello
    retry_delay: 5s
`
	path := writeTempPlaybook(t, yaml)
	pb, err := playbook.Load(path, nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if pb.Settings.Timeout.Seconds() != 30 {
		t.Errorf("Timeout = %v, want 30s", pb.Settings.Timeout)
	}
	if pb.Steps[0].RetryDelay.Seconds() != 5 {
		t.Errorf("RetryDelay = %v, want 5s", pb.Steps[0].RetryDelay)
	}
}

func TestLoad_NamedLookup(t *testing.T) {
	// 测试 ~/.xops/playbooks/ 名称查找
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot get home dir")
	}

	playbookDir := filepath.Join(home, ".xops", "playbooks")
	if err := os.MkdirAll(playbookDir, 0o755); err != nil {
		t.Skip("cannot create playbooks dir")
	}

	playbookPath := filepath.Join(playbookDir, "named-test.yaml")
	content := `
name: named-test
targets:
  tags: [web]
steps:
  - name: test
    shell: echo hello
`
	if err := os.WriteFile(playbookPath, []byte(content), 0o644); err != nil {
		t.Skip("cannot write named playbook")
	}
	defer func() { _ = os.Remove(playbookPath) }()

	// 使用名称查找（不加 .yaml 扩展名）
	pb, err := playbook.Load("named-test", nil)
	if err != nil {
		t.Fatalf("Load() by name error: %v", err)
	}
	if pb.Name != "named-test" {
		t.Errorf("Name = %q, want 'named-test'", pb.Name)
	}
}
