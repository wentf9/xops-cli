package playbook

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Load 从文件路径加载并解析 Playbook。
// 支持：
//   - 绝对路径或相对路径（带 .yaml/.yml 扩展名）
//   - ~/.xops/playbooks/<name> 名称查找（会自动补全 .yaml/.yml 扩展名）
func Load(path string, extraVars map[string]string) (*Playbook, error) {
	resolved, err := resolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("playbook not found %q: %w", path, err)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read playbook %q: %w", resolved, err)
	}

	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parse playbook %q: %w", resolved, err)
	}

	if err := pb.renderVars(extraVars); err != nil {
		return nil, fmt.Errorf("render vars in %q: %w", resolved, err)
	}

	if err := pb.Validate(); err != nil {
		return nil, fmt.Errorf("invalid playbook %q: %w", resolved, err)
	}

	return &pb, nil
}

// resolvePath 将用户提供的路径解析为实际可读的文件路径。
func resolvePath(path string) (string, error) {
	// 1. 直接尝试给定路径
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// 2. 尝试补全扩展名
	for _, ext := range []string{".yaml", ".yml"} {
		candidate := path + ext
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 3. 在 ~/.xops/playbooks/ 中按名称查找
	home, err := os.UserHomeDir()
	if err == nil {
		base := filepath.Join(home, ".xops", "playbooks", path)
		for _, ext := range []string{"", ".yaml", ".yml"} {
			candidate := base + ext
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}

	return "", os.ErrNotExist
}

// Validate 校验 Playbook 结构合法性。
func (p *Playbook) Validate() error {
	if len(p.Steps) == 0 {
		return fmt.Errorf("steps must not be empty")
	}

	if !p.Targets.hasAny() {
		return fmt.Errorf("targets must specify at least one of: tags, nodes, hosts")
	}

	for i, s := range p.Steps {
		if err := s.validate(); err != nil {
			return fmt.Errorf("step[%d] %q: %w", i, s.Name, err)
		}
	}

	switch p.Settings.OnError {
	case "", OnErrorStop, OnErrorContinue, OnErrorAbortAll:
		// valid
	default:
		return fmt.Errorf("settings.on_error must be one of: continue, stop, abort_all")
	}

	return nil
}

// hasAny 返回 Targets 是否至少指定了一种目标。
func (t *Targets) hasAny() bool {
	return len(t.Tags) > 0 || len(t.Nodes) > 0 || len(t.Hosts) > 0
}

// validate 校验单个步骤的合法性。
func (s *Step) validate() error {
	if s.Name == "" {
		return fmt.Errorf("name must not be empty")
	}

	n := s.countStepTypes()
	switch {
	case n == 0:
		return fmt.Errorf("must specify one of: shell, script, copy, ensure, template")
	case n > 1:
		return fmt.Errorf("must specify exactly one of: shell, script, copy, ensure, template")
	}

	if err := s.validateStepSpec(); err != nil {
		return err
	}
	if s.Retries < 0 {
		return fmt.Errorf("retries must be >= 0")
	}
	return nil
}

// countStepTypes 统计步骤中已设置的动作类型数量。
func (s *Step) countStepTypes() int {
	n := 0
	if s.Shell != "" {
		n++
	}
	if s.Script != "" {
		n++
	}
	if s.Copy != nil {
		n++
	}
	if s.Ensure != nil {
		n++
	}
	if s.Template != nil {
		n++
	}
	return n
}

// validateStepSpec 校验具体动作规格的字段完整性。
func (s *Step) validateStepSpec() error {
	if s.Copy != nil && (s.Copy.Src == "" || s.Copy.Dest == "") {
		return fmt.Errorf("copy requires both src and dest")
	}
	if s.Ensure != nil && (s.Ensure.Check == "" || s.Ensure.Action == "") {
		return fmt.Errorf("ensure requires both check and action")
	}
	if s.Template != nil && (s.Template.Src == "" || s.Template.Dest == "") {
		return fmt.Errorf("template requires both src and dest")
	}
	return nil
}

// renderVars 对 Playbook 中所有字符串字段执行 {{ .VarName }} 变量替换。
// extraVars 中的键值对会覆盖 Playbook.Vars 中的同名变量。
func (p *Playbook) renderVars(extraVars map[string]string) error {
	// 合并变量：Playbook.Vars 为基础，extraVars 覆盖
	vars := make(map[string]string, len(p.Vars)+len(extraVars))
	for k, v := range p.Vars {
		vars[k] = v
	}
	for k, v := range extraVars {
		vars[k] = v
	}

	if len(vars) == 0 {
		return nil
	}

	r := &varRenderer{vars: vars}
	for i := range p.Steps {
		if err := r.renderStep(&p.Steps[i]); err != nil {
			return err
		}
	}
	return nil
}

type varRenderer struct {
	vars map[string]string
}

func (r *varRenderer) render(s string) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	tmpl, err := template.New("").Option("missingkey=error").Parse(s)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r.vars); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (r *varRenderer) renderStep(s *Step) error {
	var err error

	if s.Shell, err = r.render(s.Shell); err != nil {
		return fmt.Errorf("shell: %w", err)
	}
	if s.Script, err = r.render(s.Script); err != nil {
		return fmt.Errorf("script: %w", err)
	}

	if s.Copy != nil {
		if s.Copy.Src, err = r.render(s.Copy.Src); err != nil {
			return fmt.Errorf("copy.src: %w", err)
		}
		if s.Copy.Dest, err = r.render(s.Copy.Dest); err != nil {
			return fmt.Errorf("copy.dest: %w", err)
		}
	}

	if s.Ensure != nil {
		if s.Ensure.Check, err = r.render(s.Ensure.Check); err != nil {
			return fmt.Errorf("ensure.check: %w", err)
		}
		if s.Ensure.Action, err = r.render(s.Ensure.Action); err != nil {
			return fmt.Errorf("ensure.action: %w", err)
		}
	}

	if s.Template != nil {
		if s.Template.Src, err = r.render(s.Template.Src); err != nil {
			return fmt.Errorf("template.src: %w", err)
		}
		if s.Template.Dest, err = r.render(s.Template.Dest); err != nil {
			return fmt.Errorf("template.dest: %w", err)
		}
	}

	return nil
}
