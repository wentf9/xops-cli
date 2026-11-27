package cmdops

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

const maxPlaybookFileBytes int64 = 4 << 20

type playbookArgs struct {
	sub           string
	common        clikit.CommonFlags
	cliOpts       option.OptionLayer
	filePath      string
	symlinkPolicy pathalg.SymlinkPolicy
	targets       []string
	concurrency   int
	timeout       algebraic.Option[algebraic.Duration]
	extraVars     map[string]string
	scopedRoot    algebraic.Option[pathalg.LocalDir]
	dialect       algebraic.Option[execution.LaunchDialect]
	interpreter   execution.Interpreter
	loginMode     execution.LoginMode
}

// RunPlaybook 执行 `xops playbook`（别名 `play`）：支持 `validate`（纯离线 AST 校验，零引擎初始化）与 `run`。
func RunPlaybook(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, PlaybookHelpText())
		return clikit.ExitOK
	}
	parsed, err := parsePlaybookArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, PlaybookHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	raw, sourceName, err := rt.ReadLocalInput(ctx, parsed.filePath, parsed.symlinkPolicy, maxPlaybookFileBytes)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	pb, err := DecodePlaybookDocument(raw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 解析 Playbook %q 失败: %w", clikit.ErrUsage, sourceName, err))
	}
	if parsed.sub == "validate" {
		return renderPlaybookValidate(rt, pb, sourceName, jsonOut)
	}
	return executePlaybookRun(ctx, rt, parsed, pb, jsonOut)
}

func renderPlaybookValidate(rt *clikit.Runtime, pb playbook.Playbook, sourceName string, jsonOut bool) int {
	type view struct {
		OK      bool                `json:"ok"`
		Source  string              `json:"source"`
		Version uint32              `json:"version"`
		ID      playbook.PlaybookID `json:"id"`
		Name    string              `json:"name"`
		Steps   int                 `json:"steps"`
		Digest  security.Digest     `json:"digest"`
	}
	v := view{
		OK: true, Source: sourceName, Version: pb.Version(), ID: pb.ID(),
		Name: pb.Name(), Steps: pb.Steps().Len(), Digest: pb.Digest(),
	}
	return rt.WriteResult(jsonOut, v, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "playbook valid: id=%s name=%q version=%d steps=%d digest=%s\n",
			v.ID, v.Name, v.Version, v.Steps, v.Digest)
	})
}

func executePlaybookRun(ctx context.Context, rt *clikit.Runtime, parsed playbookArgs, pb playbook.Playbook, jsonOut bool) int {
	profOpt, err := buildPlaybookDefaultProfile(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireAutomationClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		targets, err := resolvePlaybookTargets(ctx, client, parsed.targets, parsed.cliOpts)
		if err != nil {
			return rt.Fail(clikit.ExitSSHError, jsonOut, err)
		}
		res, runErr := client.RunPlaybook(ctx, engine.PlaybookRequest{
			Playbook:         pb,
			Targets:          targets,
			CLIOptions:       parsed.cliOpts,
			DefaultProfile:   profOpt,
			ScopedSourceRoot: parsed.scopedRoot,
			Concurrency:      parsed.concurrency,
			Timeout:          parsed.timeout,
			ExtraVars:        parsed.extraVars,
		})
		return renderPlaybookRunResult(rt, res, runErr, jsonOut)
	})
}

func resolvePlaybookTargets(ctx context.Context, client clikit.AutomationClient, specs []string, cliOpts option.OptionLayer) ([]engine.ResolvedTarget, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make([]engine.ResolvedTarget, 0, len(specs))
	for _, spec := range specs {
		res, err := client.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: spec, CLIOptions: cliOpts})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

type playbookRunJSONEnvelope struct {
	OK        bool                     `json:"ok"`
	Error     string                   `json:"error,omitzero"`
	ErrorCode string                   `json:"error_code,omitzero"`
	Result    engine.PlaybookRunResult `json:"result"`
}

func renderPlaybookRunResult(rt *clikit.Runtime, res engine.PlaybookRunResult, runErr error, jsonOut bool) int {
	if !res.IsValid() {
		return rt.Fail(clikit.ExitGeneral, jsonOut, runErr)
	}
	rep := res.Report()
	code := clikit.ExitOK
	if runErr != nil || res.Aborted() || res.HasUnknownOutcome() ||
		rep.Status() == playbook.NodeStatusFailed || rep.Status() == playbook.NodeStatusAborted || rep.Status() == playbook.NodeStatusOutcomeUnknown {
		code = clikit.ExitGeneral
	}
	if jsonOut {
		env := playbookRunJSONEnvelope{OK: code == clikit.ExitOK, Result: res}
		if runErr != nil {
			env.Error = runErr.Error()
			env.ErrorCode = clikit.ClassifyErrorCode(runErr)
		}
		if err := clikit.WriteJSON(rt.Stdout, env); err != nil {
			rt.WriteErr("marshal json failed: " + err.Error())
			return clikit.ExitGeneral
		}
		return code
	}
	counts := rep.StepCounts()
	_, _ = fmt.Fprintf(rt.Stdout, "playbook %s status=%s duration=%s (succeeded=%d changed=%d skipped=%d failed=%d unknown=%d aborted=%d)\n",
		rep.PlaybookID(), rep.Status(), res.Duration(),
		counts.Succeeded, counts.Changed, counts.Skipped, counts.Failed, counts.Unknown, counts.Aborted)
	for _, nr := range rep.Nodes() {
		_, _ = fmt.Fprintf(rt.Stdout, "  node=%-20s status=%-15s duration=%s\n", nr.NodeID(), nr.Status(), nr.TotalDuration())
	}
	if res.HasUnknownOutcome() {
		rt.WriteErr("playbook contains OutcomeUnknown steps; inspect remote state before retrying")
	}
	if runErr != nil {
		rt.WriteErr(runErr.Error())
	}
	return code
}

// DecodePlaybookDocument 支持严格解码 JSON 或 YAML vNext v2 格式的 Playbook 文档，
// 最终统一收敛至 core/domain/playbook 的 json/v2 判别式校验器（拒绝未知字段、重复键与非 v2 版本）。
func DecodePlaybookDocument(raw []byte) (pb playbook.Playbook, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return pb, fmt.Errorf("playbook 输入为空")
	}
	if trimmed[0] == '[' {
		return pb, fmt.Errorf("playbook 顶层文档必须为对象而非数组")
	}
	if trimmed[0] == '{' {
		var decoded playbook.Playbook
		if uErr := jsonv2.Unmarshal(trimmed, &decoded); uErr != nil {
			return pb, uErr
		}
		return decoded, nil
	}
	var doc yaml.Node
	if yErr := yaml.Unmarshal(trimmed, &doc); yErr != nil {
		return pb, fmt.Errorf("YAML 解析失败: %w", yErr)
	}
	val, vErr := yamlNodeToJSONValue(&doc)
	if vErr != nil {
		return pb, vErr
	}
	jsonBytes, mErr := jsonv2.Marshal(val, jsonv2.Deterministic(true))
	if mErr != nil {
		return pb, fmt.Errorf("YAML 转规范 JSON 失败: %w", mErr)
	}
	var decoded playbook.Playbook
	if uErr := jsonv2.Unmarshal(jsonBytes, &decoded); uErr != nil {
		return pb, uErr
	}
	return decoded, nil
}

func yamlNodeToJSONValue(n *yaml.Node) (any, error) {
	if n == nil {
		return nil, fmt.Errorf("空 YAML 节点")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, fmt.Errorf("YAML 必须包含单一文档")
		}
		return yamlNodeToJSONValue(n.Content[0])
	case yaml.AliasNode:
		return nil, fmt.Errorf("playbook YAML 禁止使用别名引用")
	case yaml.MappingNode:
		return yamlMappingToMap(n)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			v, err := yamlNodeToJSONValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		if n.Tag == "!!timestamp" {
			return n.Value, nil
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, fmt.Errorf("YAML 标量解码失败: %w", err)
		}
		return v, nil
	default:
		return nil, fmt.Errorf("不支持的 YAML 节点类型 %d", n.Kind)
	}
}

func yamlMappingToMap(n *yaml.Node) (map[string]any, error) {
	if len(n.Content)%2 != 0 {
		return nil, fmt.Errorf("YAML 映射键值对不完整")
	}
	out := make(map[string]any, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		kNode, vNode := n.Content[i], n.Content[i+1]
		if kNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("YAML 映射键必须为标量字符串")
		}
		key := kNode.Value
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("YAML 存在重复键 %q", key)
		}
		val, err := yamlNodeToJSONValue(vNode)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	return out, nil
}

func parsePlaybookArgs(args []string) (playbookArgs, error) {
	out := playbookArgs{
		sub:           args[0],
		cliOpts:       option.UnsetOptionLayer(),
		symlinkPolicy: pathalg.SymlinkReject,
		extraVars:     map[string]string{},
	}
	if out.sub != "run" && out.sub != "validate" {
		return playbookArgs{}, fmt.Errorf("%w: playbook 子命令必须为 run 或 validate，实际=%q", clikit.ErrUsage, out.sub)
	}
	cur := clikit.NewFlagCursor(args[1:])
	for cur.HasNext() {
		if err := parsePlaybookToken(cur, &out); err != nil {
			return playbookArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	if err := out.cliOpts.Validate(); err != nil {
		return playbookArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", clikit.ErrUsage, err)
	}
	return out, nil
}

func parsePlaybookToken(cur *clikit.FlagCursor, out *playbookArgs) error {
	tok := cur.Peek()
	if tok == "-h" || tok == "--help" {
		out.common.ShowHelp = true
		return nil
	}
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		if out.filePath == "" {
			out.filePath = cur.Next()
			return nil
		}
		return fmt.Errorf("%w: playbook %s 多余位置参数 %q", clikit.ErrUsage, out.sub, tok)
	}
	return parsePlaybookFlag(cur, out)
}

func parsePlaybookFlag(cur *clikit.FlagCursor, out *playbookArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		return parsePlaybookLongFlag(cur, out)
	}
	tok := cur.Next()
	cluster := tok[1:]
	if cluster == "" {
		return nil
	}
	ch := cluster[0]
	if ch == 'h' {
		if len(cluster) > 1 {
			return fmt.Errorf("%w: playbook 未知短选项 -%s", clikit.ErrUsage, cluster)
		}
		out.common.ShowHelp = true
		return nil
	}
	if ok, err := clikit.ApplyCommonSSHShortOption(cur, ch, cluster[1:], &out.cliOpts, &out.common.ConfigFile); ok || err != nil {
		return err
	}
	r, _ := utf8.DecodeRuneInString(cluster)
	return fmt.Errorf("%w: playbook 未知短选项 -%c", clikit.ErrUsage, r)
}

func parsePlaybookLongFlag(cur *clikit.FlagCursor, out *playbookArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if name == "stdin" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		if err == nil && v {
			out.filePath = "-"
		}
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	return applyPlaybookLongValue(name, val, tok, out)
}

func applyPlaybookLongValue(name, val, rawTok string, out *playbookArgs) error {
	switch name {
	case "file":
		out.filePath = val
	case "target", "targets":
		out.targets = append(out.targets, clikit.SplitCSV(val)...)
	case "concurrency":
		v, err := clikit.ParsePositiveInt("--concurrency", val)
		out.concurrency = v
		return err
	case "timeout":
		d, err := clikit.ParsePositiveDuration("--timeout", val)
		if err == nil {
			out.timeout = algebraic.Some(d)
		}
		return err
	case "var":
		k, v, err := clikit.ParseKeyValue("--var", val)
		if err == nil {
			out.extraVars[k] = v
		}
		return err
	case "scoped-root":
		d, err := pathalg.ParseLocalDir(val)
		if err != nil {
			return fmt.Errorf("%w: --scoped-root 非法: %w", clikit.ErrUsage, err)
		}
		out.scopedRoot = algebraic.Some(d)
	case "symlink-policy":
		p, err := pathalg.ParseSymlinkPolicy(val)
		if err != nil {
			return fmt.Errorf("%w: --symlink-policy 非法: %w", clikit.ErrUsage, err)
		}
		out.symlinkPolicy = p
	case "dialect":
		d, err := execution.ParseLaunchDialect(val)
		if err != nil {
			return fmt.Errorf("%w: --dialect 非法: %w", clikit.ErrUsage, err)
		}
		out.dialect = algebraic.Some(d)
	case "interpreter":
		interp, err := execution.ParseInterpreter(val)
		if err != nil {
			return fmt.Errorf("%w: --interpreter 非法: %w", clikit.ErrUsage, err)
		}
		out.interpreter = interp
	case "login":
		lm, err := execution.ParseLoginMode(val)
		if err != nil {
			return fmt.Errorf("%w: --login 非法: %w", clikit.ErrUsage, err)
		}
		out.loginMode = lm
	default:
		return fmt.Errorf("%w: playbook 未知长选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}

func buildPlaybookDefaultProfile(parsed playbookArgs) (algebraic.Option[execution.LaunchProfile], error) {
	return clikit.BuildOptionalLaunchProfile(parsed.dialect, parsed.interpreter, parsed.loginMode)
}
