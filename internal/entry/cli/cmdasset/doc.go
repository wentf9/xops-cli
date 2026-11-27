// Package cmdasset 实现 XOps v2 的资产目录、凭据库管理与统一配置导入命令族
// （`hosts` / `inventory` / `creds` / `vault` / `config import`）。
//
// 核心架构与安全不变量：
//   - 100% 零 v1 迁移/兼容代码：配置导入严格经 core/engine 的统一 FormatImporter / ImportBundle 扩展入口调度；
//   - 零明文口令入参：凭据库 init/unlock 与加密私钥 enroll-key 均通过 core/engine 的交互式
//     InteractionPort.PromptSecret 借用闭包执行，绝不在命令行参数或 JSON 输出中暴露任何明文；
//   - 删除资产或凭据遇反向引用 / 5 位置凭据引用拒绝时，经 engine.ExtractReferenceConflict 结构化呈现冲突详情；
//   - 全包 0 init()、0 可变包级 var、0 裸 go、0 os.Exit、0 internal/host/** 或 core/osfs 导入、0 //nolint:。
package cmdasset

import (
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func requireInventoryClient(runner clikit.SessionRunner) (clikit.InventoryClient, error) {
	c, ok := runner.(clikit.InventoryClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "InventoryClient"))
	}
	return c, nil
}

func requireVaultClient(runner clikit.SessionRunner) (clikit.VaultClient, error) {
	c, ok := runner.(clikit.VaultClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "VaultClient"))
	}
	return c, nil
}

func parseOptionalRevision(raw string) (algebraic.Option[engine.Revision], error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return algebraic.None[engine.Revision](), nil
	}
	rev, err := engine.ParseRevision(trimmed)
	if err != nil {
		return algebraic.None[engine.Revision](), i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--expected-revision"), i18n.BoundStr("value", raw))
	}
	return algebraic.Some(rev), nil
}

func parseTagsCSV(raw string, dst *[]inventory.Tag) error {
	for _, item := range clikit.SplitCSV(raw) {
		tag, err := inventory.ParseTag(item)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "tag"), i18n.BoundStr("value", item))
		}
		*dst = append(*dst, tag)
	}
	return nil
}

func parseAliasesCSV(raw string, dst *[]inventory.Alias) error {
	for _, item := range clikit.SplitCSV(raw) {
		a, err := inventory.ParseAlias(item)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "alias"), i18n.BoundStr("value", item))
		}
		*dst = append(*dst, a)
	}
	return nil
}

// newVaultSecretPrompt 构造携带规范英文兜底与结构化双语 TitleMessage/BodyMessage 的机密口令提示请求。
func newVaultSecretPrompt(titleID, bodyID domi18n.MessageID, subject string) (engine.SecretPromptRequest, error) {
	titleMsg := i18n.NewMessage(titleID)
	bodyMsg := i18n.NewMessage(bodyID)
	return engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title:        titleMsg.Canonical(),
		Prompt:       bodyMsg.Canonical(),
		Subject:      subject,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  algebraic.Some(bodyMsg),
	})
}
