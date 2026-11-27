package corecatalog

import (
	"slices"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog/common"
	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog/domain"
	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog/ports"
	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog/runtime"
	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog/usecase"
)

// Lookup 按纯字符串键路由查询 core/ 模块注册消息对应的规范英文兜底模板；未注册或空键一律返回空串。
func Lookup(id string) string {
	if id == "" {
		return ""
	}
	if text := common.Lookup(id); text != "" {
		return text
	}
	if text := domain.Lookup(id); text != "" {
		return text
	}
	if text := ports.Lookup(id); text != "" {
		return text
	}
	if text := runtime.Lookup(id); text != "" {
		return text
	}
	return usecase.Lookup(id)
}

// AllKeys 汇总 5 个域叶分片的全部核心消息键（严格按字典序升序排列、每次返回独立切片副本）。
func AllKeys() []string {
	cKeys := common.AllKeys()
	dKeys := domain.AllKeys()
	pKeys := ports.AllKeys()
	rKeys := runtime.AllKeys()
	uKeys := usecase.AllKeys()
	out := make([]string, 0, len(cKeys)+len(dKeys)+len(pKeys)+len(rKeys)+len(uKeys))
	out = append(out, cKeys...)
	out = append(out, dKeys...)
	out = append(out, pKeys...)
	out = append(out, rKeys...)
	out = append(out, uKeys...)
	slices.Sort(out)
	return out
}
