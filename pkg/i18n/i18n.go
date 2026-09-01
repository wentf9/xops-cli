package i18n

import (
	"embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

//go:embed locales/*.yaml
var localeFS embed.FS

var (
	bundle      *i18n.Bundle
	localizer   *i18n.Localizer
	curLang     string
	initialized atomic.Uint32
	mu          sync.Mutex
	pendingLang string
)

type messageLoaderFunc func(b *i18n.Bundle) error

func defaultMessageLoader(b *i18n.Bundle) error {
	var errs []error
	if _, err := b.LoadMessageFileFS(localeFS, "locales/active.zh.yaml"); err != nil {
		errs = append(errs, fmt.Errorf("load active.zh.yaml failed: %w", err))
	}
	if _, err := b.LoadMessageFileFS(localeFS, "locales/active.en.yaml"); err != nil {
		errs = append(errs, fmt.Errorf("load active.en.yaml failed: %w", err))
	}
	return errors.Join(errs...)
}

// Init 初始化 i18n，解析语言偏好并加载翻译文件。
// 传入空字符串时自动从环境变量检测。
func Init(lang string) error {
	return initWithLoader(lang, defaultMessageLoader)
}

func initWithLoader(lang string, loader messageLoaderFunc) error {
	mu.Lock()
	defer mu.Unlock()

	detected := detectLang(lang)

	newBundle := i18n.NewBundle(language.Chinese)
	newBundle.RegisterUnmarshalFunc("yaml", yaml.Unmarshal)

	if err := loader(newBundle); err != nil {
		// 加载失败时不发布未就绪的状态，不标记 initialized
		return err
	}

	newLocalizer := i18n.NewLocalizer(newBundle, detected)

	// 一次性原子发布就绪状态
	bundle = newBundle
	localizer = newLocalizer
	curLang = detected
	initialized.Store(1)

	return nil
}

// T 根据 messageID 返回当前语言的翻译文本。
// 找不到或未初始化时 fallback 到 messageID 本身。
func T(id string) string {
	if initialized.Load() == 0 {
		return id
	}

	mu.Lock()
	applyPendingLang()
	loc := localizer
	mu.Unlock()

	if loc == nil {
		return id
	}
	msg, err := loc.Localize(&i18n.LocalizeConfig{MessageID: id})
	if err != nil || msg == "" {
		return id
	}
	return msg
}

// Tf 带模板参数的翻译，data 为 map[string]any。
// 找不到或未初始化时 fallback 到 messageID 本身。
func Tf(id string, data map[string]any) string {
	if initialized.Load() == 0 {
		return id
	}

	mu.Lock()
	applyPendingLang()
	loc := localizer
	mu.Unlock()

	if loc == nil {
		return id
	}
	msg, err := loc.Localize(&i18n.LocalizeConfig{
		MessageID:    id,
		TemplateData: data,
	})
	if err != nil || msg == "" {
		return id
	}
	return msg
}

// Lang 返回当前生效的语言标签。
func Lang() string {
	mu.Lock()
	defer mu.Unlock()
	return curLang
}

// SetLang 切换语言并重建 localizer（用于 --lang flag 覆盖）。
func SetLang(lang string) {
	if lang == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	curLang = normalizeLang(lang)
	if bundle != nil {
		localizer = i18n.NewLocalizer(bundle, curLang)
	}
}

// SetPendingLang 设置待切换的语言（在 main 中提前调用）。
// 该函数用于在命令构造前设置语言，解决 --help 时 init() 先于语言设置的问题。
func SetPendingLang(lang string) {
	if lang != "" {
		mu.Lock()
		defer mu.Unlock()
		pendingLang = normalizeLang(lang)
	}
}

// applyPendingLang 应用待切换的语言
func applyPendingLang() {
	if pendingLang != "" && pendingLang != curLang {
		curLang = pendingLang
		if bundle != nil {
			localizer = i18n.NewLocalizer(bundle, curLang)
		}
	}
}

func detectLang(explicit string) string {
	if explicit != "" {
		return normalizeLang(explicit)
	}

	for _, key := range []string{"XOPS_LANG", "LANG", "LC_ALL"} {
		if val := os.Getenv(key); val != "" {
			return normalizeLang(val)
		}
	}

	return "zh"
}

func normalizeLang(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	// 去除 .UTF-8 等后缀
	if idx := strings.Index(raw, "."); idx > 0 {
		raw = raw[:idx]
	}
	switch {
	case strings.HasPrefix(raw, "zh"):
		return "zh"
	case strings.HasPrefix(raw, "en"):
		return "en"
	default:
		return "zh"
	}
}
