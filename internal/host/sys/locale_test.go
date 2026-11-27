package sys

import (
	"maps"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

// stubEnvPort 为 DetectLocale 提供纯内存确定性环境变量桩，零进程全局污染与零磁盘 I/O。
type stubEnvPort struct {
	vars map[string]string
}

func (s stubEnvPort) LookupEnv(key string) (string, bool) {
	v, ok := s.vars[key]
	return v, ok
}

func (s stubEnvPort) Environ() map[string]string {
	return maps.Clone(s.vars)
}

func (s stubEnvPort) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	return zeroVal[ports.LocalIdentityInfo](), ports.ErrInvalidArgument
}

// TestDetectLocalePriorityMatrix 验证环境变量优先级链、POSIX 阻断语义、空白回退与 OS 区域标签归一化。
func TestDetectLocalePriorityMatrix(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		osTag      string
		want       domi18n.Locale
		wantOSCall bool
	}{
		{
			name: "xops_lang_zh_overrides_all_env_and_os",
			env: map[string]string{
				"XOPS_LANG":   "zh",
				"LC_ALL":      "en_US.UTF-8",
				"LC_MESSAGES": "en_US.UTF-8",
				"LANG":        "en_US.UTF-8",
			},
			osTag:      "en-US",
			want:       domi18n.LocaleZh,
			wantOSCall: false,
		},
		{
			name: "xops_lang_en_overrides_all_zh_env_and_os",
			env: map[string]string{
				"XOPS_LANG":   "en",
				"LC_ALL":      "zh_CN.UTF-8",
				"LC_MESSAGES": "zh_CN.UTF-8",
				"LANG":        "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "xops_lang_unsupported_blocks_lower_zh",
			env: map[string]string{
				"XOPS_LANG": "fr_FR.UTF-8",
				"LANG":      "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "lc_all_C_overrides_lang_zh_and_os",
			env: map[string]string{
				"LC_ALL":      "C",
				"LC_MESSAGES": "zh_CN.UTF-8",
				"LANG":        "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "lc_all_C_utf8_overrides_lang_zh",
			env: map[string]string{
				"LC_ALL": "C.UTF-8",
				"LANG":   "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "lc_all_POSIX_overrides_lang_zh_and_os",
			env: map[string]string{
				"LC_ALL":      "POSIX",
				"LC_MESSAGES": "zh_CN.UTF-8",
				"LANG":        "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "lc_all_zh_overrides_lc_messages_and_lang_en",
			env: map[string]string{
				"LC_ALL":      "zh_CN.UTF-8",
				"LC_MESSAGES": "en_US.UTF-8",
				"LANG":        "en_US.UTF-8",
			},
			osTag:      "en-US",
			want:       domi18n.LocaleZh,
			wantOSCall: false,
		},
		{
			name: "lc_messages_zh_overrides_lang_en",
			env: map[string]string{
				"LC_MESSAGES": "zh_CN.UTF-8",
				"LANG":        "en_US.UTF-8",
			},
			osTag:      "en-US",
			want:       domi18n.LocaleZh,
			wantOSCall: false,
		},
		{
			name: "lc_messages_C_overrides_lang_zh",
			env: map[string]string{
				"LC_MESSAGES": "C",
				"LANG":        "zh_CN.UTF-8",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleEn,
			wantOSCall: false,
		},
		{
			name: "lang_zh_with_codeset_and_modifier",
			env: map[string]string{
				"LANG": "zh_CN.UTF-8@cjknarrow",
			},
			osTag:      "en-US",
			want:       domi18n.LocaleZh,
			wantOSCall: false,
		},
		{
			name: "gnu_language_list_explicitly_ignored",
			env: map[string]string{
				"LANGUAGE": "zh_CN:zh:en_US",
			},
			osTag:      "",
			want:       domi18n.LocaleEn,
			wantOSCall: true,
		},
		{
			name: "whitespace_only_higher_env_falls_through_to_lang",
			env: map[string]string{
				"XOPS_LANG":   "   \t ",
				"LC_ALL":      "\n ",
				"LC_MESSAGES": "  ",
				"LANG":        "zh_CN.UTF-8",
			},
			osTag:      "en-US",
			want:       domi18n.LocaleZh,
			wantOSCall: false,
		},
		{
			name: "whitespace_only_all_env_falls_through_to_os_tag",
			env: map[string]string{
				"XOPS_LANG":   " ",
				"LC_ALL":      "\t",
				"LC_MESSAGES": "  ",
				"LANG":        "   ",
			},
			osTag:      "zh-CN",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_zh_CN",
			env:        map[string]string{},
			osTag:      "zh-CN",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_zh_Hans_CN",
			env:        map[string]string{},
			osTag:      "zh-Hans-CN",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_zh_Hant_TW",
			env:        map[string]string{},
			osTag:      "zh-Hant-TW",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_zh_CN_stroke",
			env:        map[string]string{},
			osTag:      "zh-CN_stroke",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_zh_TW_radstr",
			env:        map[string]string{},
			osTag:      "zh-TW_radstr",
			want:       domi18n.LocaleZh,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_en_US",
			env:        map[string]string{},
			osTag:      "en-US",
			want:       domi18n.LocaleEn,
			wantOSCall: true,
		},
		{
			name:       "empty_env_windows_os_tag_fr_FR_fallback_en",
			env:        map[string]string{},
			osTag:      "fr-FR",
			want:       domi18n.LocaleEn,
			wantOSCall: true,
		},
		{
			name:       "empty_env_empty_os_tag_fallback_en",
			env:        map[string]string{},
			osTag:      "",
			want:       domi18n.LocaleEn,
			wantOSCall: true,
		},
		{
			name:       "empty_env_whitespace_os_tag_fallback_en",
			env:        map[string]string{},
			osTag:      "  \t ",
			want:       domi18n.LocaleEn,
			wantOSCall: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			osCalled := false
			got := detectLocaleWithOS(stubEnvPort{vars: tc.env}, func() string {
				osCalled = true
				return tc.osTag
			})
			if got != tc.want {
				t.Fatalf("detectLocaleWithOS = %v, 期望 %v", got, tc.want)
			}
			if osCalled != tc.wantOSCall {
				t.Fatalf("osTag 调用状态 = %v, 期望 %v", osCalled, tc.wantOSCall)
			}
		})
	}
}

// TestDetectLocaleFailClosedAndEdgeCases 验证 nil EnvPort、nil osTag 回调与真实 SystemEnv 衔接行为。
func TestDetectLocaleFailClosedAndEdgeCases(t *testing.T) {
	t.Run("nil_env_returns_en_without_os_call", func(t *testing.T) {
		if got := DetectLocale(nil); got != domi18n.LocaleEn {
			t.Fatalf("DetectLocale(nil) = %v, 期望 LocaleEn", got)
		}
		osCalled := false
		got := detectLocaleWithOS(nil, func() string {
			osCalled = true
			return "zh-CN"
		})
		if got != domi18n.LocaleEn {
			t.Fatalf("detectLocaleWithOS(nil, ...) = %v, 期望 LocaleEn", got)
		}
		if osCalled {
			t.Fatal("env 为 nil 时不得调用 osTag 回调")
		}
	})

	t.Run("nil_os_callback_falls_back_to_en", func(t *testing.T) {
		got := detectLocaleWithOS(stubEnvPort{vars: map[string]string{}}, nil)
		if got != domi18n.LocaleEn {
			t.Fatalf("detectLocaleWithOS(empty, nil) = %v, 期望 LocaleEn", got)
		}
	})

	t.Run("zero_system_env_returns_valid_locale_without_panic", func(t *testing.T) {
		var zeroEnv SystemEnv
		if got := DetectLocale(&zeroEnv); !got.IsValid() {
			t.Fatalf("DetectLocale(&zeroEnv) = %v, 期望有效 Locale", got)
		}
	})

	t.Run("system_env_respects_xops_lang", func(t *testing.T) {
		env := NewSystemEnv()
		t.Setenv("XOPS_LANG", "zh-CN")
		if got := DetectLocale(env); got != domi18n.LocaleZh {
			t.Fatalf("XOPS_LANG=zh-CN 时 DetectLocale = %v, 期望 LocaleZh", got)
		}
		t.Setenv("XOPS_LANG", "en-US")
		if got := DetectLocale(env); got != domi18n.LocaleEn {
			t.Fatalf("XOPS_LANG=en-US 时 DetectLocale = %v, 期望 LocaleEn", got)
		}
	})
}
