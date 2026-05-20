package host

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		val      string
		expected []string
		changed  bool
	}{
		{"append new item", []string{"a", "b"}, "c", []string{"a", "b", "c"}, true},
		{"append existing item", []string{"a", "b", "c"}, "b", []string{"a", "b", "c"}, false},
		{"append to empty slice", []string{}, "a", []string{"a"}, true},
		{"append empty item", []string{"a"}, "", []string{"a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, changed := appendUnique(tt.slice, tt.val)
			if changed != tt.changed {
				t.Errorf("expected changed %v, got %v", tt.changed, changed)
			}
			if !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("expected result %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestRunInventoryLoad_TemplateExport(t *testing.T) {
	// 创建临时文件路径作为导出的目标
	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "template.csv")

	// 1. 测试中文环境下的导出表头
	i18n.SetLang("zh")
	TemplateFile = tempFilePath // 设置全局变量
	err := RunInventoryLoad(nil, nil)
	if err != nil {
		t.Fatalf("RunInventoryLoad failed: %v", err)
	}

	contentZh, err := os.ReadFile(tempFilePath)
	if err != nil {
		t.Fatalf("failed to read template file: %v", err)
	}

	expectedZh := "主机,端口,别名,用户,密码,私钥,私钥密码\n"
	if string(contentZh) != expectedZh {
		t.Errorf("expected header %q, got %q", expectedZh, string(contentZh))
	}

	// 2. 测试英文环境下的导出表头
	i18n.SetLang("en")
	err = RunInventoryLoad(nil, nil)
	if err != nil {
		t.Fatalf("RunInventoryLoad failed: %v", err)
	}

	contentEn, err := os.ReadFile(tempFilePath)
	if err != nil {
		t.Fatalf("failed to read template file: %v", err)
	}

	expectedEn := "host,port,alias,user,password,key,keypass\n"
	if string(contentEn) != expectedEn {
		t.Errorf("expected header %q, got %q", expectedEn, string(contentEn))
	}
}
