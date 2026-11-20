package host

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
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
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("init i18n zh failed: %v", err)
	}
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

func TestPass10_M1_LoadRejectsReservedOpenSSHAliases(t *testing.T) {
	dir := t.TempDir()
	repo, err := config.NewRepositoryWithoutOpenSSH(
		config.NewProviderWithoutOpenSSH(nil).Snapshot(),
		config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key")),
	)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	for _, badAlias := range []string{"openssh", "OPENSSH", "openssh:prod"} {
		_, err := prepareImport(repo, utils.HostInfo{
			Host:  "10.0.0.50",
			Port:  22,
			User:  "ops",
			Alias: badAlias,
		}, "imported")
		if err == nil {
			t.Errorf("prepareImport allowed reserved alias %q", badAlias)
		}
	}
}

func TestRound7_P2_9_HostCommandsRejectOpenSSHSelectorsWhileCSVPreserves(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"openssh:web", "OPENSSH:prod", "openssh:user@web", "  openssh:web  "} {
		if _, err := normalizeImportAddress(utils.HostInfo{Host: bad, Port: 22, User: "ops"}); err == nil {
			t.Errorf("normalizeImportAddress(%q) unexpectedly succeeded", bad)
		}
		var addAliases []string
		addAddr, addUser, addPort := bad, "", uint16(22)
		if err := applyAddTargetArgs(nil, &addAliases, &addAddr, &addUser, &addPort, false); err == nil {
			t.Errorf("applyAddTargetArgs(--address %q) unexpectedly succeeded", bad)
		}
		addAliases, addAddr, addUser, addPort = nil, "", "", 22
		if err := applyAddTargetArgs([]string{bad}, &addAliases, &addAddr, &addUser, &addPort, false); err == nil {
			t.Errorf("applyAddTargetArgs(arg %q) unexpectedly succeeded", bad)
		}
		editFlagsVal := &editFlags{address: bad, port: 22}
		if err := applyEditTargetArgs(nil, editFlagsVal, false); err == nil {
			t.Errorf("applyEditTargetArgs(--address %q) unexpectedly succeeded", bad)
		}
		editFlagsPos := &editFlags{port: 22}
		if err := applyEditTargetArgs([]string{bad}, editFlagsPos, false); err == nil {
			t.Errorf("applyEditTargetArgs(arg %q) unexpectedly succeeded", bad)
		}
	}
	var addAliases []string
	addAddr, addUser, addPort := "", "", uint16(22)
	if err := applyAddTargetArgs([]string{"user@openssh:web"}, &addAliases, &addAddr, &addUser, &addPort, false); err == nil {
		t.Errorf("applyAddTargetArgs(user@openssh:web) unexpectedly succeeded")
	}

	// Ensure utils.ReadCSVFile still permits openssh: rows for exec/scp batch inventory.
	csvPath := filepath.Join(t.TempDir(), "hosts.csv")
	if err := os.WriteFile(csvPath, []byte("host,port,alias,user\nopenssh:web,22,,ops\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rows, err := utils.ReadCSVFile(csvPath)
	if err != nil || len(rows) != 1 || rows[0].Host != "openssh:web" {
		t.Fatalf("utils.ReadCSVFile(openssh:web) = (%+v, %v), want preserved openssh:web row", rows, err)
	}
}
