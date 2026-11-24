package pathalg_test

import (
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// TestExternalOpaqueAndJSONv2Contract 验证外部包经导出构造器使用全部 pathalg 不透明类型并支持 json/v2 确定性往返。
func TestExternalOpaqueAndJSONv2Contract(t *testing.T) {
	rp, err := pathalg.ParseAbsRemotePath("/etc//ssh/sshd_config")
	if err != nil {
		t.Fatalf("ParseAbsRemotePath 失败: %v", err)
	}
	rn, ok := rp.Base()
	if !ok || rn.String() != "sshd_config" {
		t.Fatalf("RemotePath.Base = (%q, %v)", rn.String(), ok)
	}
	dest, err := pathalg.ParseLocalRootedDest("backups/sshd_config")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest 失败: %v", err)
	}
	dir, err := pathalg.ParseLocalDir(`c:\Users\alice\.xops`)
	if err != nil {
		t.Fatalf("ParseLocalDir 失败: %v", err)
	}
	src, err := pathalg.ParseLocalSourcePath(`D:\Temp\bundle.tgz`)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath 失败: %v", err)
	}

	type transferRecord struct {
		Remote  pathalg.RemotePath      `json:"remote"`
		Name    pathalg.RemoteName      `json:"name"`
		Dest    pathalg.LocalRootedDest `json:"dest"`
		RootDir pathalg.LocalDir        `json:"root_dir"`
		Source  pathalg.LocalSourcePath `json:"source"`
		Policy  pathalg.SymlinkPolicy   `json:"symlink_policy"`
	}
	rec := transferRecord{
		Remote:  rp,
		Name:    rn,
		Dest:    dest,
		RootDir: dir,
		Source:  src,
		Policy:  pathalg.SymlinkContainedRelative,
	}

	raw, err := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal 失败: %v", err)
	}
	wantJSON := `{"remote":"/etc/ssh/sshd_config","name":"sshd_config","dest":"backups/sshd_config","root_dir":"C:/Users/alice/.xops","source":"D:/Temp/bundle.tgz","symlink_policy":"contained_relative"}`
	if string(raw) != wantJSON {
		t.Fatalf("确定性 JSON 输出不一致:\ngot:  %s\nwant: %s", raw, wantJSON)
	}

	var decoded transferRecord
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("jsonv2.Unmarshal 失败: %v", err)
	}
	if !decoded.Remote.Equal(rp) || !decoded.Name.Equal(rn) || !decoded.Dest.Equal(dest) ||
		!decoded.RootDir.Equal(dir) || !decoded.Source.Equal(src) || decoded.Policy != pathalg.SymlinkContainedRelative {
		t.Fatalf("jsonv2 往返值不相等: %+v", decoded)
	}
}
