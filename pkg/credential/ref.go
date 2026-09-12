package credential

import (
	"fmt"
	"strings"
	"time"
)

// Kind 标识凭据的种类。
type Kind string

const (
	// KindLoginPassword 标识 SSH 登录密码。
	KindLoginPassword Kind = "login_password"
	// KindPassphrase 标识 SSH 私钥密码短语。
	KindPassphrase Kind = "passphrase"
	// KindPrivilegePassword 标识提权密码（sudo 或 su）。
	KindPrivilegePassword Kind = "privilege_password"
)

// Validate 验证 Kind 是否合法。
func (k Kind) Validate() error {
	switch k {
	case KindLoginPassword, KindPassphrase, KindPrivilegePassword:
		return nil
	default:
		return fmt.Errorf("%w: unknown credential kind %q", ErrInvalidRef, string(k))
	}
}

// Ref 定义凭据在外部凭据存储中的引用。
// 引用由 StoreID 和不可变的 ItemID 组成。
type Ref struct {
	StoreID string `yaml:"store_id" json:"storeID"`
	ItemID  string `yaml:"item_id" json:"itemID"`
}

// CredentialRef 是 Ref 的别名，与设计文档中的命名保持一致。
type CredentialRef = Ref

// IsEmpty 检查引用是否为空（StoreID 和 ItemID 均为空）。
func (r Ref) IsEmpty() bool {
	return r.StoreID == "" && r.ItemID == ""
}

// IsComplete 检查引用是否完整（StoreID 和 ItemID 均非空）。
func (r Ref) IsComplete() bool {
	return r.StoreID != "" && r.ItemID != ""
}

// Validate 验证引用的完整性和合法性。
// 空引用被视作合法（表示未配置引用）。
// 引用若非空，必须保证 StoreID 与 ItemID 均非空，且不包含危险路径或注入字符。
func (r Ref) Validate() error {
	if r.IsEmpty() {
		return nil
	}
	if (r.StoreID == "") != (r.ItemID == "") {
		return fmt.Errorf("%w: storeID and itemID must both be empty or non-empty", ErrInvalidRef)
	}
	if err := validateRefIdentifier("storeID", r.StoreID); err != nil {
		return err
	}
	if err := validateRefIdentifier("itemID", r.ItemID); err != nil {
		return err
	}
	return nil
}

func validateRefIdentifier(field, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("%w: %s cannot be blank", ErrInvalidRef, field)
	}
	if strings.ContainsAny(val, "/\\ \t\r\n\x00") {
		return fmt.Errorf("%w: %s contains invalid characters", ErrInvalidRef, field)
	}
	return nil
}

// String 返回引用的可读非敏感标识（storeID/itemID）。空引用返回空字符串。
func (r Ref) String() string {
	if r.IsEmpty() {
		return ""
	}
	return r.StoreID + "/" + r.ItemID
}

// Clone 返回引用的深拷贝指针。如果接收者为 nil 则返回 nil。
func (r *Ref) Clone() *Ref {
	if r == nil {
		return nil
	}
	return &Ref{
		StoreID: r.StoreID,
		ItemID:  r.ItemID,
	}
}

// Secret 包含从凭据存储解析的机密字节和可选的过期时间。
type Secret struct {
	Value     []byte     `json:"-"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// NewSecret 创建一个没有明确过期时间的机密对象。
func NewSecret(val []byte) Secret {
	var copied []byte
	if val != nil {
		copied = make([]byte, len(val))
		copy(copied, val)
	}
	return Secret{
		Value: copied,
	}
}

// NewSecretWithExpiry 创建一个带有过期时间的机密对象。
func NewSecretWithExpiry(val []byte, expiresAt time.Time) Secret {
	s := NewSecret(val)
	exp := expiresAt.UTC()
	s.ExpiresAt = &exp
	return s
}

// Zero 尽力将底层机密字节清零，并将引用置空，防止明文驻留堆内存。
func (s *Secret) Zero() {
	if s == nil {
		return
	}
	for i := range s.Value {
		s.Value[i] = 0
	}
	s.Value = nil
	s.ExpiresAt = nil
}

// Clone 返回机密对象的独立深拷贝，调用方可以安全修改或清零而不影响原对象。
func (s Secret) Clone() Secret {
	var copied []byte
	if s.Value != nil {
		copied = make([]byte, len(s.Value))
		copy(copied, s.Value)
	}
	var exp *time.Time
	if s.ExpiresAt != nil {
		t := *s.ExpiresAt
		exp = &t
	}
	return Secret{
		Value:     copied,
		ExpiresAt: exp,
	}
}

// IsExpired 判断该机密在指定时间点是否已过期。
func (s Secret) IsExpired(now time.Time) bool {
	if s.ExpiresAt == nil {
		return false
	}
	return now.After(*s.ExpiresAt)
}
