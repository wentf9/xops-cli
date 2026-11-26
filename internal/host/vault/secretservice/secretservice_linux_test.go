//go:build linux

package secretservice_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/vault/secretservice"
	"go.uber.org/goleak"
)

const (
	helperSockEnv   = "XOPS_SS_MOCK_SOCK"
	helperDHEnv     = "XOPS_SS_MOCK_DH"
	helperLockedEnv = "XOPS_SS_MOCK_LOCKED"
	helperDenyEnv   = "XOPS_SS_MOCK_DENY"
	helperDupEnv    = "XOPS_SS_MOCK_DUP"
)

const testDHPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
	"FFFFFFFFFFFFFFFF"

type mockSSSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type mockSSItem struct {
	path  dbus.ObjectPath
	attrs map[string]string
	value []byte
}

type mockDBusSecretServer struct {
	ln        net.Listener
	nursery   *conc.Nursery
	supportDH bool
	locked    bool
	denyAuth  bool
	dupOnPut  bool
	mu        sync.Mutex
	nextID    int
	sessions  map[dbus.ObjectPath][]byte // nil => plain, 16B => DH AES-128 key
	items     map[dbus.ObjectPath]*mockSSItem
	serial    atomic.Uint32
}

// TestSecretServiceHelperProcess 在独立测试子进程中托管 D-Bus Secret Service 桩，
// 既可完整验证跨进程 Unix 套接字凭证认证（SO_PEERCRED + 0600 权限），又确保主测试进程零常驻后台协程。
func TestSecretServiceHelperProcess(t *testing.T) {
	sock := os.Getenv(helperSockEnv)
	if sock == "" {
		return
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(2)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		os.Exit(2)
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		os.Exit(3)
	}
	srv := &mockDBusSecretServer{
		ln:        ln,
		nursery:   n,
		supportDH: os.Getenv(helperDHEnv) == "1",
		locked:    os.Getenv(helperLockedEnv) == "1",
		denyAuth:  os.Getenv(helperDenyEnv) == "1",
		dupOnPut:  os.Getenv(helperDupEnv) == "1",
		sessions:  make(map[dbus.ObjectPath][]byte),
		items:     make(map[dbus.ObjectPath]*mockSSItem),
	}
	if err := n.Go(func(context.Context) error {
		return srv.acceptLoop()
	}); err != nil {
		_ = ln.Close()
		_ = n.Close()
		os.Exit(4)
	}
	_, _ = io.WriteString(os.Stdout, "READY\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = ln.Close()
	_ = n.Close()
	os.Exit(0)
}

func startMockDBusSecretServer(t *testing.T, supportDH, locked bool, extraEnv ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	// 使用短路径且无符号链接的临时目录，满足 Linux 108B sun_path 上限与 osfs.DialUnixVerified 校验。
	shortDir, err := os.MkdirTemp("", "xops-ss-*")
	if err != nil {
		t.Fatalf("os.MkdirTemp 失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
	realDir, err := filepath.EvalSymlinks(shortDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) 失败: %v", shortDir, err)
	}
	sock := filepath.Join(realDir, "d.sock")
	cmd := exec.Command(exe, "-test.run=^TestSecretServiceHelperProcess$")
	dhVal, lockVal := "0", "0"
	if supportDH {
		dhVal = "1"
	}
	if locked {
		lockVal = "1"
	}
	cmd.Env = append(os.Environ(),
		helperSockEnv+"="+sock,
		helperDHEnv+"="+dhVal,
		helperLockedEnv+"="+lockVal,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	stdinW, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe 失败: %v", err)
	}
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinW.Close()
		t.Fatalf("StdoutPipe 失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		t.Fatalf("启动 D-Bus Secret Service 子进程桩失败: %v", err)
	}
	line, rErr := bufio.NewReader(stdoutR).ReadString('\n')
	if rErr != nil || strings.TrimSpace(line) != "READY" {
		_ = stdinW.Close()
		_ = cmd.Wait()
		t.Fatalf("D-Bus Secret Service 子进程桩未就绪: line=%q err=%v", line, rErr)
	}
	t.Cleanup(func() {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = cmd.Wait()
	})
	return "unix:path=" + sock
}

func (s *mockDBusSecretServer) acceptLoop() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return nil
		}
		if gErr := s.nursery.Go(func(context.Context) error {
			defer func() { _ = conn.Close() }()
			s.serveConn(conn)
			return nil
		}); gErr != nil {
			_ = conn.Close()
		}
	}
}

func (s *mockDBusSecretServer) serveConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	if err := s.handshakeSASL(br, conn); err != nil {
		return
	}
	for {
		msg, err := dbus.DecodeMessage(br)
		if err != nil {
			return
		}
		if msg.Type != dbus.TypeMethodCall {
			continue
		}
		reply := s.handleCall(msg)
		if err := s.writeMessage(conn, reply); err != nil {
			return
		}
	}
}

func (s *mockDBusSecretServer) handshakeSASL(br *bufio.Reader, w io.Writer) error {
	nul, err := br.ReadByte()
	if err != nil {
		return err
	}
	if nul != 0 {
		return fmt.Errorf("expected leading NUL byte")
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "BEGIN" {
			return nil
		}
		if _, wErr := io.WriteString(w, saslResponseLine(trimmed)); wErr != nil {
			return wErr
		}
	}
}

func saslResponseLine(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "AUTH EXTERNAL"):
		return "OK 0123456789abcdef0123456789abcdef\r\n"
	case strings.HasPrefix(cmd, "NEGOTIATE_UNIX_FD"):
		return "ERROR\r\n"
	default:
		return "REJECTED EXTERNAL\r\n"
	}
}

func (s *mockDBusSecretServer) handleCall(req *dbus.Message) *dbus.Message {
	member, _ := req.Headers[dbus.FieldMember].Value().(string)
	path, _ := req.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	switch member {
	case "Hello":
		return s.methodReply(req, ":1.1")
	case "OpenSession":
		return s.handleOpenSession(req)
	case "Close":
		s.mu.Lock()
		delete(s.sessions, path)
		s.mu.Unlock()
		return s.methodReply(req)
	case "Get":
		return s.methodReply(req, dbus.MakeVariant(s.locked))
	case "SearchItems":
		return s.handleSearchItems(req)
	case "CreateItem":
		return s.handleCreateItem(req)
	case "GetSecret":
		return s.handleGetSecret(req, path)
	case "Delete":
		return s.handleDeleteItem(req, path)
	default:
		return s.errorReply(req, "org.freedesktop.DBus.Error.UnknownMethod", member)
	}
}

func (s *mockDBusSecretServer) handleOpenSession(req *dbus.Message) *dbus.Message {
	if s.denyAuth {
		return s.errorReply(req, "org.freedesktop.DBus.Error.AccessDenied", "denied")
	}
	if len(req.Body) < 2 {
		return s.errorReply(req, "org.freedesktop.DBus.Error.InvalidArgs", "bad args")
	}
	algo, _ := req.Body[0].(string)
	inputV, _ := req.Body[1].(dbus.Variant)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	sessPath := dbus.ObjectPath("/org/freedesktop/secrets/session/s" + strconv.Itoa(s.nextID))
	switch algo {
	case "plain":
		s.sessions[sessPath] = nil
		return s.methodReply(req, dbus.MakeVariant(""), sessPath)
	case "dh-ietf1024-sha256-aes128-cbc-pkcs7":
		if !s.supportDH {
			return s.errorReply(req, "org.freedesktop.DBus.Error.NotSupported", "dh disabled")
		}
		clientPub, _ := inputV.Value().([]byte)
		srvPub, aesKey, err := testServerDH(clientPub)
		if err != nil {
			return s.errorReply(req, "org.freedesktop.DBus.Error.Failed", err.Error())
		}
		s.sessions[sessPath] = aesKey
		return s.methodReply(req, dbus.MakeVariant(srvPub), sessPath)
	default:
		return s.errorReply(req, "org.freedesktop.DBus.Error.NotSupported", algo)
	}
}

func (s *mockDBusSecretServer) handleSearchItems(req *dbus.Message) *dbus.Message {
	attrs, _ := req.Body[0].(map[string]string)
	s.mu.Lock()
	defer s.mu.Unlock()
	var unlocked, locked []dbus.ObjectPath
	for p, it := range s.items {
		if attrsMatch(it.attrs, attrs) {
			if s.locked {
				locked = append(locked, p)
			} else {
				unlocked = append(unlocked, p)
			}
		}
	}
	return s.methodReply(req, unlocked, locked)
}

func (s *mockDBusSecretServer) handleCreateItem(req *dbus.Message) *dbus.Message {
	if s.locked {
		return s.errorReply(req, "org.freedesktop.Secret.Error.IsLocked", "locked")
	}
	props, _ := req.Body[0].(map[string]dbus.Variant)
	rawSec, ok := req.Body[1].([]any)
	if !ok || len(rawSec) != 4 {
		return s.errorReply(req, "org.freedesktop.DBus.Error.InvalidArgs", "bad secret struct")
	}
	sessPath, _ := rawSec[0].(dbus.ObjectPath)
	params, _ := rawSec[1].([]byte)
	val, _ := rawSec[2].([]byte)
	attrs, _ := props["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string)

	s.mu.Lock()
	defer s.mu.Unlock()
	aesKey := s.sessions[sessPath]
	plain, err := decodeSessionValue(aesKey, params, val)
	if err != nil {
		return s.errorReply(req, "org.freedesktop.DBus.Error.Failed", err.Error())
	}
	for p, it := range s.items {
		if attrsMatch(it.attrs, attrs) {
			it.value = plain
			return s.methodReply(req, p, dbus.ObjectPath("/"))
		}
	}
	s.nextID++
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/default/i" + strconv.Itoa(s.nextID))
	s.items[itemPath] = &mockSSItem{path: itemPath, attrs: attrs, value: plain}
	if s.dupOnPut {
		s.nextID++
		dupPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/default/i" + strconv.Itoa(s.nextID))
		s.items[dupPath] = &mockSSItem{path: dupPath, attrs: attrs, value: plain}
	}
	return s.methodReply(req, itemPath, dbus.ObjectPath("/"))
}

func (s *mockDBusSecretServer) handleGetSecret(req *dbus.Message, itemPath dbus.ObjectPath) *dbus.Message {
	sessPath, _ := req.Body[0].(dbus.ObjectPath)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return s.errorReply(req, "org.freedesktop.Secret.Error.IsLocked", "locked")
	}
	it, ok := s.items[itemPath]
	if !ok {
		return s.errorReply(req, "org.freedesktop.Secret.Error.NoSuchObject", "missing")
	}
	aesKey := s.sessions[sessPath]
	iv, enc, err := encodeSessionValue(aesKey, it.value)
	if err != nil {
		return s.errorReply(req, "org.freedesktop.DBus.Error.Failed", err.Error())
	}
	return s.methodReply(req, mockSSSecret{
		Session:     sessPath,
		Parameters:  iv,
		Value:       enc,
		ContentType: "application/octet-stream",
	})
}

func (s *mockDBusSecretServer) handleDeleteItem(req *dbus.Message, itemPath dbus.ObjectPath) *dbus.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return s.errorReply(req, "org.freedesktop.Secret.Error.IsLocked", "locked")
	}
	if _, ok := s.items[itemPath]; !ok {
		return s.errorReply(req, "org.freedesktop.Secret.Error.NoSuchObject", "missing")
	}
	delete(s.items, itemPath)
	return s.methodReply(req, dbus.ObjectPath("/"))
}

func (s *mockDBusSecretServer) methodReply(req *dbus.Message, body ...any) *dbus.Message {
	headers := map[dbus.HeaderField]dbus.Variant{
		dbus.FieldReplySerial: dbus.MakeVariant(req.Serial()),
		dbus.FieldSender:      dbus.MakeVariant("org.freedesktop.secrets"),
	}
	if len(body) > 0 {
		headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
	}
	return &dbus.Message{Type: dbus.TypeMethodReply, Headers: headers, Body: body}
}

func (s *mockDBusSecretServer) errorReply(req *dbus.Message, errName, text string) *dbus.Message {
	return &dbus.Message{
		Type: dbus.TypeError,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(req.Serial()),
			dbus.FieldErrorName:   dbus.MakeVariant(errName),
			dbus.FieldSender:      dbus.MakeVariant("org.freedesktop.secrets"),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(text)),
		},
		Body: []any{text},
	}
}

func (s *mockDBusSecretServer) writeMessage(w io.Writer, msg *dbus.Message) error {
	var buf bytes.Buffer
	if err := msg.EncodeTo(&buf, binary.LittleEndian); err != nil {
		return err
	}
	raw := buf.Bytes()
	if len(raw) < 12 {
		return fmt.Errorf("encoded dbus message too short")
	}
	binary.LittleEndian.PutUint32(raw[8:12], s.serial.Add(1))
	_, err := w.Write(raw)
	return err
}

func attrsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func testServerDH(clientPubBytes []byte) ([]byte, []byte, error) {
	pRaw, err := hex.DecodeString(testDHPrimeHex)
	if err != nil {
		return nil, nil, err
	}
	p := new(big.Int).SetBytes(pRaw)
	privRaw := make([]byte, 128)
	if _, err := io.ReadFull(rand.Reader, privRaw); err != nil {
		return nil, nil, err
	}
	priv := new(big.Int).SetBytes(privRaw)
	priv.Mod(priv, new(big.Int).Sub(p, big.NewInt(2)))
	priv.Add(priv, big.NewInt(1))
	srvPub := new(big.Int).Exp(big.NewInt(2), priv, p).Bytes()
	shared := make([]byte, 128)
	new(big.Int).Exp(new(big.Int).SetBytes(clientPubBytes), priv, p).FillBytes(shared)
	key, err := hkdf.Key(sha256.New, shared, nil, "", 16)
	return srvPub, key, err
}

func encodeSessionValue(aesKey, plain []byte) ([]byte, []byte, error) {
	if len(aesKey) == 0 {
		out := make([]byte, len(plain))
		copy(out, plain)
		return nil, out, nil
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	padLen := aes.BlockSize - (len(plain) % aes.BlockSize)
	padded := make([]byte, len(plain)+padLen)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return iv, ct, nil
}

func decodeSessionValue(aesKey, iv, val []byte) ([]byte, error) {
	if len(aesKey) == 0 {
		out := make([]byte, len(val))
		copy(out, val)
		return out, nil
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	dec := make([]byte, len(val))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, val)
	pad := int(dec[len(dec)-1])
	return dec[:len(dec)-pad], nil
}

func TestTCKSecretVault_SecretServiceDHAndPlain(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("DH_AES128CBC", func(t *testing.T) {
		tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
			NewVault: func(t *testing.T) ports.SecretVault {
				addr := startMockDBusSecretServer(t, true, false)
				st, err := secretservice.NewStore(secretservice.Spec{
					Entropy:    sys.NewCryptoEntropy(),
					BusAddress: addr,
				})
				if err != nil {
					t.Fatalf("NewStore(DH) 失败: %v", err)
				}
				return st
			},
			NewLockedVault: func(t *testing.T) ports.SecretVault {
				addr := startMockDBusSecretServer(t, true, true)
				st, err := secretservice.NewStore(secretservice.Spec{
					Entropy:    sys.NewCryptoEntropy(),
					BusAddress: addr,
				})
				if err != nil {
					t.Fatalf("NewStore(locked) 失败: %v", err)
				}
				return st
			},
		})
	})

	t.Run("PlainFallback", func(t *testing.T) {
		tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
			NewVault: func(t *testing.T) ports.SecretVault {
				addr := startMockDBusSecretServer(t, false, false)
				st, err := secretservice.NewStore(secretservice.Spec{
					Entropy:            sys.NewCryptoEntropy(),
					BusAddress:         addr,
					AllowPlainFallback: true,
				})
				if err != nil {
					t.Fatalf("NewStore(plain) 失败: %v", err)
				}
				return st
			},
		})
	})
}

func mustNewSecretServiceStore(t *testing.T, addr string, allowPlain bool) *secretservice.Store {
	t.Helper()
	st, err := secretservice.NewStore(secretservice.Spec{
		Entropy:            sys.NewCryptoEntropy(),
		BusAddress:         addr,
		AllowPlainFallback: allowPlain,
	})
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}
	return st
}

// TestSecretService_ErrorMappingAndMultiItemDelete 验证 DH 失败错误归一化与重复条目全量删除。
func TestSecretService_ErrorMappingAndMultiItemDelete(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	ref := tck.MustRef(t, "ss", "item1")

	t.Run("DisallowPlainMapsToErrUnsupported", func(t *testing.T) {
		st := mustNewSecretServiceStore(t, startMockDBusSecretServer(t, false, false), false)
		if err := st.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrUnsupported) {
			t.Fatalf("禁止 plain 回退时期望 ErrUnsupported，实际得到: %v", err)
		}
	})

	t.Run("AccessDeniedMapsToErrPermissionDenied", func(t *testing.T) {
		st := mustNewSecretServiceStore(t, startMockDBusSecretServer(t, true, false, helperDenyEnv+"=1"), false)
		if err := st.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrPermissionDenied) {
			t.Fatalf("D-Bus AccessDenied 期望 ErrPermissionDenied，实际得到: %v", err)
		}
	})

	t.Run("DeleteRemovesAllMatchingItems", func(t *testing.T) {
		st := mustNewSecretServiceStore(t, startMockDBusSecretServer(t, true, false, helperDupEnv+"=1"), false)
		if err := secret.WithBytes([]byte("dup-secret"), func(box *secret.SecretBox) error {
			return st.PutAndVerify(ctx, ref, box)
		}); err != nil {
			t.Fatalf("PutAndVerify 失败: %v", err)
		}
		if err := st.Delete(ctx, ref); err != nil {
			t.Fatalf("Delete 失败: %v", err)
		}
		if err := st.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
			t.Fatalf("删除全部重复项后 WithSecret 期望 ErrSecretNotFound，实际得到: %v", err)
		}
	})
}
