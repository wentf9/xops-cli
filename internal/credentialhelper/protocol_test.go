package credentialhelper

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestProtocolVersionAndEncoding(t *testing.T) {
	// 1. 合法请求编码
	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "system",
		ItemID:          "item-001",
		Secret:          "cGFzc3dvcmQ=", // "password"
	}

	var buf bytes.Buffer
	if err := EncodeRequest(&buf, req); err != nil {
		t.Fatalf("EncodeRequest failed: %v", err)
	}

	if !strings.Contains(buf.String(), `"protocolVersion":1`) {
		t.Fatalf("expected protocolVersion 1 in output, got: %s", buf.String())
	}

	// 2. 非法版本拒绝
	badReq := &Request{
		ProtocolVersion: 2,
		StoreID:         "system",
		ItemID:          "item-001",
	}
	var badBuf bytes.Buffer
	if err := EncodeRequest(&badBuf, badReq); err == nil {
		t.Fatalf("expected error on unsupported protocol version 2")
	}
}

func TestDecodeResponseSuccessAndUnknownFields(t *testing.T) {
	// 包含未知字段 extraField，根据规范应平滑忽略
	rawJSON := `{
		"secret": "cGFzc3dvcmQ=",
		"expiresAt": "2026-09-07T12:00:00Z",
		"extraField": "ignored-value"
	}`

	resp, err := DecodeResponse(strings.NewReader(rawJSON))
	if err != nil {
		t.Fatalf("DecodeResponse failed: %v", err)
	}

	if resp.Secret != "cGFzc3dvcmQ=" {
		t.Fatalf("unexpected secret: %s", resp.Secret)
	}
	if resp.ExpiresAt == nil || resp.ExpiresAt.UTC() != time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected expiresAt: %v", resp.ExpiresAt)
	}

	decodedBytes, err := DecodeSecretBytes(resp)
	if err != nil {
		t.Fatalf("DecodeSecretBytes failed: %v", err)
	}
	if string(decodedBytes) != "password" {
		t.Fatalf("decoded secret mismatch: got %s, want password", string(decodedBytes))
	}
}

func TestDecodeResponseErrorCodes(t *testing.T) {
	cases := []struct {
		code        string
		expectedErr error
	}{
		{"not-found", credential.ErrCredentialNotFound},
		{"locked", credential.ErrCredentialStoreLocked},
		{"unavailable", credential.ErrCredentialStoreUnavailable},
		{"denied", credential.ErrCredentialAccessDenied},
		{"read-only", credential.ErrCredentialStoreReadOnly},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			rawJSON := `{"code": "` + tc.code + `", "message": "test details"}`
			resp, err := DecodeResponse(strings.NewReader(rawJSON))
			if resp == nil {
				t.Fatalf("expected non-nil response object")
			}
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("code %s: expected %v, got %v", tc.code, tc.expectedErr, err)
			}
			if !strings.Contains(err.Error(), "test details") {
				t.Fatalf("expected error to include details, got: %v", err)
			}
		})
	}
}

func TestDecodeResponseInvalidBase64(t *testing.T) {
	rawJSON := `{"secret": "not-a-valid-base64!@#$"}`
	_, err := DecodeResponse(strings.NewReader(rawJSON))
	if err == nil {
		t.Fatalf("expected error on invalid base64")
	}
	if !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDecodeResponseExceedsMaxSize(t *testing.T) {
	// 构造超过 64KB 的响应
	hugePayload := `{"secret": "` + strings.Repeat("A", MaxResponseBytes+10) + `"}`
	_, err := DecodeResponse(strings.NewReader(hugePayload))
	if err == nil {
		t.Fatalf("expected size limit error on huge payload")
	}
	if !strings.Contains(err.Error(), "maximum allowed size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeResponseEmptyAndMalformed(t *testing.T) {
	_, err := DecodeResponse(strings.NewReader(""))
	if err == nil {
		t.Fatalf("expected error on empty response")
	}

	_, err = DecodeResponse(strings.NewReader("{not-valid-json"))
	if err == nil {
		t.Fatalf("expected error on malformed json")
	}
}

func TestUnknownErrorCodeDoesNotExposeKnownSecret(t *testing.T) {
	rawJSON := `{"code": "p@ssword-secret!", "message": "diagnostic"}`
	resp, err := DecodeResponse(strings.NewReader(rawJSON))
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
	if err == nil {
		t.Fatalf("expected error on unknown error code")
	}
	if strings.Contains(err.Error(), "p@ssword-secret!") {
		t.Fatalf("unknown error code leaked into error message: %v", err)
	}
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("expected ErrCredentialStoreUnavailable for unknown error code, got: %v", err)
	}
}
