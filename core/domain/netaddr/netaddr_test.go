package netaddr

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestCanonicalHostZeroAndValidCases(t *testing.T) {
	var zero CanonicalHost
	if zero.IsValid() || !zero.IsZero() || zero.Kind() != HostKindInvalid || zero.Kind().String() != "invalid" {
		t.Fatalf("零值 CanonicalHost 状态异常: %+v", zero)
	}
	if zero.IsIP() || zero.IsIPv4() || zero.IsIPv6() || zero.IsDNS() ||
		zero.String() != "" || zero.Bracketed() != "" || zero.Zone() != "" || zero.Equal(zero) {
		t.Fatal("零值 CanonicalHost 谓词与 Equal 必须失败关闭")
	}
	if _, ok := zero.Addr(); ok {
		t.Fatal("零值 CanonicalHost.Addr() 应返回 false")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("零值 MarshalText = %v, 期望 ErrInvalidHost", err)
	}

	validCases := []struct {
		raw      string
		wantStr  string
		wantBrk  string
		wantKind HostKind
		wantZone string
	}{
		{"192.0.2.10", "192.0.2.10", "192.0.2.10", HostKindIPv4, ""},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1", HostKindIPv4, ""},
		{"2001:0DB8:0000:0000::0001", "2001:db8::1", "[2001:db8::1]", HostKindIPv6, ""},
		{"[2001:0DB8::1]", "2001:db8::1", "[2001:db8::1]", HostKindIPv6, ""},
		{"fe80::1%eth0", "fe80::1%eth0", "[fe80::1%eth0]", HostKindIPv6, "eth0"},
		{"[FE80:0000::1%Eth0]", "fe80::1%Eth0", "[fe80::1%Eth0]", HostKindIPv6, "Eth0"},
		{"fe80::1%eth0.100", "fe80::1%eth0.100", "[fe80::1%eth0.100]", HostKindIPv6, "eth0.100"},
		{"fe80::1%br-lan", "fe80::1%br-lan", "[fe80::1%br-lan]", HostKindIPv6, "br-lan"},
		{"fe80::1%12", "fe80::1%12", "[fe80::1%12]", HostKindIPv6, "12"},
		{"fe80::1%wg_0", "fe80::1%wg_0", "[fe80::1%wg_0]", HostKindIPv6, "wg_0"},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]", HostKindIPv6, ""},
		{"[::FFFF:192.0.2.1]", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]", HostKindIPv6, ""},
		{"Example.COM", "example.com", "example.com", HostKindDNS, ""},
		{"web-01.prod.internal", "web-01.prod.internal", "web-01.prod.internal", HostKindDNS, ""},
		{"localhost", "localhost", "localhost", HostKindDNS, ""},
		{"123-host", "123-host", "123-host", HostKindDNS, ""},
		{"web-0x1", "web-0x1", "web-0x1", HostKindDNS, ""},
		{"0xhost", "0xhost", "0xhost", HostKindDNS, ""},
		{"3f8a9b1c.example.com", "3f8a9b1c.example.com", "3f8a9b1c.example.com", HostKindDNS, ""},
		{strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", HostKindDNS, ""},
		{maxValidHostname253(), maxValidHostname253(), maxValidHostname253(), HostKindDNS, ""},
	}
	for _, tc := range validCases {
		assertValidCanonicalHost(t, tc.raw, tc.wantStr, tc.wantBrk, tc.wantKind, tc.wantZone)
	}
}

func assertValidCanonicalHost(t *testing.T, raw, wantStr, wantBrk string, wantKind HostKind, wantZone string) {
	t.Helper()
	h, err := ParseCanonicalHost(raw)
	if err != nil {
		t.Fatalf("ParseCanonicalHost(%q) 意外失败: %v", raw, err)
	}
	if !h.IsValid() || h.IsZero() || h.Kind() != wantKind || h.String() != wantStr || h.Bracketed() != wantBrk || h.Zone() != wantZone {
		t.Fatalf("ParseCanonicalHost(%q) = (str=%q brk=%q kind=%v zone=%q)", raw, h.String(), h.Bracketed(), h.Kind(), h.Zone())
	}
	isIP := wantKind == HostKindIPv4 || wantKind == HostKindIPv6
	if h.IsIP() != isIP || h.IsIPv4() != (wantKind == HostKindIPv4) || h.IsIPv6() != (wantKind == HostKindIPv6) || h.IsDNS() != (wantKind == HostKindDNS) {
		t.Fatalf("ParseCanonicalHost(%q) 类型谓词错误", raw)
	}
	h2, err := ParseCanonicalHost(h.String())
	if err != nil || !h.Equal(h2) || h.Compare(h2) != 0 {
		t.Fatalf("CanonicalHost 幂等性失败: raw=%q canon=%q err=%v", raw, h.String(), err)
	}
}

func TestCanonicalHostIPv4MappedAddrAndRejections(t *testing.T) {
	v4, err := ParseCanonicalHost("192.0.2.1")
	if err != nil {
		t.Fatalf("ParseCanonicalHost(v4) 失败: %v", err)
	}
	v4in6, err := ParseCanonicalHost("::ffff:192.0.2.1")
	if err != nil {
		t.Fatalf("ParseCanonicalHost(v4in6) 失败: %v", err)
	}
	if v4.Equal(v4in6) || v4in6.IsIPv4() || !v4in6.IsIPv6() {
		t.Fatal("IPv4-mapped IPv6 不得与纯 IPv4 相等或降级")
	}

	if _, err := CanonicalHostFromAddr(netip.Addr{}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("CanonicalHostFromAddr(零值) = %v, 期望 ErrInvalidHost", err)
	}
	badZoneAddr := netip.MustParseAddr("fe80::1").WithZone("eth0/bad")
	if _, err := CanonicalHostFromAddr(badZoneAddr); !errors.Is(err, ErrInvalidHost) || !errors.Is(err, ErrInvalidZone) {
		t.Fatalf("非法区段 Addr 错误 = %v, 期望同时匹配 ErrInvalidHost 与 ErrInvalidZone", err)
	}

	badHosts := []string{
		"", " ", " example.com", "example.com ", "exam ple.com",
		"example.com\n", "example.com\x00", "example.com\u2028", "example.com\u2029",
		string([]byte{0xff, 0xfe}), "[]", "[", "]", "[2001:db8::1", "2001:db8::1]",
		"[[2001:db8::1]]", "[192.0.2.1]", "[example.com]",
		"2001:db8::1%eth0%extra", "fe80::1%", "fe80::1%eth/0", "fe80::1%eth\\0",
		"fe80::1%eth@0", "fe80::1%eth,0", "fe80::1%eth:0", "fe80::1%" + strings.Repeat("z", 65),
		// IPv6 区段对抗输入：known_hosts 通配/否定/注释、选项/shell 注入、Unicode 格式/Bidi 与首尾点
		"fe80::1%*", "fe80::1%?", "fe80::1%!all", "fe80::1%#comment",
		"fe80::1%-oProxyCommand=x", "fe80::1%eth0;id", "fe80::1%eth0$x",
		"fe80::1%eth0\u200b", "fe80::1%eth0\u202e", "fe80::1%eth0\ufeff",
		"fe80::1%.eth0", "fe80::1%eth0.",
		".example.com", "example.com.", "a..b.com", "-bad.com", "bad-.com",
		"a.-b.com", "a.b-.com", "under_score.com",
		// 十进制、八进制及 POSIX/WinSock inet_aton 十六进制 IPv4 伪装主机名
		"999.999.999.999", "127.1", "192.168.1.256", "0177.0.0.1", "2130706433", "12345", "host.123",
		"0x7f000001", "0x7f.0.0.0x1", "0X7F.1", "127.0x000001", "0X7F",
		"中文.com", strings.Repeat("a", 64) + ".com", maxValidHostname253() + "a",
	}
	for _, bad := range badHosts {
		if _, err := ParseCanonicalHost(bad); !errors.Is(err, ErrInvalidHost) {
			t.Fatalf("ParseCanonicalHost(%q) = %v, 期望 ErrInvalidHost", bad, err)
		}
	}
}

func TestHostPortValidRoundTripAndConstructors(t *testing.T) {
	var zero HostPort
	if zero.IsValid() || !zero.IsZero() || zero.Port() != 0 || zero.String() != "" || zero.Equal(zero) {
		t.Fatalf("零值 HostPort 必须严格失败关闭: %+v", zero)
	}
	if _, err := NewHostPort(CanonicalHost{}, 22); !errors.Is(err, ErrInvalidHostPort) || !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("NewHostPort(零值主机) = %v", err)
	}
	h, err := ParseCanonicalHost("Example.COM")
	if err != nil {
		t.Fatalf("ParseCanonicalHost 失败: %v", err)
	}
	if _, err := NewHostPort(h, 0); !errors.Is(err, ErrInvalidHostPort) || !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("NewHostPort(port=0) = %v", err)
	}

	validCases := []struct {
		raw      string
		wantStr  string
		wantPort uint16
	}{
		{"Example.COM:8080", "example.com:8080", 8080},
		{"192.0.2.10:1", "192.0.2.10:1", 1},
		{"192.0.2.10:65535", "192.0.2.10:65535", 65535},
		{"[2001:0DB8::1]:443", "[2001:db8::1]:443", 443},
		{"[FE80::1%eth0]:2222", "[fe80::1%eth0]:2222", 2222},
		{"[::ffff:192.0.2.1]:22", "[::ffff:192.0.2.1]:22", 22},
	}
	for _, tc := range validCases {
		assertValidHostPortJSONv2(t, tc.raw, tc.wantStr, tc.wantPort)
	}
}

func assertValidHostPortJSONv2(t *testing.T, raw, wantStr string, wantPort uint16) {
	t.Helper()
	hp, err := ParseHostPort(raw)
	if err != nil || !hp.IsValid() || hp.Port() != wantPort || hp.String() != wantStr {
		t.Fatalf("ParseHostPort(%q) = (%q, %d, %v), 期望 (%q, %d)", raw, hp.String(), hp.Port(), err, wantStr, wantPort)
	}
	rawJSON, err := jsonv2.Marshal(hp, jsonv2.Deterministic(true))
	if err != nil || string(rawJSON) != `"`+wantStr+`"` {
		t.Fatalf("jsonv2.Marshal(HostPort %q) = (%s, %v)", raw, rawJSON, err)
	}
	var out HostPort
	if err := jsonv2.Unmarshal(rawJSON, &out); err != nil || !out.Equal(hp) {
		t.Fatalf("jsonv2.Unmarshal(HostPort %s) = (%+v, %v)", rawJSON, out, err)
	}
}

func TestHostPortRejectsInvalidAndResets(t *testing.T) {
	badHostPorts := []string{
		"", "example.com", "192.0.2.10", "2001:db8::1", "[2001:db8::1]",
		"[2001:db8::1]:", "example.com:", ":22", "example.com:0",
		"example.com:022", "example.com:0080", "example.com:+22", "example.com:-22",
		"example.com:65536", "example.com:999999", "example.com:abc",
		"[192.0.2.1]:22", "[example.com]:22", " example.com:22", "example.com:22 ", "a:b:22",
	}
	for _, bad := range badHostPorts {
		if _, err := ParseHostPort(bad); !errors.Is(err, ErrInvalidHostPort) {
			t.Fatalf("ParseHostPort(%q) = %v, 期望 ErrInvalidHostPort", bad, err)
		}
	}

	hp, err := ParseHostPort("example.com:80")
	if err != nil {
		t.Fatalf("ParseHostPort 失败: %v", err)
	}
	if err := hp.UnmarshalText([]byte("example.com")); !errors.Is(err, ErrInvalidHostPort) || hp.IsValid() {
		t.Fatalf("HostPort.UnmarshalText 失败后未重置: hp=%+v err=%v", hp, err)
	}
	var nilHP *HostPort
	if err := nilHP.UnmarshalText([]byte("example.com:80")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil HostPort.UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}
}

func TestEndpointZeroAndValidKnownHosts(t *testing.T) {
	var zero Endpoint
	if zero.IsValid() || !zero.IsZero() || zero.Port() != 0 || zero.String() != "" ||
		zero.KnownHostsKey() != "" || zero.Equal(zero) || zero.HostEqual(zero) {
		t.Fatalf("零值 Endpoint 必须严格失败关闭: %+v", zero)
	}
	if _, err := zero.WithPort(22); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("零值 WithPort = %v, 期望 ErrInvalidEndpoint", err)
	}
	if _, err := NewEndpointFromHostPort(HostPort{}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("NewEndpointFromHostPort(零值) = %v, 期望 ErrInvalidEndpoint", err)
	}
	if _, err := jsonv2.Marshal(zero); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("jsonv2.Marshal(零值 Endpoint) = %v, 期望包装 ErrInvalidEndpoint", err)
	}

	validCases := []struct {
		raw           string
		wantStr       string
		wantKnownHost string
		wantPort      uint16
	}{
		{"Example.COM", "example.com:22", "example.com", 22},
		{"Example.COM:22", "example.com:22", "example.com", 22},
		{"Example.COM:2222", "example.com:2222", "[example.com]:2222", 2222},
		{"192.0.2.10", "192.0.2.10:22", "192.0.2.10", 22},
		{"192.0.2.10:2200", "192.0.2.10:2200", "[192.0.2.10]:2200", 2200},
		{"2001:0DB8::1", "[2001:db8::1]:22", "2001:db8::1", 22},
		{"[2001:0DB8::1]", "[2001:db8::1]:22", "2001:db8::1", 22},
		{"[2001:0DB8::1]:2222", "[2001:db8::1]:2222", "[2001:db8::1]:2222", 2222},
		{"fe80::1%eth0", "[fe80::1%eth0]:22", "fe80::1%eth0", 22},
		{"[fe80::1%eth0]:2222", "[fe80::1%eth0]:2222", "[fe80::1%eth0]:2222", 2222},
	}
	for _, tc := range validCases {
		assertValidEndpointRoundTrip(t, tc.raw, tc.wantStr, tc.wantKnownHost, tc.wantPort)
	}
}

func assertValidEndpointRoundTrip(t *testing.T, raw, wantStr, wantKnownHost string, wantPort uint16) {
	t.Helper()
	ep, err := ParseEndpoint(raw)
	if err != nil || !ep.IsValid() || ep.Port() != wantPort || ep.String() != wantStr ||
		ep.KnownHostsKey() != wantKnownHost || ep.HostPort().String() != wantStr {
		t.Fatalf("ParseEndpoint(%q) = (str=%q kh=%q port=%d err=%v)", raw, ep.String(), ep.KnownHostsKey(), ep.Port(), err)
	}
	appended, err := ep.AppendText([]byte("ep="))
	if err != nil || string(appended) != "ep="+wantStr {
		t.Fatalf("AppendText(%q) = (%q, %v)", raw, appended, err)
	}
	rawJSON, err := jsonv2.Marshal(ep, jsonv2.Deterministic(true))
	if err != nil || string(rawJSON) != `"`+wantStr+`"` {
		t.Fatalf("jsonv2.Marshal(Endpoint %q) = (%s, %v)", raw, rawJSON, err)
	}
	var out Endpoint
	if err := jsonv2.Unmarshal(rawJSON, &out); err != nil || !out.Equal(ep) {
		t.Fatalf("jsonv2.Unmarshal(Endpoint %s) = (%+v, %v)", rawJSON, out, err)
	}
}

func TestEndpointEqualityOrderingAndWithPort(t *testing.T) {
	var zero Endpoint
	ep22, err := ParseEndpoint("example.com")
	if err != nil {
		t.Fatalf("ParseEndpoint 失败: %v", err)
	}
	ep2222, err := ep22.WithPort(2222)
	if err != nil {
		t.Fatalf("WithPort(2222) 失败: %v", err)
	}
	if ep22.Port() != 22 || ep2222.Port() != 2222 || ep22.Equal(ep2222) || !ep22.HostEqual(ep2222) {
		t.Fatal("WithPort、Equal 或 HostEqual 语义异常")
	}
	if _, err := ep22.WithPort(0); !errors.Is(err, ErrInvalidEndpoint) || !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("WithPort(0) = %v, 期望 ErrInvalidEndpoint + ErrInvalidPort", err)
	}

	epV4, _ := ParseEndpoint("192.0.2.1:22")
	epV6, _ := ParseEndpoint("[2001:db8::1]:22")
	ordered := []Endpoint{zero, epV4, epV6, ep22, ep2222}
	for i := range ordered {
		if ordered[i].Compare(ordered[i]) != 0 {
			t.Fatalf("Compare 自反律失败: i=%d", i)
		}
		assertStrictlyOrderedAfter(t, ordered, i)
	}
}

func assertStrictlyOrderedAfter(t *testing.T, ordered []Endpoint, i int) {
	t.Helper()
	for j := i + 1; j < len(ordered); j++ {
		if ordered[i].Compare(ordered[j]) >= 0 || ordered[j].Compare(ordered[i]) <= 0 {
			t.Fatalf("Compare 全序律失败: i=%d (%q) vs j=%d (%q)", i, ordered[i], j, ordered[j])
		}
	}
}

func TestEndpointRejectsInvalidAndCompositeJSONv2(t *testing.T) {
	badEndpoints := []string{
		"", " example.com", "example.com ", "example.com:0", "example.com:022",
		"[2001:db8::1]:0", "[2001:db8::1]:022", "[2001:db8::1]extra",
		"[192.0.2.1]", "[example.com]", "1:2:3", ":22", "example.com:", "999.999.999.999:22",
	}
	for _, bad := range badEndpoints {
		if _, err := ParseEndpoint(bad); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ParseEndpoint(%q) = %v, 期望 ErrInvalidEndpoint", bad, err)
		}
	}

	type dto struct {
		Host     CanonicalHost `json:"host"`
		Forward  HostPort      `json:"forward"`
		Target   Endpoint      `json:"target"`
		Optional Endpoint      `json:"optional,omitzero"`
	}
	v4Host, _ := ParseCanonicalHost("192.0.2.10")
	fwd, _ := ParseHostPort("[2001:db8::1]:8443")
	target, _ := ParseEndpoint("example.com:2222")
	payload := dto{Host: v4Host, Forward: fwd, Target: target}

	encoded, err := jsonv2.Marshal(payload, jsonv2.Deterministic(true))
	wantEncoded := `{"host":"192.0.2.10","forward":"[2001:db8::1]:8443","target":"example.com:2222"}`
	if err != nil || string(encoded) != wantEncoded {
		t.Fatalf("Marshal(dto) = (%s, %v), 期望 %s", encoded, err, wantEncoded)
	}
	var decoded dto
	if err := jsonv2.Unmarshal(encoded, &decoded); err != nil ||
		!decoded.Host.Equal(v4Host) || !decoded.Forward.Equal(fwd) || !decoded.Target.Equal(target) || decoded.Optional.IsValid() {
		t.Fatalf("Unmarshal(dto) 失败: decoded=%+v err=%v", decoded, err)
	}
	var buf bytes.Buffer
	if err := jsonv2.MarshalWrite(&buf, payload, jsonv2.Deterministic(true)); err != nil || buf.String() != wantEncoded {
		t.Fatalf("MarshalWrite(dto) = (%q, %v)", buf.String(), err)
	}

	resetTarget := target
	if err := resetTarget.UnmarshalText([]byte("example.com:0")); !errors.Is(err, ErrInvalidEndpoint) || resetTarget.IsValid() {
		t.Fatalf("Endpoint.UnmarshalText 失败后未重置: target=%+v err=%v", resetTarget, err)
	}
	var nilEP *Endpoint
	var nilHost *CanonicalHost
	if err := nilEP.UnmarshalText([]byte("example.com:22")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Endpoint.UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}
	if err := nilHost.UnmarshalText([]byte("example.com")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil CanonicalHost.UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}
}

func FuzzParseCanonicalHost(f *testing.F) {
	for _, seed := range []string{"192.0.2.1", "2001:0DB8::1", "[fe80::1%eth0]", "Example.COM", "", "999.999.999.999"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		h, err := ParseCanonicalHost(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("ParseCanonicalHost(%q) 错误未包装 ErrInvalidHost: %v", raw, err)
			}
			return
		}
		h2, err := ParseCanonicalHost(h.String())
		if err != nil || !h.Equal(h2) {
			t.Fatalf("CanonicalHost 幂等性失败: raw=%q canon=%q err=%v", raw, h.String(), err)
		}
	})
}

func FuzzParseHostPort(f *testing.F) {
	for _, seed := range []string{"example.com:22", "[2001:db8::1]:443", "[fe80::1%eth0]:2222", "example.com:0", "example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		hp, err := ParseHostPort(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidHostPort) {
				t.Fatalf("ParseHostPort(%q) 错误未包装 ErrInvalidHostPort: %v", raw, err)
			}
			return
		}
		hp2, err := ParseHostPort(hp.String())
		if err != nil || !hp.Equal(hp2) {
			t.Fatalf("HostPort 幂等性失败: raw=%q canon=%q err=%v", raw, hp.String(), err)
		}
	})
}

func FuzzParseEndpoint(f *testing.F) {
	for _, seed := range []string{"example.com", "example.com:2222", "2001:db8::1", "[fe80::1%eth0]:22", "example.com:0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("ParseEndpoint(%q) 错误未包装 ErrInvalidEndpoint: %v", raw, err)
			}
			return
		}
		ep2, err := ParseEndpoint(ep.String())
		if err != nil || !ep.Equal(ep2) {
			t.Fatalf("Endpoint 幂等性失败: raw=%q canon=%q err=%v", raw, ep.String(), err)
		}
	})
}

func maxValidHostname253() string {
	l63 := strings.Repeat("a", 63)
	l61 := strings.Repeat("b", 61)
	return l63 + "." + l63 + "." + l63 + "." + l61
}
