package ssh

import (
	"errors"
	"net/netip"
	"testing"
)

func TestEndpoint_ZeroAndEqual(t *testing.T) {
	t.Parallel()

	var zero Endpoint
	if zero.IsValid() || zero.IsIP() || zero.Host() != "" || zero.Port() != 0 || zero.String() != "" {
		t.Fatalf("zero Endpoint invalid state: valid=%v ip=%v host=%q port=%d str=%q",
			zero.IsValid(), zero.IsIP(), zero.Host(), zero.Port(), zero.String())
	}
	if zero.Equal(zero) {
		t.Fatal("zero Endpoint must never equal itself (fail-closed)")
	}
	if _, err := zero.WithPort(2222); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("zero.WithPort error = %v, want ErrInvalidEndpoint", err)
	}

	valid, err := ParseEndpoint("Web.Example.COM:0")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if valid.Equal(zero) || zero.Equal(valid) {
		t.Fatal("valid Endpoint must never equal zero Endpoint")
	}
	if valid.Port() != 22 || valid.Host() != "web.example.com" || valid.String() != "web.example.com:22" {
		t.Fatalf("unexpected normalized endpoint: host=%q port=%d str=%q", valid.Host(), valid.Port(), valid.String())
	}
}

func TestEndpoint_NormalizationAndEquivalence(t *testing.T) {
	t.Parallel()

	eqCases := []struct {
		name string
		a, b string
		want bool
	}{
		{"case_folded_hostname_default_port", "Web.Example.COM", "web.example.com:22", true},
		{"surrounding_spaces_trimmed", "  Web.Example.COM:22  ", "web.example.com:22", true},
		{"zero_port_normalized_to_22", "web.example.com:0", "web.example.com:22", true},
		{"leading_zero_port", "web.example.com:0022", "web.example.com:22", true},
		{"different_ports_never_equal", "10.0.0.1:22", "10.0.0.1:2222", false},
		{"different_ports_hostname", "web.example.com:22", "web.example.com:2222", false},
		{"ipv6_bracketed_vs_bare", "[2001:0DB8::0001]", "2001:db8::1", true},
		{"ipv6_with_port", "[2001:0DB8::1]:2222", "[2001:db8::1]:2222", true},
		{"ipv6_zone_same_case", "[fe80::0001%eth0]:22", "fe80::1%eth0", true},
		{"ipv6_zone_case_sensitive", "fe80::1%eth0", "fe80::1%ETH0", false},
		{"ipv4_mapped_ipv6_canonical", "::ffff:10.0.0.1", "::ffff:0a00:0001", true},
		{"ipv4_mapped_distinct_from_ipv4", "::ffff:10.0.0.1", "10.0.0.1", false},
		{"single_label_hostname", "LocalHost", "localhost:22", true},
		{"digit_leading_rfc1123_label", "3com.Example.COM:2200", "3com.example.com:2200", true},
	}

	for _, tc := range eqCases {
		t.Run(tc.name, func(t *testing.T) {
			ea, err := ParseEndpoint(tc.a)
			if err != nil {
				t.Fatalf("ParseEndpoint(%q): %v", tc.a, err)
			}
			eb, err := ParseEndpoint(tc.b)
			if err != nil {
				t.Fatalf("ParseEndpoint(%q): %v", tc.b, err)
			}
			if got := ea.Equal(eb); got != tc.want {
				t.Errorf("(%q).Equal(%q) = %v, want %v (ea=%q eb=%q)", tc.a, tc.b, got, tc.want, ea.String(), eb.String())
			}
			if got := eb.Equal(ea); got != tc.want {
				t.Errorf("symmetry violated for %q vs %q", tc.a, tc.b)
			}
		})
	}
}

func TestEndpoint_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	badRaw := []string{
		"",
		"   ",
		":22",
		"example.com:",
		"example.com:-1",
		"example.com:+22",
		"example.com:65536",
		"example.com:abc",
		"example.com :22",
		"example.com: 22",
		"[ ::1 ]:22",
		"[::1] :22",
		"[10.0.0.1]:22",
		"[example.com]:22",
		"[::1",
		"::1]",
		"[[::1]]:22",
		"[::1]extra",
		"a:b:c",
		"example.com:22:22",
		".example.com",
		"example.com.",
		"a..b.com",
		"-bad.example.com",
		"bad-.example.com",
		"bad_host.example.com",
		"bad host.example.com",
		"999.999.999.999",
		"127.1",
		"12345",
		"example.com\n",
		"example.com\x00",
		"example.com\u2028",
		"[fe80::1%eth 0]:22",
		"[fe80::1%eth/0]:22",
		"a" + string(make([]byte, 64)) + ".com",
	}

	for _, raw := range badRaw {
		ep, err := ParseEndpoint(raw)
		if err == nil || !errors.Is(err, ErrInvalidEndpoint) || ep.IsValid() {
			t.Errorf("ParseEndpoint(%q) = (%+v, %v), want invalid + ErrInvalidEndpoint", raw, ep, err)
		}
	}

	if _, err := NewEndpoint("example.com", -1); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("NewEndpoint negative port err = %v", err)
	}
	if _, err := NewEndpoint("example.com", 65536); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("NewEndpoint port > 65535 err = %v", err)
	}
	if _, err := NewAddrEndpoint(netip.Addr{}, 22); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("NewAddrEndpoint invalid addr err = %v", err)
	}
	badZone := netip.MustParseAddr("fe80::1").WithZone("eth 0")
	if _, err := NewAddrEndpoint(badZone, 22); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("NewAddrEndpoint bad zone err = %v", err)
	}
}

func TestEndpoint_AccessorsAndWithPort(t *testing.T) {
	t.Parallel()

	ipEp, err := NewAddrEndpoint(netip.MustParseAddr("192.0.2.10"), 0)
	if err != nil {
		t.Fatalf("NewAddrEndpoint: %v", err)
	}
	if !ipEp.IsIP() || ipEp.Port() != 22 {
		t.Fatalf("unexpected ipEp: isIP=%v port=%d", ipEp.IsIP(), ipEp.Port())
	}
	if addr, ok := ipEp.Addr(); !ok || addr.String() != "192.0.2.10" {
		t.Fatalf("Addr() = (%v, %v)", addr, ok)
	}
	if h, ok := ipEp.Hostname(); ok || h != "" {
		t.Fatalf("Hostname() on IP = (%q, %v)", h, ok)
	}

	shifted, err := ipEp.WithPort(2222)
	if err != nil || shifted.Port() != 2222 || shifted.Equal(ipEp) {
		t.Fatalf("WithPort(2222) = (%+v, %v)", shifted, err)
	}
	back, err := shifted.WithPort(0)
	if err != nil || !back.Equal(ipEp) {
		t.Fatalf("WithPort(0) = (%+v, %v), want %+v", back, err, ipEp)
	}

	hostEp, err := NewEndpoint("DB-01.Prod.Example.COM", 2222)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if hostEp.IsIP() {
		t.Fatal("hostname Endpoint reported IsIP=true")
	}
	if _, ok := hostEp.Addr(); ok {
		t.Fatal("hostname Endpoint reported Addr ok=true")
	}
	if h, ok := hostEp.Hostname(); !ok || h != "db-01.prod.example.com" {
		t.Fatalf("Hostname() = (%q, %v)", h, ok)
	}
}

func TestEndpoint_HostEqual(t *testing.T) {
	t.Parallel()

	ipEp, err := NewAddrEndpoint(netip.MustParseAddr("192.0.2.10"), 22)
	if err != nil {
		t.Fatalf("NewAddrEndpoint: %v", err)
	}
	shifted, err := ipEp.WithPort(2222)
	if err != nil {
		t.Fatalf("WithPort(2222): %v", err)
	}
	if !shifted.HostEqual(ipEp) || !ipEp.HostEqual(shifted) {
		t.Fatalf("HostEqual should ignore port mismatch between %v and %v", shifted, ipEp)
	}
	var zeroEp Endpoint
	if zeroEp.HostEqual(zeroEp) || zeroEp.HostEqual(ipEp) || ipEp.HostEqual(zeroEp) {
		t.Fatal("HostEqual must fail closed for zero/invalid Endpoint")
	}
	otherIP, _ := NewEndpoint("192.0.2.11", 22)
	if ipEp.HostEqual(otherIP) {
		t.Fatalf("HostEqual(%v, %v) = true, want false", ipEp, otherIP)
	}
}

func FuzzEndpointRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:2222",
		"Web.Example.COM",
		"web.example.com:22",
		"[::1]",
		"[::1]:2222",
		"2001:db8::1",
		"[fe80::1%eth0]:22",
		"::ffff:10.0.0.1",
		"[10.0.0.1]:22",
		"999.999.999.999",
		"",
		"bad\n:22",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			if ep.IsValid() {
				t.Fatalf("ParseEndpoint(%q) returned error %v with valid endpoint %+v", raw, err, ep)
			}
			return
		}
		if !ep.IsValid() || ep.Port() == 0 {
			t.Fatalf("ParseEndpoint(%q) produced invalid endpoint %+v", raw, ep)
		}
		formatted := ep.String()
		reparsed, err := ParseEndpoint(formatted)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q) -> %q failed re-parse: %v", raw, formatted, err)
		}
		if !ep.Equal(reparsed) || reparsed.String() != formatted {
			t.Fatalf("round-trip mismatch for %q: first=%q reparsed=%q", raw, formatted, reparsed.String())
		}
		viaNew, err := NewEndpoint(ep.Host(), int(ep.Port()))
		if err != nil || !ep.Equal(viaNew) {
			t.Fatalf("NewEndpoint(%q, %d) = (%+v, %v), want %+v", ep.Host(), ep.Port(), viaNew, err, ep)
		}
	})
}
