package kdfhelper

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func fixtures(t testing.TB) map[string][]byte {
	t.Helper()
	b, err := os.ReadFile("../credentialfile/format/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(raw))
	for k, v := range raw {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = b
	}
	return out
}

func TestIndependentProtocolVectors(t *testing.T) {
	v := fixtures(t)
	r, err := ParseRequest(v["request"])
	if err != nil {
		t.Fatal(err)
	}
	defer r.Zero()
	if !bytes.Equal(r.Password, v["password"]) {
		t.Fatal("password bytes changed")
	}
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b)
	if !bytes.Equal(b, v["request"]) {
		t.Fatal("request differs")
	}
	for _, name := range []string{"response", "failure"} {
		t.Run(name, func(t *testing.T) {
			r, err := ParseResponse(v[name])
			if err != nil {
				t.Fatal(err)
			}
			defer r.Zero()
			b, err := r.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(b)
			if !bytes.Equal(b, v[name]) {
				t.Fatal("response differs")
			}
		})
	}
}

func TestProtocolRejectsMalformedInput(t *testing.T) {
	v := fixtures(t)
	for _, name := range []string{"request", "response", "failure"} {
		t.Run(name, func(t *testing.T) {
			parse := func(b []byte) error {
				if name == "request" {
					r, err := ParseRequest(b)
					r.Zero()
					return err
				}
				r, err := ParseResponse(b)
				r.Zero()
				return err
			}
			for n := 0; n < len(v[name]); n++ {
				if err := parse(v[name][:n]); err == nil {
					t.Fatalf("truncation %d accepted", n)
				}
			}
			if err := parse(append(bytes.Clone(v[name]), v[name]...)); err == nil {
				t.Fatal("multiple frames accepted")
			}
			if err := parse(append(bytes.Clone(v[name]), 0)); err == nil {
				t.Fatal("trailing byte accepted")
			}
		})
	}
	for _, offset := range []int{8, 10, 14, 15, 19, 23, 24, 42, 46} {
		b := bytes.Clone(v["request"])
		b[offset] ^= 0x80
		r, err := ParseRequest(b)
		r.Zero()
		if err == nil {
			t.Fatalf("invalid header at %d accepted", offset)
		}
	}
	for _, p := range [][]byte{nil, {0xff}, []byte("a\nb"), []byte("a\rb"), []byte("a\x00b"), bytes.Repeat([]byte("a"), 1025)} {
		if _, err := (Request{Password: p}).MarshalBinary(); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	for _, r := range []Response{{Status: Success}, {Status: InvalidRequest, Key: make([]byte, 32)}, {Status: 255}} {
		if _, err := r.MarshalBinary(); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
}

func TestProtocolCopiesAndClearsSecrets(t *testing.T) {
	v := fixtures(t)
	r, err := ParseRequest(v["request"])
	if err != nil {
		t.Fatal(err)
	}
	p := r.Password
	clear(v["request"])
	if !bytes.Equal(p, v["password"]) {
		t.Fatal("password aliases wire frame")
	}
	r.Zero()
	if !bytes.Equal(p, make([]byte, len(p))) || r.Password != nil {
		t.Fatal("password not cleared")
	}
	response, err := ParseResponse(v["response"])
	if err != nil {
		t.Fatal(err)
	}
	k := response.Key
	clear(v["response"])
	if !bytes.Equal(k, v["password_key"]) {
		t.Fatal("key aliases wire frame")
	}
	response.Zero()
	if !bytes.Equal(k, make([]byte, len(k))) {
		t.Fatal("key not cleared")
	}
}

func FuzzProtocol(f *testing.F) {
	v := fixtures(f)
	f.Add(v["request"])
	f.Add(v["response"])
	f.Add(v["failure"])
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseRequest(b); err == nil {
			defer r.Zero()
			out, err := r.MarshalBinary()
			defer clear(out)
			if err != nil || !bytes.Equal(out, b) {
				t.Fatal("noncanonical request")
			}
		}
		if r, err := ParseResponse(b); err == nil {
			defer r.Zero()
			out, err := r.MarshalBinary()
			defer clear(out)
			if err != nil || !bytes.Equal(out, b) {
				t.Fatal("noncanonical response")
			}
		}
	})
}
