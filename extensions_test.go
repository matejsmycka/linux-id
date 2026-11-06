package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/memory"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/matejsmycka/linux-id/tpm"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

// fakeDeriver is a SecretDeriver with a fixed key.
type fakeDeriver struct {
	mu    sync.Mutex
	key   []byte
	calls int
}

func (d *fakeDeriver) DeriveSecret(input []byte) ([]byte, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	mac := hmac.New(sha256.New, d.key)
	mac.Write(input)
	return mac.Sum(nil), nil
}

func newExtServer(t *testing.T, performsUV bool) (*server, *fakeVerifier) {
	t.Helper()
	v := &fakeVerifier{performsUV: performsUV, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	s.secrets = &fakeDeriver{key: []byte("fake deriver key")}
	return s, v
}

// restarted returns a server that shares s's keys, secrets and credential
// store but has fresh PIN/UV state, as after a daemon restart.
func restarted(t *testing.T, s *server) *server {
	t.Helper()
	pu, err := pinuv.New()
	if err != nil {
		t.Fatal(err)
	}
	// A restart keeps what is on disk: the store, the PIN and the generation.
	return &server{pe: s.pe, verifier: s.verifier, signer: s.signer, secrets: s.secrets, cs: s.cs, pinuv: pu,
		pin: s.pin, gens: s.gens, startedAt: time.Now()}
}

var testCDH = bytes.Repeat([]byte{0xcd}, 32)

type mcResult struct {
	status   byte
	credID   []byte
	pub      *ecdsa.PublicKey
	flags    byte
	authData []byte
	ext      map[string]cbor.RawMessage
}

func makeCred(t *testing.T, s *server, rpID, user string, rk bool, exts *ctap2.MakeCredExts) mcResult {
	t.Helper()
	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   testCDH,
		RP:               ctap2.RPEntity{ID: rpID},
		User:             ctap2.UserEntity{ID: []byte(user), Name: user},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
		Extensions:       exts,
	}
	if rk {
		req.Options = &ctap2.MakeCredOptions{RK: true}
	}
	payload, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: append([]byte{ctap2.CmdMakeCredential}, payload...)})
	w := resp.lastCtap2()
	if w.status != ctap2.StatusOK {
		return mcResult{status: w.status}
	}
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(w.data, &top); err != nil {
		t.Fatal(err)
	}
	r := mcResult{status: w.status}
	if err := cbor.Unmarshal(top[2], &r.authData); err != nil {
		t.Fatal(err)
	}
	ad := r.authData
	r.flags = ad[32]
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	r.credID = ad[55 : 55+n]
	var cose map[int]interface{}
	rest, err := cbor.UnmarshalFirst(ad[55+n:], &cose)
	if err != nil {
		t.Fatal(err)
	}
	r.pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(cose[-2].([]byte)), Y: new(big.Int).SetBytes(cose[-3].([]byte))}
	if r.flags&ctap2.AuthFlagED != 0 {
		if rest, err = cbor.UnmarshalFirst(rest, &r.ext); err != nil {
			t.Fatal(err)
		}
	}
	if len(rest) != 0 {
		t.Fatalf("%d trailing bytes after authenticatorData (ED=%v)", len(rest), r.flags&ctap2.AuthFlagED != 0)
	}
	return r
}

type gaResult struct {
	status   byte
	credID   []byte
	flags    byte
	authData []byte
	sig      []byte
	ext      map[string]cbor.RawMessage
	top      map[int]cbor.RawMessage
}

func parseAssertion(t *testing.T, w ctap2Write) gaResult {
	t.Helper()
	r := gaResult{status: w.status}
	if w.status != ctap2.StatusOK {
		return r
	}
	r.top = decodeAssertion(t, w.data)
	r.credID = credIDOf(t, r.top)
	cbor.Unmarshal(r.top[2], &r.authData)
	cbor.Unmarshal(r.top[3], &r.sig)
	r.flags = r.authData[32]
	if r.flags&ctap2.AuthFlagED != 0 {
		rest, err := cbor.UnmarshalFirst(r.authData[37:], &r.ext)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) != 0 {
			t.Fatalf("%d trailing bytes after extensions", len(rest))
		}
	} else if len(r.authData) != 37 {
		t.Fatalf("authData is %d bytes without ED", len(r.authData))
	}
	return r
}

func getAssertion(t *testing.T, s *server, rpID string, allow [][]byte, opts *ctap2.GetAssertOptions, exts *ctap2.GetAssertExts) gaResult {
	t.Helper()
	req := ctap2.GetAssertionRequest{RPID: rpID, ClientDataHash: testCDH, Options: opts, Extensions: exts}
	for _, id := range allow {
		req.AllowList = append(req.AllowList, ctap2.CredDescriptor{Type: "public-key", ID: id})
	}
	payload, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: append([]byte{ctap2.CmdGetAssertion}, payload...)})
	return parseAssertion(t, resp.lastCtap2())
}

func getNextAssertion(t *testing.T, s *server) gaResult {
	t.Helper()
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdGetNextAssertion}})
	return parseAssertion(t, resp.lastCtap2())
}

// platform is the client side of hmac-secret, built on go-ctap's platform
// crypto.
type platform struct {
	p      protocol.PinUvAuthProtocol
	pp     *ctapcrypto.PinUvAuthProtocol
	key    map[int]any
	secret []byte
}

func newPlatform(t *testing.T, s *server, p protocol.PinUvAuthProtocol) *platform {
	t.Helper()
	authKey, err := s.pinuv.KeyAgreement()
	if err != nil {
		t.Fatal(err)
	}
	pp, err := ctapcrypto.NewPinUvAuthProtocol(p)
	if err != nil {
		t.Fatal(err)
	}
	key, secret, err := pp.Encapsulate(authKey)
	if err != nil {
		t.Fatal(err)
	}
	return &platform{p: p, pp: pp, key: key, secret: secret}
}

func (pl *platform) input(t *testing.T, salts ...[]byte) *protocol.HMACSecret {
	t.Helper()
	enc, err := pl.pp.Encrypt(pl.secret, bytes.Join(salts, nil))
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.HMACSecret{
		KeyAgreement:      pl.key,
		SaltEnc:           enc,
		SaltAuth:          ctapcrypto.Authenticate(pl.p, pl.secret, enc),
		PinUvAuthProtocol: pl.p,
	}
}

func (pl *platform) output(t *testing.T, ext map[string]cbor.RawMessage, name string) []byte {
	t.Helper()
	raw, ok := ext[name]
	if !ok {
		t.Fatalf("no %s output in %v", name, ext)
	}
	var enc []byte
	if err := cbor.Unmarshal(raw, &enc); err != nil {
		t.Fatal(err)
	}
	out, err := pl.pp.Decrypt(pl.secret, enc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func salt(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func hmacExt(in *protocol.HMACSecret) *ctap2.GetAssertExts {
	return &ctap2.GetAssertExts{HmacSecret: in}
}

var protocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo}

func TestGetInfo_Extensions(t *testing.T) {
	s, _ := newExtServer(t, true)
	resp := &fakeResponder{}
	s.handleGetInfo(context.Background(), resp, fidohid.AuthEvent{})
	var info protocol.AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(resp.lastCtap2().data, &info); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range info.Extensions {
		got = append(got, string(e))
	}
	if want := []string{"credProtect", "hmac-secret", "hmac-secret-mc"}; !slices.Equal(got, want) {
		t.Errorf("extensions = %v, want %v", got, want)
	}

	// Without a SecretDeriver, hmac-secret is not offered.
	s.secrets = nil
	resp = &fakeResponder{}
	s.handleGetInfo(context.Background(), resp, fidohid.AuthEvent{})
	cbor.Unmarshal(resp.lastCtap2().data, &info)
	if len(info.Extensions) != 1 || info.Extensions[0] != "credProtect" {
		t.Errorf("extensions without deriver = %v", info.Extensions)
	}
}

func TestMakeCredential_ExtensionOutputs(t *testing.T) {
	s, _ := newExtServer(t, true)
	r := makeCred(t, s, "ext.example", "u", false, &ctap2.MakeCredExts{CredProtect: 2, HmacSecret: true})
	if r.status != ctap2.StatusOK {
		t.Fatalf("status 0x%02x", r.status)
	}
	if r.flags&ctap2.AuthFlagED == 0 {
		t.Fatal("ED flag not set")
	}
	var ext map[string]interface{}
	raw, _ := cbor.Marshal(r.ext)
	cbor.Unmarshal(raw, &ext)
	if ext["credProtect"] != uint64(2) || ext["hmac-secret"] != true || len(ext) != 2 {
		t.Errorf("extensions = %v", ext)
	}
	// The extensions map must be canonical.
	enc, _ := ctap2Enc.Marshal(ext)
	if !bytes.HasSuffix(r.authData, enc) {
		t.Error("extensions map is not canonically encoded")
	}

	// No extensions: no ED flag; the credential ID still carries the header.
	r = makeCred(t, s, "ext.example", "v", false, nil)
	if r.flags&ctap2.AuthFlagED != 0 || r.ext != nil {
		t.Error("ED set without extensions")
	}
	if !bytes.HasPrefix(r.credID, []byte(credIDMagic)) {
		t.Error("credential without options has no header")
	}

	// Unsupported credProtect values are ignored; hmac-secret: false gives no output.
	r = makeCred(t, s, "ext.example", "w", false, &ctap2.MakeCredExts{CredProtect: 7})
	if r.status != ctap2.StatusOK || r.flags&ctap2.AuthFlagED != 0 {
		t.Errorf("credProtect 7: status 0x%02x flags 0x%02x", r.status, r.flags)
	}
}

func TestHmacSecret_Salts(t *testing.T) {
	for _, p := range protocols {
		t.Run(fmt.Sprintf("protocol%d", p), func(t *testing.T) {
			s, _ := newExtServer(t, true)
			mc := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecret: true})
			pl := newPlatform(t, s, p)
			rpIdHash := rpIDHash("prf.example")
			credRandom, err := s.credRandom(mc.credID, rpIdHash[:], true)
			if err != nil {
				t.Fatal(err)
			}

			one := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1))))
			if one.status != ctap2.StatusOK {
				t.Fatalf("status 0x%02x", one.status)
			}
			if one.flags&(ctap2.AuthFlagED|ctap2.AuthFlagUV) != ctap2.AuthFlagED|ctap2.AuthFlagUV {
				t.Fatalf("flags 0x%02x", one.flags)
			}
			out1 := pl.output(t, one.ext, "hmac-secret")
			if !bytes.Equal(out1, hmacSHA256(credRandom, salt(1))) {
				t.Fatal("one-salt output is not HMAC(CredRandomWithUV, salt1)")
			}

			two := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1), salt(2))))
			out2 := pl.output(t, two.ext, "hmac-secret")
			if len(out2) != 64 || !bytes.Equal(out2[:32], out1) || !bytes.Equal(out2[32:], hmacSHA256(credRandom, salt(2))) {
				t.Fatal("two-salt output is wrong")
			}

			// The signature covers the authenticatorData with extensions.
			digest := sha256.Sum256(append(append([]byte(nil), two.authData...), testCDH...))
			if !ecdsa.VerifyASN1(mc.pub, digest[:], two.sig) {
				t.Fatal("signature over authData with extensions does not verify")
			}
		})
	}
}

func TestHmacSecret_DefaultProtocolIsOne(t *testing.T) {
	s, _ := newExtServer(t, true)
	mc := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecret: true})
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolOne)
	in := pl.input(t, salt(1))
	in.PinUvAuthProtocol = 0
	r := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(in))
	if r.status != ctap2.StatusOK || len(pl.output(t, r.ext, "hmac-secret")) != 32 {
		t.Fatalf("status 0x%02x", r.status)
	}
}

func TestHmacSecret_UVSelectsCredRandom(t *testing.T) {
	s, v := newExtServer(t, true)
	mc := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecret: true})
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)

	withUV := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1))))
	v.performsUV = false // presence only
	withoutUV := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1))))
	if withUV.flags&ctap2.AuthFlagUV == 0 || withoutUV.flags&ctap2.AuthFlagUV != 0 {
		t.Fatalf("flags 0x%02x / 0x%02x", withUV.flags, withoutUV.flags)
	}
	a, b := pl.output(t, withUV.ext, "hmac-secret"), pl.output(t, withoutUV.ext, "hmac-secret")
	if bytes.Equal(a, b) {
		t.Fatal("UV and non-UV outputs are equal")
	}
	rpIdHash := rpIDHash("prf.example")
	cr, _ := s.credRandom(mc.credID, rpIdHash[:], false)
	if !bytes.Equal(b, hmacSHA256(cr, salt(1))) {
		t.Fatal("non-UV output is not HMAC(CredRandomWithoutUV, salt)")
	}
}

func TestHmacSecret_StableAcrossRestartAndPerCredential(t *testing.T) {
	s, _ := newExtServer(t, true)
	mcA := makeCred(t, s, "prf.example", "a", true, &ctap2.MakeCredExts{HmacSecret: true})
	mcB := makeCred(t, s, "prf.example", "b", false, &ctap2.MakeCredExts{HmacSecret: true})

	eval := func(s *server, id []byte) []byte {
		pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)
		var allow [][]byte
		if id != nil {
			allow = [][]byte{id}
		}
		r := getAssertion(t, s, "prf.example", allow, nil, hmacExt(pl.input(t, salt(9))))
		if r.status != ctap2.StatusOK {
			t.Fatalf("status 0x%02x", r.status)
		}
		return pl.output(t, r.ext, "hmac-secret")
	}
	a1, b1 := eval(s, nil), eval(s, mcB.credID) // resident (discoverable) and non-resident
	s2 := restarted(t, s)
	a2, b2 := eval(s2, nil), eval(s2, mcB.credID)
	if !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
		t.Fatal("hmac-secret output changed across a restart")
	}
	if a3 := eval(s2, mcA.credID); !bytes.Equal(a1, a3) {
		t.Fatal("resident credential gives different output via allowList")
	}
	if bytes.Equal(a1, b1) {
		t.Fatal("two credentials give the same output")
	}
}

func TestHmacSecret_CredentialWithoutHmacSecret(t *testing.T) {
	s, _ := newExtServer(t, true)
	mc := makeCred(t, s, "prf.example", "u", false, nil)
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)
	r := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1))))
	if r.status != ctap2.StatusOK || r.flags&ctap2.AuthFlagED != 0 {
		t.Fatalf("status 0x%02x flags 0x%02x", r.status, r.flags)
	}
}

func TestHmacSecret_InvalidInputs(t *testing.T) {
	s, v := newExtServer(t, true)
	mc := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecret: true})
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)

	cases := []struct {
		name   string
		mutate func(*protocol.HMACSecret)
		want   byte
	}{
		{"bad saltAuth", func(h *protocol.HMACSecret) { h.SaltAuth[0] ^= 1 }, ctap2.StatusPinAuthInvalid},
		{"truncated saltAuth", func(h *protocol.HMACSecret) { h.SaltAuth = h.SaltAuth[:16] }, ctap2.StatusPinAuthInvalid},
		{"saltAuth for protocol 1", func(h *protocol.HMACSecret) { h.PinUvAuthProtocol = protocol.PinUvAuthProtocolOne }, ctap2.StatusPinAuthInvalid},
		{"missing saltAuth", func(h *protocol.HMACSecret) { h.SaltAuth = nil }, ctap2.StatusMissingParameter},
		{"missing saltEnc", func(h *protocol.HMACSecret) { h.SaltEnc = nil }, ctap2.StatusMissingParameter},
		{"missing keyAgreement", func(h *protocol.HMACSecret) { h.KeyAgreement = nil }, ctap2.StatusMissingParameter},
		{"unsupported protocol", func(h *protocol.HMACSecret) { h.PinUvAuthProtocol = 3 }, ctap2.StatusInvalidParameter},
		{"bad keyAgreement", func(h *protocol.HMACSecret) {
			h.KeyAgreement = map[int]any{1: 2, 3: -25, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)}
		}, ctap2.StatusInvalidParameter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := pl.input(t, salt(1))
			c.mutate(in)
			before := v.callCount
			r := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(in))
			if r.status != c.want {
				t.Fatalf("status 0x%02x, want 0x%02x", r.status, c.want)
			}
			if v.callCount != before {
				t.Error("user was asked for a request with invalid hmac-secret input")
			}
		})
	}

	t.Run("salt length", func(t *testing.T) {
		r := getAssertion(t, s, "prf.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, make([]byte, 48))))
		if r.status != ctap2.StatusInvalidLength {
			t.Fatalf("status 0x%02x", r.status)
		}
	})
}

func TestHmacSecret_GetNextAssertion(t *testing.T) {
	s, _ := newExtServer(t, true)
	makeCred(t, s, "prf.example", "a", true, &ctap2.MakeCredExts{HmacSecret: true})
	makeCred(t, s, "prf.example", "b", true, nil)
	makeCred(t, s, "prf.example", "c", true, &ctap2.MakeCredExts{HmacSecret: true})
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolOne)
	rpIdHash := rpIDHash("prf.example")

	first := getAssertion(t, s, "prf.example", nil, nil, hmacExt(pl.input(t, salt(5))))
	results := []gaResult{first, getNextAssertion(t, s), getNextAssertion(t, s)}
	withOutput := 0
	for _, r := range results {
		if r.status != ctap2.StatusOK {
			t.Fatalf("status 0x%02x", r.status)
		}
		if !credOptionsOf(r.credID).hmacSecret {
			if r.flags&ctap2.AuthFlagED != 0 {
				t.Error("output for a credential without hmac-secret")
			}
			continue
		}
		withOutput++
		cr, _ := s.credRandom(r.credID, rpIdHash[:], true)
		if !bytes.Equal(pl.output(t, r.ext, "hmac-secret"), hmacSHA256(cr, salt(5))) {
			t.Error("wrong output")
		}
	}
	if withOutput != 2 {
		t.Errorf("%d outputs, want 2", withOutput)
	}
}

func TestHmacSecretMC(t *testing.T) {
	for _, p := range protocols {
		t.Run(fmt.Sprintf("protocol%d", p), func(t *testing.T) {
			s, _ := newExtServer(t, true)
			pl := newPlatform(t, s, p)
			mc := makeCred(t, s, "prf.example", "u", true, &ctap2.MakeCredExts{HmacSecret: true, HmacSecretMC: pl.input(t, salt(1), salt(2))})
			if mc.status != ctap2.StatusOK {
				t.Fatalf("status 0x%02x", mc.status)
			}
			atCreate := pl.output(t, mc.ext, "hmac-secret-mc")
			r := getAssertion(t, s, "prf.example", nil, nil, hmacExt(pl.input(t, salt(1), salt(2))))
			if got := pl.output(t, r.ext, "hmac-secret"); !bytes.Equal(got, atCreate) {
				t.Fatal("hmac-secret-mc output differs from the assertion's")
			}
		})
	}

	s, v := newExtServer(t, true)
	pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)
	bad := pl.input(t, salt(1))
	bad.SaltAuth[0] ^= 1
	if r := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecret: true, HmacSecretMC: bad}); r.status != ctap2.StatusPinAuthInvalid {
		t.Errorf("bad saltAuth: status 0x%02x", r.status)
	}
	if v.callCount != 0 {
		t.Error("user was asked for a request with invalid hmac-secret-mc input")
	}
	// Without hmac-secret: true, hmac-secret-mc is ignored.
	r := makeCred(t, s, "prf.example", "u", false, &ctap2.MakeCredExts{HmacSecretMC: pl.input(t, salt(1))})
	if r.status != ctap2.StatusOK || r.flags&ctap2.AuthFlagED != 0 {
		t.Errorf("status 0x%02x flags 0x%02x", r.status, r.flags)
	}
}

func TestCredProtect(t *testing.T) {
	type check struct {
		allowList bool
		uv        bool
		usable    bool
	}
	levels := map[int][]check{
		1: {{false, false, true}, {true, false, true}, {false, true, true}, {true, true, true}},
		2: {{false, false, false}, {true, false, true}, {false, true, true}, {true, true, true}},
		3: {{false, false, false}, {true, false, false}, {false, true, true}, {true, true, true}},
	}
	for level, checks := range levels {
		for _, rk := range []bool{true, false} {
			t.Run(fmt.Sprintf("level%d/rk=%v", level, rk), func(t *testing.T) {
				s, v := newExtServer(t, true)
				mc := makeCred(t, s, "cp.example", "u", rk, &ctap2.MakeCredExts{CredProtect: level})
				var ext map[string]int
				raw, _ := cbor.Marshal(mc.ext)
				cbor.Unmarshal(raw, &ext)
				if ext["credProtect"] != level {
					t.Fatalf("credProtect output %v", mc.ext)
				}
				if rk {
					stored, _ := s.cs.FindByRPID(func() []byte { h := rpIDHash("cp.example"); return h[:] }())
					if len(stored) != 1 || stored[0].CredProtect != level {
						t.Fatalf("stored credProtect = %+v", stored)
					}
				}
				for _, c := range checks {
					if !c.allowList && !rk {
						continue
					}
					v.performsUV = c.uv
					var allow [][]byte
					if c.allowList {
						allow = [][]byte{mc.credID}
					}
					before := v.callCount
					r := getAssertion(t, s, "cp.example", allow, nil, nil)
					if c.usable != (r.status == ctap2.StatusOK) {
						t.Errorf("allowList=%v uv=%v: status 0x%02x, want usable=%v", c.allowList, c.uv, r.status, c.usable)
					}
					if !c.usable && (r.status != ctap2.StatusNoCredentials || v.callCount != before) {
						t.Errorf("allowList=%v uv=%v: status 0x%02x, verifier calls %d; want NO_CREDENTIALS before asking the user", c.allowList, c.uv, r.status, v.callCount-before)
					}
				}
			})
		}
	}
}

// A silent probe (up=false) involves no user verification, so it never
// reveals credentials that need it.
func TestCredProtect_SilentProbe(t *testing.T) {
	s, _ := newExtServer(t, true)
	l3 := makeCred(t, s, "cp.example", "u", false, &ctap2.MakeCredExts{CredProtect: 3})
	l2 := makeCred(t, s, "cp.example", "v", true, &ctap2.MakeCredExts{CredProtect: 2})
	probe := &ctap2.GetAssertOptions{UP: boolPtr(false)}
	if r := getAssertion(t, s, "cp.example", [][]byte{l3.credID}, probe, nil); r.status != ctap2.StatusNoCredentials {
		t.Errorf("level 3 probe: status 0x%02x", r.status)
	}
	if r := getAssertion(t, s, "cp.example", [][]byte{l2.credID}, probe, nil); r.status != ctap2.StatusOK {
		t.Errorf("level 2 probe with allowList: status 0x%02x", r.status)
	}
	if r := getAssertion(t, s, "cp.example", nil, probe, nil); r.status != ctap2.StatusNoCredentials {
		t.Errorf("level 2 discoverable probe: status 0x%02x", r.status)
	}
}

func TestCredProtect_DiscoverableSkipsProtected(t *testing.T) {
	s, v := newExtServer(t, true)
	open := makeCred(t, s, "cp.example", "open", true, nil)
	makeCred(t, s, "cp.example", "l2", true, &ctap2.MakeCredExts{CredProtect: 2})
	makeCred(t, s, "cp.example", "l3", true, &ctap2.MakeCredExts{CredProtect: 3})

	v.performsUV = false
	r := getAssertion(t, s, "cp.example", nil, nil, nil)
	if r.status != ctap2.StatusOK || !bytes.Equal(r.credID, open.credID) || r.top[5] != nil {
		t.Fatalf("without UV: status 0x%02x, want only the unprotected credential", r.status)
	}
	v.performsUV = true
	r = getAssertion(t, s, "cp.example", nil, nil, nil)
	var n int
	cbor.Unmarshal(r.top[5], &n)
	if n != 3 {
		t.Fatalf("with UV: numberOfCredentials %d, want 3", n)
	}
}

// The options in a credential ID are bound to its key: changing or stripping
// them makes the credential unusable, while plain key handles (credentials
// without options and those from before this format) keep working.
func TestCredentialID_OptionsBoundToKey(t *testing.T) {
	s, v := newExtServer(t, true)
	mem, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	s.signer = mem
	mc := makeCred(t, s, "cp.example", "u", false, &ctap2.MakeCredExts{CredProtect: 3, HmacSecret: true})
	if !bytes.HasPrefix(mc.credID, []byte(credIDMagic)) {
		t.Fatal("no options header")
	}
	v.performsUV = false

	stripped := mc.credID[credIDHeaderLen:]
	downgraded := slices.Clone(mc.credID)
	downgraded[len(credIDMagic)] = 1
	for name, id := range map[string][]byte{"stripped": stripped, "downgraded": downgraded} {
		if r := getAssertion(t, s, "cp.example", [][]byte{id}, nil, nil); r.status != ctap2.StatusNoCredentials {
			t.Errorf("%s credential ID: status 0x%02x", name, r.status)
		}
	}
	v.performsUV = true
	if r := getAssertion(t, s, "cp.example", [][]byte{mc.credID}, nil, nil); r.status != ctap2.StatusOK {
		t.Errorf("genuine credential ID: status 0x%02x", r.status)
	}
	if r := getAssertion(t, s, "other.example", [][]byte{mc.credID}, nil, nil); r.status != ctap2.StatusNoCredentials {
		t.Errorf("other RP: status 0x%02x", r.status)
	}

	// A bare key handle registered for the plain rpIdHash is a legacy
	// credential: usable until a reset (legacy_test.go).
	app := rpIDHash("cp.example")
	bare, _, _, err := mem.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	if r := getAssertion(t, s, "cp.example", [][]byte{bare}, nil, nil); r.status != ctap2.StatusOK {
		t.Fatalf("legacy key handle: status 0x%02x", r.status)
	}
}

// TestExtensions_TPM runs MakeCredential and GetAssertion with hmac-secret
// and credProtect against the real TPM backend. It is skipped unless
// LINUXID_TPM_TEST=1, and creates only transient TPM objects.
func TestExtensions_TPM(t *testing.T) {
	if os.Getenv("LINUXID_TPM_TEST") != "1" {
		t.Skip("set LINUXID_TPM_TEST=1 to run against the TPM")
	}
	dev := os.Getenv("LINUXID_TPM_DEVICE")
	if dev == "" {
		dev = "/dev/tpmrm0"
	}
	tp, err := tpm.New(dev)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newExtServer(t, true)
	s.signer, s.secrets = tp, tp

	mc := makeCred(t, s, "tpm.example", "u", false, &ctap2.MakeCredExts{CredProtect: 3, HmacSecret: true})
	if mc.status != ctap2.StatusOK {
		t.Fatalf("status 0x%02x", mc.status)
	}
	eval := func(s *server) gaResult {
		pl := newPlatform(t, s, protocol.PinUvAuthProtocolTwo)
		r := getAssertion(t, s, "tpm.example", [][]byte{mc.credID}, nil, hmacExt(pl.input(t, salt(1))))
		if r.status != ctap2.StatusOK {
			t.Fatalf("status 0x%02x", r.status)
		}
		digest := sha256.Sum256(append(append([]byte(nil), r.authData...), testCDH...))
		if !ecdsa.VerifyASN1(mc.pub, digest[:], r.sig) {
			t.Fatal("signature does not verify")
		}
		r.ext["out"], _ = cbor.Marshal(pl.output(t, r.ext, "hmac-secret"))
		return r
	}
	a := eval(s)
	tp2, err := tpm.New(dev)
	if err != nil {
		t.Fatal(err)
	}
	s2 := restarted(t, s)
	s2.signer, s2.secrets = tp2, tp2
	if b := eval(s2); !bytes.Equal(a.ext["out"], b.ext["out"]) {
		t.Fatal("output changed across a restart")
	}
	stripped := mc.credID[credIDHeaderLen:]
	if r := getAssertion(t, s, "tpm.example", [][]byte{stripped}, nil, nil); r.status != ctap2.StatusNoCredentials {
		t.Fatalf("stripped credential ID: status 0x%02x", r.status)
	}
}
