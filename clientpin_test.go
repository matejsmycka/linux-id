package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/memory"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/telesma-app/ctap/cose"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

// testPINStore is a PIN store in a temp dir with a cheap KDF, so tests
// never touch ~/.config and -race runs stay fast.
func testPINStore(t *testing.T) *pinStore {
	t.Helper()
	mem, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	return newPINStore(filepath.Join(t.TempDir(), "pin.json"), mem)
}

// pinPlatform plays the platform side of the PIN protocol with go-ctap's
// platform implementation.
type pinPlatform struct {
	t *testing.T
	s *server
	p protocol.PinUvAuthProtocol
}

func (pl pinPlatform) send(req protocol.AuthenticatorClientPINRequest) (byte, protocol.AuthenticatorClientPINResponse) {
	pl.t.Helper()
	b, err := ctap2Enc.Marshal(req)
	if err != nil {
		pl.t.Fatal(err)
	}
	r := &fakeResponder{}
	pl.s.handleClientPIN(context.Background(), r, fidohid.AuthEvent{}, b)
	var resp protocol.AuthenticatorClientPINResponse
	w := r.lastCtap2()
	if w.status == ctap2.StatusOK && len(w.data) > 0 {
		if err := cbor.Unmarshal(w.data, &resp); err != nil {
			pl.t.Fatal(err)
		}
	}
	return w.status, resp
}

// session runs getKeyAgreement and encapsulates, returning the platform key
// and shared secret for one PIN operation.
func (pl pinPlatform) session() (*ctapcrypto.PinUvAuthProtocol, cose.Key, []byte) {
	pl.t.Helper()
	st, resp := pl.send(protocol.AuthenticatorClientPINRequest{PinUvAuthProtocol: pl.p, SubCommand: protocol.ClientPINSubCommandGetKeyAgreement})
	if st != ctap2.StatusOK {
		pl.t.Fatalf("getKeyAgreement: 0x%02x", st)
	}
	proto, err := ctapcrypto.NewPinUvAuthProtocol(pl.p)
	if err != nil {
		pl.t.Fatal(err)
	}
	key, secret, err := proto.Encapsulate(resp.KeyAgreement)
	if err != nil {
		pl.t.Fatal(err)
	}
	return proto, key, secret
}

func padPIN(pin string) []byte {
	b := make([]byte, paddedPINLen)
	copy(b, pin)
	return b
}

func pinHashOf(pin string) []byte {
	h := sha256.Sum256([]byte(pin))
	return h[:16]
}

func (pl pinPlatform) setPINRaw(padded []byte) byte {
	pl.t.Helper()
	proto, key, secret := pl.session()
	enc, err := proto.Encrypt(secret, padded)
	if err != nil {
		pl.t.Fatal(err)
	}
	st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pl.p, SubCommand: protocol.ClientPINSubCommandSetPIN, KeyAgreement: key,
		NewPinEnc: enc, PinUvAuthParam: ctapcrypto.Authenticate(pl.p, secret, enc),
	})
	return st
}

func (pl pinPlatform) setPIN(pin string) byte { pl.t.Helper(); return pl.setPINRaw(padPIN(pin)) }

func (pl pinPlatform) changePIN(old, pin string) byte {
	pl.t.Helper()
	proto, key, secret := pl.session()
	hashEnc, err := proto.Encrypt(secret, pinHashOf(old))
	if err != nil {
		pl.t.Fatal(err)
	}
	newEnc, err := proto.Encrypt(secret, padPIN(pin))
	if err != nil {
		pl.t.Fatal(err)
	}
	st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pl.p, SubCommand: protocol.ClientPINSubCommandChangePIN, KeyAgreement: key,
		PinHashEnc: hashEnc, NewPinEnc: newEnc,
		PinUvAuthParam: ctapcrypto.Authenticate(pl.p, secret, slices.Concat(newEnc, hashEnc)),
	})
	return st
}

// tokenWithPIN uses getPinUvAuthTokenUsingPinWithPermissions, or the legacy
// getPinToken when perms is 0.
func (pl pinPlatform) tokenWithPIN(pin string, perms protocol.Permission, rpID string) ([]byte, byte) {
	pl.t.Helper()
	proto, key, secret := pl.session()
	hashEnc, err := proto.Encrypt(secret, pinHashOf(pin))
	if err != nil {
		pl.t.Fatal(err)
	}
	req := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pl.p, SubCommand: protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement: key, PinHashEnc: hashEnc, Permissions: perms, RPID: rpID,
	}
	if perms == 0 {
		req.SubCommand = protocol.ClientPINSubCommandGetPinToken
	}
	st, resp := pl.send(req)
	if st != ctap2.StatusOK {
		return nil, st
	}
	tok, err := proto.Decrypt(secret, resp.PinUvAuthToken)
	if err != nil {
		pl.t.Fatal(err)
	}
	return tok, st
}

func (pl pinPlatform) tokenWithUV(perms protocol.Permission, rpID string) ([]byte, byte) {
	pl.t.Helper()
	proto, key, secret := pl.session()
	st, resp := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pl.p, SubCommand: protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement: key, Permissions: perms, RPID: rpID,
	})
	if st != ctap2.StatusOK {
		return nil, st
	}
	tok, err := proto.Decrypt(secret, resp.PinUvAuthToken)
	if err != nil {
		pl.t.Fatal(err)
	}
	return tok, st
}

func (pl pinPlatform) retries() (pin uint, powerCycle bool, uv uint) {
	pl.t.Helper()
	st, resp := pl.send(protocol.AuthenticatorClientPINRequest{SubCommand: protocol.ClientPINSubCommandGetPINRetries})
	if st != ctap2.StatusOK || resp.PinRetries == nil || resp.PowerCycleState == nil {
		pl.t.Fatalf("getPINRetries: 0x%02x %+v", st, resp)
	}
	st, uvResp := pl.send(protocol.AuthenticatorClientPINRequest{SubCommand: protocol.ClientPINSubCommandGetUVRetries})
	if st != ctap2.StatusOK || uvResp.UvRetries == nil {
		pl.t.Fatalf("getUVRetries: 0x%02x", st)
	}
	return *resp.PinRetries, *resp.PowerCycleState, *uvResp.UvRetries
}

const mcga = protocol.PermissionMakeCredential | protocol.PermissionGetAssertion

// makeCred runs MakeCredential, authorised by tok if non-nil, and returns
// the status and authenticatorData flags.
func pinMakeCred(t *testing.T, s *server, p protocol.PinUvAuthProtocol, tok []byte, rpID string, rk, uv bool) (byte, byte) {
	t.Helper()
	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   bytes.Repeat([]byte{7}, 32),
		RP:               ctap2.RPEntity{ID: rpID},
		User:             ctap2.UserEntity{ID: []byte("u-" + rpID), Name: "u"},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
		Options:          &ctap2.MakeCredOptions{RK: rk, UV: uv},
	}
	if tok != nil {
		req.PinUvAuthParam = ctapcrypto.Authenticate(p, tok, req.ClientDataHash)
		req.PinUvAuthProtocol = p
	}
	b, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeResponder{}
	s.handleMakeCredential(context.Background(), r, fidohid.AuthEvent{}, b)
	return r.lastCtap2().status, flagsOf(t, r.lastCtap2())
}

func pinGetAssertion(t *testing.T, s *server, p protocol.PinUvAuthProtocol, tok []byte, rpID string, uv bool) (byte, byte) {
	t.Helper()
	req := ctap2.GetAssertionRequest{RPID: rpID, ClientDataHash: bytes.Repeat([]byte{9}, 32)}
	if uv {
		req.Options = &ctap2.GetAssertOptions{UV: true}
	}
	if tok != nil {
		req.PinUvAuthParam = ctapcrypto.Authenticate(p, tok, req.ClientDataHash)
		req.PinUvAuthProtocol = p
	}
	b, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeResponder{}
	s.handleGetAssertion(context.Background(), r, fidohid.AuthEvent{}, b)
	return r.lastCtap2().status, flagsOf(t, r.lastCtap2())
}

func flagsOf(t *testing.T, w ctap2Write) byte {
	t.Helper()
	if w.status != ctap2.StatusOK {
		return 0
	}
	top := decodeAssertion(t, w.data)
	var authData []byte
	if err := cbor.Unmarshal(top[2], &authData); err != nil || len(authData) < 33 {
		t.Fatalf("authData: %v", err)
	}
	return authData[32]
}

func getInfoOptions(t *testing.T, s *server) (map[string]bool, map[int]cbor.RawMessage) {
	t.Helper()
	r := &fakeResponder{}
	s.handleGetInfo(context.Background(), r, fidohid.AuthEvent{})
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(r.lastCtap2().data, &top); err != nil {
		t.Fatal(err)
	}
	var opts map[string]bool
	if err := cbor.Unmarshal(top[4], &opts); err != nil {
		t.Fatal(err)
	}
	return opts, top
}

func forProtocols(t *testing.T, f func(t *testing.T, p protocol.PinUvAuthProtocol)) {
	for _, p := range pinuv.Supported {
		t.Run(fmt.Sprintf("protocol%d", p), func(t *testing.T) { f(t, p) })
	}
}

func TestClientPIN_SetChangeAndTokens(t *testing.T) {
	forProtocols(t, func(t *testing.T, p protocol.PinUvAuthProtocol) {
		v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
		s := newTestServer(t, v, &fakePinentry{})
		pl := pinPlatform{t, s, p}

		opts, top := getInfoOptions(t, s)
		if opts["clientPin"] || !opts["pinUvAuthToken"] || !opts["makeCredUvNotRqd"] {
			t.Fatalf("GetInfo options before setPIN: %v", opts)
		}
		var minLen int
		var force bool
		if cbor.Unmarshal(top[13], &minLen); minLen != 4 {
			t.Errorf("minPINLength = %d", minLen)
		}
		if err := cbor.Unmarshal(top[12], &force); err != nil || force {
			t.Errorf("forcePINChange = %v (%v)", force, err)
		}
		if _, st := pl.tokenWithPIN("1234", mcga, "rp.example"); st != ctap2.StatusPinNotSet {
			t.Fatalf("token before setPIN: 0x%02x", st)
		}
		if st := pl.changePIN("1234", "5678"); st != ctap2.StatusPinNotSet {
			t.Fatalf("changePIN before setPIN: 0x%02x", st)
		}

		if st := pl.setPIN("1234"); st != ctap2.StatusOK {
			t.Fatalf("setPIN: 0x%02x", st)
		}
		if opts, _ := getInfoOptions(t, s); !opts["clientPin"] {
			t.Fatal("clientPin false after setPIN")
		}
		if st := pl.setPIN("9999"); st != ctap2.StatusPinAuthInvalid {
			t.Fatalf("second setPIN: 0x%02x", st)
		}
		fi, err := os.Stat(s.pin.path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("pin file: %v %v", fi, err)
		}
		raw, _ := os.ReadFile(s.pin.path)
		if bytes.Contains(raw, pinHashOf("1234")) || strings.Contains(string(raw), "1234") {
			t.Fatal("pin file contains the PIN or its hash")
		}

		tok, st := pl.tokenWithPIN("1234", mcga, "pin.example")
		if st != ctap2.StatusOK {
			t.Fatalf("token: 0x%02x", st)
		}
		v.callCount = 0
		st, flags := pinMakeCred(t, s, p, tok, "pin.example", true, false)
		if st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP|ctap2.AuthFlagUV {
			t.Fatalf("makeCredential with PIN token: 0x%02x flags 0x%02x", st, flags)
		}
		if v.callCount != 1 {
			t.Errorf("PIN token must still ask for presence, verifier calls = %d", v.callCount)
		}
		if st, _ := pinGetAssertion(t, s, p, tok, "other.example", false); st != ctap2.StatusPinAuthInvalid {
			t.Fatalf("token bound to another RP: 0x%02x", st)
		}

		if st := pl.changePIN("0000", "5678"); st != ctap2.StatusPinInvalid {
			t.Fatalf("changePIN with wrong PIN: 0x%02x", st)
		}
		if st := pl.changePIN("1234", "5678"); st != ctap2.StatusOK {
			t.Fatalf("changePIN: 0x%02x", st)
		}
		if st, _ := pinGetAssertion(t, s, p, tok, "pin.example", false); st != ctap2.StatusPinAuthInvalid {
			t.Fatalf("token survived changePIN: 0x%02x", st)
		}
		if _, st := pl.tokenWithPIN("1234", 0, ""); st != ctap2.StatusPinInvalid {
			t.Fatalf("old PIN after change: 0x%02x", st)
		}
		legacy, st := pl.tokenWithPIN("5678", 0, "")
		if st != ctap2.StatusOK {
			t.Fatalf("getPinToken: 0x%02x", st)
		}
		st, flags = pinGetAssertion(t, s, p, legacy, "pin.example", false)
		if st != ctap2.StatusOK || flags&ctap2.AuthFlagUV == 0 {
			t.Fatalf("getAssertion with legacy token: 0x%02x flags 0x%02x", st, flags)
		}
		if pin, pc, _ := pl.retries(); pin != maxPINRetries || pc {
			t.Fatalf("retries after success: %d powerCycle %v", pin, pc)
		}
	})
}

func TestClientPIN_RequestValidation(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	p := protocol.PinUvAuthProtocolTwo
	pl := pinPlatform{t, s, p}

	for _, tc := range []struct {
		name   string
		padded []byte
		want   byte
	}{
		{"3 code points", padPIN("123"), ctap2.StatusPinPolicyViolation},
		{"4 bytes but 2 code points", padPIN("ää"), ctap2.StatusPinPolicyViolation},
		{"64 bytes, no padding", bytes.Repeat([]byte("1"), 64), ctap2.StatusPinPolicyViolation},
		{"invalid UTF-8", padPIN("\xff\xfe\xfd\xfc"), ctap2.StatusPinPolicyViolation},
		{"not padded to 64", []byte("12345678123456781234567812345678"), ctap2.StatusInvalidParameter},
	} {
		if st := pl.setPINRaw(tc.padded); st != tc.want {
			t.Errorf("setPIN %s: 0x%02x, want 0x%02x", tc.name, st, tc.want)
		}
	}
	if s.pin.isSet() {
		t.Fatal("rejected setPIN stored a PIN")
	}

	// A pinUvAuthParam that does not cover newPinEnc.
	proto, key, secret := pl.session()
	enc, _ := proto.Encrypt(secret, padPIN("1234"))
	if st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: p, SubCommand: protocol.ClientPINSubCommandSetPIN, KeyAgreement: key,
		NewPinEnc: enc, PinUvAuthParam: ctapcrypto.Authenticate(p, secret, []byte("other")),
	}); st != ctap2.StatusPinAuthInvalid {
		t.Errorf("setPIN with bad pinUvAuthParam: 0x%02x", st)
	}
	if st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: p, SubCommand: protocol.ClientPINSubCommandSetPIN, KeyAgreement: key, NewPinEnc: enc,
	}); st != ctap2.StatusMissingParameter {
		t.Errorf("setPIN without pinUvAuthParam: 0x%02x", st)
	}
	if st, _ := pl.send(protocol.AuthenticatorClientPINRequest{SubCommand: protocol.ClientPINSubCommandSetPIN}); st != ctap2.StatusMissingParameter {
		t.Errorf("setPIN without protocol: 0x%02x", st)
	}

	if st := pl.setPIN("ä123"); st != ctap2.StatusOK {
		t.Fatalf("setPIN: 0x%02x", st)
	}
	if _, st := pl.tokenWithPIN("ä123", protocol.PermissionBioEnrollment, ""); st != ctap2.StatusUnauthorizedPermission {
		t.Errorf("unsupported permission: 0x%02x", st)
	}
	proto, key, secret = pl.session()
	hashEnc, _ := proto.Encrypt(secret, pinHashOf("ä123"))
	if st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: p, SubCommand: protocol.ClientPINSubCommandGetPinToken,
		KeyAgreement: key, PinHashEnc: hashEnc, Permissions: mcga,
	}); st != ctap2.StatusInvalidParameter {
		t.Errorf("getPinToken with permissions: 0x%02x", st)
	}
	if st, _ := pl.send(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: p, SubCommand: protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement: key, PinHashEnc: hashEnc,
	}); st != ctap2.StatusMissingParameter {
		t.Errorf("token without permissions: 0x%02x", st)
	}
	if pin, _, _ := pl.retries(); pin != maxPINRetries {
		t.Errorf("parameter errors consumed PIN retries: %d", pin)
	}
	// Changing to a PIN that violates the policy keeps the old PIN.
	if st := pl.changePIN("ä123", "12"); st != ctap2.StatusPinPolicyViolation {
		t.Errorf("changePIN to short PIN: 0x%02x", st)
	}
	if _, st := pl.tokenWithPIN("ä123", mcga, ""); st != ctap2.StatusOK {
		t.Errorf("old PIN after rejected change: 0x%02x", st)
	}
}

func TestClientPIN_WrongPINRetriesAndBlocking(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	p := protocol.PinUvAuthProtocolOne
	pl := pinPlatform{t, s, p}
	if st := pl.setPIN("1234"); st != ctap2.StatusOK {
		t.Fatal(st)
	}
	keyBefore, _ := s.pinuv.KeyAgreement()

	for i, want := range []byte{ctap2.StatusPinInvalid, ctap2.StatusPinInvalid, ctap2.StatusPinAuthBlocked} {
		if _, st := pl.tokenWithPIN("0000", mcga, ""); st != want {
			t.Fatalf("wrong PIN #%d: 0x%02x, want 0x%02x", i+1, st, want)
		}
		if pin, pc, _ := pl.retries(); pin != uint(maxPINRetries-1-i) || pc != (i == 2) {
			t.Fatalf("after wrong PIN #%d: retries %d powerCycle %v", i+1, pin, pc)
		}
	}
	if keyAfter, _ := s.pinuv.KeyAgreement(); reflect.DeepEqual(keyAfter, keyBefore) {
		t.Error("key agreement key not regenerated after a wrong PIN")
	}
	// Blocked until power cycle, even with the right PIN, without
	// consuming retries.
	if _, st := pl.tokenWithPIN("1234", mcga, ""); st != ctap2.StatusPinAuthBlocked {
		t.Fatalf("right PIN while auth-blocked: 0x%02x", st)
	}
	if st := pl.changePIN("1234", "5678"); st != ctap2.StatusPinAuthBlocked {
		t.Fatalf("changePIN while auth-blocked: 0x%02x", st)
	}
	if pin, _, _ := pl.retries(); pin != 5 {
		t.Fatalf("retries consumed while auth-blocked: %d", pin)
	}

	// "Power cycle": a fresh daemon on the same PIN file and the same
	// backend (a TPM outlives the daemon).
	powerCycle := func() {
		path, sealer := s.pin.path, s.pin.sealer
		s = newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
		s.pin.path, s.pin.sealer = path, sealer
		pl.s = s
	}
	powerCycle()
	if pin, pc, _ := pl.retries(); pin != 5 || pc {
		t.Fatalf("after power cycle: retries %d powerCycle %v", pin, pc)
	}
	if _, st := pl.tokenWithPIN("1234", mcga, ""); st != ctap2.StatusOK {
		t.Fatalf("right PIN after power cycle: 0x%02x", st)
	}
	if pin, _, _ := pl.retries(); pin != maxPINRetries {
		t.Fatalf("retries not reset: %d", pin)
	}

	// Exhaust all retries across power cycles.
	mismatches := 0
	for left := maxPINRetries - 1; left >= 0; left-- {
		if mismatches == maxConsecutivePINMismatches {
			powerCycle()
			mismatches = 0
		}
		_, st := pl.tokenWithPIN("0000", mcga, "")
		mismatches++
		want := ctap2.StatusPinInvalid
		switch {
		case left == 0:
			want = ctap2.StatusPinBlocked
		case mismatches == maxConsecutivePINMismatches:
			want = ctap2.StatusPinAuthBlocked
		}
		if st != want {
			t.Fatalf("wrong PIN with %d left: 0x%02x, want 0x%02x", left, st, want)
		}
	}
	powerCycle()
	if _, st := pl.tokenWithPIN("1234", mcga, ""); st != ctap2.StatusPinBlocked {
		t.Fatalf("right PIN when blocked: 0x%02x", st)
	}
	if st := pl.changePIN("1234", "5678"); st != ctap2.StatusPinBlocked {
		t.Fatalf("changePIN when blocked: 0x%02x", st)
	}
	if pin, _, _ := pl.retries(); pin != 0 {
		t.Fatalf("retries = %d", pin)
	}
}

func TestClientPIN_UVNoMatchFallsBackToPIN(t *testing.T) {
	forProtocols(t, func(t *testing.T, p protocol.PinUvAuthProtocol) {
		v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{Reason: ReasonNoMatch}}
		s := newTestServer(t, v, &fakePinentry{})
		pl := pinPlatform{t, s, p}
		if st := pl.setPIN("1234"); st != ctap2.StatusOK {
			t.Fatal(st)
		}
		for i, want := range []byte{ctap2.StatusUVInvalid, ctap2.StatusUVInvalid, ctap2.StatusUVBlocked} {
			if _, st := pl.tokenWithUV(mcga, "fp.example"); st != want {
				t.Fatalf("UV attempt %d: 0x%02x, want 0x%02x", i+1, st, want)
			}
			if _, _, uv := pl.retries(); uv != uint(maxUVRetries-1-i) {
				t.Fatalf("uvRetries after attempt %d: %d", i+1, uv)
			}
		}
		calls := v.callCount
		if _, st := pl.tokenWithUV(mcga, "fp.example"); st != ctap2.StatusUVBlocked || v.callCount != calls {
			t.Fatalf("blocked UV: 0x%02x, verifier called %d more times", st, v.callCount-calls)
		}
		// uv=true without a token now needs the PIN.
		if st, _ := pinMakeCred(t, s, p, nil, "fp.example", false, true); st != ctap2.StatusPinRequired {
			t.Fatalf("uv=true while UV blocked: 0x%02x", st)
		}

		tok, st := pl.tokenWithPIN("1234", mcga, "fp.example")
		if st != ctap2.StatusOK {
			t.Fatalf("PIN token: 0x%02x", st)
		}
		if _, _, uv := pl.retries(); uv != maxUVRetries {
			t.Fatalf("PIN did not reset uvRetries: %d", uv)
		}
		// The finger still does not match, but touching the sensor is
		// presence; the PIN provided the verification.
		st, flags := pinMakeCred(t, s, p, tok, "fp.example", true, false)
		if st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP|ctap2.AuthFlagUV {
			t.Fatalf("makeCredential with PIN token: 0x%02x flags 0x%02x", st, flags)
		}
		if st, flags := pinGetAssertion(t, s, p, tok, "fp.example", false); st != ctap2.StatusOK || flags&ctap2.AuthFlagUV == 0 {
			t.Fatalf("getAssertion with PIN token: 0x%02x flags 0x%02x", st, flags)
		}
		// A match restores the counter too.
		pl.tokenWithUV(mcga, "fp.example")
		v.nextResult = VerifyResult{OK: true}
		if _, st := pl.tokenWithUV(mcga, "fp.example"); st != ctap2.StatusOK {
			t.Fatalf("UV token after match: 0x%02x", st)
		}
		if _, _, uv := pl.retries(); uv != maxUVRetries {
			t.Fatalf("match did not reset uvRetries: %d", uv)
		}
	})
}

func TestClientPIN_UVNoMatchWithoutPINDoesNotBlock(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{Reason: ReasonNoMatch}}
	s := newTestServer(t, v, &fakePinentry{})
	pl := pinPlatform{t, s, protocol.PinUvAuthProtocolTwo}
	for i := range 5 {
		if _, st := pl.tokenWithUV(mcga, "fp.example"); st != ctap2.StatusUVInvalid {
			t.Fatalf("attempt %d: 0x%02x", i+1, st)
		}
	}
	if _, _, uv := pl.retries(); uv != maxUVRetries {
		t.Fatalf("uvRetries without PIN: %d", uv)
	}
}

func TestClientPIN_VerifierUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    *fakeVerifier
	}{
		{"start error", &fakeVerifier{performsUV: true, startErr: errors.New("no fingerprint devices found")}},
		{"device error", &fakeVerifier{performsUV: true, nextResult: VerifyResult{Reason: ReasonUnavailable, Error: errors.New("verify-disconnected")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, tc.v, &fakePinentry{})
			p := protocol.PinUvAuthProtocolTwo
			pl := pinPlatform{t, s, p}

			if _, st := pl.tokenWithUV(mcga, "fp.example"); st != ctap2.StatusOperationDenied {
				t.Fatalf("no PIN: 0x%02x, want OPERATION_DENIED", st)
			}
			if st := pl.setPIN("1234"); st != ctap2.StatusOK {
				t.Fatal(st)
			}
			if _, st := pl.tokenWithUV(mcga, "fp.example"); st != ctap2.StatusUVBlocked {
				t.Fatalf("PIN set: 0x%02x, want UV_BLOCKED", st)
			}
			if st, _ := pinMakeCred(t, s, p, nil, "fp.example", false, true); st != ctap2.StatusPinRequired {
				t.Fatalf("uv=true with PIN set: 0x%02x, want PUAT_REQUIRED", st)
			}
			tok, st := pl.tokenWithPIN("1234", mcga, "fp.example")
			if st != ctap2.StatusOK {
				t.Fatal(st)
			}
			// No presence fallback: the request cannot get UP.
			if st, _ := pinMakeCred(t, s, p, tok, "fp.example", true, false); st != ctap2.StatusOperationDenied {
				t.Fatalf("no presence fallback: 0x%02x", st)
			}
			fallback := &fakeVerifier{nextResult: VerifyResult{OK: true}}
			s.presence = fallback
			tok, _ = pl.tokenWithPIN("1234", mcga, "fp.example")
			st, flags := pinMakeCred(t, s, p, tok, "fp.example", true, false)
			if st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP|ctap2.AuthFlagUV || fallback.callCount != 1 {
				t.Fatalf("presence fallback: 0x%02x flags 0x%02x calls %d", st, flags, fallback.callCount)
			}
		})
	}
}

func TestZeroLengthPinUvAuthParam(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{Reason: ReasonNoMatch}}
	s := newTestServer(t, v, &fakePinentry{})
	p := protocol.PinUvAuthProtocolTwo
	probe := func() (byte, byte) {
		// Maps, because the request structs omit an empty pinUvAuthParam.
		cdh := bytes.Repeat([]byte{1}, 32)
		mc := map[int]any{
			1: cdh, 2: ctap2.RPEntity{ID: "x.example"}, 3: ctap2.UserEntity{ID: []byte("x")},
			4: []ctap2.CredParam{{Type: "public-key", Alg: -7}}, 8: []byte{}, 9: p,
		}
		ga := map[int]any{1: "x.example", 2: cdh, 6: []byte{}, 7: p}
		mb, _ := cbor.Marshal(mc)
		gb, _ := cbor.Marshal(ga)
		r1, r2 := &fakeResponder{}, &fakeResponder{}
		s.handleMakeCredential(context.Background(), r1, fidohid.AuthEvent{}, mb)
		s.handleGetAssertion(context.Background(), r2, fidohid.AuthEvent{}, gb)
		return r1.lastCtap2().status, r2.lastCtap2().status
	}
	// Any touch selects the authenticator, even a non-matching finger.
	if mc, ga := probe(); mc != ctap2.StatusPinNotSet || ga != ctap2.StatusPinNotSet {
		t.Fatalf("no PIN: 0x%02x 0x%02x", mc, ga)
	}
	if st := (pinPlatform{t, s, p}).setPIN("1234"); st != ctap2.StatusOK {
		t.Fatal(st)
	}
	if mc, ga := probe(); mc != ctap2.StatusPinInvalid || ga != ctap2.StatusPinInvalid {
		t.Fatalf("PIN set: 0x%02x 0x%02x", mc, ga)
	}
	v.nextResult = VerifyResult{} // declined
	if mc, ga := probe(); mc != ctap2.StatusOperationDenied || ga != ctap2.StatusOperationDenied {
		t.Fatalf("declined: 0x%02x 0x%02x", mc, ga)
	}
}

func TestRequestsWithoutTokenWhilePINSet(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	p := protocol.PinUvAuthProtocolTwo
	if st := (pinPlatform{t, s, p}).setPIN("1234"); st != ctap2.StatusOK {
		t.Fatal(st)
	}

	v.callCount = 0
	if st, _ := pinMakeCred(t, s, p, nil, "rk.example", true, false); st != ctap2.StatusPinRequired || v.callCount != 0 {
		t.Fatalf("discoverable makeCredential without uv: 0x%02x (verifier calls %d), want PUAT_REQUIRED", st, v.callCount)
	}
	// makeCredUvNotRqd: a non-discoverable credential needs only UP.
	if st, flags := pinMakeCred(t, s, p, nil, "nonrk.example", false, false); st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP {
		t.Fatalf("non-discoverable makeCredential: 0x%02x flags 0x%02x", st, flags)
	}
	// Built-in UV via uv=true keeps working with a PIN set.
	if st, flags := pinMakeCred(t, s, p, nil, "rk.example", true, true); st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP|ctap2.AuthFlagUV {
		t.Fatalf("uv=true makeCredential: 0x%02x flags 0x%02x", st, flags)
	}
	if st, flags := pinGetAssertion(t, s, p, nil, "rk.example", false); st != ctap2.StatusOK || flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != ctap2.AuthFlagUP {
		t.Fatalf("getAssertion without uv: 0x%02x flags 0x%02x, want UP only", st, flags)
	}
	if st, flags := pinGetAssertion(t, s, p, nil, "rk.example", true); st != ctap2.StatusOK || flags&ctap2.AuthFlagUV == 0 {
		t.Fatalf("getAssertion uv=true: 0x%02x flags 0x%02x", st, flags)
	}
	v.nextResult = VerifyResult{Reason: ReasonNoMatch}
	if st, _ := pinGetAssertion(t, s, p, nil, "rk.example", true); st != ctap2.StatusPinRequired {
		t.Fatalf("uv=true no-match with PIN set: 0x%02x, want PUAT_REQUIRED", st)
	}
	if st, flags := pinGetAssertion(t, s, p, nil, "rk.example", false); st != ctap2.StatusOK || flags != ctap2.AuthFlagUP {
		t.Fatalf("getAssertion without uv, non-matching touch: 0x%02x flags 0x%02x", st, flags)
	}
}

func TestPINStore_FileFormatAndFailClosed(t *testing.T) {
	ps := testPINStore(t)
	if ps.isSet() {
		t.Fatal("fresh store has a PIN")
	}
	if err := ps.set(pinHashOf("1234")); err != nil {
		t.Fatal(err)
	}
	var f pinFile
	raw, _ := os.ReadFile(ps.path)
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != pinFileVer || len(f.Object) == 0 || f.Retries != maxPINRetries {
		t.Fatalf("pin file: %+v", f)
	}
	if bytes.Contains(raw, pinHashOf("1234")) {
		t.Fatal("pin file contains the PIN hash")
	}
	if err := ps.set(pinHashOf("1234")); err != nil {
		t.Fatal(err)
	}
	var f2 pinFile
	raw, _ = os.ReadFile(ps.path)
	json.Unmarshal(raw, &f2)
	if bytes.Equal(f.Object, f2.Object) {
		t.Error("PIN object reused across set")
	}
	entries, _ := os.ReadDir(filepath.Dir(ps.path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}

	// Retries persist across instances.
	if res, err := ps.verify(pinHashOf("0000")); err != nil || res != pinMismatch {
		t.Fatal(res, err)
	}
	if r, _, _ := newPINStore(ps.path, ps.sealer).state(); r != maxPINRetries-1 {
		t.Fatalf("persisted retries = %d", r)
	}

	// A damaged file keeps the PIN requirement and refuses PIN use.
	os.WriteFile(ps.path, []byte("{"), 0o600)
	if !ps.isSet() {
		t.Error("damaged pin file treated as no PIN")
	}
	if res, err := ps.verify(pinHashOf("1234")); err == nil {
		t.Errorf("verify on damaged file: %v", res)
	}
	// The earlier argon2 format is not read: it is refused, not migrated.
	os.WriteFile(ps.path, []byte(`{"version":1,"kdf":{"time":1,"memoryKiB":64,"threads":1},"salt":"AAAAAAAAAAAAAAAAAAAAAA==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","retries":8}`), 0o600)
	if _, err := ps.verify(pinHashOf("1234")); err == nil {
		t.Error("version 1 PIN file accepted")
	}
}
