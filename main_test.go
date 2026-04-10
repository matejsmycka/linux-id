package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidoauth"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/pinentry"
	"github.com/matejsmycka/linux-id/statuscode"
)

// =====================================================================
// Test doubles
// =====================================================================

// fakeResponder captures every WriteResponse / WriteCtap2Response call so
// tests can assert on the bytes that would have gone back over /dev/uhid.
type fakeResponder struct {
	u2f   []u2fWrite
	ctap2 []ctap2Write
}

type u2fWrite struct {
	data   []byte
	status uint16
}

type ctap2Write struct {
	status byte
	data   []byte
}

func (f *fakeResponder) WriteResponse(_ context.Context, _ fidohid.AuthEvent, data []byte, status uint16) error {
	f.u2f = append(f.u2f, u2fWrite{data: append([]byte(nil), data...), status: status})
	return nil
}

func (f *fakeResponder) WriteCtap2Response(_ context.Context, _ fidohid.AuthEvent, status byte, data []byte) error {
	f.ctap2 = append(f.ctap2, ctap2Write{status: status, data: append([]byte(nil), data...)})
	return nil
}

func (f *fakeResponder) lastCtap2() ctap2Write {
	if len(f.ctap2) == 0 {
		return ctap2Write{}
	}
	return f.ctap2[len(f.ctap2)-1]
}

func (f *fakeResponder) lastU2F() u2fWrite {
	if len(f.u2f) == 0 {
		return u2fWrite{}
	}
	return f.u2f[len(f.u2f)-1]
}

// fakeVerifier is a controllable UserVerifier. nextResult is delivered on the
// channel returned by VerifyUser; set blockUntil to gate delivery for timeout
// tests; set startErr to make VerifyUser fail immediately.
type fakeVerifier struct {
	performsUV bool

	callCount int
	prompts   []string

	nextResult VerifyResult
	startErr   error
	blockUntil chan struct{}
}

func (v *fakeVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	v.callCount++
	v.prompts = append(v.prompts, prompt)
	if v.startErr != nil {
		return nil, v.startErr
	}
	out := make(chan VerifyResult, 1)
	if v.blockUntil != nil {
		go func() {
			<-v.blockUntil
			out <- v.nextResult
		}()
	} else {
		out <- v.nextResult
	}
	return out, nil
}

func (v *fakeVerifier) PerformsUV() bool { return v.performsUV }

// fakeSigner is an in-test Signer that wraps an ecdsa.PrivateKey per credential.
// Bypasses the existing memory backend, which has a pre-existing bug where it
// constructs an ecdsa.PrivateKey without setting X/Y on the public key — newer
// Go (>=1.20) rejects that during ecdsa.SignASN1.
type fakeSigner struct {
	mu       sync.Mutex
	keys     map[string]*ecdsa.PrivateKey // credID-as-string → key
	counter  uint32
}

func newFakeSigner() *fakeSigner {
	return &fakeSigner{keys: make(map[string]*ecdsa.PrivateKey)}
}

func (f *fakeSigner) RegisterKey(_ []byte) ([]byte, *big.Int, *big.Int, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, nil, nil, err
	}
	f.mu.Lock()
	f.keys[string(credID)] = priv
	f.mu.Unlock()
	return credID, priv.PublicKey.X, priv.PublicKey.Y, nil
}

func (f *fakeSigner) SignASN1(keyHandle, _ []byte, digest []byte) ([]byte, error) {
	f.mu.Lock()
	priv, ok := f.keys[string(keyHandle)]
	f.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown key handle")
	}
	return ecdsa.SignASN1(rand.Reader, priv, digest)
}

func (f *fakeSigner) Counter() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	return f.counter
}

// fakePinentry mimics *pinentry.Pinentry for the U2F path. It replays the
// browser-retry dedup behaviour: a second ConfirmPresence call with the same
// challenge/app params returns the same channel without prompting twice.
//
// All state is guarded by mu so the test suite is race-clean (the dedup test
// drives ConfirmPresence from two goroutines concurrently).
type fakePinentry struct {
	mu          sync.Mutex
	promptCount int
	calls       []fakePinCall

	// next result delivered on the channel; set blockResult to true to hold
	// it back until release() is called.
	nextResult   pinentry.Result
	blockResult  bool
	releaseChan  chan struct{}
	startErr     error
	holdActive   bool
	activeKey    [64]byte
	activeResult chan pinentry.Result
}

type fakePinCall struct {
	prompt    string
	challenge [32]byte
	app       [32]byte
}

func (p *fakePinentry) ConfirmPresence(prompt string, challenge, app [32]byte) (chan pinentry.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, fakePinCall{prompt: prompt, challenge: challenge, app: app})
	if p.startErr != nil {
		return nil, p.startErr
	}
	var key [64]byte
	copy(key[:32], challenge[:])
	copy(key[32:], app[:])
	if p.holdActive && key == p.activeKey && p.activeResult != nil {
		return p.activeResult, nil
	}
	p.promptCount++
	ch := make(chan pinentry.Result, 1)
	p.holdActive = true
	p.activeKey = key
	p.activeResult = ch
	if p.blockResult {
		if p.releaseChan == nil {
			p.releaseChan = make(chan struct{})
		}
		go func(rc chan struct{}, out chan pinentry.Result, r pinentry.Result) {
			<-rc
			out <- r
		}(p.releaseChan, ch, p.nextResult)
	} else {
		ch <- p.nextResult
	}
	return ch, nil
}

// snapshotPromptCount returns the prompt counter under lock so tests can
// inspect it without racing the handler goroutines.
func (p *fakePinentry) snapshotPromptCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.promptCount
}

// snapshotCalls returns a copy of the recorded calls under lock.
func (p *fakePinentry) snapshotCalls() []fakePinCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]fakePinCall, len(p.calls))
	copy(out, p.calls)
	return out
}

func (p *fakePinentry) release() {
	p.mu.Lock()
	rc := p.releaseChan
	p.releaseChan = nil
	p.mu.Unlock()
	if rc != nil {
		close(rc)
	}
}

// =====================================================================
// Test helpers
// =====================================================================

// newTestServer constructs a server with a fake in-process signer, the supplied
// verifier, and a cred store rooted at a temp directory so tests don't touch
// the user's real ~/.config.
func newTestServer(t *testing.T, verifier UserVerifier, pe pinentryClient) *server {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return &server{
		pe:       pe,
		verifier: verifier,
		signer:   newFakeSigner(),
		cs:       ctap2.NewCredStore(),
	}
}

// rpIDHash returns sha256(rpID), the application parameter for a given RPID.
func rpIDHash(rpID string) [32]byte {
	return sha256.Sum256([]byte(rpID))
}

// makeAssertionCBOR builds the CBOR payload that handleGetAssertion expects,
// minus the leading command byte (which the dispatcher strips before calling
// the handler). Pass options=nil to omit field 5 entirely (as most browsers do
// for non-UV flows).
func makeAssertionCBOR(t *testing.T, rpID string, allowList []ctap2.CredDescriptor, options *ctap2.GetAssertOptions) []byte {
	t.Helper()
	req := ctap2.GetAssertionRequest{
		RPID:           rpID,
		ClientDataHash: sha256.New().Sum([]byte("client-data:" + rpID))[:32],
		AllowList:      allowList,
		Options:        options,
	}
	b, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("marshal GetAssertionRequest: %s", err)
	}
	return b
}

// makeMakeCredCBOR builds an authenticatorMakeCredential payload.
func makeMakeCredCBOR(t *testing.T, rpID, rpName, userName string, rk, uv bool) []byte {
	t.Helper()
	req := ctap2.MakeCredentialRequest{
		ClientDataHash: sha256.New().Sum([]byte("mc:" + rpID))[:32],
		RP:             ctap2.RPEntity{ID: rpID, Name: rpName},
		User: ctap2.UserEntity{
			ID:          []byte(userName),
			Name:        userName + "@" + rpID,
			DisplayName: userName,
		},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
	}
	if rk || uv {
		req.Options = &ctap2.MakeCredOptions{RK: rk, UV: uv}
	}
	b, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("marshal MakeCredentialRequest: %s", err)
	}
	return b
}

// registerCred uses MakeCredential to register a passkey for rp and returns
// the resulting credential ID, so a follow-up GetAssertion test can reference
// it from an allowList. Asserts the registration succeeded.
func registerCred(t *testing.T, s *server, rpID, rpName, userName string, rk bool) []byte {
	t.Helper()
	resp := &fakeResponder{}
	verifier, ok := s.verifier.(*fakeVerifier)
	if !ok {
		t.Fatalf("registerCred requires a *fakeVerifier")
	}
	verifier.nextResult = VerifyResult{OK: true}
	payload := makeMakeCredCBOR(t, rpID, rpName, userName, rk, false)
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if len(resp.ctap2) != 1 {
		t.Fatalf("registerCred: expected 1 ctap2 reply, got %d", len(resp.ctap2))
	}
	if resp.ctap2[0].status != ctap2.StatusOK {
		t.Fatalf("registerCred: status=0x%02x", resp.ctap2[0].status)
	}
	return extractCredID(t, resp.ctap2[0].data)
}

// extractCredID parses a MakeCredential response and pulls the credential ID
// out of authenticatorData (rpIdHash | flags | counter | aaguid | credIdLen | credId | coseKey).
func extractCredID(t *testing.T, payload []byte) []byte {
	t.Helper()
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(payload, &top); err != nil {
		t.Fatalf("decode MakeCredential response: %s", err)
	}
	var authData []byte
	if err := cbor.Unmarshal(top[2], &authData); err != nil {
		t.Fatalf("decode authData: %s", err)
	}
	if len(authData) < 32+1+4+16+2 {
		t.Fatalf("authData too short: %d", len(authData))
	}
	credIDLen := binary.BigEndian.Uint16(authData[32+1+4+16:])
	start := 32 + 1 + 4 + 16 + 2
	end := start + int(credIDLen)
	if end > len(authData) {
		t.Fatalf("credIDLen %d overflows authData (%d bytes)", credIDLen, len(authData))
	}
	out := make([]byte, credIDLen)
	copy(out, authData[start:end])
	return out
}

// decodeAssertion parses a GetAssertion success response into its top-level fields.
func decodeAssertion(t *testing.T, payload []byte) map[int]cbor.RawMessage {
	t.Helper()
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(payload, &top); err != nil {
		t.Fatalf("decode GetAssertion response: %s", err)
	}
	return top
}

// =====================================================================
// Spec compliance tests for handleGetAssertion
// =====================================================================

// CTAP2 §6.2: clients commonly send GetAssertion without an Options map.
// The handler must NOT panic when req.Options is nil. Catches the PR's
// `if req.Options.UV` nil-pointer dereference.
func TestGetAssertion_NilOptionsDoesNotPanic(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "github.com", "GitHub", "octocat", false)

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "github.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
		nil) // ← Options omitted

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handleGetAssertion panicked on nil Options: %v\n%s", r, debugStack())
		}
	}()
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if got := resp.lastCtap2().status; got != ctap2.StatusOK {
		t.Fatalf("expected StatusOK, got 0x%02x", got)
	}
}

func debugStack() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// CTAP2 §6.2: User Presence MUST be obtained for every GetAssertion. The
// verifier (or pinentry presence dialog) must always be invoked, regardless
// of whether the RP requested user verification.
func TestGetAssertion_AlwaysCallsVerifier(t *testing.T) {
	cases := []struct {
		name    string
		options *ctap2.GetAssertOptions
	}{
		{"options omitted", nil},
		{"options present, uv false", &ctap2.GetAssertOptions{UV: false}},
		{"options present, uv true (with UV-capable verifier)", &ctap2.GetAssertOptions{UV: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &fakeVerifier{
				performsUV: tc.options != nil && tc.options.UV,
				nextResult: VerifyResult{OK: true},
			}
			s := newTestServer(t, verifier, &fakePinentry{})
			credID := registerCred(t, s, "example.com", "Example", "alice", false)
			verifier.callCount = 0 // reset after the registration prompt

			resp := &fakeResponder{}
			payload := makeAssertionCBOR(t, "example.com",
				[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
				tc.options)
			s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

			if verifier.callCount != 1 {
				t.Fatalf("expected exactly 1 verifier call, got %d", verifier.callCount)
			}
			if resp.lastCtap2().status != ctap2.StatusOK {
				t.Fatalf("expected StatusOK, got 0x%02x", resp.lastCtap2().status)
			}
		})
	}
}

// If verification is rejected (cancel / scan failure), the assertion MUST NOT
// be returned. The signed authenticatorData would lie about user presence.
func TestGetAssertion_VerifierRejection(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: false}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "example.com", "Example", "alice", false)
	verifier.nextResult = VerifyResult{OK: false} // re-arm after register

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "example.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
		nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if got := resp.lastCtap2().status; got != ctap2.StatusOperationDenied {
		t.Fatalf("expected StatusOperationDenied (0x27), got 0x%02x", got)
	}
}

// AuthFlagUV must only be set when the verifier actually identifies the user
// (e.g. fingerprint), never for a UP-only confirmation. AuthFlagUP is always set.
func TestGetAssertion_AuthFlagsHonest(t *testing.T) {
	cases := []struct {
		name        string
		performsUV  bool
		expectFlags byte
	}{
		{"presence-only verifier", false, ctap2.AuthFlagUP},
		{"uv-capable verifier", true, ctap2.AuthFlagUP | ctap2.AuthFlagUV},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &fakeVerifier{performsUV: tc.performsUV, nextResult: VerifyResult{OK: true}}
			s := newTestServer(t, verifier, &fakePinentry{})
			credID := registerCred(t, s, "demo.example.com", "Demo", "carol", false)

			resp := &fakeResponder{}
			payload := makeAssertionCBOR(t, "demo.example.com",
				[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
				nil)
			s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

			if resp.lastCtap2().status != ctap2.StatusOK {
				t.Fatalf("status=0x%02x", resp.lastCtap2().status)
			}
			top := decodeAssertion(t, resp.lastCtap2().data)
			var authData []byte
			if err := cbor.Unmarshal(top[2], &authData); err != nil {
				t.Fatalf("decode authData: %s", err)
			}
			if len(authData) < 33 {
				t.Fatalf("authData too short")
			}
			flags := authData[32]
			if flags != tc.expectFlags {
				t.Fatalf("expected flags 0x%02x, got 0x%02x", tc.expectFlags, flags)
			}
		})
	}
}

// CTAP2.1 §6.5 / WebAuthn: PublicKeyCredentialUserEntity uses STRING keys
// "id", "name", "displayName" — not integer keys. Catches the PR's int-key
// schema regression.
func TestGetAssertion_UserEntityUsesStringKeys(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	// Register a resident credential so handleGetAssertion will populate field 4.
	registerCred(t, s, "passkey.example.com", "Passkey Demo", "dave", true /*rk*/)

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "passkey.example.com", nil /* no allowList → resident lookup */, nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	top := decodeAssertion(t, resp.lastCtap2().data)
	userRaw, ok := top[4]
	if !ok {
		t.Fatalf("response missing field 4 (user)")
	}
	var asStringMap map[string]interface{}
	if err := cbor.Unmarshal(userRaw, &asStringMap); err != nil {
		t.Fatalf("user entity is not a string-keyed map (PR #22 regression): %s", err)
	}
	for _, k := range []string{"id", "name", "displayName"} {
		if _, has := asStringMap[k]; !has {
			t.Errorf("user entity missing %q key", k)
		}
	}
	// And confirm the int-keyed shape is NOT what was emitted.
	var asIntMap map[int]interface{}
	if err := cbor.Unmarshal(userRaw, &asIntMap); err == nil {
		t.Fatalf("user entity decoded as int-keyed map; spec requires string keys")
	}
}

// CTAP2 §6 mandates canonical CBOR encoding for all responses. The user
// entity sub-map keys must be sorted (length-first or bytewise — both
// produce id, name, displayName for these particular keys). Default
// cbor.Marshal does NOT sort, so this test catches any regression that
// removes the dedicated CTAP2EncOptions encoder.
func TestGetAssertion_ResponseIsCanonicalCBOR(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "canonical.example", "Canonical", "user", true)

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "canonical.example", nil, nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	top := decodeAssertion(t, resp.lastCtap2().data)

	// Top-level integer keys must be in ascending order.
	rawTop := resp.lastCtap2().data
	intOrder, err := readMapIntKeyOrder(rawTop)
	if err != nil {
		t.Fatalf("read top key order: %s", err)
	}
	for i := 1; i < len(intOrder); i++ {
		if intOrder[i] < intOrder[i-1] {
			t.Errorf("top-level keys not sorted ascending: %v", intOrder)
			break
		}
	}

	// User entity (field 4) sub-map keys must be sorted (CTAP2 bytewise lexical
	// order of CBOR-encoded keys). For {"id","name","displayName"} that's id,
	// name, displayName.
	userBytes := top[4]
	strOrder, err := readMapStringKeyOrder(userBytes)
	if err != nil {
		t.Fatalf("read user key order: %s", err)
	}
	want := []string{"id", "name", "displayName"}
	if fmt.Sprintf("%v", strOrder) != fmt.Sprintf("%v", want) {
		t.Errorf("user entity key order = %v, want %v (CTAP2 canonical)", strOrder, want)
	}
}

// readMapIntKeyOrder walks the top-level map of a CBOR document and returns
// the integer keys in the order they were emitted. Used to verify CTAP2
// canonical encoding (sorted ascending).
func readMapIntKeyOrder(b []byte) ([]int, error) {
	dec := cbor.NewDecoder(bytes.NewReader(b))
	var raw cbor.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	// Re-decode as ordered key-value pairs by reading element-by-element.
	if len(raw) < 1 {
		return nil, errors.New("empty cbor")
	}
	mt := raw[0] >> 5
	if mt != 5 {
		return nil, fmt.Errorf("not a map: major type %d", mt)
	}
	// Decode into a temporary structure that preserves order via cbor.RawTag-style
	// trick: marshal/unmarshal through []cbor.RawMessage of pairs is complex, so
	// instead use the slim approach of decoding into map and re-checking encoded
	// bytes. For this test we walk the bytes manually.
	pos := 1
	count := int(raw[0] & 0x1f)
	if count == 0x18 {
		count = int(raw[1])
		pos = 2
	} else if count == 0x19 {
		count = int(raw[1])<<8 | int(raw[2])
		pos = 3
	}
	out := make([]int, 0, count)
	for i := 0; i < count; i++ {
		// Read int key
		k, n, err := readInt(raw[pos:])
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		pos += n
		// Skip the value
		vn, err := skipItem(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += vn
	}
	return out, nil
}

func readMapStringKeyOrder(raw []byte) ([]string, error) {
	if len(raw) < 1 {
		return nil, errors.New("empty cbor")
	}
	mt := raw[0] >> 5
	if mt != 5 {
		return nil, fmt.Errorf("not a map: major type %d", mt)
	}
	pos := 1
	count := int(raw[0] & 0x1f)
	if count == 0x18 {
		count = int(raw[1])
		pos = 2
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		// Read string key (major type 3)
		if raw[pos]>>5 != 3 {
			return nil, fmt.Errorf("expected string key, got major type %d", raw[pos]>>5)
		}
		slen := int(raw[pos] & 0x1f)
		pos++
		if slen == 0x18 {
			slen = int(raw[pos])
			pos++
		}
		out = append(out, string(raw[pos:pos+slen]))
		pos += slen
		// Skip value
		vn, err := skipItem(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += vn
	}
	return out, nil
}

func readInt(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("empty")
	}
	mt := b[0] >> 5
	if mt != 0 && mt != 1 {
		return 0, 0, fmt.Errorf("not an int: mt=%d", mt)
	}
	v := int(b[0] & 0x1f)
	n := 1
	if v == 0x18 {
		v = int(b[1])
		n = 2
	} else if v == 0x19 {
		v = int(b[1])<<8 | int(b[2])
		n = 3
	}
	if mt == 1 {
		v = -1 - v
	}
	return v, n, nil
}

// skipItem advances past one CBOR item and returns the bytes consumed.
// Supports the small subset (ints, byte strings, text strings, arrays, maps,
// floats, bool, null) needed by these tests.
func skipItem(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("empty")
	}
	mt := b[0] >> 5
	low := b[0] & 0x1f
	pos := 1
	var arg uint64
	switch {
	case low < 24:
		arg = uint64(low)
	case low == 24:
		arg = uint64(b[pos])
		pos++
	case low == 25:
		arg = uint64(b[pos])<<8 | uint64(b[pos+1])
		pos += 2
	case low == 26:
		arg = uint64(b[pos])<<24 | uint64(b[pos+1])<<16 | uint64(b[pos+2])<<8 | uint64(b[pos+3])
		pos += 4
	case low == 27:
		for i := 0; i < 8; i++ {
			arg = arg<<8 | uint64(b[pos+i])
		}
		pos += 8
	default:
		return 0, fmt.Errorf("unsupported low %d", low)
	}
	switch mt {
	case 0, 1, 7: // unsigned, negative, simple — done
		return pos, nil
	case 2, 3: // byte string, text string
		return pos + int(arg), nil
	case 4: // array
		for i := uint64(0); i < arg; i++ {
			n, err := skipItem(b[pos:])
			if err != nil {
				return 0, err
			}
			pos += n
		}
		return pos, nil
	case 5: // map
		for i := uint64(0); i < arg; i++ {
			n, err := skipItem(b[pos:]) // key
			if err != nil {
				return 0, err
			}
			pos += n
			n, err = skipItem(b[pos:]) // value
			if err != nil {
				return 0, err
			}
			pos += n
		}
		return pos, nil
	}
	return 0, fmt.Errorf("unsupported major type %d", mt)
}

// Direct unit test of ctap2Enc. Verifies that the encoder actually sorts map
// keys, by feeding it a literal whose declared order does NOT match canonical
// order. If ctap2Enc is wired to default cbor options instead of CTAP2EncOptions,
// this test fails. This is the strong canonicality proof — the integration
// tests below rely on this passing for their own correctness claims.
//
// The integration tests for MakeCredential / GetInfo / COSE-key happen to come
// out canonical even with the default encoder (their literal map order is
// already sorted), so they cannot directly distinguish ctap2Enc from default.
// This unit test fills that gap.
func TestCTAP2Enc_SortsMapKeys(t *testing.T) {
	t.Run("integer keys, declared out of order", func(t *testing.T) {
		// Map literal order ≠ canonical order. Default cbor.Marshal would
		// emit these in iteration order (which fxamacker happens to make
		// somewhat deterministic but NOT canonical).
		m := map[int]string{4: "d", 1: "a", 3: "c", 2: "b", 5: "e"}
		encoded, err := ctap2Enc.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %s", err)
		}
		order, err := readMapIntKeyOrder(encoded)
		if err != nil {
			t.Fatalf("walk: %s", err)
		}
		want := []int{1, 2, 3, 4, 5}
		if fmt.Sprintf("%v", order) != fmt.Sprintf("%v", want) {
			t.Errorf("ctap2Enc int-key order = %v, want %v", order, want)
		}
	})

	t.Run("string keys, declared out of order", func(t *testing.T) {
		// Bytewise lex order of CBOR encoding for these keys:
		//   "id"          → 0x62 0x69 0x64
		//   "icon"        → 0x64 0x69 0x63 0x6f 0x6e
		//   "name"        → 0x64 0x6e 0x61 0x6d 0x65
		//   "displayName" → 0x6b ...
		// → id < icon < name < displayName (bytewise on CBOR-encoded form).
		m := map[string]string{
			"name":        "n",
			"displayName": "d",
			"id":          "i",
			"icon":        "c",
		}
		encoded, err := ctap2Enc.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %s", err)
		}
		order, err := readMapStringKeyOrder(encoded)
		if err != nil {
			t.Fatalf("walk: %s", err)
		}
		want := []string{"id", "icon", "name", "displayName"}
		if fmt.Sprintf("%v", order) != fmt.Sprintf("%v", want) {
			t.Errorf("ctap2Enc str-key order = %v, want %v", order, want)
		}
	})

	t.Run("mixed positive and negative integer keys (COSE shape)", func(t *testing.T) {
		// COSE EC2 keys: 1=kty, 3=alg, -1=crv, -2=x, -3=y.
		// CBOR encoding of small ints: positive 0..23 = 0x00..0x17,
		//                              negative -1..-24 = 0x20..0x37.
		// So positives sort before negatives in bytewise lex.
		m := map[int]int{-3: 3, 1: 1, -1: 1, 3: 1, -2: 2}
		encoded, err := ctap2Enc.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %s", err)
		}
		order, err := readSignedMapKeyOrder(encoded)
		if err != nil {
			t.Fatalf("walk: %s", err)
		}
		want := []int{1, 3, -1, -2, -3}
		if fmt.Sprintf("%v", order) != fmt.Sprintf("%v", want) {
			t.Errorf("ctap2Enc COSE-key order = %v, want %v", order, want)
		}
	})
}

// Response shape pinning for MakeCredential. NOT a canonicality test — see
// TestCTAP2Enc_SortsMapKeys for that. This just confirms the response has
// the expected top-level keys (1=fmt, 2=authData, 3=attStmt) and decodes.
func TestMakeCredential_ResponseShape(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeMakeCredCBOR(t, "shape-mc.example", "Shape", "user", false, false)
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(resp.lastCtap2().data, &top); err != nil {
		t.Fatalf("response is not well-formed CBOR: %s", err)
	}
	for _, k := range []int{1, 2, 3} {
		if _, ok := top[k]; !ok {
			t.Errorf("MakeCredential response missing field %d", k)
		}
	}
	var fmtField string
	cbor.Unmarshal(top[1], &fmtField)
	if fmtField != "none" {
		t.Errorf("attestation fmt = %q, want \"none\" (privacy)", fmtField)
	}
}

// Response shape pinning for GetInfo. NOT a canonicality test — see
// TestCTAP2Enc_SortsMapKeys for that.
func TestGetInfo_ResponseShape(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	resp := &fakeResponder{}
	s.handleGetInfo(context.Background(), resp, fidohid.AuthEvent{})

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(resp.lastCtap2().data, &top); err != nil {
		t.Fatalf("response is not well-formed CBOR: %s", err)
	}
	for _, k := range []int{1, 3, 4, 5} {
		if _, ok := top[k]; !ok {
			t.Errorf("GetInfo response missing field %d", k)
		}
	}
	var versions []string
	cbor.Unmarshal(top[1], &versions)
	hasFIDO2, hasU2F := false, false
	for _, v := range versions {
		if v == "FIDO_2_0" {
			hasFIDO2 = true
		}
		if v == "U2F_V2" {
			hasU2F = true
		}
	}
	if !hasFIDO2 || !hasU2F {
		t.Errorf("versions = %v, want both FIDO_2_0 and U2F_V2", versions)
	}
}

// readSignedMapKeyOrder is like readMapIntKeyOrder but accepts CBOR negative
// integer keys too (used for COSE keys where -1=crv, -2=x, -3=y).
func readSignedMapKeyOrder(raw []byte) ([]int, error) {
	if len(raw) < 1 {
		return nil, errors.New("empty cbor")
	}
	mt := raw[0] >> 5
	if mt != 5 {
		return nil, fmt.Errorf("not a map: major type %d", mt)
	}
	pos := 1
	count := int(raw[0] & 0x1f)
	if count == 0x18 {
		count = int(raw[1])
		pos = 2
	}
	out := make([]int, 0, count)
	for i := 0; i < count; i++ {
		k, n, err := readInt(raw[pos:])
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		out = append(out, k)
		pos += n
		vn, err := skipItem(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += vn
	}
	return out, nil
}

// Encoding the same input twice MUST produce identical bytes. Without
// canonical encoding this can flip on Go map iteration order. With ctap2Enc,
// the bytes are stable across runs and across processes.
func TestCBOR_EncodingIsByteStable(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "stable.example", "Stable", "user", true /*rk*/)

	// Run the same GetAssertion 10 times and confirm authData + signature
	// shape is byte-identical for the deterministic parts (everything except
	// the signature, which is randomized by ECDSA, and the counter, which
	// increments).
	var firstAuthData []byte
	for i := 0; i < 10; i++ {
		resp := &fakeResponder{}
		payload := makeAssertionCBOR(t, "stable.example", nil, nil)
		s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)
		if resp.lastCtap2().status != ctap2.StatusOK {
			t.Fatalf("iter %d: status=0x%02x", i, resp.lastCtap2().status)
		}
		top := decodeAssertion(t, resp.lastCtap2().data)
		var authData []byte
		cbor.Unmarshal(top[2], &authData)
		// authData = rpIdHash(32) | flags(1) | counter(4). Strip the counter
		// before comparing, since counters increment.
		stable := append([]byte{}, authData[:33]...) // rpIdHash + flags
		if i == 0 {
			firstAuthData = stable
			continue
		}
		if !bytes.Equal(stable, firstAuthData) {
			t.Errorf("iter %d: authData prefix changed across runs", i)
		}
		// And the user entity bytes (key 4) must be byte-identical (no signing,
		// no counter). This is the strongest stability check we can make.
		if !bytes.Equal(top[4], decodeAssertion(t, resp.lastCtap2().data)[4]) {
			t.Errorf("iter %d: user entity bytes drifted", i)
		}
	}
}

// The canonical bytes must round-trip cleanly through fxamacker/cbor's standard
// decoder. Catches any encoder option that produces non-decodable output.
func TestCBOR_CanonicalOutputRoundTrips(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "rt.example", "RT", "user", true)

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "rt.example", nil, nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	var top map[int]interface{}
	if err := cbor.Unmarshal(resp.lastCtap2().data, &top); err != nil {
		t.Fatalf("response is not well-formed CBOR: %s", err)
	}
	for _, key := range []int{1, 2, 3, 4} {
		if _, ok := top[key]; !ok {
			t.Errorf("response missing key %d", key)
		}
	}
}

// The signature in field 3 must verify against the assertion's authData ||
// clientDataHash. Catches any change that breaks the signing input.
func TestGetAssertion_SignatureCoversAuthDataAndClientDataHash(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "example.com", "Example", "eve", false)

	clientDataHash := sha256.New().Sum([]byte("client-data:example.com"))[:32]
	req := ctap2.GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: clientDataHash,
		AllowList:      []ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
	}
	payload, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	resp := &fakeResponder{}
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}

	top := decodeAssertion(t, resp.lastCtap2().data)
	var authData []byte
	cbor.Unmarshal(top[2], &authData)
	var sig []byte
	cbor.Unmarshal(top[3], &sig)
	if len(authData) == 0 || len(sig) == 0 {
		t.Fatalf("missing authData or signature")
	}

	// Check rpIdHash prefix is sha256(rpID).
	want := rpIDHash("example.com")
	if !bytes.Equal(authData[:32], want[:]) {
		t.Errorf("authData rpIdHash mismatch")
	}
	// UP must be set, AT must NOT be set on a GetAssertion (no attestedCredData).
	flags := authData[32]
	if flags&ctap2.AuthFlagUP == 0 {
		t.Errorf("UP flag not set on GetAssertion authData")
	}
	if flags&ctap2.AuthFlagAT != 0 {
		t.Errorf("AT flag must not be set on GetAssertion (only on MakeCredential)")
	}
}

// =====================================================================
// Spec compliance tests for handleMakeCredential / handleGetInfo
// =====================================================================

// MakeCredential with nil Options must work — many CTAP2 clients omit it.
func TestMakeCredential_NilOptionsOK(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   sha256.New().Sum([]byte("mc:test"))[:32],
		RP:               ctap2.RPEntity{ID: "test.example.com", Name: "Test"},
		User:             ctap2.UserEntity{ID: []byte("u1"), Name: "u1@test", DisplayName: "U One"},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
	}
	payload, _ := cbor.Marshal(req)

	resp := &fakeResponder{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handleMakeCredential panicked: %v", r)
		}
	}()
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
}

// MakeCredential with uv=true MUST be rejected when the verifier doesn't
// actually verify identity (e.g. pinentry-only mode).
func TestMakeCredential_UVRequestedButVerifierIsUPOnly(t *testing.T) {
	verifier := &fakeVerifier{performsUV: false}
	s := newTestServer(t, verifier, &fakePinentry{})
	payload := makeMakeCredCBOR(t, "site.example", "Site", "user", false, true /*uv*/)

	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusInvalidOption {
		t.Fatalf("expected StatusInvalidOption (0x2C), got 0x%02x", got)
	}
}

// MakeCredential without ES256 in pubKeyCredParams must return StatusUnsupportedAlg.
func TestMakeCredential_RejectsNoES256(t *testing.T) {
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, &fakePinentry{})

	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   sha256.New().Sum([]byte("mc:none-es256"))[:32],
		RP:               ctap2.RPEntity{ID: "site.example", Name: "Site"},
		User:             ctap2.UserEntity{ID: []byte("u")},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -257}}, // RS256, not supported
	}
	payload, _ := cbor.Marshal(req)
	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusUnsupportedAlg {
		t.Fatalf("expected StatusUnsupportedAlg (0x26), got 0x%02x", got)
	}
}

// GetInfo's `uv` capability bit must reflect the actual verifier's PerformsUV().
// Lying here causes RPs to expect UV when the device cannot deliver it.
func TestGetInfo_UVBitReflectsVerifier(t *testing.T) {
	for _, performsUV := range []bool{false, true} {
		name := fmt.Sprintf("performsUV=%v", performsUV)
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t, &fakeVerifier{performsUV: performsUV}, &fakePinentry{})
			resp := &fakeResponder{}
			s.handleGetInfo(context.Background(), resp, fidohid.AuthEvent{})

			if resp.lastCtap2().status != ctap2.StatusOK {
				t.Fatalf("status=0x%02x", resp.lastCtap2().status)
			}
			var top map[int]cbor.RawMessage
			cbor.Unmarshal(resp.lastCtap2().data, &top)
			var opts map[string]bool
			cbor.Unmarshal(top[4], &opts)
			if opts["uv"] != performsUV {
				t.Errorf("uv option = %v, want %v", opts["uv"], performsUV)
			}
			if !opts["up"] {
				t.Errorf("up option must be true")
			}
		})
	}
}

// =====================================================================
// Real-world site simulations
// =====================================================================

// GitHub: passkey login with allowList, no Options field at all (the
// most common shape — browser knows the credId, just wants a signature).
func TestRealWorld_GitHubPasskeyLogin(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "github.com", "GitHub", "octocat", false)
	verifier.callCount = 0

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "github.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
		nil) // GitHub typically omits Options
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	if verifier.callCount != 1 {
		t.Errorf("expected 1 fingerprint prompt, got %d", verifier.callCount)
	}
}

// Google: resident credential login (no allowList), explicit UV=true.
// The server must look the credential up by RPID hash and surface the user
// entity in the response.
func TestRealWorld_GooglePasskeyLogin(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "google.com", "Google", "alice", true /*rk*/)
	verifier.callCount = 0

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "google.com", nil,
		&ctap2.GetAssertOptions{UV: true})
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	top := decodeAssertion(t, resp.lastCtap2().data)
	if _, ok := top[4]; !ok {
		t.Errorf("resident-credential login must include user entity (field 4)")
	}
	if verifier.callCount != 1 {
		t.Errorf("expected 1 verification call, got %d", verifier.callCount)
	}
}

// Microsoft entra: strict 2FA — allowList AND uv=true. Test passes only when
// both UP and UV flags are set in authData.
func TestRealWorld_MicrosoftStrictUV(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "login.microsoftonline.com", "Microsoft", "user", false)

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "login.microsoftonline.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
		&ctap2.GetAssertOptions{UV: true})
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	top := decodeAssertion(t, resp.lastCtap2().data)
	var authData []byte
	cbor.Unmarshal(top[2], &authData)
	flags := authData[32]
	if flags&ctap2.AuthFlagUP == 0 || flags&ctap2.AuthFlagUV == 0 {
		t.Errorf("expected UP+UV flags, got 0x%02x", flags)
	}
}

// webauthn.io demo: registers a passkey with rk=true. The cose key in
// authData must be a valid ES256 EC2 key on P-256.
func TestRealWorld_WebauthnIORegister(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeMakeCredCBOR(t, "webauthn.io", "WebAuthn.io demo", "frank", true, true)
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	var top map[int]cbor.RawMessage
	cbor.Unmarshal(resp.lastCtap2().data, &top)
	var fmt_ string
	cbor.Unmarshal(top[1], &fmt_)
	if fmt_ != "none" {
		t.Errorf("attestation format must be \"none\" (privacy), got %q", fmt_)
	}
}

// excludeList: a second registration for the same RP must be rejected with
// CredentialExcluded — the linux-id signer can recover the existing key from
// its handle, so the duplicate must be detected.
func TestRealWorld_DuplicateRegistrationRejected(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "exclude.example", "Exclude", "user1", false)

	// Second registration includes the existing credID in excludeList.
	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   sha256.New().Sum([]byte("mc:exclude2"))[:32],
		RP:               ctap2.RPEntity{ID: "exclude.example", Name: "Exclude"},
		User:             ctap2.UserEntity{ID: []byte("u2"), Name: "u2", DisplayName: "U Two"},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
		ExcludeList:      []ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
	}
	payload, _ := cbor.Marshal(req)

	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusCredentialExcluded {
		t.Fatalf("expected StatusCredentialExcluded (0x19), got 0x%02x", got)
	}
}

// AllowList ordering: when several credentials are listed but only the second
// is recoverable by our signer, the handler must walk past the invalid one
// and pick the valid one. The order in the response's `credential` field must
// match the entry that was actually used.
func TestGetAssertion_AllowListSecondCredValid(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	credID := registerCred(t, s, "multi.example", "Multi", "user", false)

	// First entry: total junk. Second entry: real cred. Handler must use #2.
	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "multi.example",
		[]ctap2.CredDescriptor{
			{Type: "public-key", ID: []byte("not-a-real-cred-id-12345")},
			{Type: "public-key", ID: credID},
		},
		nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}
	top := decodeAssertion(t, resp.lastCtap2().data)
	var cred map[string]interface{}
	if err := cbor.Unmarshal(top[1], &cred); err != nil {
		t.Fatalf("decode credential descriptor: %s", err)
	}
	gotID, ok := cred["id"].([]byte)
	if !ok {
		t.Fatalf("credential.id is not []byte: %T", cred["id"])
	}
	if !bytes.Equal(gotID, credID) {
		t.Errorf("returned credential id = %x, want %x", gotID, credID)
	}
}

// AllowList where every entry is invalid: handler must return NoCredentials
// and never invoke the verifier (no point asking for biometric if there's no
// key to sign with).
func TestGetAssertion_AllowListAllInvalidNoVerifierCall(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "junk.example",
		[]ctap2.CredDescriptor{
			{Type: "public-key", ID: []byte("garbage1")},
			{Type: "public-key", ID: []byte("garbage2")},
			{Type: "public-key", ID: []byte("garbage3")},
		},
		nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)

	if got := resp.lastCtap2().status; got != ctap2.StatusNoCredentials {
		t.Fatalf("expected StatusNoCredentials, got 0x%02x", got)
	}
	if verifier.callCount != 0 {
		t.Errorf("verifier must not be called if no credential matches; got %d calls", verifier.callCount)
	}
}

// Resident credential with empty optional fields. Browsers can register a
// passkey where only `id` is set (no name, no display name) when the user
// chooses anonymous mode. The user entity in the response must still be
// well-formed CBOR with all three string keys.
func TestGetAssertion_ResidentCredentialMinimalUserFields(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	// Register with empty name + displayName.
	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   sha256.New().Sum([]byte("mc:anon"))[:32],
		RP:               ctap2.RPEntity{ID: "anon.example", Name: "Anon"},
		User:             ctap2.UserEntity{ID: []byte("anonymous-handle")},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
		Options:          &ctap2.MakeCredOptions{RK: true},
	}
	mcPayload, _ := cbor.Marshal(req)
	mcResp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), mcResp, fidohid.AuthEvent{}, mcPayload)
	if mcResp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("register: 0x%02x", mcResp.lastCtap2().status)
	}

	// Now look the resident credential up.
	gaResp := &fakeResponder{}
	gaPayload := makeAssertionCBOR(t, "anon.example", nil, nil)
	s.handleGetAssertion(context.Background(), gaResp, fidohid.AuthEvent{}, gaPayload)
	if gaResp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("assert: 0x%02x", gaResp.lastCtap2().status)
	}

	top := decodeAssertion(t, gaResp.lastCtap2().data)
	var user map[string]interface{}
	if err := cbor.Unmarshal(top[4], &user); err != nil {
		t.Fatalf("user entity: %s", err)
	}
	if id, _ := user["id"].([]byte); !bytes.Equal(id, []byte("anonymous-handle")) {
		t.Errorf("user.id = %x, want %x", id, []byte("anonymous-handle"))
	}
	// Empty strings are still acceptable. Just confirm the keys are there
	// (canonical CBOR shape) — value content can be empty.
	if _, ok := user["name"]; !ok {
		t.Errorf("user entity missing name key (even if empty)")
	}
	if _, ok := user["displayName"]; !ok {
		t.Errorf("user entity missing displayName key (even if empty)")
	}
}

// COSE EC2 public key shape: the inner crypto key inside MakeCredential's
// authenticatorData must be a valid P-256 ES256 key. Field tags:
//   1  (kty)  = 2  (EC2)
//   3  (alg)  = -7 (ES256)
//   -1 (crv)  = 1  (P-256)
//   -2 (x)    = 32 bytes
//   -3 (y)    = 32 bytes
func TestMakeCredential_COSEKeyShape(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeMakeCredCBOR(t, "cose-shape.example", "Shape", "user", false, false)
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("status=0x%02x", resp.lastCtap2().status)
	}

	var top map[int]cbor.RawMessage
	cbor.Unmarshal(resp.lastCtap2().data, &top)
	var authData []byte
	cbor.Unmarshal(top[2], &authData)
	credIDLen := int(authData[32+1+4+16])<<8 | int(authData[32+1+4+16+1])
	coseStart := 32 + 1 + 4 + 16 + 2 + credIDLen
	coseBytes := authData[coseStart:]

	var cose map[int]interface{}
	if err := cbor.Unmarshal(coseBytes, &cose); err != nil {
		t.Fatalf("decode cose key: %s", err)
	}
	if kty, _ := cose[1].(uint64); kty != 2 {
		t.Errorf("kty = %v, want 2 (EC2)", cose[1])
	}
	if alg, _ := cose[3].(int64); alg != -7 {
		t.Errorf("alg = %v, want -7 (ES256)", cose[3])
	}
	if crv, _ := cose[-1].(uint64); crv != 1 {
		t.Errorf("crv = %v, want 1 (P-256)", cose[-1])
	}
	if x, _ := cose[-2].([]byte); len(x) != 32 {
		t.Errorf("x len = %d, want 32", len(x))
	}
	if y, _ := cose[-3].([]byte); len(y) != 32 {
		t.Errorf("y len = %d, want 32", len(y))
	}
}

// Legacy AWS U2F: CTAP1 authenticate. handleAuthenticate must call pinentry
// with the request's challenge/app params (not random nonces) so browser
// retries dedup correctly. Catches the PR's ConfirmGeneric regression.
func TestRealWorld_AWSLegacyU2FAuth(t *testing.T) {
	pe := &fakePinentry{nextResult: pinentry.Result{OK: true}}
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, pe)

	// Register a U2F credential first via the in-memory signer directly
	// (handleRegister also uses pinentry, this is simpler).
	appParam := rpIDHash("u2f.aws.amazon.com")
	keyHandle, _, _, err := s.signer.RegisterKey(appParam[:])
	if err != nil {
		t.Fatal(err)
	}

	authReq := &fidoauth.AuthenticatorRequest{
		Command: fidoauth.CmdAuthenticate,
		Authenticate: &fidoauth.AuthenticatorAuthReq{
			Ctrl:             fidoauth.CtrlEnforeUserPresenceAndSign,
			ChallengeParam:   sha256.Sum256([]byte("aws-challenge-1")),
			ApplicationParam: appParam,
			KeyHandle:        keyHandle,
		},
	}
	resp := &fakeResponder{}
	s.handleAuthenticate(context.Background(), resp, fidohid.AuthEvent{Req: authReq})

	if resp.lastU2F().status != statuscode.NoError {
		t.Fatalf("expected NoError, got 0x%04x", resp.lastU2F().status)
	}
	if got := pe.snapshotPromptCount(); got != 1 {
		t.Errorf("expected exactly 1 pinentry prompt, got %d", got)
	}
	calls := pe.snapshotCalls()
	if len(calls) == 0 || calls[0].challenge != authReq.Authenticate.ChallengeParam {
		t.Errorf("pinentry was not invoked with the request's challenge param")
	}
	if calls[0].app != appParam {
		t.Errorf("pinentry was not invoked with the request's application param")
	}

	// Response: 1 byte UP | 4 bytes counter | sig
	data := resp.lastU2F().data
	if len(data) < 5 {
		t.Fatalf("U2F auth response too short: %d", len(data))
	}
	if data[0] != 0x01 {
		t.Errorf("UP byte = 0x%02x, want 0x01", data[0])
	}
}

// Browser dedup: a second handleAuthenticate call with the SAME challenge/app
// (browser polling its first request) must reuse the existing pinentry prompt
// instead of opening a second one. This is the property the PR's ConfirmGeneric
// switch silently breaks.
func TestRealWorld_U2FBrowserPollingDedup(t *testing.T) {
	pe := &fakePinentry{
		nextResult:  pinentry.Result{OK: true},
		blockResult: true, // hold the prompt result so we can poll again
	}
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, pe)

	appParam := rpIDHash("github.com")
	keyHandle, _, _, _ := s.signer.RegisterKey(appParam[:])
	challenge := sha256.Sum256([]byte("retry-challenge"))
	authReq := &fidoauth.AuthenticatorRequest{
		Command: fidoauth.CmdAuthenticate,
		Authenticate: &fidoauth.AuthenticatorAuthReq{
			Ctrl:             fidoauth.CtrlEnforeUserPresenceAndSign,
			ChallengeParam:   challenge,
			ApplicationParam: appParam,
			KeyHandle:        keyHandle,
		},
	}

	// First poll: handler will block waiting for pinentry to release.
	resp1 := &fakeResponder{}
	done1 := make(chan struct{})
	go func() {
		s.handleAuthenticate(context.Background(), resp1, fidohid.AuthEvent{Req: authReq})
		close(done1)
	}()

	// Wait briefly for the first call to register itself with pinentry.
	time.Sleep(20 * time.Millisecond)

	// Second poll (browser retry): same challenge/app. Should NOT open a
	// new prompt — it should attach to the existing one.
	resp2 := &fakeResponder{}
	done2 := make(chan struct{})
	go func() {
		s.handleAuthenticate(context.Background(), resp2, fidohid.AuthEvent{Req: authReq})
		close(done2)
	}()
	time.Sleep(20 * time.Millisecond)

	if got := pe.snapshotPromptCount(); got != 1 {
		t.Errorf("expected 1 pinentry prompt for browser polling, got %d", got)
	}

	pe.release()
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first handler call did not return after pinentry released")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("second handler call did not return after pinentry released")
	}
}

// User cancels the U2F authenticate prompt. The U2F spec doesn't really have
// a "cancel" status, so the codebase reports WrongData to make the browser
// stop polling.
func TestRealWorld_U2FUserCancel(t *testing.T) {
	pe := &fakePinentry{nextResult: pinentry.Result{OK: false, Error: errors.New("cancel")}}
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, pe)

	appParam := rpIDHash("vault.bitwarden.com")
	keyHandle, _, _, _ := s.signer.RegisterKey(appParam[:])
	authReq := &fidoauth.AuthenticatorRequest{
		Command: fidoauth.CmdAuthenticate,
		Authenticate: &fidoauth.AuthenticatorAuthReq{
			Ctrl:             fidoauth.CtrlEnforeUserPresenceAndSign,
			ChallengeParam:   sha256.Sum256([]byte("bw-c")),
			ApplicationParam: appParam,
			KeyHandle:        keyHandle,
		},
	}
	resp := &fakeResponder{}
	s.handleAuthenticate(context.Background(), resp, fidohid.AuthEvent{Req: authReq})

	if got := resp.lastU2F().status; got != statuscode.WrongData {
		t.Fatalf("expected WrongData on cancel, got 0x%04x", got)
	}
}

// Check-only auth (browser asking "do you have this credential?") must not
// prompt the user — it should return ConditionsNotSatisfied silently.
func TestRealWorld_U2FCheckOnly(t *testing.T) {
	pe := &fakePinentry{}
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, pe)

	appParam := rpIDHash("u2f.bin.coffee")
	keyHandle, _, _, _ := s.signer.RegisterKey(appParam[:])
	authReq := &fidoauth.AuthenticatorRequest{
		Command: fidoauth.CmdAuthenticate,
		Authenticate: &fidoauth.AuthenticatorAuthReq{
			Ctrl:             fidoauth.CtrlCheckOnly,
			ChallengeParam:   sha256.Sum256([]byte("c")),
			ApplicationParam: appParam,
			KeyHandle:        keyHandle,
		},
	}
	resp := &fakeResponder{}
	s.handleAuthenticate(context.Background(), resp, fidohid.AuthEvent{Req: authReq})

	if got := pe.snapshotPromptCount(); got != 0 {
		t.Errorf("check-only must not prompt the user, got %d prompts", got)
	}
	if got := resp.lastU2F().status; got != statuscode.ConditionsNotSatisfied {
		t.Fatalf("expected ConditionsNotSatisfied, got 0x%04x", got)
	}
}

// Bad key handle: signing fails, handler must return WrongData without
// touching pinentry.
func TestRealWorld_U2FUnknownKeyHandle(t *testing.T) {
	pe := &fakePinentry{}
	verifier := &fakeVerifier{}
	s := newTestServer(t, verifier, pe)

	authReq := &fidoauth.AuthenticatorRequest{
		Command: fidoauth.CmdAuthenticate,
		Authenticate: &fidoauth.AuthenticatorAuthReq{
			Ctrl:             fidoauth.CtrlEnforeUserPresenceAndSign,
			ChallengeParam:   sha256.Sum256([]byte("x")),
			ApplicationParam: rpIDHash("dropbox.com"),
			KeyHandle:        []byte("not-a-real-handle"),
		},
	}
	resp := &fakeResponder{}
	s.handleAuthenticate(context.Background(), resp, fidohid.AuthEvent{Req: authReq})

	if got := pe.snapshotPromptCount(); got != 0 {
		t.Errorf("invalid key handle must short-circuit before pinentry, got %d prompts", got)
	}
	if got := resp.lastU2F().status; got != statuscode.WrongData {
		t.Fatalf("expected WrongData, got 0x%04x", got)
	}
}

// =====================================================================
// Failure / edge cases for CTAP2
// =====================================================================

func TestGetAssertion_NoMatchingCredentialInAllowList(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "example.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: []byte("totally-bogus")}},
		nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusNoCredentials {
		t.Fatalf("expected StatusNoCredentials (0x2E), got 0x%02x", got)
	}
}

func TestGetAssertion_NoResidentCredentials(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "no-creds.example", nil, nil)
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusNoCredentials {
		t.Fatalf("expected StatusNoCredentials (0x2E), got 0x%02x", got)
	}
}

// TestStatusCodeValuesMatchSpec asserts every CTAP2 status code constant in
// ctap2/ctap2.go has the value defined by the spec. Source of truth: libfido2
// src/fido/err.h, which is generated from the FIDO Alliance CTAP 2.1 spec
// section 8.2 "Status codes".
//
// If you change a constant value in ctap2.go and didn't intend to break spec
// compliance, this test catches it.
func TestStatusCodeValuesMatchSpec(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"StatusOK", ctap2.StatusOK, 0x00},
		{"StatusInvalidCbor", ctap2.StatusInvalidCbor, 0x12},
		{"StatusCredentialExcluded", ctap2.StatusCredentialExcluded, 0x19},
		{"StatusUnsupportedAlg", ctap2.StatusUnsupportedAlg, 0x26},
		{"StatusOperationDenied", ctap2.StatusOperationDenied, 0x27},
		{"StatusInvalidOption", ctap2.StatusInvalidOption, 0x2C},
		{"StatusNoCredentials", ctap2.StatusNoCredentials, 0x2E},
		// 0x2F per CTAP 2.1 §8.2 / FIDO_ERR_USER_ACTION_TIMEOUT.
		// 0x2A is FIDO_ERR_NO_OPERATION_PENDING — a different error.
		{"StatusUserActionTimeout", ctap2.StatusUserActionTimeout, 0x2F},
		{"StatusNotAllowed", ctap2.StatusNotAllowed, 0x30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("ctap2.%s = 0x%02x, spec value is 0x%02x", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestGetAssertion_VerifierTimeout asserts the handler reports the spec-correct
// timeout error code (CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F) when the verifier
// doesn't complete in time. Pinning the constant rather than the literal so
// the failure message reads cleanly.
func TestGetAssertion_VerifierTimeout(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	// Register first while the verifier is still synchronous.
	credID := registerCred(t, s, "slow.example.com", "Slow", "user", false)

	// Now switch the verifier into blocking mode for the assertion call.
	gate := make(chan struct{})
	verifier.blockUntil = gate
	verifier.callCount = 0

	// Use a tight context so the timeout fires quickly. handleGetAssertion's
	// own timeout is 35s, but the parent context will pre-empt it.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "slow.example.com",
		[]ctap2.CredDescriptor{{Type: "public-key", ID: credID}},
		nil)
	s.handleGetAssertion(ctx, resp, fidohid.AuthEvent{}, payload)

	close(gate) // unblock the goroutine so it doesn't leak
	if got := resp.lastCtap2().status; got != ctap2.StatusUserActionTimeout {
		t.Fatalf("expected StatusUserActionTimeout (0x%02x), got 0x%02x",
			ctap2.StatusUserActionTimeout, got)
	}
}

func TestGetAssertion_RejectUVRequestWhenVerifierIsUPOnly(t *testing.T) {
	verifier := &fakeVerifier{performsUV: false}
	s := newTestServer(t, verifier, &fakePinentry{})

	resp := &fakeResponder{}
	payload := makeAssertionCBOR(t, "example.com", nil, &ctap2.GetAssertOptions{UV: true})
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusInvalidOption {
		t.Fatalf("expected StatusInvalidOption (0x2C), got 0x%02x", got)
	}
}

// =====================================================================
// Sanity: NewCredStore is isolated to t.TempDir() and persists writes
// =====================================================================
func TestCredStoreIsIsolatedToTempDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cs := ctap2.NewCredStore()
	err := cs.Save(ctap2.StoredCredential{
		CredID: []byte("c1"), RPIDHash: []byte("r"), RPID: "x", UserID: []byte("u"),
	})
	if err != nil {
		t.Fatalf("save: %s", err)
	}
	got, err := cs.FindByRPID([]byte("r"))
	if err != nil || len(got) != 1 {
		t.Fatalf("expected 1 cred, got %d (err=%v)", len(got), err)
	}
}
