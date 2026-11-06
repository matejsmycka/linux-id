package main

import (
	"bytes"
	"context"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
)

func boolPtr(b bool) *bool { return &b }

func assertResident(t *testing.T, s *server, rpID string, options *ctap2.GetAssertOptions) (byte, map[int]cbor.RawMessage) {
	t.Helper()
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{
		RawCbor: append([]byte{ctap2.CmdGetAssertion}, makeAssertionCBOR(t, rpID, nil, options)...),
	})
	w := resp.lastCtap2()
	if w.status != ctap2.StatusOK {
		return w.status, nil
	}
	return w.status, decodeAssertion(t, w.data)
}

func getNext(t *testing.T, s *server) (byte, map[int]cbor.RawMessage) {
	t.Helper()
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdGetNextAssertion}})
	w := resp.lastCtap2()
	if w.status != ctap2.StatusOK {
		return w.status, nil
	}
	return w.status, decodeAssertion(t, w.data)
}

func credIDOf(t *testing.T, top map[int]cbor.RawMessage) []byte {
	t.Helper()
	var desc struct {
		ID []byte `cbor:"id"`
	}
	if err := cbor.Unmarshal(top[1], &desc); err != nil {
		t.Fatal(err)
	}
	return desc.ID
}

func userOf(t *testing.T, top map[int]cbor.RawMessage) map[string]interface{} {
	t.Helper()
	var user map[string]interface{}
	if err := cbor.Unmarshal(top[4], &user); err != nil {
		t.Fatal(err)
	}
	return user
}

// Every resident credential for an RP is reachable: the first via
// GetAssertion with numberOfCredentials, the rest via GetNextAssertion,
// most recently created first.
func TestGetAssertion_MultipleResidentCredentials(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	alice := registerCred(t, s, "multi.example", "Multi", "alice", true)
	bob := registerCred(t, s, "multi.example", "Multi", "bob", true)
	registerCred(t, s, "other.example", "Other", "carol", true)

	verifier.callCount = 0
	status, first := assertResident(t, s, "multi.example", nil)
	if status != ctap2.StatusOK {
		t.Fatalf("GetAssertion: 0x%02x", status)
	}
	var n int
	if err := cbor.Unmarshal(first[5], &n); err != nil || n != 2 {
		t.Fatalf("numberOfCredentials = %d (%v), want 2", n, err)
	}
	if !bytes.Equal(credIDOf(t, first), bob) {
		t.Error("first assertion should use the newest credential (bob)")
	}

	status, second := getNext(t, s)
	if status != ctap2.StatusOK {
		t.Fatalf("GetNextAssertion: 0x%02x", status)
	}
	if !bytes.Equal(credIDOf(t, second), alice) {
		t.Error("second assertion should use alice's credential")
	}
	if _, ok := second[5]; ok {
		t.Error("numberOfCredentials must only be in the first response")
	}
	if verifier.callCount != 1 {
		t.Errorf("user asked %d times, want once for the whole iteration", verifier.callCount)
	}

	if status, _ := getNext(t, s); status != ctap2.StatusNotAllowed {
		t.Errorf("GetNextAssertion past the end: 0x%02x, want NotAllowed", status)
	}
}

func TestGetNextAssertion_EndedByOtherCommand(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "multi.example", "Multi", "alice", true)
	registerCred(t, s, "multi.example", "Multi", "bob", true)

	assertResident(t, s, "multi.example", nil)
	s.handleCtap2(context.Background(), &fakeResponder{}, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdGetInfo}})
	if status, _ := getNext(t, s); status != ctap2.StatusNotAllowed {
		t.Errorf("GetNextAssertion after GetInfo: 0x%02x, want NotAllowed", status)
	}
}

// Registering again for the same account at the same RP replaces the
// resident credential instead of piling up duplicates.
func TestMakeCredential_SameUserOverwritesResidentCredential(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "dup.example", "Dup", "alice", true)
	second := registerCred(t, s, "dup.example", "Dup", "alice", true)

	h := rpIDHash("dup.example")
	creds, err := s.cs.FindByRPID(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || !bytes.Equal(creds[0].CredID, second) {
		t.Fatalf("got %d credentials, want only the newest", len(creds))
	}
}

// up=false probes for credentials without involving the user and without
// claiming presence or verification in the flags.
func TestGetAssertion_SilentProbe(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "silent.example", "Silent", "alice", true)

	verifier.callCount = 0
	status, top := assertResident(t, s, "silent.example", &ctap2.GetAssertOptions{UP: boolPtr(false)})
	if status != ctap2.StatusOK {
		t.Fatalf("GetAssertion: 0x%02x", status)
	}
	if verifier.callCount != 0 {
		t.Errorf("verifier called %d times for up=false", verifier.callCount)
	}
	var authData []byte
	cbor.Unmarshal(top[2], &authData)
	if flags := authData[32]; flags&(ctap2.AuthFlagUP|ctap2.AuthFlagUV) != 0 {
		t.Errorf("flags = %#x, want neither UP nor UV", flags)
	}
	if user := userOf(t, top); user["name"] != nil || user["displayName"] != nil {
		t.Errorf("unverified assertion leaked user details: %v", user)
	}
}

// Without user verification only the user handle is returned (CTAP 2.1
// §6.2.2 step 12): name and displayName are personally identifying.
func TestGetAssertion_UPOnlyOmitsUserDetails(t *testing.T) {
	verifier := &fakeVerifier{nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	registerCred(t, s, "uponly.example", "UP", "alice", true)

	status, top := assertResident(t, s, "uponly.example", nil)
	if status != ctap2.StatusOK {
		t.Fatalf("GetAssertion: 0x%02x", status)
	}
	user := userOf(t, top)
	if !bytes.Equal(user["id"].([]byte), []byte("alice")) {
		t.Errorf("user.id = %v", user["id"])
	}
	if _, ok := user["name"]; ok {
		t.Error("name returned without UV")
	}
}

func TestMakeCredential_RejectsUPFalse(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	req := ctap2.MakeCredentialRequest{
		ClientDataHash:   make([]byte, 32),
		RP:               ctap2.RPEntity{ID: "up.example"},
		User:             ctap2.UserEntity{ID: []byte("u")},
		PubKeyCredParams: []ctap2.CredParam{{Type: "public-key", Alg: -7}},
		Options:          &ctap2.MakeCredOptions{UP: boolPtr(false)},
	}
	payload, _ := cbor.Marshal(req)
	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if got := resp.lastCtap2().status; got != ctap2.StatusInvalidOption {
		t.Fatalf("status 0x%02x, want InvalidOption", got)
	}
}

func TestSelection(t *testing.T) {
	verifier := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, verifier, &fakePinentry{})
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdSelection}})
	if got := resp.lastCtap2().status; got != ctap2.StatusOK || verifier.callCount != 1 {
		t.Fatalf("status 0x%02x calls %d", got, verifier.callCount)
	}

	verifier.nextResult = VerifyResult{OK: false, Reason: ReasonNoMatch}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdSelection}})
	if got := resp.lastCtap2().status; got == ctap2.StatusOK {
		t.Fatal("selection succeeded without the user")
	}
}

func TestUnknownCtap2CommandIsInvalidCommand(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{}, &fakePinentry{})
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{0xBF}})
	if got := resp.lastCtap2().status; got != ctap2.StatusInvalidCommand {
		t.Fatalf("status 0x%02x", got)
	}
}
