package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/telesma-app/ctap/protocol"
)

func assertWith(t *testing.T, s *server, rpID string, credID []byte) byte {
	t.Helper()
	var allow []ctap2.CredDescriptor
	if credID != nil {
		allow = []ctap2.CredDescriptor{{Type: "public-key", ID: credID}}
	}
	resp := &fakeResponder{}
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, makeAssertionCBOR(t, rpID, allow, nil))
	return resp.lastCtap2().status
}

func ctapReset(t *testing.T, s *server) byte {
	t.Helper()
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdReset}})
	return resp.lastCtap2().status
}

func TestReset_RetiresEveryCredential(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	nonResident := registerCred(t, s, "a.example", "A", "alice", false)
	resident := registerCred(t, s, "b.example", "B", "bob", true)
	if err := s.pin.set(bytes.Repeat([]byte{1}, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pinuv.IssueToken(protocol.PermissionGetAssertion, "", true, true); err != nil {
		t.Fatal(err)
	}

	calls := v.callCount
	if got := ctapReset(t, s); got != ctap2.StatusOK {
		t.Fatalf("reset: 0x%02x", got)
	}
	if v.callCount != calls+1 {
		t.Error("reset did not ask the user")
	}
	if req := v.lastReq; !req.Fresh || req.Action != ActionReset {
		t.Errorf("reset verification request = %+v, want fresh ActionReset", req)
	}

	// The credential IDs a relying party still holds no longer sign.
	if got := assertWith(t, s, "a.example", nonResident); got != ctap2.StatusNoCredentials {
		t.Errorf("non-resident after reset: 0x%02x", got)
	}
	if got := assertWith(t, s, "b.example", resident); got != ctap2.StatusNoCredentials {
		t.Errorf("resident (allowList) after reset: 0x%02x", got)
	}
	if got := assertWith(t, s, "b.example", nil); got != ctap2.StatusNoCredentials {
		t.Errorf("discoverable after reset: 0x%02x", got)
	}
	if creds, _ := s.cs.List(); len(creds) != 0 {
		t.Errorf("%d credentials left in the store", len(creds))
	}
	if s.pin.isSet() {
		t.Error("PIN survived the reset")
	}
	if s.pinuv.UserVerified() {
		t.Error("pinUvAuthToken survived the reset")
	}

	// New credentials work.
	fresh := registerCred(t, s, "a.example", "A", "alice", false)
	if got := assertWith(t, s, "a.example", fresh); got != ctap2.StatusOK {
		t.Errorf("credential made after reset: 0x%02x", got)
	}
}

func TestReset_OnlyRightAfterPowerUp(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	cred := registerCred(t, s, "a.example", "A", "alice", false)
	s.startedAt = time.Now().Add(-resetWindow - time.Second)

	calls := v.callCount
	if got := ctapReset(t, s); got != ctap2.StatusNotAllowed {
		t.Fatalf("late reset: 0x%02x, want NOT_ALLOWED", got)
	}
	if v.callCount != calls {
		t.Error("late reset asked the user")
	}
	if got := assertWith(t, s, "a.example", cred); got != ctap2.StatusOK {
		t.Errorf("credential after refused reset: 0x%02x", got)
	}
}

func TestReset_NeedsTheUser(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	cred := registerCred(t, s, "a.example", "A", "alice", true)

	v.nextResult = VerifyResult{OK: false, Reason: ReasonNoMatch}
	if got := ctapReset(t, s); got == ctap2.StatusOK {
		t.Fatal("reset without the user's finger")
	}
	v.nextResult = VerifyResult{OK: true}
	if got := assertWith(t, s, "a.example", cred); got != ctap2.StatusOK {
		t.Errorf("credential after declined reset: 0x%02x", got)
	}
	if creds, _ := s.cs.List(); len(creds) != 1 {
		t.Error("declined reset touched the store")
	}
}

// `linux-id reset` works on the files; the running daemon notices the new
// generation on its next request and drops its tokens.
func TestResetCLI_ReachesRunningDaemon(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	cred := registerCred(t, s, "a.example", "A", "alice", true)
	s.syncGeneration()
	if _, err := s.pinuv.IssueToken(protocol.PermissionGetAssertion, "", true, true); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	cli := resetCLI{gens: s.gens, cs: s.cs, pin: s.pin,
		stdin: strings.NewReader("no\n"), stdout: &out, stderr: &errOut}
	if code := cli.run(nil); code == 0 {
		t.Fatal("reset without confirmation")
	}
	if got := assertWith(t, s, "a.example", cred); got != ctap2.StatusOK {
		t.Fatalf("declined CLI reset changed something: 0x%02x", got)
	}

	cli.stdin = strings.NewReader("reset\n")
	if code := cli.run(nil); code != 0 {
		t.Fatalf("reset: %d: %s", code, errOut.String())
	}
	s.handleEvent(context.Background(), &fakeResponder{}, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdGetInfo}})
	if s.pinuv.UserVerified() {
		t.Error("daemon kept its token after a CLI reset")
	}
	if got := assertWith(t, s, "a.example", cred); got != ctap2.StatusNoCredentials {
		t.Errorf("credential after CLI reset: 0x%02x", got)
	}
}

// failingGenerations is a backend whose generation counter cannot be read.
type failingGenerations struct{ generationBackend }

func (failingGenerations) Generation() (uint64, error) { return 0, errors.New("tpm unavailable") }

// An unreadable generation counter fails closed: nothing is created or signed.
func TestGeneration_UnreadableFailsClosed(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	cred := registerCred(t, s, "a.example", "A", "alice", false)
	s.gens, s.genSecret = failingGenerations{s.gens}, nil
	if got := assertWith(t, s, "a.example", cred); got == ctap2.StatusOK {
		t.Error("signed with an unreadable generation")
	}
	h := sha256.Sum256([]byte("a.example"))
	if _, _, _, err := s.newCredential(h[:], credOptions{}); err == nil {
		t.Error("created a credential with an unreadable generation")
	}
}

// Credential IDs in any other form, including the earlier "lxe\x01" one,
// are not this authenticator's.
func TestCredID_OnlyCurrentFormat(t *testing.T) {
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	cred := registerCred(t, s, "a.example", "A", "alice", false)
	if !bytes.HasPrefix(cred, []byte(credIDMagic)) {
		t.Fatalf("credential ID %x lacks the header", cred[:8])
	}
	old := append([]byte("lxe\x01"), cred[len(credIDMagic):]...)
	if got := assertWith(t, s, "a.example", old); got != ctap2.StatusNoCredentials {
		t.Errorf("v1-format ID: 0x%02x", got)
	}
	if got := assertWith(t, s, "a.example", cred[credIDHeaderLen:]); got != ctap2.StatusNoCredentials {
		t.Errorf("bare key handle: 0x%02x", got)
	}
}
