package pinuv

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

// The platform side of go-ctap must agree with our authenticator side on the
// shared secret, encryption and authentication for both protocols.
func TestInteropWithPlatformImplementation(t *testing.T) {
	for _, p := range Supported {
		t.Run(fmt.Sprintf("protocol%d", p), func(t *testing.T) {
			s, err := New()
			if err != nil {
				t.Fatal(err)
			}
			authKey, err := s.KeyAgreement()
			if err != nil {
				t.Fatal(err)
			}

			platform, err := ctapcrypto.NewPinUvAuthProtocol(p)
			if err != nil {
				t.Fatal(err)
			}
			platformKey, platformSecret, err := platform.Encapsulate(authKey)
			if err != nil {
				t.Fatal(err)
			}

			secret, err := s.SharedSecret(p, platformKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(secret, platformSecret) {
				t.Fatal("shared secrets differ")
			}

			plaintext := bytes.Repeat([]byte{0x42}, 64)
			ct, err := platform.Encrypt(platformSecret, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decrypt(p, secret, ct)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("decrypt platform ciphertext: %v", err)
			}
			ct2, err := Encrypt(p, secret, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := platform.Decrypt(platformSecret, ct2); err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("platform decrypt: %v", err)
			}

			msg := []byte("message")
			sig := ctapcrypto.Authenticate(p, platformSecret, msg)
			if !Verify(p, secret, msg, sig) {
				t.Fatal("Verify rejected platform signature")
			}
			if Verify(p, secret, []byte("other"), sig) {
				t.Fatal("Verify accepted signature over a different message")
			}
		})
	}
}

func issue(t *testing.T, s *State, perms protocol.Permission, rpID string) []byte {
	t.Helper()
	tok, err := s.IssueToken(perms, rpID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCheckPermissionsAndRPBinding(t *testing.T) {
	p := protocol.PinUvAuthProtocolTwo
	s, _ := New()
	tok := issue(t, s, protocol.PermissionGetAssertion|protocol.PermissionCredentialManagement, "")
	msg := []byte("cdh")
	param := ctapcrypto.Authenticate(p, tok, msg)

	if err := s.Check(p, param, msg, protocol.PermissionMakeCredential, "a.example"); err != ErrPermission {
		t.Errorf("missing permission: %v", err)
	}
	if err := s.Check(p, param, msg, protocol.PermissionGetAssertion, "a.example"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Now bound to a.example.
	if err := s.Check(p, param, msg, protocol.PermissionGetAssertion, "b.example"); err != ErrPermission {
		t.Errorf("other RP after binding: %v", err)
	}
	// Non-RP-scoped use still works.
	if err := s.Check(p, param, msg, protocol.PermissionCredentialManagement, ""); err != nil {
		t.Errorf("credential management: %v", err)
	}
	if err := s.Check(p, ctapcrypto.Authenticate(p, tok, []byte("x")), msg, protocol.PermissionGetAssertion, "a.example"); err != ErrInvalidParam {
		t.Errorf("bad param: %v", err)
	}
	if err := s.Check(protocol.PinUvAuthProtocolOne, param, msg, protocol.PermissionGetAssertion, "a.example"); err != ErrInvalidParam {
		t.Errorf("wrong protocol: %v", err)
	}
}

func TestTokenBoundAtIssue(t *testing.T) {
	p := protocol.PinUvAuthProtocolOne
	s, _ := New()
	tok := issue(t, s, protocol.PermissionMakeCredential, "a.example")
	msg := []byte("m")
	if err := s.Check(p, ctapcrypto.Authenticate(p, tok, msg), msg, protocol.PermissionMakeCredential, "b.example"); err != ErrPermission {
		t.Errorf("got %v", err)
	}
}

func TestReissueInvalidatesOldToken(t *testing.T) {
	p := protocol.PinUvAuthProtocolTwo
	s, _ := New()
	old := issue(t, s, protocol.PermissionGetAssertion, "")
	issue(t, s, protocol.PermissionGetAssertion, "")
	msg := []byte("m")
	if err := s.Check(p, ctapcrypto.Authenticate(p, old, msg), msg, protocol.PermissionGetAssertion, "a.example"); err != ErrInvalidParam {
		t.Errorf("old token still valid: %v", err)
	}
}

func TestTokenExpires(t *testing.T) {
	p := protocol.PinUvAuthProtocolTwo
	s, _ := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	tok := issue(t, s, protocol.PermissionGetAssertion, "")
	now = now.Add(tokenLifetime + time.Second)
	msg := []byte("m")
	if err := s.Check(p, ctapcrypto.Authenticate(p, tok, msg), msg, protocol.PermissionGetAssertion, "a.example"); err != ErrTokenNotInUse {
		t.Errorf("got %v", err)
	}
}

func TestUserPresentConsumedOnce(t *testing.T) {
	s, _ := New()
	issue(t, s, protocol.PermissionGetAssertion, "")
	if !s.UserPresent() || !s.UserVerified() {
		t.Fatal("flags not set at issue")
	}
	s.ConsumeUserPresent()
	if s.UserPresent() {
		t.Error("user present not consumed")
	}
	if !s.UserVerified() {
		t.Error("consuming presence must not clear verification")
	}
}

func TestResetChangesKeyAndClearsToken(t *testing.T) {
	s, _ := New()
	k1, _ := s.KeyAgreement()
	issue(t, s, protocol.PermissionGetAssertion, "")
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	k2, _ := s.KeyAgreement()
	if bytes.Equal(k1[-2].([]byte), k2[-2].([]byte)) {
		t.Error("key agreement key not regenerated")
	}
	if s.UserVerified() {
		t.Error("token survived reset")
	}
}
