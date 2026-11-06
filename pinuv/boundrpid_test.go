package pinuv

import (
	"testing"

	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

func TestBoundRPID(t *testing.T) {
	p := protocol.PinUvAuthProtocolTwo
	s, _ := New()
	if got := s.BoundRPID(); got != "" {
		t.Errorf("no token: %q", got)
	}
	tok := issue(t, s, protocol.PermissionGetAssertion|protocol.PermissionCredentialManagement, "")
	if got := s.BoundRPID(); got != "" {
		t.Errorf("unbound token: %q", got)
	}
	msg := []byte("cdh")
	if err := s.Check(p, ctapcrypto.Authenticate(p, tok, msg), msg, protocol.PermissionGetAssertion, "a.example"); err != nil {
		t.Fatal(err)
	}
	if got := s.BoundRPID(); got != "a.example" {
		t.Errorf("after first use: %q", got)
	}
	issue(t, s, protocol.PermissionCredentialManagement, "b.example")
	if got := s.BoundRPID(); got != "b.example" {
		t.Errorf("bound at issue: %q", got)
	}
	s.ClearToken()
	if got := s.BoundRPID(); got != "" {
		t.Errorf("cleared token: %q", got)
	}
}
