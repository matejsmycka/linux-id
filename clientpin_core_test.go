package main

import (
	"context"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

// A token request right after a MakeCredential for the same RP must ask the
// user again: platforms read a token as "the user picked this authenticator".
func TestTokenUsingUV_NeverServedFromCache(t *testing.T) {
	inner := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, newCachingVerifier(inner), &fakePinentry{})

	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, makeMakeCredCBOR(t, "step.example", "Step", "alice", true, true))
	if resp.lastCtap2().status != ctap2.StatusOK || inner.callCount != 1 {
		t.Fatalf("register: status 0x%02x calls %d", resp.lastCtap2().status, inner.callCount)
	}

	key, err := s.pinuv.KeyAgreement()
	if err != nil {
		t.Fatal(err)
	}
	platform, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		t.Fatal(err)
	}
	platformKey, _, err := platform.Encapsulate(key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement:      platformKey,
		Permissions:       protocol.PermissionGetAssertion,
		RPID:              "step.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.handleClientPIN(context.Background(), resp, fidohid.AuthEvent{}, payload)
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatalf("token: status 0x%02x", resp.lastCtap2().status)
	}
	if inner.callCount != 2 {
		t.Fatalf("token issued from the verification cache (calls %d)", inner.callCount)
	}
}
