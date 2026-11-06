package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/memory"
)

// legacyServer is a test server on the memory backend, so legacy key handles
// are real backend handles and their public keys can be derived.
func legacyServer(t *testing.T) (*server, *memory.Mem) {
	t.Helper()
	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	mem, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	s.signer, s.secrets, s.gens = mem, mem, mem
	return s, mem
}

// A credential from before credential generations (a bare key handle for the
// plain rpIdHash, as linux-id used to make) keeps working after an upgrade,
// over CTAP2 and CTAP1, and stops working at the first reset.
func TestLegacyKeyHandle_ValidUntilReset(t *testing.T) {
	s, mem := legacyServer(t)
	app := rpIDHash("legacy.example")
	legacy, _, _, err := mem.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := assertWith(t, s, "legacy.example", legacy); got != ctap2.StatusOK {
		t.Fatalf("legacy credential before reset: 0x%02x", got)
	}
	if got := assertWith(t, s, "other.example", legacy); got != ctap2.StatusNoCredentials {
		t.Fatalf("legacy credential for another RP: 0x%02x", got)
	}

	if got := ctapReset(t, s); got != ctap2.StatusOK {
		t.Fatalf("reset: 0x%02x", got)
	}
	if got := assertWith(t, s, "legacy.example", legacy); got != ctap2.StatusNoCredentials {
		t.Errorf("legacy credential after reset: 0x%02x", got)
	}
	// Still retired after a restart of the daemon.
	s2 := restarted(t, s)
	if got := assertWith(t, s2, "legacy.example", legacy); got != ctap2.StatusNoCredentials {
		t.Errorf("legacy credential after reset and restart: 0x%02x", got)
	}
}

// A discoverable legacy credential from an old store: found, signs, and is
// enumerated by credential management with its public key derived from the
// key handle.
func TestLegacyResidentCredential_ListedWithDerivedKey(t *testing.T) {
	s, mem := legacyServer(t)
	app := rpIDHash("legacy.example")
	legacy, x, y, err := mem.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := s.cs.Save(ctap2.StoredCredential{CredID: legacy, RPIDHash: app[:], RPID: "legacy.example", UserID: []byte("u"), UserName: "u"}); err != nil {
		t.Fatal(err)
	}
	if got := assertWith(t, s, "legacy.example", nil); got != ctap2.StatusOK {
		t.Fatalf("discoverable legacy credential: 0x%02x", got)
	}
	creds, _ := s.cs.List()
	key, err := s.credentialPublicKey(creds[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if want := (&ecdsa.PublicKey{Curve: pub.(*ecdsa.PublicKey).Curve, X: x, Y: y}); !pub.(*ecdsa.PublicKey).Equal(want) {
		t.Error("derived public key is wrong")
	}
	if c, _ := s.cs.Find(legacy); len(c.PublicKey) == 0 {
		t.Error("derived public key not recorded")
	}
}

// failingNextGeneration fails to move the generation counter.
type failingNextGeneration struct{ generationBackend }

func (failingNextGeneration) NextGeneration() (uint64, error) {
	return 0, errors.New("tpm unavailable")
}

// Legacy credentials are retired before the generation moves, so a reset
// that fails halfway never leaves them valid.
func TestReset_RetiresLegacyFirst(t *testing.T) {
	s, mem := legacyServer(t)
	app := rpIDHash("legacy.example")
	legacy, _, _, _ := mem.RegisterKey(app[:])
	s.gens = failingNextGeneration{s.gens}

	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdReset}})
	if got := resp.lastCtap2().status; got == ctap2.StatusOK {
		t.Fatal("reset reported success although the generation did not move")
	}
	if got := assertWith(t, s, "legacy.example", legacy); got != ctap2.StatusNoCredentials {
		t.Errorf("legacy credential after a failed reset: 0x%02x", got)
	}
}
