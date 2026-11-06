package main

import (
	"crypto/sha256"
	"testing"

	"github.com/matejsmycka/linux-id/ctap2"
)

// Credentials whose ID carries options (credProtect, hmac-secret) hand the
// signer only the inner key handle. Deleting one must still revoke it.
func TestDeletedCredentialWithOptionsIsRevoked(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}, &fakePinentry{})
	rpIdHash := sha256.Sum256([]byte("opts.example"))
	credID, _, _, err := s.newCredential(rpIdHash[:], credOptions{credProtect: 2, hmacSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	if !s.credentialExists(credID, rpIdHash[:]) {
		t.Fatal("new credential does not sign")
	}
	if err := s.cs.Save(ctap2.StoredCredential{CredID: credID, RPIDHash: rpIdHash[:], RPID: "opts.example", UserID: []byte("u")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cs.Delete(credID); err != nil {
		t.Fatal(err)
	}
	if s.credentialExists(credID, rpIdHash[:]) {
		t.Fatal("deleted credential with options still signs")
	}
}
