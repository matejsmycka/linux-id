package memory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestRegisterSignVerifyRoundTrip is the spec-correct end-to-end check for the
// in-memory backend: register a key for a site, sign a digest with the
// returned key handle, then verify the signature against the public key the
// register call returned. If the backend can't produce a verifiable signature,
// nothing about it works.
//
// This test caught a pre-existing bug on Go ≥1.20 where SignASN1 was building
// an ecdsa.PrivateKey without populating PublicKey.X/Y. crypto/ecdsa now
// validates the curve point in SignASN1 and panics with x=y=0:
//
//	crypto/ecdsa.pointFromAffine: ... pointFromAffine(x=0, y=0) ...
//
// The fix: derive (X, Y) from the scalar D via curve.ScalarBaseMult(D.Bytes())
// in SignASN1, the same way the curve point is computed in RegisterKey.
func TestRegisterSignVerifyRoundTrip(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	appParam := sha256.Sum256([]byte("https://example.com"))

	// Step 1: register a fresh key.
	keyHandle, x, y, err := m.RegisterKey(appParam[:])
	if err != nil {
		t.Fatalf("RegisterKey: %s", err)
	}
	if x == nil || y == nil {
		t.Fatalf("RegisterKey returned nil pubkey coordinates")
	}
	if len(keyHandle) == 0 {
		t.Fatalf("RegisterKey returned empty key handle")
	}

	// Step 2: sign a digest with that key handle.
	digest := sha256.Sum256([]byte("message-to-sign"))
	sig, err := m.SignASN1(keyHandle, appParam[:], digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %s", err)
	}
	if len(sig) == 0 {
		t.Fatalf("SignASN1 returned empty signature")
	}

	// Step 3: verify the signature with the public key from RegisterKey.
	// If the backend's internal key derivation is wrong, this fails — the
	// signature won't validate against the claimed public key.
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("signature did not verify against pubkey from RegisterKey")
	}
}

// TestRegisterSignWithWrongAppParamFails: the application parameter is
// authenticated by the AEAD wrap. Trying to unwrap with the wrong appParam
// must fail (otherwise a credential could be used cross-origin).
func TestRegisterSignWithWrongAppParamFails(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}

	correctApp := sha256.Sum256([]byte("https://github.com"))
	wrongApp := sha256.Sum256([]byte("https://attacker.example"))

	keyHandle, _, _, err := m.RegisterKey(correctApp[:])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("anything"))

	if _, err := m.SignASN1(keyHandle, wrongApp[:], digest[:]); err == nil {
		t.Fatalf("SignASN1 with wrong appParam should fail (cross-origin protection)")
	}
}

// TestSignWithMalformedKeyHandleFails: corrupted/short key handles must fail
// the AEAD open, not panic.
func TestSignWithMalformedKeyHandleFails(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	appParam := sha256.Sum256([]byte("x"))
	digest := sha256.Sum256([]byte("y"))

	// Too short to even contain the nonce.
	if _, err := m.SignASN1([]byte("short"), appParam[:], digest[:]); err == nil {
		t.Errorf("SignASN1 should reject too-short key handle")
	}
	// Right length-ish but garbage payload — AEAD open should fail.
	garbage := make([]byte, 64)
	if _, err := m.SignASN1(garbage, appParam[:], digest[:]); err == nil {
		t.Errorf("SignASN1 should reject garbage key handle")
	}
}

// TestCounterMonotonic: each call returns a value strictly greater than the
// previous one. Required so signatures from a given credential can't be
// replayed.
func TestCounterMonotonic(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prev := m.Counter()
	for i := 0; i < 10; i++ {
		next := m.Counter()
		if next <= prev {
			t.Errorf("counter went backwards: prev=%d next=%d", prev, next)
		}
		prev = next
	}
}

// Sanity check on the math the SignASN1 fix relies on: D from a freshly-
// generated P-256 key, multiplied by the curve's base point, produces a
// valid non-zero point that is itself on the curve. This is the operation
// the fix uses to recover (X, Y) from a stored scalar.
func TestScalarBaseMultProducesValidPoint(t *testing.T) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := curve.ScalarBaseMult(priv.D.Bytes())
	if x == nil || y == nil || x.Sign() == 0 || y.Sign() == 0 {
		t.Errorf("ScalarBaseMult produced invalid point: x=%v y=%v", x, y)
	}
	if !curve.IsOnCurve(x, y) {
		t.Errorf("derived point is not on P-256")
	}
	// And the recovered point must match the public key from GenerateKey.
	if x.Cmp(priv.PublicKey.X) != 0 || y.Cmp(priv.PublicKey.Y) != 0 {
		t.Errorf("ScalarBaseMult result does not match GenerateKey's public key")
	}
}
