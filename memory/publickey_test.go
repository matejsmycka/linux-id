package memory

import (
	"crypto/sha256"
	"testing"
)

func TestPublicKeyMatchesRegisterKey(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	app := sha256.Sum256([]byte("example.com"))
	for range 50 { // some scalars have leading zero bytes
		kh, x, y, err := m.RegisterKey(app[:])
		if err != nil {
			t.Fatal(err)
		}
		gx, gy, err := m.PublicKey(kh, app[:])
		if err != nil {
			t.Fatal(err)
		}
		if gx.Cmp(x) != 0 || gy.Cmp(y) != 0 {
			t.Fatal("PublicKey differs from the key RegisterKey returned")
		}
	}
	kh, _, _, _ := m.RegisterKey(app[:])
	other := sha256.Sum256([]byte("other.example"))
	if _, _, err := m.PublicKey(kh, other[:]); err == nil {
		t.Error("PublicKey accepted a key handle for another application")
	}
	if _, _, err := m.PublicKey(kh[:10], app[:]); err == nil {
		t.Error("PublicKey accepted a truncated key handle")
	}
}
