package tpm

import (
	"bytes"
	"os"
	"testing"
)

// TestDeriveSecret runs against a real TPM. It is skipped unless
// LINUXID_TPM_TEST=1; LINUXID_TPM_DEVICE overrides /dev/tpmrm0. It creates
// only transient objects.
func TestDeriveSecret(t *testing.T) {
	if os.Getenv("LINUXID_TPM_TEST") != "1" {
		t.Skip("set LINUXID_TPM_TEST=1 to run against the TPM")
	}
	dev := os.Getenv("LINUXID_TPM_DEVICE")
	if dev == "" {
		dev = "/dev/tpmrm0"
	}
	t1, err := New(dev)
	if err != nil {
		t.Fatal(err)
	}
	a, err := t1.DeriveSecret([]byte("input a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("len = %d, want 32", len(a))
	}
	// A fresh instance (as after a restart) derives the same value.
	t2, err := New(dev)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := t2.DeriveSecret([]byte("input a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, a2) {
		t.Fatal("DeriveSecret is not stable across instances")
	}
	b, err := t1.DeriveSecret([]byte("input b"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different inputs gave the same secret")
	}
	if _, err := t1.DeriveSecret(make([]byte, maxSecretInput+1)); err == nil {
		t.Fatal("oversized input accepted")
	}
}

// TestRegisterKeyAppParamBinding checks that a key handle registered for one
// application parameter does not sign for another, which is what binds the
// options encoded in a credential ID to its key.
func TestRegisterKeyAppParamBinding(t *testing.T) {
	if os.Getenv("LINUXID_TPM_TEST") != "1" {
		t.Skip("set LINUXID_TPM_TEST=1 to run against the TPM")
	}
	dev := os.Getenv("LINUXID_TPM_DEVICE")
	if dev == "" {
		dev = "/dev/tpmrm0"
	}
	tp, err := New(dev)
	if err != nil {
		t.Fatal(err)
	}
	app := bytes.Repeat([]byte{1}, 32)
	other := bytes.Repeat([]byte{2}, 32)
	kh, _, _, err := tp.RegisterKey(app)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{3}, 32)
	if _, err := tp.SignASN1(kh, app, digest); err != nil {
		t.Fatalf("sign with registered app param: %s", err)
	}
	if _, err := tp.SignASN1(kh, other, digest); err == nil {
		t.Fatal("key handle signed for a different app param")
	}
}
