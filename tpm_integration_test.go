package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/tpm"
)

// TestResetAndPIN_TPM drives reset and the PIN through the server against the
// real TPM: credentials registered on it, and legacy key handles, stop working
// after a reset (the NV counter moved and the legacy marker exists), and a PIN set on it is a TPM object that checks the right
// PIN. Skipped unless LINUXID_TPM_TEST=1. Uses test NV indices, removed
// afterwards, and makes no wrong PIN guess (the TPM's lockout counter is
// shared).
func TestResetAndPIN_TPM(t *testing.T) {
	if os.Getenv("LINUXID_TPM_TEST") != "1" {
		t.Skip("set LINUXID_TPM_TEST=1 to run against /dev/tpmrm0")
	}
	tp, err := tpm.New("/dev/tpmrm0")
	if err != nil {
		t.Fatal(err)
	}
	oldGen, oldLegacy := tpm.GenerationIndex, tpm.LegacyRetiredIndex
	tpm.GenerationIndex, tpm.LegacyRetiredIndex = tpm2.TPMHandle(0x013C1DFD), tpm2.TPMHandle(0x013C1DFC)
	t.Cleanup(func() {
		tpm.UndefineGenerationForTest(tp)
		tpm.GenerationIndex, tpm.LegacyRetiredIndex = oldGen, oldLegacy
	})

	v := &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}
	s := newTestServer(t, v, &fakePinentry{})
	s.signer, s.secrets, s.gens = tp, tp, tp
	s.pin = newPINStore(s.pin.path, tp)
	s.startedAt = time.Now()

	cred := registerCred(t, s, "tpm.example", "TPM", "alice", true)
	if got := assertWith(t, s, "tpm.example", cred); got != ctap2.StatusOK {
		t.Fatalf("credential on the TPM: 0x%02x", got)
	}
	app := sha256.Sum256([]byte("tpm.example"))
	legacy, _, _, err := tp.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := assertWith(t, s, "tpm.example", legacy); got != ctap2.StatusOK {
		t.Fatalf("legacy TPM key handle before reset: 0x%02x", got)
	}

	pinHash := sha256.Sum256([]byte("4711"))
	if err := s.pin.set(pinHash[:16]); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(s.pin.path)
	if bytes.Contains(raw, pinHash[:16]) {
		t.Fatal("PIN file contains the PIN hash")
	}
	if res, err := s.pin.verify(pinHash[:16]); err != nil || res != pinOK {
		t.Fatalf("right PIN: %v, %v", res, err)
	}

	before, _ := tp.Generation()
	if got := ctapReset(t, s); got != ctap2.StatusOK {
		t.Fatalf("reset: 0x%02x", got)
	}
	if after, _ := tp.Generation(); after != before+1 {
		t.Fatalf("generation %d after reset from %d", after, before)
	}
	if got := assertWith(t, s, "tpm.example", cred); got != ctap2.StatusNoCredentials {
		t.Errorf("credential after reset: 0x%02x", got)
	}
	if got := assertWith(t, s, "tpm.example", legacy); got != ctap2.StatusNoCredentials {
		t.Errorf("legacy TPM key handle after reset: 0x%02x", got)
	}
	if s.pin.isSet() {
		t.Error("PIN survived the reset")
	}
}
