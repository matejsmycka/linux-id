package tpm

import (
	"bytes"
	"os"
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
)

func realTPM(t *testing.T) *TPM {
	t.Helper()
	if os.Getenv("LINUXID_TPM_TEST") != "1" {
		t.Skip("set LINUXID_TPM_TEST=1 to run against /dev/tpmrm0")
	}
	tp, err := New("/dev/tpmrm0")
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// The generation counter is defined on first use, only goes up, and is
// recognised again by a fresh TPM handle. Uses a test index, removed after.
func TestGenerationCounter_TPM(t *testing.T) {
	tp := realTPM(t)
	old := GenerationIndex
	GenerationIndex = tpm2.TPMHandle(0x013C1DFE)
	t.Cleanup(func() {
		UndefineGenerationForTest(tp)
		GenerationIndex = old
	})

	g1, err := tp.Generation()
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := tp.Generation(); g != g1 {
		t.Fatalf("Generation not stable: %d then %d", g1, g)
	}
	g2, err := tp.NextGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if g2 <= g1 {
		t.Fatalf("NextGeneration %d after %d", g2, g1)
	}
	tp2, _ := New("/dev/tpmrm0")
	if g, err := tp2.Generation(); err != nil || g != g2 {
		t.Fatalf("fresh handle: %d, %v; want %d", g, err, g2)
	}
}

// A sealed PIN object accepts its PIN and refuses another. Makes exactly one
// wrong guess against the real TPM's dictionary attack counter.
func TestPINObject_TPM(t *testing.T) {
	tp := realTPM(t)
	pin := bytes.Repeat([]byte{0x42}, 16)
	blob, err := tp.SealPIN(pin)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pin) {
		t.Fatal("PIN hash appears in the blob")
	}
	if ok, err := tp.CheckPIN(blob, pin); !ok || err != nil {
		t.Fatalf("right PIN: %v, %v", ok, err)
	}
	if ok, err := tp.CheckPIN(blob, bytes.Repeat([]byte{0x43}, 16)); ok || err != nil {
		t.Fatalf("wrong PIN: %v, %v", ok, err)
	}
	if ok, err := tp.CheckPIN(blob, pin); !ok || err != nil {
		t.Fatalf("right PIN after a wrong one: %v, %v", ok, err)
	}
	if _, err := tp.CheckPIN(append([]byte{}, blob[:len(blob)-1]...), pin); err == nil {
		t.Fatal("truncated blob accepted")
	}
}
