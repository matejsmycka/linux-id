package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// GenerationIndex is the NV index of linux-id's credential generation
// counter: a TPM monotonic counter, so the generation can only go up and an
// authenticatorReset cannot be undone by restoring old files. It is in the
// owner range of the TCG handle registry (0x01000000–0x013FFFFF). Tests point
// it elsewhere.
var GenerationIndex = tpm2.TPMHandle(0x013C1D01)

// generationAttrs are the counter's attributes: a counter that anyone with
// access to the TPM may read and increment (no authValue; incrementing only
// ever retires credentials), and whose use never counts towards dictionary
// attack lockout.
var generationAttrs = tpm2.TPMANV{
	AuthWrite: true,
	AuthRead:  true,
	NT:        tpm2.TPMNTCounter,
	NoDA:      true,
}

var errForeignNVIndex = errors.New("tpm: the generation NV index exists with other attributes; it is not linux-id's")

// Generation returns the credential generation counter, defining the NV
// counter (and taking it to its first value) if it does not exist yet.
func (t *TPM) Generation() (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return 0, fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()

	name, err := generationIndexName(conn)
	if errors.Is(err, tpm2.TPMRCHandle) {
		if name, err = defineGeneration(conn); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	return readGeneration(conn, name)
}

// NextGeneration increments the generation counter and returns its new
// value. Every credential of the previous generation stops working.
func (t *TPM) NextGeneration() (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return 0, fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()

	name, err := generationIndexName(conn)
	if errors.Is(err, tpm2.TPMRCHandle) {
		if name, err = defineGeneration(conn); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	if err := incrementGeneration(conn, name); err != nil {
		return 0, err
	}
	// Incrementing changes the index's attributes (WRITTEN) and so its name.
	if name, err = generationIndexName(conn); err != nil {
		return 0, err
	}
	return readGeneration(conn, name)
}

// generationIndexName returns the counter's name, failing with
// TPMRCHandle when it is not defined and errForeignNVIndex when the index
// is something else.
func generationIndexName(conn transport.TPM) (tpm2.TPM2BName, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: GenerationIndex}.Execute(conn)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	attrs := pub.Attributes
	if pub.DataSize != 8 || attrs.NT != tpm2.TPMNTCounter || !attrs.AuthRead || !attrs.AuthWrite || !attrs.NoDA ||
		pub.NameAlg != tpm2.TPMAlgSHA256 {
		return tpm2.TPM2BName{}, errForeignNVIndex
	}
	return rsp.NVName, nil
}

func defineGeneration(conn transport.TPM) (tpm2.TPM2BName, error) {
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    GenerationIndex,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: generationAttrs,
			DataSize:   8,
		}),
	}.Execute(conn)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("tpm: define generation counter at 0x%08x: %w", uint32(GenerationIndex), err)
	}
	name, err := generationIndexName(conn)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	// A counter has no value until its first increment.
	if err := incrementGeneration(conn, name); err != nil {
		return tpm2.TPM2BName{}, err
	}
	return generationIndexName(conn)
}

func incrementGeneration(conn transport.TPM, name tpm2.TPM2BName) error {
	idx := tpm2.AuthHandle{Handle: GenerationIndex, Name: name, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.NVIncrement{AuthHandle: idx, NVIndex: tpm2.NamedHandle{Handle: GenerationIndex, Name: name}}).Execute(conn); err != nil {
		return fmt.Errorf("tpm: increment generation counter: %w", err)
	}
	return nil
}

func readGeneration(conn transport.TPM, name tpm2.TPM2BName) (uint64, error) {
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: GenerationIndex, Name: name, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: GenerationIndex, Name: name},
		Size:       8,
	}.Execute(conn)
	if err != nil {
		return 0, fmt.Errorf("tpm: read generation counter: %w", err)
	}
	if len(rsp.Data.Buffer) != 8 {
		return 0, fmt.Errorf("tpm: generation counter: %d bytes", len(rsp.Data.Buffer))
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}
