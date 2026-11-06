package tpm

import (
	"errors"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"
)

// LegacyRetiredIndex is the NV index whose existence records that the
// authenticator was reset, which retires credentials from before credential
// generations (bare key handles). It holds no data. It is defined by the
// first reset, before the generation counter moves, so a reset interrupted in
// between never leaves those credentials valid. Tests point it elsewhere.
var LegacyRetiredIndex = tpm2.TPMHandle(0x013C1D02)

// LegacyRetired reports whether a reset has retired legacy credentials.
func (t *TPM) LegacyRetired() (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return false, fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()
	_, err = tpm2.NVReadPublic{NVIndex: LegacyRetiredIndex}.Execute(conn)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, tpm2.TPMRCHandle):
		return false, nil
	}
	return false, fmt.Errorf("tpm: read legacy marker: %w", err)
}

// RetireLegacy records that legacy credentials are retired, for good.
func (t *TPM) RetireLegacy() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()
	if _, err := (tpm2.NVReadPublic{NVIndex: LegacyRetiredIndex}).Execute(conn); err == nil {
		return nil
	}
	_, err = tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    LegacyRetiredIndex,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{AuthRead: true, AuthWrite: true, NoDA: true, NT: tpm2.TPMNTOrdinary},
			DataSize:   1,
		}),
	}.Execute(conn)
	if err != nil {
		return fmt.Errorf("tpm: define legacy marker at 0x%08x: %w", uint32(LegacyRetiredIndex), err)
	}
	return nil
}
