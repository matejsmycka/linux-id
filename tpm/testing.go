package tpm

import tpm2 "github.com/google/go-tpm/tpm2"

// UndefineGenerationForTest removes the NV indices GenerationIndex and
// LegacyRetiredIndex name. Tests point them at test indices and call this to
// clean up; nothing else may.
func UndefineGenerationForTest(t *TPM) {
	conn, err := t.open()
	if err != nil {
		return
	}
	defer conn.Close()
	for _, idx := range []tpm2.TPMHandle{GenerationIndex, LegacyRetiredIndex} {
		tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: idx},
		}.Execute(conn)
	}
}
