package tpm

import (
	"crypto/sha256"
	"errors"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"
)

// secretKeyLabel names the TPM HMAC key behind DeriveSecret. It is the
// unique field of the key's template, so no other template (in particular
// none of the per-credential signing parents) yields the same key.
const secretKeyLabel = "linux-id secret deriver v1"

// maxSecretInput bounds DeriveSecret's input to a single TPM2_HMAC call
// (MAX_DIGEST_BUFFER is at least 1024 on every TPM 2.0).
const maxSecretInput = 1024

// secretKeyTmpl is the template of the HMAC key that DeriveSecret uses: a
// keyed-hash primary key in the owner hierarchy. A primary key's secret is
// derived from the hierarchy's primary seed and the template, so creating it
// again with the same template gives the same key on this TPM, while the
// seed never leaves the TPM and the key is FixedTPM. The key changes only
// when the owner hierarchy is cleared, which also invalidates every
// credential key.
func secretKeyTmpl() tpm2.TPMTPublic {
	unique := sha256.Sum256([]byte(secretKeyLabel))
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme:  tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{Buffer: unique[:]},
		),
	}
}

// DeriveSecret returns HMAC-SHA-256(K, input), where K is an HMAC key that
// exists only inside this TPM (see secretKeyTmpl). The same input always
// gives the same 32 bytes on this TPM, across restarts, and cannot be
// computed without it. Callers provide domain separation in input.
//
// The key is created transiently for each call and flushed afterwards;
// nothing persistent is created in the TPM.
func (t *TPM) DeriveSecret(input []byte) ([]byte, error) {
	if len(input) > maxSecretInput {
		return nil, errors.New("tpm: DeriveSecret input too long")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	tpmConn, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpmConn.Close()

	createPrimaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(secretKeyTmpl()),
	}.Execute(tpmConn)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary (hmac key) err: %w", err)
	}
	keyHandle := createPrimaryRsp.ObjectHandle
	defer func() {
		tpm2.FlushContext{FlushHandle: keyHandle}.Execute(tpmConn)
	}()

	hmacRsp, err := tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: keyHandle,
			Name:   createPrimaryRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: input},
		HashAlg: tpm2.TPMAlgSHA256,
	}.Execute(tpmConn)
	if err != nil {
		return nil, fmt.Errorf("HMAC err: %w", err)
	}
	if len(hmacRsp.OutHMAC.Buffer) != sha256.Size {
		return nil, fmt.Errorf("HMAC: unexpected output length %d", len(hmacRsp.OutHMAC.Buffer))
	}
	return hmacRsp.OutHMAC.Buffer, nil
}
