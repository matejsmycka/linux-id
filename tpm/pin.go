package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/matejsmycka/linux-id/internal/lencode"
)

// The CTAP PIN as a TPM object.
//
// SealPIN creates a sealed data object whose authValue is the PIN hash
// (LEFT(SHA-256(PIN), 16), the only form of the PIN a platform sends). The
// object is subject to the TPM's dictionary attack protection, so checking a
// guess means asking the TPM to unseal it, and the TPM counts and limits
// failures itself. Nothing on disk lets anyone test a guess without the TPM:
// the blob SealPIN returns is the object wrapped by a parent key that only
// this TPM can recreate.
//
// The PIN hash never crosses the TPM interface in clear: creating the object
// and unsealing it use an HMAC session salted to the parent key, with
// parameter encryption for the Create command.
//
// The dictionary attack counter is the TPM's, shared with everything else
// that uses DA-protected TPM objects on this machine.

// ErrPINLockout means the TPM is in dictionary attack lockout and refuses to
// check PINs until enough failures have decayed.
var ErrPINLockout = errors.New("tpm: dictionary attack lockout")

// pinParentSeed fixes the parent key of PIN objects: a storage primary under
// the owner hierarchy, recreated identically on every use.
var pinParentSeed = func() []byte {
	h := sha256.Sum256([]byte("linux-id pin parent v1"))
	return h[:seedSizeBytes]
}()

func pinObjectTmpl() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			// NoDA is false: wrong PINs count towards lockout.
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
	}
}

func createPINParent(conn transport.TPM) (*tpm2.CreatePrimaryResponse, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(primaryKeyTmpl(pinParentSeed, nil)),
	}.Execute(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: create PIN parent: %w", err)
	}
	return rsp, func() { tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(conn) }, nil
}

func saltedSession(parent *tpm2.CreatePrimaryResponse, auth []byte, opts ...tpm2.AuthOption) (tpm2.Session, error) {
	pub, err := parent.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	opts = append([]tpm2.AuthOption{tpm2.Auth(auth), tpm2.Salted(parent.ObjectHandle, *pub)}, opts...)
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...), nil
}

// SealPIN creates a PIN object for pinHash and returns its wrapped blob.
func (t *TPM) SealPIN(pinHash []byte) ([]byte, error) {
	if len(pinHash) == 0 || len(pinHash) > sha256.Size {
		return nil, errors.New("tpm: PIN hash length")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()

	parent, flush, err := createPINParent(conn)
	if err != nil {
		return nil, err
	}
	defer flush()

	sess, err := saltedSession(parent, nil, tpm2.AESEncryption(128, tpm2.EncryptIn))
	if err != nil {
		return nil, err
	}
	filler := make([]byte, 16) // a sealed object needs data; its value is unused
	if _, err := rand.Read(filler); err != nil {
		return nil, err
	}
	createRsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: sess},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: pinHash},
			Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: filler}),
		}},
		InPublic: tpm2.New2B(pinObjectTmpl()),
	}.Execute(conn)
	if err != nil {
		return nil, fmt.Errorf("tpm: create PIN object: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))
	enc.Encode(createRsp.OutPrivate.Buffer)
	enc.Encode(createRsp.OutPublic.Bytes())
	return out.Bytes(), nil
}

// CheckPIN reports whether pinHash is the PIN of the object blob. A wrong
// PIN is (false, nil) and counts towards the TPM's lockout; ErrPINLockout
// means the TPM refused to check.
func (t *TPM) CheckPIN(blob, pinHash []byte) (bool, error) {
	dec := lencode.NewDecoder(bytes.NewReader(blob), lencode.SeparatorOpt(separator))
	priv, err1 := dec.Decode()
	pub, err2 := dec.Decode()
	if _, err3 := dec.Decode(); err1 != nil || err2 != nil || err3 != io.EOF {
		return false, errors.New("tpm: invalid PIN object")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.open()
	if err != nil {
		return false, fmt.Errorf("open tpm err: %w", err)
	}
	defer conn.Close()

	parent, flush, err := createPINParent(conn)
	if err != nil {
		return false, err
	}
	defer flush()

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: priv},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](pub),
	}.Execute(conn)
	if err != nil {
		return false, fmt.Errorf("tpm: load PIN object: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(conn)

	sess, err := saltedSession(parent, pinHash)
	if err != nil {
		return false, err
	}
	_, err = tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name, Auth: sess},
	}.Execute(conn)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return false, nil
	case errors.Is(err, tpm2.TPMRCLockout):
		return false, ErrPINLockout
	}
	return false, fmt.Errorf("tpm: check PIN: %w", err)
}
