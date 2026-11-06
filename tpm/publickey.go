package tpm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/matejsmycka/linux-id/internal/lencode"
)

var errInvalidHandle = errors.New("invalid key handle")

// PublicKey returns the public key of a key handle made by RegisterKey for
// applicationParam. It loads the key into the TPM and reads its public area,
// so a handle that this TPM did not create, or that belongs to another
// application, is rejected.
func (t *TPM) PublicKey(keyHandle, applicationParam []byte) (*big.Int, *big.Int, error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))
	privBytes, err := dec.Decode()
	if err != nil {
		return nil, nil, errInvalidHandle
	}
	pubBytes, err := dec.Decode()
	if err != nil {
		return nil, nil, errInvalidHandle
	}
	seed, err := dec.Decode()
	if err != nil {
		return nil, nil, errInvalidHandle
	}
	if _, err := dec.Decode(); err != io.EOF {
		return nil, nil, errInvalidHandle
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	tpmConn, err := t.open()
	if err != nil {
		return nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpmConn.Close()

	createPrimaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(primaryKeyTmpl(seed, applicationParam)),
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: createPrimaryRsp.ObjectHandle}.Execute(tpmConn)

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: createPrimaryRsp.ObjectHandle,
			Name:   createPrimaryRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: privBytes},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](pubBytes),
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, fmt.Errorf("Load err: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpmConn)

	readPubRsp, err := tpm2.ReadPublic{ObjectHandle: loadRsp.ObjectHandle}.Execute(tpmConn)
	if err != nil {
		return nil, nil, fmt.Errorf("read public key err: %w", err)
	}
	pubArea, err := readPubRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("parse public area: %w", err)
	}
	eccPoint, err := pubArea.Unique.ECC()
	if err != nil {
		return nil, nil, fmt.Errorf("get ECC point: %w", err)
	}
	return new(big.Int).SetBytes(eccPoint.X.Buffer), new(big.Int).SetBytes(eccPoint.Y.Buffer), nil
}
