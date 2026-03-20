package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/matejsmycka/linux-id/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (transport.TPMCloser, error) {
	return linuxtpm.Open(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}

	tpmConn, err := t.open()
	if err != nil {
		return nil, err
	}
	tpmConn.Close()

	return t, nil
}

func primaryKeyTmpl(seed, applicationParam []byte) tpm2.TPMTPublic {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	if _, err := io.ReadFull(r, xBytes); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, yBytes); err != nil {
		panic(err)
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:          true,
			Decrypt:             true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
		),
	}
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

// RegisterKey generates a new key pair protected by the TPM.
// Returns the key handle bytes, and the public key X/Y coordinates.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpmConn, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpmConn.Close()

	randSeed := mustRand(seedSizeBytes)

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam)

	childTmpl := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{},
		),
	}

	createPrimaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(primaryTmpl),
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	parentHandle := createPrimaryRsp.ObjectHandle
	defer func() {
		tpm2.FlushContext{FlushHandle: parentHandle}.Execute(tpmConn)
	}()

	createRsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   createPrimaryRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(childTmpl),
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreateKey (child) err: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))

	enc.Encode(createRsp.OutPrivate.Buffer)
	enc.Encode(createRsp.OutPublic.Bytes())
	enc.Encode(randSeed)

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   createPrimaryRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: createRsp.OutPrivate,
		InPublic:  createRsp.OutPublic,
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load child key err: %w", err)
	}

	keyHandle := loadRsp.ObjectHandle
	defer func() {
		tpm2.FlushContext{FlushHandle: keyHandle}.Execute(tpmConn)
	}()

	readPubRsp, err := tpm2.ReadPublic{
		ObjectHandle: keyHandle,
	}.Execute(tpmConn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	pubArea, err := readPubRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse public area: %w", err)
	}

	eccPoint, err := pubArea.Unique.ECC()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get ECC point: %w", err)
	}

	x := new(big.Int).SetBytes(eccPoint.X.Buffer)
	y := new(big.Int).SetBytes(eccPoint.Y.Buffer)

	return out.Bytes(), x, y, nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpmConn, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpmConn.Close()

	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	invalidHandleErr := fmt.Errorf("invalid key handle")

	privBytes, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	pubBytes, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	seed, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	_, err = dec.Decode()
	if err != io.EOF {
		return nil, invalidHandleErr
	}

	srkTemplate := primaryKeyTmpl(seed, applicationParam)

	createPrimaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(srkTemplate),
	}.Execute(tpmConn)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	parentHandle := createPrimaryRsp.ObjectHandle
	defer func() {
		tpm2.FlushContext{FlushHandle: parentHandle}.Execute(tpmConn)
	}()

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   createPrimaryRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: privBytes},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](pubBytes),
	}.Execute(tpmConn)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}

	signingKey := loadRsp.ObjectHandle
	defer func() {
		tpm2.FlushContext{FlushHandle: signingKey}.Execute(tpmConn)
	}()

	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: signingKey,
			Name:   loadRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(tpmConn)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	ecdsaSig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("get ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	return b.Bytes()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
