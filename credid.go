package main

import (
	"crypto/sha256"
	"errors"
	"log"
	"math/big"
)

// Credential IDs.
//
// Non-resident credentials are not stored anywhere, so what the authenticator
// must remember about them (the credProtect level, whether hmac-secret was
// enabled) travels in the credential ID itself:
//
//	"lxe\x02" | credProtect (1 byte) | flags (1 byte) | backend key handle
//
// The backend key is registered for the application parameter
// SHA-256(credIDLabel | generation secret | rpIdHash | header) instead of
// rpIdHash. The TPM backend feeds the application parameter into the
// derivation of the key's parent, and the memory backend authenticates it as
// AEAD additional data. So a credential ID whose header was changed or
// stripped (to downgrade credProtect, say) no longer signs, and
// authenticatorReset, which replaces the generation secret (generation.go),
// retires every credential at once.
//
// IDs without the header are legacy: bare backend key handles, registered
// for the plain rpIdHash, which is what every credential was before this
// format. They keep working, unbound to a generation, until the first reset
// retires them (generationBackend.RetireLegacy), so upgrading breaks no
// existing credential. TPM key handles always start with "TPM", so they
// never carry the header.
const credIDMagic = "lxe\x02"

const credIDHeaderLen = len(credIDMagic) + 2

const credIDLabel = "linux-id credential v2\x00"

// credFlagHmacSecret marks a credential created with hmac-secret: true.
const credFlagHmacSecret = 0x01

// credOptions are the creation options a credential ID carries.
type credOptions struct {
	credProtect int // 0 or 1: userVerificationOptional
	hmacSecret  bool
}

// header is the credential ID header for o.
func (o credOptions) header() []byte {
	h := make([]byte, 0, credIDHeaderLen)
	h = append(h, credIDMagic...)
	h = append(h, byte(o.credProtect))
	var flags byte
	if o.hmacSecret {
		flags |= credFlagHmacSecret
	}
	return append(h, flags)
}

// credAppParam is the application parameter a credential's key is
// registered for.
func credAppParam(secret, rpIdHash, header []byte) []byte {
	h := sha256.New()
	h.Write([]byte(credIDLabel))
	h.Write(secret)
	h.Write(rpIdHash)
	h.Write(header)
	return h.Sum(nil)
}

// parsedCredID is a credential ID split into its header, options and backend
// key handle. A legacy ID is all key handle, with no header or options.
type parsedCredID struct {
	header    []byte
	keyHandle []byte
	opts      credOptions
	legacy    bool
}

var errLegacyRetired = errors.New("legacy credential retired by an authenticator reset")

func parseCredID(credID []byte) (parsedCredID, error) {
	if len(credID) <= credIDHeaderLen || string(credID[:len(credIDMagic)]) != credIDMagic {
		if len(credID) == 0 {
			return parsedCredID{}, errors.New("empty credential ID")
		}
		return parsedCredID{keyHandle: credID, legacy: true}, nil
	}
	header := credID[:credIDHeaderLen]
	return parsedCredID{
		header:    header,
		keyHandle: credID[credIDHeaderLen:],
		opts: credOptions{
			credProtect: int(header[len(credIDMagic)]),
			hmacSecret:  header[len(credIDMagic)+1]&credFlagHmacSecret != 0,
		},
	}, nil
}

// credOptionsOf returns the options credID carries; none for a foreign ID.
func credOptionsOf(credID []byte) credOptions {
	p, _ := parseCredID(credID)
	return p.opts
}

// newCredential registers a key for rpIdHash in the current generation and
// returns its credential ID, which carries opts.
func (s *server) newCredential(rpIdHash []byte, opts credOptions) ([]byte, *big.Int, *big.Int, error) {
	secret, err := s.generationSecret()
	if err != nil {
		return nil, nil, nil, err
	}
	header := opts.header()
	keyHandle, x, y, err := s.signer.RegisterKey(credAppParam(secret, rpIdHash, header))
	if err != nil {
		return nil, nil, nil, err
	}
	return append(header, keyHandle...), x, y, nil
}

// signWithCredential signs digest with the key of credential credID for
// rpIdHash. It fails for a credential ID that is not this authenticator's,
// is for another relying party, was tampered with, was deleted, or predates
// the last reset.
func (s *server) signWithCredential(credID, rpIdHash, digest []byte) ([]byte, error) {
	if s.cs != nil {
		revoked, err := s.cs.Revoked(credID)
		if err != nil {
			log.Printf("revoked credentials list unreadable, refusing to sign: %s", err)
		}
		if revoked {
			return nil, errors.New("credential was deleted")
		}
	}
	keyHandle, appParam, err := s.credKey(credID, rpIdHash)
	if err != nil {
		return nil, err
	}
	return s.signer.SignASN1(keyHandle, appParam, digest)
}

// credKey returns the backend key handle of credID and the application
// parameter its key was registered for: bound to the current generation, or
// the plain rpIdHash for a legacy ID while legacy IDs are not retired.
func (s *server) credKey(credID, rpIdHash []byte) (keyHandle, appParam []byte, err error) {
	p, err := parseCredID(credID)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.generationSecret() // also reads whether legacy IDs are retired
	if err != nil {
		return nil, nil, err
	}
	if p.legacy {
		if s.legacyRetired {
			return nil, nil, errLegacyRetired
		}
		return p.keyHandle, rpIdHash, nil
	}
	return p.keyHandle, credAppParam(secret, rpIdHash, p.header), nil
}

// credentialExists reports whether credID is a valid credential of this
// authenticator for rpIdHash.
func (s *server) credentialExists(credID, rpIdHash []byte) bool {
	dummy := sha256.Sum256([]byte("meticulously-Bacardi"))
	_, err := s.signWithCredential(credID, rpIdHash, dummy[:])
	return err == nil
}
