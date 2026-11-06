package main

import (
	"encoding/binary"
	"errors"
)

// The credential generation makes authenticatorReset real.
//
// Every credential key is bound to the secret of the current generation (see
// credid.go): the backend registers it for an application parameter that
// hashes the secret in. Resetting the authenticator moves to the next
// generation, so no credential created before the reset can be loaded again,
// on the TPM or in the memory backend, wherever its ID is still held.
//
// Nothing about the generation is stored in a file. Its number is the
// backend's monotonic counter (on the TPM, an NV counter: tpm/nvcounter.go),
// so a reset cannot be undone, and its secret is derived from that number
// with the backend's secret derivation (on the TPM, an HMAC under a key that
// never leaves it) every time it is needed.

// generationBackend is the backend's generation counter and secret
// derivation. The TPM and memory backends implement it.
type generationBackend interface {
	Generation() (uint64, error)
	NextGeneration() (uint64, error)
	// LegacyRetired reports whether a reset has retired legacy credentials
	// (credential IDs from before generations, see credid.go); RetireLegacy
	// records that it has.
	LegacyRetired() (bool, error)
	RetireLegacy() error
	SecretDeriver
}

const generationLabel = "linux-id credential generation v1\x00"

func deriveGenerationSecret(b generationBackend, n uint64) ([]byte, error) {
	return b.DeriveSecret(binary.BigEndian.AppendUint64([]byte(generationLabel), n))
}

var errNoGeneration = errors.New("credential generation unavailable")

// generationSecret returns the current generation's secret, reading the
// counter if this daemon has not yet.
func (s *server) generationSecret() ([]byte, error) {
	if s.genSecret == nil {
		if err := s.refreshGeneration(); err != nil {
			return nil, err
		}
	}
	return s.genSecret, nil
}

// refreshGeneration reads the generation counter and derives its secret. If
// the generation moved since this daemon last looked (a `linux-id reset`),
// it drops its volatile state, as the device would on its own reset.
func (s *server) refreshGeneration() error {
	if s.gens == nil {
		return errNoGeneration
	}
	n, err := s.gens.Generation()
	if err != nil {
		return err
	}
	retired, err := s.gens.LegacyRetired()
	if err != nil {
		return err
	}
	s.legacyRetired = retired
	if s.genSecret != nil && n == s.genN {
		return nil
	}
	secret, err := deriveGenerationSecret(s.gens, n)
	if err != nil {
		return err
	}
	if s.genSecret != nil {
		s.resetVolatile()
	}
	s.genN, s.genSecret = n, secret
	return nil
}
