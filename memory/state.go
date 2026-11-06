package memory

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// The memory backend keeps everything in process memory: its generation
// counter and PIN objects, like its keys, last only as long as the process.

// Generation returns the credential generation counter.
func (m *Mem) Generation() (uint64, error) {
	m.genMu.Lock()
	defer m.genMu.Unlock()
	return m.generation, nil
}

// NextGeneration increments the generation counter.
func (m *Mem) NextGeneration() (uint64, error) {
	m.genMu.Lock()
	defer m.genMu.Unlock()
	m.generation++
	return m.generation, nil
}

// LegacyRetired reports whether a reset retired legacy credentials.
func (m *Mem) LegacyRetired() (bool, error) {
	m.genMu.Lock()
	defer m.genMu.Unlock()
	return m.legacyRetired, nil
}

// RetireLegacy retires legacy credentials.
func (m *Mem) RetireLegacy() error {
	m.genMu.Lock()
	defer m.genMu.Unlock()
	m.legacyRetired = true
	return nil
}

// SealPIN returns a PIN object for pinHash: an empty plaintext sealed under
// the process key with pinHash as additional data, so only the right PIN
// opens it and no form of the PIN is kept.
func (m *Mem) SealPIN(pinHash []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(m.masterPrivateKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, nil, append([]byte("linux-id pin\x00"), pinHash...)), nil
}

// CheckPIN reports whether pinHash opens the PIN object blob.
func (m *Mem) CheckPIN(blob, pinHash []byte) (bool, error) {
	aead, err := chacha20poly1305.NewX(m.masterPrivateKey)
	if err != nil {
		return false, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return false, errors.New("memory: invalid PIN object")
	}
	nonce, sealed := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	_, err = aead.Open(nil, nonce, sealed, append([]byte("linux-id pin\x00"), pinHash...))
	return err == nil, nil
}
