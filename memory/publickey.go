package memory

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

// PublicKey returns the public key of a key handle made by RegisterKey for
// applicationParam, by unwrapping its private key.
func (m *Mem) PublicKey(keyHandle, applicationParam []byte) (*big.Int, *big.Int, error) {
	aead, err := chacha20poly1305.NewX(m.masterPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	if len(keyHandle) < chacha20poly1305.NonceSizeX {
		return nil, nil, fmt.Errorf("incorrect size for key handle: %d smaller than nonce", len(keyHandle))
	}
	nonce, cipherText := keyHandle[:chacha20poly1305.NonceSizeX], keyHandle[chacha20poly1305.NonceSizeX:]
	sum := sha256.Sum256(append([]byte("fido_wrapping_key"), applicationParam...))
	d, err := aead.Open(nil, nonce, cipherText, sum[:])
	if err != nil {
		return nil, nil, fmt.Errorf("open child private key err: %w", err)
	}
	defer clear(d)
	if len(d) > 32 {
		return nil, nil, fmt.Errorf("invalid child private key")
	}
	// RegisterKey stores D.Bytes(), which drops leading zero bytes.
	scalar := make([]byte, 32)
	copy(scalar[32-len(d):], d)
	defer clear(scalar)
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PublicKey().Bytes() // 0x04 || X || Y
	return new(big.Int).SetBytes(pub[1:33]), new(big.Int).SetBytes(pub[33:]), nil
}
