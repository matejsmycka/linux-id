package memory

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveSecret returns HMAC-SHA-256 of input under a random key generated
// when the backend was created. Like the memory backend's credentials, the
// secrets last only as long as the process.
func (m *Mem) DeriveSecret(input []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, m.secretKey)
	mac.Write(input)
	return mac.Sum(nil), nil
}
