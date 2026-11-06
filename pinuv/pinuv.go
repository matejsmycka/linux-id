// Package pinuv implements the authenticator side of the CTAP 2.1 PIN/UV
// auth protocols (§6.5): the key agreement key, shared secrets, and the
// pinUvAuthToken with its permissions and lifetime.
//
// The protocol primitives (KDF, AES-CBC, HMAC truncation) come from
// github.com/telesma-app/ctap, which implements them for the platform side;
// they are the same on both ends. This package only adds authenticator state.
package pinuv

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	"github.com/telesma-app/ctap/protocol"
)

// Protocol numbers this authenticator supports, in order of preference.
var Supported = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolOne}

// tokenLifetime bounds how long a pinUvAuthToken stays usable after it was
// issued (the "maximum usage time period" of CTAP 2.1 §6.5.2.1).
const tokenLifetime = 10 * time.Minute

var (
	ErrUnsupportedProtocol = errors.New("pinuv: unsupported pinUvAuthProtocol")
	ErrInvalidParam        = errors.New("pinuv: pinUvAuthParam does not verify")
	ErrTokenNotInUse       = errors.New("pinuv: no pinUvAuthToken in use")
	ErrPermission          = errors.New("pinuv: pinUvAuthToken lacks the permission or is bound to another RP")
)

// IsSupported reports whether p is a protocol this authenticator implements.
func IsSupported(p protocol.PinUvAuthProtocol) bool {
	return p == protocol.PinUvAuthProtocolOne || p == protocol.PinUvAuthProtocolTwo
}

// State is the authenticator's PIN/UV protocol state. It is reset on every
// start of the daemon, which plays the role of a power cycle.
type State struct {
	mu  sync.Mutex
	now func() time.Time

	keyAgreement *ecdh.PrivateKey

	token        [32]byte
	inUse        bool
	issued       time.Time
	permissions  protocol.Permission
	rpID         string // empty: not bound to an RP (yet)
	userPresent  bool
	userVerified bool
}

// New returns fresh protocol state with a new key agreement key and token.
func New() (*State, error) {
	s := &State{now: time.Now}
	if err := s.Reset(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reset regenerates the key agreement key and invalidates any token
// (CTAP 2.1 §6.5.5.1 initialize / regenerate).
func (s *State) Reset() error {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("pinuv: generate key agreement key: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyAgreement = key
	s.clearTokenLocked()
	return nil
}

// Regenerate replaces the key agreement key and leaves the token alone
// (CTAP 2.1 §6.5.6 regenerate), as required after a wrong PIN.
func (s *State) Regenerate() error {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("pinuv: generate key agreement key: %w", err)
	}
	s.mu.Lock()
	s.keyAgreement = key
	s.mu.Unlock()
	return nil
}

// KeyAgreement returns the authenticator's key agreement public key as the
// COSE_Key that getKeyAgreement reports.
func (s *State) KeyAgreement() (cose.Key, error) {
	s.mu.Lock()
	pub := s.keyAgreement.PublicKey()
	s.mu.Unlock()
	return cose.KeyFromP256PublicKey(pub)
}

// SharedSecret derives the protocol's shared secret from the platform's key
// agreement key (decapsulate, CTAP 2.1 §6.5.6/§6.5.7).
func (s *State) SharedSecret(p protocol.PinUvAuthProtocol, platformKey cose.Key) ([]byte, error) {
	if !IsSupported(p) {
		return nil, ErrUnsupportedProtocol
	}
	peer, err := platformKey.P256PublicKey()
	if err != nil {
		return nil, fmt.Errorf("pinuv: platform key agreement key: %w", err)
	}
	s.mu.Lock()
	key := s.keyAgreement
	s.mu.Unlock()
	z, err := key.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("pinuv: ecdh: %w", err)
	}
	defer clear(z)
	if p == protocol.PinUvAuthProtocolOne {
		return protocolone.KDF(z), nil
	}
	return protocoltwo.KDF(z)
}

// Encrypt encrypts plaintext under a shared secret.
func Encrypt(p protocol.PinUvAuthProtocol, sharedSecret, plaintext []byte) ([]byte, error) {
	switch p {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Encrypt(sharedSecret, plaintext)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Encrypt(sharedSecret, plaintext)
	}
	return nil, ErrUnsupportedProtocol
}

// Decrypt decrypts ciphertext under a shared secret.
func Decrypt(p protocol.PinUvAuthProtocol, sharedSecret, ciphertext []byte) ([]byte, error) {
	switch p {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Decrypt(sharedSecret, ciphertext)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Decrypt(sharedSecret, ciphertext)
	}
	return nil, ErrUnsupportedProtocol
}

// Verify reports whether signature is the protocol's authenticate(key,
// message), in constant time. key is a shared secret or a pinUvAuthToken.
func Verify(p protocol.PinUvAuthProtocol, key, message, signature []byte) bool {
	var want []byte
	switch p {
	case protocol.PinUvAuthProtocolOne:
		want = protocolone.Authenticate(key, message)
	case protocol.PinUvAuthProtocolTwo:
		want = protocoltwo.Authenticate(key, message)
	default:
		return false
	}
	return len(signature) == len(want) && hmac.Equal(want, signature)
}

// IssueToken generates a new pinUvAuthToken with the given permissions,
// optionally bound to rpID, and returns its value for the caller to encrypt
// for the platform. Any previous token stops working (§6.5.5.7).
// userVerified is true when the user's identity was established (fingerprint
// or PIN); userPresent when the same gesture also proved presence.
func (s *State) IssueToken(perms protocol.Permission, rpID string, userPresent, userVerified bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearTokenLocked()
	if _, err := rand.Read(s.token[:]); err != nil {
		return nil, fmt.Errorf("pinuv: generate token: %w", err)
	}
	s.inUse = true
	s.issued = s.now()
	s.permissions = perms
	s.rpID = rpID
	s.userPresent = userPresent
	s.userVerified = userVerified
	return append([]byte(nil), s.token[:]...), nil
}

// Check verifies a pinUvAuthParam computed with the current token over
// message, and that the token grants perm for rpID (§6.5.5.8). rpID may be
// empty for permissions that are not RP-scoped. A token that is not yet bound
// to an RP becomes bound to rpID by a successful MakeCredential or
// GetAssertion check.
func (s *State) Check(p protocol.PinUvAuthProtocol, param, message []byte, perm protocol.Permission, rpID string) error {
	if !IsSupported(p) {
		return ErrUnsupportedProtocol
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inUse || s.now().Sub(s.issued) > tokenLifetime {
		s.clearTokenLocked()
		return ErrTokenNotInUse
	}
	if !Verify(p, s.token[:], message, param) {
		return ErrInvalidParam
	}
	if s.permissions&perm != perm {
		return ErrPermission
	}
	if rpID != "" && s.rpID != "" && s.rpID != rpID {
		return ErrPermission
	}
	if rpID != "" && s.rpID == "" && perm&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0 {
		s.rpID = rpID
	}
	return nil
}

// BoundRPID returns the RP ID the current token is bound to, or "" when it
// is not bound or no token is in use.
func (s *State) BoundRPID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inUse {
		return ""
	}
	return s.rpID
}

// UserPresent reports whether the token's issuance included a user presence
// gesture that has not been consumed yet.
func (s *State) UserPresent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inUse && s.userPresent
}

// UserVerified reports whether the current token was issued after verifying
// the user.
func (s *State) UserVerified() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inUse && s.userVerified
}

// ConsumeUserPresent clears the token's user present flag; a presence
// gesture authorises one MakeCredential or GetAssertion (§6.5.2.1).
func (s *State) ConsumeUserPresent() {
	s.mu.Lock()
	s.userPresent = false
	s.mu.Unlock()
}

// ClearToken invalidates the current token.
func (s *State) ClearToken() {
	s.mu.Lock()
	s.clearTokenLocked()
	s.mu.Unlock()
}

func (s *State) clearTokenLocked() {
	clear(s.token[:])
	s.inUse = false
	s.permissions = 0
	s.rpID = ""
	s.userPresent = false
	s.userVerified = false
}
