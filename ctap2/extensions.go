package ctap2

import "github.com/telesma-app/ctap/protocol"

// Status codes and flags used by extension processing.
const (
	StatusInvalidLength = byte(0x03) // CTAP1_ERR_INVALID_LENGTH

	AuthFlagED = byte(0x80) // Extension data included in authenticatorData
)

// credProtect levels (CTAP 2.1 §12.1).
const (
	CredProtectUVOptional                     = 1 // userVerificationOptional
	CredProtectUVOptionalWithCredentialIDList = 2 // userVerificationOptionalWithCredentialIDList
	CredProtectUVRequired                     = 3 // userVerificationRequired
)

// Extension identifiers this authenticator implements.
const (
	ExtCredProtect  = "credProtect"
	ExtHmacSecret   = "hmac-secret"
	ExtHmacSecretMC = "hmac-secret-mc"
)

// MakeCredExts is the extensions map (key 6) of a MakeCredential
// request. Extensions this authenticator does not implement are ignored.
type MakeCredExts struct {
	CredProtect int  `cbor:"credProtect,omitempty"`
	HmacSecret  bool `cbor:"hmac-secret,omitempty"`
	// HmacSecretMC (CTAP 2.2) asks for the hmac-secret output of the new
	// credential in the MakeCredential response.
	HmacSecretMC *protocol.HMACSecret `cbor:"hmac-secret-mc,omitempty"`
}

// GetAssertExts is the extensions map (key 4) of a GetAssertion
// request.
type GetAssertExts struct {
	HmacSecret *protocol.HMACSecret `cbor:"hmac-secret,omitempty"`
}
