package ctap2

// CTAP2 command codes (first byte of CmdCbor payload).
const (
	CmdMakeCredential = 0x01
	CmdGetAssertion   = 0x02
	CmdGetInfo        = 0x04
)

// CTAP2 status codes (first byte of CmdCbor response).
const (
	StatusOK                  = byte(0x00)
	StatusInvalidCbor         = byte(0x12)
	StatusCredentialExcluded  = byte(0x19) // credential in excludeList already exists
	StatusUnsupportedAlg      = byte(0x26)
	StatusOperationDenied     = byte(0x27)
	StatusUserActionTimeout   = byte(0x2A)
	StatusInvalidOption       = byte(0x2C) // uv=true but authenticator cannot verify identity
	StatusNoCredentials       = byte(0x2E)
	StatusNotAllowed          = byte(0x30)
)

// authenticatorData flags (WebAuthn §6.1).
const (
	AuthFlagUP = byte(0x01) // User Present
	AuthFlagUV = byte(0x04) // User Verified — only set when identity was verified (e.g. biometric)
	AuthFlagAT = byte(0x40) // Attested Credential Data present (MakeCredential only)
)

// MakeCredentialRequest is the CTAP2 0x01 authenticatorMakeCredential request.
type MakeCredentialRequest struct {
	ClientDataHash   []byte           `cbor:"1,keyasint"`
	RP               RPEntity         `cbor:"2,keyasint"`
	User             UserEntity       `cbor:"3,keyasint"`
	PubKeyCredParams []CredParam      `cbor:"4,keyasint"`
	ExcludeList      []CredDescriptor `cbor:"5,keyasint,omitempty"`
	Options          *MakeCredOptions `cbor:"7,keyasint,omitempty"`
}

// GetAssertionRequest is the CTAP2 0x02 authenticatorGetAssertion request.
type GetAssertionRequest struct {
	RPID           string            `cbor:"1,keyasint"`
	ClientDataHash []byte            `cbor:"2,keyasint"`
	AllowList      []CredDescriptor  `cbor:"3,keyasint,omitempty"`
	Options        *GetAssertOptions `cbor:"5,keyasint,omitempty"`
}

type RPEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

type UserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

type CredParam struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

type CredDescriptor struct {
	Type string `cbor:"type"`
	ID   []byte `cbor:"id"`
}

type MakeCredOptions struct {
	RK bool `cbor:"rk,omitempty"`
	UV bool `cbor:"uv,omitempty"`
}

type GetAssertOptions struct {
	UV bool `cbor:"uv,omitempty"`
}
