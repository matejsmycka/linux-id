package ctap2

import "github.com/telesma-app/ctap/protocol"

// CTAP2 command codes (first byte of CmdCbor payload).
const (
	CmdMakeCredential   = 0x01
	CmdGetAssertion     = 0x02
	CmdGetInfo          = 0x04
	CmdClientPIN        = 0x06
	CmdReset            = 0x07
	CmdGetNextAssertion = 0x08
	CmdSelection        = 0x0B
	// CmdCredentialManagement is authenticatorCredentialManagement;
	// CmdCredentialManagementPreview is its CTAP 2.1-PRE alias.
	CmdCredentialManagement        = 0x0A
	CmdCredentialManagementPreview = 0x41
)

// CTAP2 status codes (first byte of CmdCbor response).
const (
	StatusOK                     = byte(0x00)
	StatusInvalidCommand         = byte(0x01)
	StatusInvalidParameter       = byte(0x02)
	StatusInvalidCbor            = byte(0x12)
	StatusMissingParameter       = byte(0x14)
	StatusCredentialExcluded     = byte(0x19) // credential in excludeList already exists
	StatusUnsupportedAlg         = byte(0x26)
	StatusOperationDenied        = byte(0x27)
	StatusInvalidOption          = byte(0x2C) // uv=true but authenticator cannot verify identity
	StatusKeepaliveCancel        = byte(0x2D) // request cancelled with CTAPHID_CANCEL
	StatusNoCredentials          = byte(0x2E)
	StatusUserActionTimeout      = byte(0x2F) // CTAP 2.1 §8.2 / FIDO_ERR_USER_ACTION_TIMEOUT
	StatusNotAllowed             = byte(0x30)
	StatusPinInvalid             = byte(0x31)
	StatusPinBlocked             = byte(0x32)
	StatusPinAuthInvalid         = byte(0x33)
	StatusPinAuthBlocked         = byte(0x34)
	StatusPinNotSet              = byte(0x35)
	StatusPinRequired            = byte(0x36) // PUAT_REQUIRED in CTAP 2.1
	StatusPinPolicyViolation     = byte(0x37)
	StatusUVBlocked              = byte(0x3C)
	StatusInvalidSubcommand      = byte(0x3E)
	StatusUVInvalid              = byte(0x3F)
	StatusUnauthorizedPermission = byte(0x40)
	StatusOther                  = byte(0x7F)
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
	Extensions       *MakeCredExts    `cbor:"6,keyasint,omitempty"`
	Options          *MakeCredOptions `cbor:"7,keyasint,omitempty"`
	// PinUvAuthParam is nil when absent and empty when the platform sent a
	// zero-length one (the "touch to select" probe).
	PinUvAuthParam    []byte                     `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol protocol.PinUvAuthProtocol `cbor:"9,keyasint,omitempty"`
}

// GetAssertionRequest is the CTAP2 0x02 authenticatorGetAssertion request.
type GetAssertionRequest struct {
	RPID           string            `cbor:"1,keyasint"`
	ClientDataHash []byte            `cbor:"2,keyasint"`
	AllowList      []CredDescriptor  `cbor:"3,keyasint,omitempty"`
	Extensions     *GetAssertExts    `cbor:"4,keyasint,omitempty"`
	Options        *GetAssertOptions `cbor:"5,keyasint,omitempty"`
	// PinUvAuthParam is nil when absent and empty when zero-length.
	PinUvAuthParam    []byte                     `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol protocol.PinUvAuthProtocol `cbor:"7,keyasint,omitempty"`
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

// MakeCredOptions and GetAssertOptions hold the request's options map. UP is
// a pointer because it defaults to true when absent.
type MakeCredOptions struct {
	RK bool  `cbor:"rk,omitempty"`
	UP *bool `cbor:"up,omitempty"`
	UV bool  `cbor:"uv,omitempty"`
}

type GetAssertOptions struct {
	UP *bool `cbor:"up,omitempty"`
	UV bool  `cbor:"uv,omitempty"`
}
