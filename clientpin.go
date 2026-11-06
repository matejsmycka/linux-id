package main

import (
	"context"
	"log"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/telesma-app/ctap/protocol"
)

// supportedPermissions are the pinUvAuthToken permissions this authenticator
// grants. Others are answered with CTAP2_ERR_UNAUTHORIZED_PERMISSION.
var supportedPermissions = protocol.PermissionMakeCredential |
	protocol.PermissionGetAssertion |
	protocol.PermissionCredentialManagement

// handleClientPIN implements authenticatorClientPIN (CTAP 2.1 §6.5.5).
func (s *server) handleClientPIN(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	var req protocol.AuthenticatorClientPINRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("ClientPIN decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	log.Printf("got Ctap2Cmd ClientPIN subcommand %d", req.SubCommand)

	if req.SubCommand != protocol.ClientPINSubCommandGetUVRetries && req.SubCommand != protocol.ClientPINSubCommandGetPINRetries {
		if req.PinUvAuthProtocol == 0 {
			token.WriteCtap2Response(ctx, evt, ctap2.StatusMissingParameter, nil)
			return
		}
		if !pinuv.IsSupported(req.PinUvAuthProtocol) {
			token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidParameter, nil)
			return
		}
	}

	var (
		resp   protocol.AuthenticatorClientPINResponse
		status = ctap2.StatusOK
	)
	switch req.SubCommand {
	case protocol.ClientPINSubCommandGetKeyAgreement:
		key, err := s.pinuv.KeyAgreement()
		if err != nil {
			log.Printf("ClientPIN getKeyAgreement: %s", err)
			status = ctap2.StatusOther
			break
		}
		resp.KeyAgreement = key
	case protocol.ClientPINSubCommandGetUVRetries:
		n := uint(s.uv.remaining())
		resp.UvRetries = &n
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions:
		status = s.tokenUsingUV(ctx, evt, req, &resp)
	case protocol.ClientPINSubCommandGetPINRetries:
		status = s.getPINRetries(&resp)
	case protocol.ClientPINSubCommandSetPIN:
		status = s.setPIN(req)
	case protocol.ClientPINSubCommandChangePIN:
		status = s.changePIN(req)
	case protocol.ClientPINSubCommandGetPinToken, protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		status = s.tokenUsingPIN(req, &resp)
	default:
		status = ctap2.StatusInvalidSubcommand
	}
	if status != ctap2.StatusOK {
		log.Printf("ClientPIN subcommand %d: status 0x%02x", req.SubCommand, status)
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}
	if req.SubCommand == protocol.ClientPINSubCommandSetPIN || req.SubCommand == protocol.ClientPINSubCommandChangePIN {
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, nil) // no response data
		return
	}
	encoded, err := ctap2Enc.Marshal(resp)
	if err != nil {
		log.Printf("ClientPIN marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOther, nil)
		return
	}
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// tokenUsingUV implements getPinUvAuthTokenUsingUvWithPermissions
// (§6.5.5.7.3): verify the user with the built-in verifier (fingerprint) and
// issue a pinUvAuthToken encrypted for the platform.
func (s *server) tokenUsingUV(ctx context.Context, evt fidohid.AuthEvent, req protocol.AuthenticatorClientPINRequest, resp *protocol.AuthenticatorClientPINResponse) byte {
	if !s.verifier.PerformsUV() {
		return ctap2.StatusInvalidSubcommand
	}
	if req.KeyAgreement == nil || req.Permissions == 0 {
		return ctap2.StatusMissingParameter
	}
	if req.Permissions&^supportedPermissions != 0 {
		return ctap2.StatusUnauthorizedPermission
	}
	rpScoped := req.Permissions&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0
	if rpScoped && req.RPID == "" {
		return ctap2.StatusMissingParameter
	}
	sharedSecret, err := s.pinuv.SharedSecret(req.PinUvAuthProtocol, req.KeyAgreement)
	if err != nil {
		log.Printf("ClientPIN: %s", err)
		return ctap2.StatusInvalidParameter
	}
	defer clear(sharedSecret)

	// The permissions say what the platform is about to do with the token,
	// which is what the user is approving.
	// Fresh: platforms treat a token as the user having picked this
	// authenticator, so it must never come from the verification cache. A
	// cached answer made Chrome send a step-up GetAssertion meant for a phone
	// passkey here, with no touch at all, and fail it.
	vreq := VerifyRequest{RPID: req.RPID, Prompt: "FIDO2: unlock linux-id", Action: ActionManage, Fresh: true}
	switch {
	case req.Permissions&protocol.PermissionMakeCredential != 0:
		vreq.Action, vreq.Prompt = ActionRegister, "FIDO2 Register: "+req.RPID
	case req.Permissions&protocol.PermissionGetAssertion != 0:
		vreq.Action, vreq.Prompt = ActionSignIn, "FIDO2 Authenticate: "+req.RPID
	}
	if s.uvBlocked() {
		return ctap2.StatusUVBlocked
	}
	switch outcome, status := s.performBuiltInUV(ctx, evt, vreq); outcome {
	case uvMatched:
	case uvNoMatch:
		if s.uvBlocked() {
			log.Print("ClientPIN: built-in UV blocked, platform should fall back to the PIN")
			return ctap2.StatusUVBlocked
		}
		return status // UV_INVALID
	case uvUnavailable:
		if s.pin.isSet() {
			// Answer as if UV were blocked so the platform asks for
			// the PIN instead of failing outright (§6.5.5.7.3).
			log.Print("ClientPIN: built-in UV unusable, reporting UV_BLOCKED so the platform falls back to the PIN")
			return ctap2.StatusUVBlocked
		}
		return status
	default:
		return status
	}

	tok, err := s.pinuv.IssueToken(req.Permissions, req.RPID, true, true)
	if err != nil {
		log.Printf("ClientPIN: %s", err)
		return ctap2.StatusOther
	}
	defer clear(tok)
	enc, err := pinuv.Encrypt(req.PinUvAuthProtocol, sharedSecret, tok)
	if err != nil {
		log.Printf("ClientPIN: %s", err)
		return ctap2.StatusOther
	}
	resp.PinUvAuthToken = enc
	return ctap2.StatusOK
}

// userAuthRequest is how a MakeCredential or GetAssertion asks for the user.
type userAuthRequest struct {
	verify         VerifyRequest
	permission     protocol.Permission
	clientDataHash []byte
	// pinUvAuthParam is nil when the request carried none; an empty
	// non-nil slice is the platform's "touch to select" probe.
	pinUvAuthParam []byte
	protocol       protocol.PinUvAuthProtocol
	wantUP, wantUV bool
	// discoverable is MakeCredential's rk option.
	discoverable bool
}

// checkPinUvAuthParam validates a MakeCredential or GetAssertion
// pinUvAuthParam before anything else about the request is processed
// (§6.1.2 steps 1–11, §6.2.2 steps 1–6), so a caller without a valid token
// learns nothing about the credentials. It returns the UV flag the token
// grants. Requests without a pinUvAuthParam pass through.
func (s *server) checkPinUvAuthParam(ctx context.Context, evt fidohid.AuthEvent, r userAuthRequest) (byte, byte) {
	if r.pinUvAuthParam == nil {
		return 0, ctap2.StatusOK
	}
	if len(r.pinUvAuthParam) == 0 {
		// The platform wants the user to pick this authenticator. Wait
		// for presence, then report whether a PIN is set.
		if status := s.awaitPresence(ctx, evt, VerifyRequest{Prompt: "FIDO2: select linux-id", Action: ActionSelect}); status != ctap2.StatusOK {
			return 0, status
		}
		if s.pin.isSet() {
			return 0, ctap2.StatusPinInvalid
		}
		return 0, ctap2.StatusPinNotSet
	}
	if r.protocol == 0 {
		return 0, ctap2.StatusMissingParameter
	}
	if !pinuv.IsSupported(r.protocol) {
		return 0, ctap2.StatusInvalidParameter
	}
	if err := s.pinuv.Check(r.protocol, r.pinUvAuthParam, r.clientDataHash, r.permission, r.verify.RPID); err != nil {
		log.Printf("pinUvAuthParam rejected: %s", err)
		return 0, ctap2.StatusPinAuthInvalid
	}
	if s.pinuv.UserVerified() {
		return ctap2.AuthFlagUV, ctap2.StatusOK
	}
	return 0, ctap2.StatusOK
}

// authorizeUser establishes user presence and verification for a
// MakeCredential or GetAssertion whose pinUvAuthParam (if any) has already
// passed checkPinUvAuthParam with tokenFlags. With a token, the gesture that
// unlocked it covers one request; otherwise the built-in verifier asks the
// user. It returns the authenticatorData UP/UV flags, or the status to fail
// the request with.
func (s *server) authorizeUser(ctx context.Context, evt fidohid.AuthEvent, r userAuthRequest, tokenFlags byte) (byte, byte) {
	if r.pinUvAuthParam != nil {
		if !r.wantUP {
			return tokenFlags, ctap2.StatusOK
		}
		if s.pinuv.UserPresent() {
			s.pinuv.ConsumeUserPresent()
			return tokenFlags | ctap2.AuthFlagUP, ctap2.StatusOK
		}
		if status := s.awaitPresence(ctx, evt, r.verify); status != ctap2.StatusOK {
			return 0, status
		}
		return tokenFlags | ctap2.AuthFlagUP, ctap2.StatusOK
	}

	if !r.wantUP && !r.wantUV {
		return 0, ctap2.StatusOK
	}
	if s.pin.isSet() {
		return s.authorizeWithPINSet(ctx, evt, r)
	}
	if status := s.awaitUser(ctx, evt, r.verify); status != ctap2.StatusOK {
		return 0, status
	}
	flags := ctap2.AuthFlagUP
	if s.verifier.PerformsUV() {
		flags |= ctap2.AuthFlagUV
	}
	return flags, ctap2.StatusOK
}

// authorizeWithPINSet is authorizeUser for a request without a
// pinUvAuthParam while a PIN is set (§6.1.2 steps 7–11, §6.2.2 step 6).
// linux-id advertises makeCredUvNotRqd, so only a discoverable credential
// needs a pinUvAuthToken; other requests get UP, or UP and UV with uv=true.
func (s *server) authorizeWithPINSet(ctx context.Context, evt fidohid.AuthEvent, r userAuthRequest) (byte, byte) {
	if r.wantUV {
		if s.uvBlocked() {
			log.Print("built-in UV blocked, PIN required")
			return 0, ctap2.StatusPinRequired
		}
		switch outcome, status := s.performBuiltInUV(ctx, evt, r.verify); outcome {
		case uvMatched:
			return ctap2.AuthFlagUP | ctap2.AuthFlagUV, ctap2.StatusOK
		case uvNoMatch, uvUnavailable:
			// The platform should get a pinUvAuthToken with the PIN.
			return 0, ctap2.StatusPinRequired
		default:
			return 0, status
		}
	}
	if r.permission == protocol.PermissionMakeCredential && r.discoverable {
		log.Print("MakeCredential: discoverable credential without uv or pinUvAuthParam while a PIN is set")
		return 0, ctap2.StatusPinRequired
	}
	if status := s.awaitPresence(ctx, evt, r.verify); status != ctap2.StatusOK {
		return 0, status
	}
	return ctap2.AuthFlagUP, ctap2.StatusOK
}
