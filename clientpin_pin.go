package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log"
	"slices"
	"unicode/utf8"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/telesma-app/ctap/protocol"
)

// PIN policy (CTAP 2.1 §6.5.1): at least minPINLength Unicode code points,
// at most maxPINBytes bytes of UTF-8, sent padded with zeros to
// paddedPINLen bytes.
const (
	minPINLength = 4
	maxPINBytes  = 63
	paddedPINLen = 64
)

// pinStatus maps a pinStore precheck/verify outcome or error to a status.
func pinStatus(c pinCheck, err error) byte {
	switch {
	case errors.Is(err, errPINNotSet):
		return ctap2.StatusPinNotSet
	case err != nil:
		log.Printf("ClientPIN: %s", err)
		return ctap2.StatusOther
	}
	switch c {
	case pinBlocked:
		return ctap2.StatusPinBlocked
	case pinAuthBlocked:
		return ctap2.StatusPinAuthBlocked
	case pinMismatch:
		return ctap2.StatusPinInvalid
	}
	return ctap2.StatusOK
}

// getPINRetries implements §6.5.5.2.
func (s *server) getPINRetries(resp *protocol.AuthenticatorClientPINResponse) byte {
	retries, powerCycle, err := s.pin.state()
	if err != nil {
		log.Printf("ClientPIN getPINRetries: %s", err)
		return ctap2.StatusOther
	}
	n := uint(retries)
	resp.PinRetries = &n
	resp.PowerCycleState = &powerCycle
	return ctap2.StatusOK
}

// decodeNewPIN decrypts newPinEnc, checks the PIN policy, and returns
// LEFT(SHA-256(newPin), 16) (§6.5.5.5 steps 6–8).
func decodeNewPIN(p protocol.PinUvAuthProtocol, sharedSecret, newPinEnc []byte) ([]byte, byte) {
	padded, err := pinuv.Decrypt(p, sharedSecret, newPinEnc)
	if err != nil {
		return nil, ctap2.StatusPinAuthInvalid
	}
	defer clear(padded)
	if len(padded) != paddedPINLen {
		return nil, ctap2.StatusInvalidParameter
	}
	pin := bytes.TrimRight(padded, "\x00")
	if len(pin) > maxPINBytes || !utf8.Valid(pin) || utf8.RuneCount(pin) < minPINLength {
		return nil, ctap2.StatusPinPolicyViolation
	}
	sum := sha256.Sum256(pin)
	defer clear(sum[:])
	return slices.Clone(sum[:16]), ctap2.StatusOK
}

// checkPINHash decrypts pinHashEnc and verifies it against the stored PIN,
// consuming a retry (§6.5.5.7.1 steps 6–8). On a mismatch the key agreement
// key is regenerated; on a match the UV retries are restored too.
func (s *server) checkPINHash(p protocol.PinUvAuthProtocol, sharedSecret, pinHashEnc []byte) byte {
	pinHash, err := pinuv.Decrypt(p, sharedSecret, pinHashEnc)
	if err != nil {
		pinHash = nil // cannot match
	}
	defer clear(pinHash)
	res, err := s.pin.verify(pinHash)
	if err == nil && res == pinOK {
		s.uv.reset()
		return ctap2.StatusOK
	}
	if err == nil {
		retries, _, _ := s.pin.state()
		log.Printf("ClientPIN: wrong PIN, %d retries left", retries)
		if rerr := s.pinuv.Regenerate(); rerr != nil {
			log.Printf("ClientPIN: %s", rerr)
		}
	}
	return pinStatus(res, err)
}

// setPIN implements §6.5.5.5.
func (s *server) setPIN(req protocol.AuthenticatorClientPINRequest) byte {
	if req.KeyAgreement == nil || req.NewPinEnc == nil || req.PinUvAuthParam == nil {
		return ctap2.StatusMissingParameter
	}
	if s.pin.isSet() {
		return ctap2.StatusPinAuthInvalid
	}
	sharedSecret, err := s.pinuv.SharedSecret(req.PinUvAuthProtocol, req.KeyAgreement)
	if err != nil {
		log.Printf("ClientPIN setPIN: %s", err)
		return ctap2.StatusInvalidParameter
	}
	defer clear(sharedSecret)
	if !pinuv.Verify(req.PinUvAuthProtocol, sharedSecret, req.NewPinEnc, req.PinUvAuthParam) {
		return ctap2.StatusPinAuthInvalid
	}
	pinHash, status := decodeNewPIN(req.PinUvAuthProtocol, sharedSecret, req.NewPinEnc)
	if status != ctap2.StatusOK {
		return status
	}
	defer clear(pinHash)
	if err := s.pin.set(pinHash); err != nil {
		log.Printf("ClientPIN setPIN: %s", err)
		return ctap2.StatusOther
	}
	log.Print("ClientPIN: PIN set")
	return ctap2.StatusOK
}

// changePIN implements §6.5.5.6.
func (s *server) changePIN(req protocol.AuthenticatorClientPINRequest) byte {
	if req.KeyAgreement == nil || req.PinHashEnc == nil || req.NewPinEnc == nil || req.PinUvAuthParam == nil {
		return ctap2.StatusMissingParameter
	}
	if status := pinStatus(s.pin.precheck()); status != ctap2.StatusOK {
		return status
	}
	sharedSecret, err := s.pinuv.SharedSecret(req.PinUvAuthProtocol, req.KeyAgreement)
	if err != nil {
		log.Printf("ClientPIN changePIN: %s", err)
		return ctap2.StatusInvalidParameter
	}
	defer clear(sharedSecret)
	if !pinuv.Verify(req.PinUvAuthProtocol, sharedSecret, slices.Concat(req.NewPinEnc, req.PinHashEnc), req.PinUvAuthParam) {
		return ctap2.StatusPinAuthInvalid
	}
	if status := s.checkPINHash(req.PinUvAuthProtocol, sharedSecret, req.PinHashEnc); status != ctap2.StatusOK {
		return status
	}
	pinHash, status := decodeNewPIN(req.PinUvAuthProtocol, sharedSecret, req.NewPinEnc)
	if status != ctap2.StatusOK {
		return status
	}
	defer clear(pinHash)
	if err := s.pin.set(pinHash); err != nil {
		log.Printf("ClientPIN changePIN: %s", err)
		return ctap2.StatusOther
	}
	s.pinuv.ClearToken()
	log.Print("ClientPIN: PIN changed")
	return ctap2.StatusOK
}

// tokenUsingPIN implements getPinToken (§6.5.5.7.1, legacy) and
// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2).
func (s *server) tokenUsingPIN(req protocol.AuthenticatorClientPINRequest, resp *protocol.AuthenticatorClientPINResponse) byte {
	legacy := req.SubCommand == protocol.ClientPINSubCommandGetPinToken
	if req.KeyAgreement == nil || req.PinHashEnc == nil {
		return ctap2.StatusMissingParameter
	}
	perms, rpID := req.Permissions, req.RPID
	if legacy {
		if req.Permissions != 0 || req.RPID != "" {
			return ctap2.StatusInvalidParameter
		}
		perms = protocol.PermissionMakeCredential | protocol.PermissionGetAssertion
	} else {
		if req.Permissions == 0 {
			return ctap2.StatusMissingParameter
		}
		if req.Permissions&^supportedPermissions != 0 {
			return ctap2.StatusUnauthorizedPermission
		}
	}
	if status := pinStatus(s.pin.precheck()); status != ctap2.StatusOK {
		return status
	}
	sharedSecret, err := s.pinuv.SharedSecret(req.PinUvAuthProtocol, req.KeyAgreement)
	if err != nil {
		log.Printf("ClientPIN: %s", err)
		return ctap2.StatusInvalidParameter
	}
	defer clear(sharedSecret)
	if status := s.checkPINHash(req.PinUvAuthProtocol, sharedSecret, req.PinHashEnc); status != ctap2.StatusOK {
		return status
	}

	// The PIN verifies the user but is no presence gesture: requests that
	// need UP still ask for a touch.
	tok, err := s.pinuv.IssueToken(perms, rpID, false, true)
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
	log.Printf("ClientPIN: pinUvAuthToken issued via PIN (permissions 0x%02x, rp %q)", perms, rpID)
	return ctap2.StatusOK
}
