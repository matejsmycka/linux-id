package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/telesma-app/ctap/protocol"
)

// SecretDeriver derives secrets bound to the authenticator: the same input
// always gives the same 32 bytes, and computing them takes the backend's key
// (for the tpm backend, an HMAC key that never leaves the TPM). The hmac-secret
// extension derives each credential's CredRandom with it.
type SecretDeriver interface {
	DeriveSecret(input []byte) ([]byte, error)
}

// credRandomLabel separates CredRandom derivation from any other use of the
// SecretDeriver.
const credRandomLabel = "linux-id hmac-secret CredRandom v1\x00"

// supportedExtensions lists the extensions GetInfo advertises.
func (s *server) supportedExtensions() []string {
	exts := []string{ctap2.ExtCredProtect}
	if s.secrets != nil {
		exts = append(exts, ctap2.ExtHmacSecret, ctap2.ExtHmacSecretMC)
	}
	return exts
}

// credRandom returns the hmac-secret CredRandom of a credential (CTAP 2.1
// §12.5): CredRandomWithUV when uv is true, CredRandomWithoutUV otherwise.
// Rather than storing two random values per credential, it derives them:
//
//	CredRandom = DeriveSecret(label | uv | rpIdHash | SHA-256(credentialID))
//
// They are as stable as the credential ID, so they work the same for
// resident and non-resident credentials and survive restarts, and they are
// independent pseudorandom values for every (credential, uv) pair.
func (s *server) credRandom(credID, rpIdHash []byte, uv bool) ([]byte, error) {
	idHash := sha256.Sum256(credID)
	in := make([]byte, 0, len(credRandomLabel)+1+len(rpIdHash)+len(idHash))
	in = append(in, credRandomLabel...)
	if uv {
		in = append(in, 1)
	} else {
		in = append(in, 0)
	}
	in = append(in, rpIdHash...)
	in = append(in, idHash[:]...)
	return s.secrets.DeriveSecret(in)
}

// hmacSecretRequest is a validated hmac-secret (or hmac-secret-mc) input.
type hmacSecretRequest struct {
	protocol     protocol.PinUvAuthProtocol
	sharedSecret []byte
	salts        [][]byte // one or two 32-byte salts
}

func (h *hmacSecretRequest) clear() {
	if h == nil {
		return
	}
	clear(h.sharedSecret)
	for _, s := range h.salts {
		clear(s)
	}
}

// parseHmacSecret validates an hmac-secret input (CTAP 2.1 §12.5): it agrees
// on the shared secret, verifies saltAuth and decrypts the salts. It returns
// nil without error when there is no input or hmac-secret is not supported.
func (s *server) parseHmacSecret(in *protocol.HMACSecret) (*hmacSecretRequest, byte) {
	if in == nil || s.secrets == nil {
		return nil, ctap2.StatusOK
	}
	if in.KeyAgreement == nil || in.SaltEnc == nil || in.SaltAuth == nil {
		return nil, ctap2.StatusMissingParameter
	}
	p := in.PinUvAuthProtocol
	if p == 0 {
		p = protocol.PinUvAuthProtocolOne
	}
	if !pinuv.IsSupported(p) {
		return nil, ctap2.StatusInvalidParameter
	}
	sharedSecret, err := s.pinuv.SharedSecret(p, in.KeyAgreement)
	if err != nil {
		log.Printf("hmac-secret: %s", err)
		return nil, ctap2.StatusInvalidParameter
	}
	if !pinuv.Verify(p, sharedSecret, in.SaltEnc, in.SaltAuth) {
		clear(sharedSecret)
		return nil, ctap2.StatusPinAuthInvalid
	}
	salt, err := pinuv.Decrypt(p, sharedSecret, in.SaltEnc)
	if err != nil {
		clear(sharedSecret)
		log.Printf("hmac-secret: %s", err)
		return nil, ctap2.StatusInvalidParameter
	}
	if len(salt) != 32 && len(salt) != 64 {
		clear(sharedSecret)
		clear(salt)
		return nil, ctap2.StatusInvalidLength
	}
	req := &hmacSecretRequest{protocol: p, sharedSecret: sharedSecret}
	for i := 0; i < len(salt); i += 32 {
		req.salts = append(req.salts, salt[i:i+32])
	}
	return req, ctap2.StatusOK
}

// hmacSecretOutput computes the encrypted hmac-secret output for a
// credential: encrypt(HMAC-SHA-256(CredRandom, salt1) [| HMAC-SHA-256(CredRandom, salt2)]).
func (s *server) hmacSecretOutput(h *hmacSecretRequest, credID, rpIdHash []byte, uv bool) ([]byte, error) {
	credRandom, err := s.credRandom(credID, rpIdHash, uv)
	if err != nil {
		return nil, fmt.Errorf("hmac-secret: derive CredRandom: %w", err)
	}
	defer clear(credRandom)
	out := make([]byte, 0, 32*len(h.salts))
	for _, salt := range h.salts {
		mac := hmac.New(sha256.New, credRandom)
		mac.Write(salt)
		out = mac.Sum(out)
	}
	defer clear(out)
	return pinuv.Encrypt(h.protocol, h.sharedSecret, out)
}

// makeCredExtensions is the processed extensions input of a MakeCredential.
type makeCredExtensions struct {
	opts           credOptions
	credProtectOut int // echoed credProtect level; 0 for none
	hmacSecretMC   *hmacSecretRequest
}

// parseMakeCredExtensions validates MakeCredential extension inputs. Unknown
// extensions and credProtect values other than 1, 2 and 3 are ignored.
func (s *server) parseMakeCredExtensions(in *ctap2.MakeCredExts) (makeCredExtensions, byte) {
	var e makeCredExtensions
	if in == nil {
		return e, ctap2.StatusOK
	}
	switch in.CredProtect {
	case ctap2.CredProtectUVOptional, ctap2.CredProtectUVOptionalWithCredentialIDList, ctap2.CredProtectUVRequired:
		e.opts.credProtect = in.CredProtect
		e.credProtectOut = in.CredProtect
	}
	if in.HmacSecret && s.secrets != nil {
		e.opts.hmacSecret = true
		// hmac-secret-mc (CTAP 2.2) only together with hmac-secret.
		h, status := s.parseHmacSecret(in.HmacSecretMC)
		if status != ctap2.StatusOK {
			return e, status
		}
		e.hmacSecretMC = h
	}
	return e, ctap2.StatusOK
}

// makeCredExtensionOutputs returns the CBOR extensions map for the new
// credential's authenticatorData, or nil when there are no outputs.
func (s *server) makeCredExtensionOutputs(e makeCredExtensions, credID, rpIdHash []byte, uv bool) ([]byte, error) {
	out := map[string]interface{}{}
	if e.credProtectOut != 0 {
		out[ctap2.ExtCredProtect] = e.credProtectOut
	}
	if e.opts.hmacSecret {
		out[ctap2.ExtHmacSecret] = true
	}
	if e.hmacSecretMC != nil {
		enc, err := s.hmacSecretOutput(e.hmacSecretMC, credID, rpIdHash, uv)
		if err != nil {
			return nil, err
		}
		out[ctap2.ExtHmacSecretMC] = enc
	}
	if len(out) == 0 {
		return nil, nil
	}
	return ctap2Enc.Marshal(out)
}

// assertionExtensionOutputs returns the CBOR extensions map for an
// assertion's authenticatorData, or nil when there are no outputs. Only
// credentials created with hmac-secret answer it.
func (s *server) assertionExtensionOutputs(cred ctap2.StoredCredential, rpIdHash []byte, uv bool, h *hmacSecretRequest) ([]byte, error) {
	if h == nil || !credOptionsOf(cred.CredID).hmacSecret {
		return nil, nil
	}
	enc, err := s.hmacSecretOutput(h, cred.CredID, rpIdHash, uv)
	if err != nil {
		return nil, err
	}
	return ctap2Enc.Marshal(map[string]interface{}{ctap2.ExtHmacSecret: enc})
}

// credProtectLevel returns a credential's credProtect level: the one its ID
// carries, or the stored one for a resident credential, whichever is higher.
func credProtectLevel(c ctap2.StoredCredential) int {
	level := credOptionsOf(c.CredID).credProtect
	if c.CredProtect > level {
		level = c.CredProtect
	}
	if level == 0 {
		level = ctap2.CredProtectUVOptional
	}
	return level
}

// credentialUsable applies credProtect (CTAP 2.1 §12.1) to a GetAssertion:
// level 2 credentials are found without an allowList only with user
// verification, level 3 credentials are never usable without it.
func credentialUsable(c ctap2.StoredCredential, viaAllowList, uv bool) bool {
	switch credProtectLevel(c) {
	case ctap2.CredProtectUVOptionalWithCredentialIDList:
		return uv || viaAllowList
	case ctap2.CredProtectUVRequired:
		return uv
	}
	return true
}

// usableCredentials returns the credentials of creds that credProtect allows.
func usableCredentials(creds []ctap2.StoredCredential, viaAllowList, uv bool) []ctap2.StoredCredential {
	var out []ctap2.StoredCredential
	for _, c := range creds {
		if credentialUsable(c, viaAllowList, uv) {
			out = append(out, c)
		}
	}
	return out
}

// expectUV reports whether authorizeUser will report user verification for
// r, so that credentials can be located (and credProtect applied) before the
// user is asked, as CTAP 2.1 §6.2.2 orders it. With a pinUvAuthToken the
// token decides; otherwise the built-in verifier verifies whenever it asks the
// user at all.
func (s *server) expectUV(r userAuthRequest, tokenFlags byte) bool {
	if r.pinUvAuthParam != nil {
		return tokenFlags&ctap2.AuthFlagUV != 0
	}
	return (r.wantUP || r.wantUV) && s.verifier.PerformsUV()
}
