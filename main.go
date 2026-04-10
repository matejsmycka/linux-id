package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"math/big"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/attestation" // used for CTAP1 registerSite
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidoauth"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/fprintd"
	"github.com/matejsmycka/linux-id/memory"
	"github.com/matejsmycka/linux-id/pinentry"
	"github.com/matejsmycka/linux-id/sitesignatures"
	"github.com/matejsmycka/linux-id/statuscode"
	"github.com/matejsmycka/linux-id/tpm"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var auth = flag.String("auth", "pinentry", "pinentry|fprintd — pinentry confirms presence (UP only); fprintd verifies identity via fingerprint (UP+UV)")

// ctap2Enc is the CTAP2 Canonical CBOR encoder. Per CTAP §6, all CTAP2
// messages must use canonical encoding (sorted keys, shortest-form integers,
// definite-length items). The default cbor.Marshal does not enforce this and
// emits map keys in Go iteration order, which some clients reject.
var ctap2Enc cbor.EncMode = func() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// tokenResponder is the subset of *fidohid.SoftToken that the request handlers
// need to write replies. It exists so handlers can be unit-tested with a fake.
type tokenResponder interface {
	WriteResponse(ctx context.Context, evt fidohid.AuthEvent, data []byte, status uint16) error
	WriteCtap2Response(ctx context.Context, evt fidohid.AuthEvent, status byte, data []byte) error
}

func main() {
	flag.Parse()
	s := newServer()
	s.run()
}

type VerifyFailureReason int

const (
	ReasonUnspecified VerifyFailureReason = iota
	ReasonNoMatch
)

type VerifyResult struct {
	OK     bool
	Reason VerifyFailureReason
	Error  error
}

func statusForFailure(r VerifyResult) byte {
	if r.Reason == ReasonNoMatch {
		return ctap2.StatusUVInvalid
	}
	return ctap2.StatusOperationDenied
}

// UserVerifier abstracts over user confirmation methods for CTAP2.
// pinentry provides User Presence (UP); fprintd provides User Verification (UV).
type UserVerifier interface {
	// VerifyUser starts verification and returns a result channel.
	VerifyUser(prompt string) (<-chan VerifyResult, error)
	// PerformsUV returns true only when the verifier actually identifies the user
	// (e.g. fingerprint). Used to set the UV flag in authenticatorData honestly.
	PerformsUV() bool
}

type pinentryVerifier struct{ pe *pinentry.Pinentry }

func (v *pinentryVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	ch, err := v.pe.ConfirmGeneric(prompt)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() { r := <-ch; out <- VerifyResult{OK: r.OK, Error: r.Error} }()
	return out, nil
}

func (v *pinentryVerifier) PerformsUV() bool { return false }

type fprintdVerifier struct{ fp *fprintd.Fprintd }

func (v *fprintdVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	ch, err := v.fp.VerifyPresence()
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() {
		r := <-ch
		result := VerifyResult{OK: r.OK, Error: r.Error}
		if !r.OK && errors.Is(r.Error, fprintd.ErrNoMatch) {
			result.Reason = ReasonNoMatch
		}
		out <- result
	}()
	return out, nil
}

func (v *fprintdVerifier) PerformsUV() bool { return true }

// pinentryClient is the subset of *pinentry.Pinentry that the U2F handlers
// use. Exists so handleRegister/handleAuthenticate can be unit-tested with a fake.
type pinentryClient interface {
	ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan pinentry.Result, error)
}

type server struct {
	pe       pinentryClient // CTAP1/U2F — browser-retry dedup via challenge params
	verifier UserVerifier   // CTAP2 — configured via --auth flag
	signer   Signer
	cs       *ctap2.CredStore
}

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

func newServer() *server {
	pe := pinentry.New()
	s := server{
		pe: pe,
		cs: ctap2.NewCredStore(),
	}

	switch *auth {
	case "fprintd":
		s.verifier = &fprintdVerifier{fp: fprintd.New()}
	default:
		s.verifier = &pinentryVerifier{pe: pe}
	}

	if *backend == "tpm" {
		signer, err := tpm.New(*device)
		if err != nil {
			panic(err)
		}
		s.signer = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			panic(err)
		}
		s.signer = signer
	}
	return &s
}

func (s *server) run() {
	log.Printf("Starting linux-id server (auth=%s)", *auth)

	ctx := context.Background()

	if *auth == "pinentry" && pinentry.FindPinentryGUIPath() == "" {
		log.Printf("warning: no gui pinentry binary detected in PATH. linux-id may not work correctly without a gui based pinentry")
	}

	token, err := fidohid.New(ctx, "linux-id")
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		// Route CTAP2 (CmdCbor) events before accessing evt.Req.
		if evt.RawCbor != nil {
			s.handleCtap2(ctx, token, evt)
			continue
		}

		if evt.Error != nil {
			log.Printf("got token error: %s", evt.Error)
			continue
		}

		req := evt.Req

		if req.Command == fidoauth.CmdAuthenticate {
			log.Printf("got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))
			s.handleAuthenticate(ctx, token, evt)
		} else if req.Command == fidoauth.CmdRegister {
			log.Printf("got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			s.handleRegister(ctx, token, evt)
		} else if req.Command == fidoauth.CmdVersion {
			log.Print("got VersionCmd")
			s.handleVersion(ctx, token, evt)
		} else {
			log.Printf("unsupported request type: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)
			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}
}

func (s *server) handleVersion(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Printf("Sending version 'U2F_V2' for CTAP1/U2F compatibility")
	if err := token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError); err != nil {
		log.Printf("write version response err: %s", err)
		return
	}
}

func (s *server) handleAuthenticate(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))

	_, err := s.signer.SignASN1(keyHandle, appParam, dummySig[:])
	if err != nil {
		log.Printf("invalid key: %s (key handle size: %d)", err, len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Auth", req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)

		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter := s.signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Register", req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		log.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		log.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

// handleCtap2 dispatches incoming CTAP2 (CmdCbor) events.
func (s *server) handleCtap2(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	if len(evt.RawCbor) == 0 {
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	cmd, payload := evt.RawCbor[0], evt.RawCbor[1:]
	switch cmd {
	case ctap2.CmdGetInfo:
		s.handleGetInfo(ctx, token, evt)
	case ctap2.CmdMakeCredential:
		s.handleMakeCredential(ctx, token, evt, payload)
	case ctap2.CmdGetAssertion:
		s.handleGetAssertion(ctx, token, evt, payload)
	default:
		log.Printf("unsupported CTAP2 cmd 0x%02x", cmd)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNotAllowed, nil)
	}
}

// handleGetInfo returns CTAP2 authenticator capabilities.
// The UV option is honest: true only when using fprintd (actual identity verification).
func (s *server) handleGetInfo(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd GetInfo")

	options := map[string]bool{
		"rk": true,
		"up": true,
		"uv": s.verifier.PerformsUV(),
	}

	response := map[int]interface{}{
		1: []string{"FIDO_2_0", "U2F_V2"},
		3: make([]byte, 16), // AAGUID: 16 zero bytes (uncertified)
		4: options,
		5: 1200, // maxMsgSize
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("GetInfo marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleMakeCredential implements CTAP2 authenticatorMakeCredential (passkey registration).
func (s *server) handleMakeCredential(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	log.Print("got Ctap2Cmd MakeCredential")

	var req ctap2.MakeCredentialRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("MakeCredential decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	if len(req.ClientDataHash) != 32 {
		log.Printf("MakeCredential: invalid clientDataHash length %d", len(req.ClientDataHash))
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	// Verify at least one supported algorithm (ES256 = -7).
	hasES256 := false
	for _, p := range req.PubKeyCredParams {
		if p.Alg == -7 {
			hasES256 = true
			break
		}
	}
	if !hasES256 {
		log.Print("MakeCredential: no ES256 in pubKeyCredParams")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusUnsupportedAlg, nil)
		return
	}

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if req.Options != nil && req.Options.UV && !s.verifier.PerformsUV() {
		log.Print("MakeCredential: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	rpIdHash := sha256.Sum256([]byte(req.RP.ID))

	// Per spec §6.1: user presence MUST be obtained before checking excludeList.
	// Checking after UP prevents timing attacks that reveal credential existence
	// without user consent.
	resultCh, err := s.verifier.VerifyUser("FIDO2 Register: " + req.RP.ID)
	if err != nil {
		log.Printf("MakeCredential verifier err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}
	childCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	select {
	case result := <-resultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("MakeCredential verifier result err: %s", result.Error)
			}
			token.WriteCtap2Response(ctx, evt, statusForFailure(result), nil)
			return
		}
	case <-childCtx.Done():
		token.WriteCtap2Response(ctx, evt, ctap2.StatusUserActionTimeout, nil)
		return
	}

	// Check excludeList after UP: if a credential already exists for this RP, reject.
	if len(req.ExcludeList) > 0 {
		dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
		for _, cred := range req.ExcludeList {
			if _, err := s.signer.SignASN1(cred.ID, rpIdHash[:], dummySig[:]); err == nil {
				log.Printf("MakeCredential: credential already exists for rp=%s", req.RP.ID)
				token.WriteCtap2Response(ctx, evt, ctap2.StatusCredentialExcluded, nil)
				return
			}
		}
	}

	keyHandle, x, y, err := s.signer.RegisterKey(rpIdHash[:])
	if err != nil {
		log.Printf("MakeCredential RegisterKey err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// Build COSE EC public key (integer map keys per RFC 8152).
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	coseKey := map[int]interface{}{
		1:  2,      // kty: EC2
		3:  -7,     // alg: ES256
		-1: 1,      // crv: P-256
		-2: xBytes, // x
		-3: yBytes, // y
	}
	coseKeyBytes, err := ctap2Enc.Marshal(coseKey)
	if err != nil {
		log.Printf("MakeCredential coseKey marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2) | credId | coseKey
	// UV flag is set only when the verifier actually verified the user's identity.
	authFlags := ctap2.AuthFlagUP | ctap2.AuthFlagAT
	if s.verifier.PerformsUV() {
		authFlags |= ctap2.AuthFlagUV
	}

	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())
	authDataBuf.Write(make([]byte, 16)) // AAGUID: 16 zero bytes
	binary.Write(&authDataBuf, binary.BigEndian, uint16(len(keyHandle)))
	authDataBuf.Write(keyHandle)
	authDataBuf.Write(coseKeyBytes)
	authDataBytes := authDataBuf.Bytes()

	// Use "none" attestation: we have no hardware cert chain to present,
	// and returning the shared SoftU2F cert causes servers to reject the credential.
	response := map[int]interface{}{
		1: "none",
		2: authDataBytes,
		3: map[interface{}]interface{}{},
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("MakeCredential response marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// Persist as resident credential if rk option is set.
	if req.Options != nil && req.Options.RK {
		err := s.cs.Save(ctap2.StoredCredential{
			CredID:      keyHandle,
			RPIDHash:    rpIdHash[:],
			RPID:        req.RP.ID,
			RPName:      req.RP.Name,
			UserID:      req.User.ID,
			UserName:    req.User.Name,
			DisplayName: req.User.DisplayName,
		})
		if err != nil {
			log.Printf("MakeCredential credstore save err: %s", err)
		}
	}

	log.Printf("MakeCredential ok: rp=%s keyHandle=%d bytes", req.RP.ID, len(keyHandle))
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleGetAssertion implements CTAP2 authenticatorGetAssertion (passkey authentication).
func (s *server) handleGetAssertion(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	log.Print("got Ctap2Cmd GetAssertion")

	var req ctap2.GetAssertionRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("GetAssertion decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	if len(req.ClientDataHash) != 32 {
		log.Printf("GetAssertion: invalid clientDataHash length %d", len(req.ClientDataHash))
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if req.Options != nil && req.Options.UV && !s.verifier.PerformsUV() {
		log.Print("GetAssertion: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	rpIdHash := sha256.Sum256([]byte(req.RPID))

	// Resolve credential: allowList takes priority over resident credentials.
	var keyHandle []byte
	var storedCred *ctap2.StoredCredential
	if len(req.AllowList) > 0 {
		// Validate the key handle before prompting the user.
		dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
		for _, cred := range req.AllowList {
			if _, err := s.signer.SignASN1(cred.ID, rpIdHash[:], dummySig[:]); err == nil {
				keyHandle = cred.ID
				break
			}
		}
		if keyHandle == nil {
			log.Printf("GetAssertion: no valid key handle in allowList for rp=%s", req.RPID)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
			return
		}
	} else {
		creds, err := s.cs.FindByRPID(rpIdHash[:])
		if err != nil {
			log.Printf("GetAssertion credstore err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		if len(creds) == 0 {
			log.Printf("GetAssertion: no credentials for rp=%s", req.RPID)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
			return
		}
		storedCred = &creds[0]
		keyHandle = storedCred.CredID
	}

	resultCh, err := s.verifier.VerifyUser("FIDO2 Authenticate: " + req.RPID)
	if err != nil {
		log.Printf("GetAssertion verifier err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}
	childCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	select {
	case result := <-resultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("GetAssertion verifier result err: %s", result.Error)
			}
			token.WriteCtap2Response(ctx, evt, statusForFailure(result), nil)
			return
		}
	case <-childCtx.Done():
		token.WriteCtap2Response(ctx, evt, ctap2.StatusUserActionTimeout, nil)
		return
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4)
	// UV flag is set only when the verifier actually verified the user's identity.
	authFlags := ctap2.AuthFlagUP
	if s.verifier.PerformsUV() {
		authFlags |= ctap2.AuthFlagUV
	}

	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())
	authDataBytes := authDataBuf.Bytes()

	// Sign sha256(authData || clientDataHash) per WebAuthn §7.2.
	toSign := make([]byte, len(authDataBytes)+len(req.ClientDataHash))
	copy(toSign, authDataBytes)
	copy(toSign[len(authDataBytes):], req.ClientDataHash)
	digest := sha256.Sum256(toSign)

	sig, err := s.signer.SignASN1(keyHandle, rpIdHash[:], digest[:])
	if err != nil {
		log.Printf("GetAssertion sign err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	response := map[int]interface{}{
		1: map[string]interface{}{"type": "public-key", "id": keyHandle},
		2: authDataBytes,
		3: sig,
	}
	if storedCred != nil {
		response[4] = map[string]interface{}{
			"id":          storedCred.UserID,
			"name":        storedCred.UserName,
			"displayName": storedCred.DisplayName,
		}
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("GetAssertion response marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	log.Printf("GetAssertion ok: rp=%s", req.RPID)
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}


