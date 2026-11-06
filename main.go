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
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/attestation" // used for CTAP1 registerSite
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidoauth"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/fprintd"
	"github.com/matejsmycka/linux-id/memory"
	"github.com/matejsmycka/linux-id/notify"
	"github.com/matejsmycka/linux-id/pinentry"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/matejsmycka/linux-id/sitesignatures"
	"github.com/matejsmycka/linux-id/statuscode"
	"github.com/matejsmycka/linux-id/tpm"
	"github.com/telesma-app/ctap/protocol"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var credStorePath = flag.String("credstore", ctap2.DefaultCredStorePath(), "file that holds resident (discoverable) credentials")
// Browsers show their own "touch the sensor" dialog, so the notification is
// off by default; it helps clients that show nothing, such as ssh.
var notifyPrompt = flag.Bool("notify", false, "with --auth fprintd, show a desktop notification naming the site while waiting for the fingerprint (browsers already show their own prompt)")
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
	if flag.Arg(0) == "reset" {
		os.Exit(runResetCLI(flag.Args()[1:]))
	}
	if flag.Arg(0) == "creds" {
		os.Exit(runCredsCLI(flag.Args()[1:]))
	}
	s := newServer()
	s.run()
}

type VerifyFailureReason int

const (
	ReasonUnspecified VerifyFailureReason = iota
	ReasonNoMatch
	// ReasonUserDeclined: the user turned the request down (the Cancel
	// action of the prompt notification).
	ReasonUserDeclined
	// ReasonUnavailable: the verifier itself is unusable (no sensor,
	// D-Bus or device error), as opposed to the user failing, declining or
	// not answering in time.
	ReasonUnavailable
)

type VerifyResult struct {
	OK     bool
	Reason VerifyFailureReason
	Error  error
}

func statusForFailure(r VerifyResult) byte {
	switch r.Reason {
	case ReasonNoMatch:
		return ctap2.StatusUVInvalid
	case ReasonUserDeclined:
		return ctap2.StatusOperationDenied
	}
	return ctap2.StatusOperationDenied
}

// UserVerifier abstracts over user confirmation methods for CTAP2.
// pinentry provides User Presence (UP); fprintd provides User Verification (UV).
type UserVerifier interface {
	// VerifyUser starts verification and returns a result channel. Cancelling
	// ctx abandons the verification where the method supports it.
	VerifyUser(ctx context.Context, req VerifyRequest) (<-chan VerifyResult, error)
	// PerformsUV returns true only when the verifier actually identifies the user
	// (e.g. fingerprint). Used to set the UV flag in authenticatorData honestly.
	PerformsUV() bool
}

// VerifyAction is what the user approves by verifying.
type VerifyAction int

const (
	ActionUnspecified VerifyAction = iota
	ActionRegister                 // authenticatorMakeCredential
	ActionSignIn                   // authenticatorGetAssertion
	ActionSelect                   // authenticatorSelection
	ActionManage                   // credential management
	ActionReset                    // authenticatorReset
)

// VerifyRequest describes what the user is asked to approve.
type VerifyRequest struct {
	// RPID is the relying party the approval is for; empty when the request
	// is not for a relying party (authenticatorSelection).
	RPID string
	// Prompt is the text shown to the user by verifiers with a dialog of
	// their own (pinentry).
	Prompt string

	// Action, UserName and UserDisplayName describe the request for the
	// prompt notification. The user is known when registering, and when
	// signing in with exactly one resident credential for the RP.
	Action          VerifyAction
	UserName        string
	UserDisplayName string

	// OnRetry, if not nil, is called by verifiers that give the user another
	// attempt, such as fprintd after a finger that did not match.
	OnRetry func()

	// Fresh requires a new gesture from the user: a cached verification
	// must not answer it. Set when the answer tells the platform that the
	// user chose this authenticator.
	Fresh bool
}

// testVerifiers holds extra --auth modes compiled in by test-only build tags.
// It is empty in normal builds.
var testVerifiers = map[string]func() UserVerifier{}

type pinentryVerifier struct{ pe *pinentry.Pinentry }

// VerifyUser ignores ctx: an open pinentry dialog cannot be withdrawn.
func (v *pinentryVerifier) VerifyUser(_ context.Context, req VerifyRequest) (<-chan VerifyResult, error) {
	ch, err := v.pe.ConfirmGeneric(req.Prompt)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() { r := <-ch; out <- VerifyResult{OK: r.OK, Error: r.Error} }()
	return out, nil
}

func (v *pinentryVerifier) PerformsUV() bool { return false }

type fprintdVerifier struct{ fp *fprintd.Fprintd }

func (v *fprintdVerifier) VerifyUser(ctx context.Context, req VerifyRequest) (<-chan VerifyResult, error) {
	ch, err := v.fp.VerifyPresence(ctx, req.OnRetry)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() {
		r := <-ch
		result := VerifyResult{OK: r.OK, Error: r.Error}
		switch {
		case r.OK:
		case errors.Is(r.Error, fprintd.ErrNoMatch):
			result.Reason = ReasonNoMatch
		case r.Error != nil && !errors.Is(r.Error, context.Canceled) && !errors.Is(r.Error, context.DeadlineExceeded):
			result.Reason = ReasonUnavailable
		}
		out <- result
	}()
	return out, nil
}

func (v *fprintdVerifier) PerformsUV() bool { return true }

const uvCacheTTL = 5 * time.Second

// cachingVerifier reuses a successful verification for further requests from
// the same relying party within ttl, so a browser that issues several
// requests for one ceremony does not ask for the finger each time. It never
// carries a verification over to a different relying party.
type cachingVerifier struct {
	inner    UserVerifier
	ttl      time.Duration
	now      func() time.Time
	mu       sync.Mutex
	lastOK   time.Time
	lastRPID string
}

func newCachingVerifier(inner UserVerifier) *cachingVerifier {
	return &cachingVerifier{inner: inner, ttl: uvCacheTTL, now: time.Now}
}

func (v *cachingVerifier) VerifyUser(ctx context.Context, req VerifyRequest) (<-chan VerifyResult, error) {
	v.mu.Lock()
	if !req.Fresh && req.RPID != "" && req.RPID == v.lastRPID && !v.lastOK.IsZero() && v.now().Sub(v.lastOK) < v.ttl {
		v.mu.Unlock()
		log.Print("verifier: UV cache hit, skipping prompt")
		ch := make(chan VerifyResult, 1)
		ch <- VerifyResult{OK: true}
		return ch, nil
	}
	v.mu.Unlock()

	innerCh, err := v.inner.VerifyUser(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() {
		r := <-innerCh
		if r.OK {
			v.mu.Lock()
			v.lastOK = v.now()
			v.lastRPID = req.RPID
			v.mu.Unlock()
		}
		out <- r
	}()
	return out, nil
}

func (v *cachingVerifier) PerformsUV() bool { return v.inner.PerformsUV() }

const (
	deviceOpenAttempts = 10
	deviceOpenDelay    = 200 * time.Millisecond
)

func openWithRetry[T any](label string, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for i := 1; i <= deviceOpenAttempts; i++ {
		v, err := fn()
		if err == nil {
			if i > 1 {
				log.Printf("%s: opened on attempt %d/%d", label, i, deviceOpenAttempts)
			}
			return v, nil
		}
		if !errors.Is(err, os.ErrPermission) {
			return zero, err
		}
		lastErr = err
		log.Printf("%s: not yet accessible (attempt %d/%d), waiting %v",
			label, i, deviceOpenAttempts, deviceOpenDelay)
		time.Sleep(deviceOpenDelay)
	}
	return zero, fmt.Errorf("%s: not accessible after %d attempts: %w",
		label, deviceOpenAttempts, lastErr)
}

// pinentryClient is the subset of *pinentry.Pinentry that the U2F handlers
// use. Exists so handleRegister/handleAuthenticate can be unit-tested with a fake.
type pinentryClient interface {
	ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan pinentry.Result, error)
}

type server struct {
	pe       pinentryClient // CTAP1/U2F — browser-retry dedup via challenge params
	verifier UserVerifier   // CTAP2 — configured via --auth flag
	signer   Signer
	secrets  SecretDeriver // nil: hmac-secret unsupported
	cs       *ctap2.CredStore
	pinuv    *pinuv.State
	pin      *pinStore      // CTAP PIN, the fallback to the fingerprint
	uv       uvRetryCounter // built-in UV retries for this power cycle
	presence UserVerifier   // asks for presence when the verifier is unusable; may be nil

	// nextAssertions is only touched from the request handlers, which the
	// transport runs one at a time.
	nextAssertions *pendingAssertions

	// gens is the backend's credential generation (generation.go); genN
	// and genSecret are the generation this daemon last read.
	gens      generationBackend
	genN      uint64
	genSecret []byte
	// legacyRetired is whether a reset retired legacy credentials, as last
	// read with the generation.
	legacyRetired bool
	// startedAt is this daemon's "power-up", which opens the reset window.
	startedAt time.Time
	clock     func() time.Time
	// credMgmtIter is the authenticatorCredentialManagement enumeration
	// in progress, if any.
	credMgmtIter *credMgmtIteration
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
		cs: ctap2.NewCredStoreAt(*credStorePath),
	}
	pu, err := pinuv.New()
	if err != nil {
		log.Fatalf("pin/uv state: %s", err)
	}
	s.pinuv = pu
	s.startedAt, s.clock = time.Now(), time.Now

	var inner UserVerifier
	switch *auth {
	case "fprintd":
		// fprintd has no window of its own: say what the finger is for.
		inner = &fprintdVerifier{fp: fprintd.New()}
		s.presence = &pinentryVerifier{pe: pe}
		if *notifyPrompt {
			inner = newNotifyingVerifier(inner, notify.NewDBus("linux-id", "auth-fingerprint-symbolic"))
		}
	case "pinentry":
		inner = &pinentryVerifier{pe: pe}
	default:
		mk, ok := testVerifiers[*auth]
		if !ok {
			log.Fatalf("unknown --auth %q (want pinentry or fprintd)", *auth)
		}
		log.Printf("WARNING: --auth %s approves every request; test builds only", *auth)
		inner = mk()
	}
	s.verifier = newCachingVerifier(inner)

	if *backend == "tpm" {
		signer, err := openWithRetry("tpm", func() (*tpm.TPM, error) {
			return tpm.New(*device)
		})
		if err != nil {
			log.Fatalf("open tpm: %s", err)
		}
		s.signer, s.secrets, s.gens = signer, signer, signer
		s.pin = pinStoreNextTo(*credStorePath, signer)
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			panic(err)
		}
		s.signer, s.secrets, s.gens = signer, signer, signer
		s.pin = pinStoreNextTo(*credStorePath, signer)
	}
	return &s
}

func (s *server) run() {
	log.Printf("Starting linux-id server (auth=%s)", *auth)

	ctx := context.Background()

	if *auth == "pinentry" && pinentry.FindPinentryGUIPath() == "" {
		log.Printf("warning: no gui pinentry binary detected in PATH. linux-id may not work correctly without a gui based pinentry")
	}

	token, err := openWithRetry("fidohid", func() (*fidohid.SoftToken, error) {
		return fidohid.New(ctx, "linux-id")
	})
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		s.handleEvent(evt.Context(), token, evt)
		token.Complete(evt)
	}
}

// handleEvent answers one request from the transport. ctx is cancelled if the
// host cancels the request.
func (s *server) handleEvent(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	s.syncGeneration()
	// Route CTAP2 (CmdCbor) events before accessing evt.Req.
	if evt.RawCbor != nil {
		s.handleCtap2(ctx, token, evt)
		return
	}

	if evt.Error != nil {
		log.Printf("got token error: %s", evt.Error)
		return
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

	_, err := s.signWithCredential(keyHandle, appParam, dummySig[:])
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

	sig, err := s.signWithCredential(keyHandle, appParam, sigHash.Sum(nil))
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

	keyHandle, x, y, err := s.newCredential(req.Register.ApplicationParam[:], credOptions{})
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

// userActionTimeout bounds how long a CTAP2 request waits for the user.
const userActionTimeout = 35 * time.Second

// awaitUser asks the verifier to confirm the user and waits for the answer,
// reporting UPNEEDED in keepalives meanwhile. It returns StatusOK on success,
// or the CTAP2 status to answer the request with.
func (s *server) awaitUser(ctx context.Context, evt fidohid.AuthEvent, req VerifyRequest) byte {
	_, status := s.awaitResult(ctx, evt, s.verifier, req)
	return status
}

// awaitResult is awaitUser with verifier v, also returning the verifier's
// result so callers can tell a no-match from an unusable verifier.
func (s *server) awaitResult(ctx context.Context, evt fidohid.AuthEvent, v UserVerifier, req VerifyRequest) (VerifyResult, byte) {
	ctx, cancel := context.WithTimeout(ctx, userActionTimeout)
	defer cancel()

	resultCh, err := v.VerifyUser(ctx, req)
	if err != nil {
		log.Printf("verifier err: %s", err)
		return VerifyResult{Reason: ReasonUnavailable, Error: err}, ctap2.StatusOperationDenied
	}
	evt.SetKeepalive(fidohid.KeepaliveUPNeeded)
	defer evt.SetKeepalive(fidohid.KeepaliveProcessing)

	select {
	case result := <-resultCh:
		if result.OK {
			return result, ctap2.StatusOK
		}
		if result.Error != nil {
			log.Printf("verifier result err: %s", result.Error)
		}
		if ctx.Err() != nil {
			// The verifier gave up because the request was cancelled or
			// timed out; report that rather than its error.
			return result, statusForDone(ctx)
		}
		return result, statusForFailure(result)
	case <-ctx.Done():
		return VerifyResult{Error: ctx.Err()}, statusForDone(ctx)
	}
}

// statusForDone is the status for a request whose context ended while it was
// waiting for the user.
func statusForDone(ctx context.Context) byte {
	if errors.Is(ctx.Err(), context.Canceled) {
		log.Print("verifier: request cancelled by host")
		return ctap2.StatusKeepaliveCancel
	}
	return ctap2.StatusUserActionTimeout
}

// handleCtap2 dispatches incoming CTAP2 (CmdCbor) events.
func (s *server) handleCtap2(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	if len(evt.RawCbor) == 0 {
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	cmd, payload := evt.RawCbor[0], evt.RawCbor[1:]
	if cmd != ctap2.CmdGetNextAssertion {
		// Any other command ends a GetAssertion's credential iteration.
		s.nextAssertions = nil
	}
	if cmd != ctap2.CmdCredentialManagement && cmd != ctap2.CmdCredentialManagementPreview {
		s.credMgmtIter = nil
	}
	switch cmd {
	case ctap2.CmdGetInfo:
		s.handleGetInfo(ctx, token, evt)
	case ctap2.CmdMakeCredential:
		s.handleMakeCredential(ctx, token, evt, payload)
	case ctap2.CmdGetAssertion:
		s.handleGetAssertion(ctx, token, evt, payload)
	case ctap2.CmdGetNextAssertion:
		s.handleGetNextAssertion(ctx, token, evt)
	case ctap2.CmdClientPIN:
		s.handleClientPIN(ctx, token, evt, payload)
	case ctap2.CmdReset:
		s.handleReset(ctx, token, evt)
	case ctap2.CmdSelection:
		s.handleSelection(ctx, token, evt)
	case ctap2.CmdCredentialManagement, ctap2.CmdCredentialManagementPreview:
		s.handleCredentialManagement(ctx, token, evt, payload)
	default:
		log.Printf("unsupported CTAP2 cmd 0x%02x", cmd)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCommand, nil)
	}
}

// maxCredentialCountInList is the most allowList/excludeList entries the
// platform should send in one request. Each entry costs a TPM key load.
const maxCredentialCountInList = 16

// handleGetInfo returns CTAP2 authenticator capabilities.
// The UV option is honest: true only when using fprintd (actual identity verification).
func (s *server) handleGetInfo(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd GetInfo")

	options := map[string]bool{
		"rk": true,
		"up": true,
		"uv": s.verifier.PerformsUV(),
		// authenticatorCredentialManagement; it needs a pinUvAuthToken.
		"credMgmt":              true,
		"credentialMgmtPreview": true,
		// Platforms get a pinUvAuthToken via the fingerprint or the PIN.
		"pinUvAuthToken":   true,
		"clientPin":        s.pin.isSet(),
		"makeCredUvNotRqd": true,
	}

	response := map[int]interface{}{
		1:  []string{"FIDO_2_0", "FIDO_2_1", "U2F_V2"},
		2:  s.supportedExtensions(),
		3:  make([]byte, 16), // AAGUID: 16 zero bytes (uncertified)
		4:  options,
		5:  1200, // maxMsgSize
		7:  maxCredentialCountInList,
		8:  tpm.MaxKeyHandleLength + credIDHeaderLen, // maxCredentialIdLength; memory backend IDs are shorter
		9:  []string{"usb"},
		6:  pinuv.Supported,
		10: []map[string]interface{}{{"type": "public-key", "alg": -7}},
		12: false,        // forcePINChange
		13: minPINLength, // in Unicode code points
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

	userAuth := userAuthRequest{
		verify: VerifyRequest{
			RPID:            req.RP.ID,
			Prompt:          "FIDO2 Register: " + req.RP.ID,
			Action:          ActionRegister,
			UserName:        req.User.Name,
			UserDisplayName: req.User.DisplayName,
		},
		permission:     protocol.PermissionMakeCredential,
		clientDataHash: req.ClientDataHash,
		pinUvAuthParam: req.PinUvAuthParam,
		protocol:       req.PinUvAuthProtocol,
		wantUP:         true,
		wantUV:         req.Options != nil && req.Options.UV,
		discoverable:   req.Options != nil && req.Options.RK,
	}
	tokenFlags, status := s.checkPinUvAuthParam(ctx, evt, userAuth)
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
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

	// Creating a credential always requires user presence (CTAP 2.1 §6.1.2 step 5).
	if req.Options != nil && req.Options.UP != nil && !*req.Options.UP {
		log.Print("MakeCredential: up=false is not allowed")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if req.Options != nil && req.Options.UV && !s.verifier.PerformsUV() {
		log.Print("MakeCredential: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	exts, status := s.parseMakeCredExtensions(req.Extensions)
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}
	defer exts.hmacSecretMC.clear()

	rpIdHash := sha256.Sum256([]byte(req.RP.ID))

	// Per spec §6.1: user presence MUST be obtained before checking excludeList.
	// Checking after UP prevents timing attacks that reveal credential existence
	// without user consent.
	userFlags, status := s.authorizeUser(ctx, evt, userAuth, tokenFlags)
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}

	// Check excludeList after UP: if a credential already exists for this RP, reject.
	if len(req.ExcludeList) > 0 {
		for _, cred := range req.ExcludeList {
			if s.credentialExists(cred.ID, rpIdHash[:]) {
				log.Printf("MakeCredential: credential already exists for rp=%s", req.RP.ID)
				token.WriteCtap2Response(ctx, evt, ctap2.StatusCredentialExcluded, nil)
				return
			}
		}
	}

	keyHandle, x, y, err := s.newCredential(rpIdHash[:], exts.opts)
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
	// UV flag is set only when the user's identity was actually verified.
	authFlags := userFlags | ctap2.AuthFlagAT
	extBytes, err := s.makeCredExtensionOutputs(exts, keyHandle, rpIdHash[:], userFlags&ctap2.AuthFlagUV != 0)
	if err != nil {
		log.Printf("MakeCredential extensions err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOther, nil)
		return
	}
	if extBytes != nil {
		authFlags |= ctap2.AuthFlagED
	}

	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())
	authDataBuf.Write(make([]byte, 16)) // AAGUID: 16 zero bytes
	binary.Write(&authDataBuf, binary.BigEndian, uint16(len(keyHandle)))
	authDataBuf.Write(keyHandle)
	authDataBuf.Write(coseKeyBytes)
	authDataBuf.Write(extBytes)
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
			CredProtect: exts.opts.credProtect,
			PublicKey:   coseKeyBytes,
			Created:     time.Now().UTC().Truncate(time.Second),
		})
		if err != nil {
			log.Printf("MakeCredential credstore save err: %s", err)
		}
	}

	log.Printf("MakeCredential ok: rp=%s keyHandle=%d bytes", req.RP.ID, len(keyHandle))
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// getNextAssertionTimeout is how long the remaining credentials of a
// GetAssertion stay available to authenticatorGetNextAssertion (CTAP 2.1 §6.3).
const getNextAssertionTimeout = 30 * time.Second

// pendingAssertions holds the credentials a GetAssertion matched beyond the
// first, for the platform to fetch with authenticatorGetNextAssertion.
type pendingAssertions struct {
	creds          []ctap2.StoredCredential
	rpIdHash       [32]byte
	clientDataHash []byte
	flags          byte
	hmacSecret     *hmacSecretRequest
	expires        time.Time
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

	wantUV := req.Options != nil && req.Options.UV
	// up defaults to true; platforms send up=false to probe for credentials
	// without bothering the user (CTAP 2.1 §6.2.2 step 5).
	wantUP := req.Options == nil || req.Options.UP == nil || *req.Options.UP

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if wantUV && !s.verifier.PerformsUV() {
		log.Print("GetAssertion: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	userAuth := userAuthRequest{
		verify:         VerifyRequest{RPID: req.RPID, Prompt: "FIDO2 Authenticate: " + req.RPID, Action: ActionSignIn},
		permission:     protocol.PermissionGetAssertion,
		clientDataHash: req.ClientDataHash,
		pinUvAuthParam: req.PinUvAuthParam,
		protocol:       req.PinUvAuthProtocol,
		wantUP:         wantUP,
		wantUV:         wantUV,
	}
	tokenFlags, status := s.checkPinUvAuthParam(ctx, evt, userAuth)
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}

	rpIdHash := sha256.Sum256([]byte(req.RPID))
	expectUV := s.expectUV(userAuth, tokenFlags)

	// Resolve credentials: allowList takes priority over resident credentials.
	var creds []ctap2.StoredCredential
	if len(req.AllowList) > 0 {
		// Validate the key handle before prompting the user.
		for _, cred := range req.AllowList {
			c := ctap2.StoredCredential{CredID: cred.ID}
			if credentialUsable(c, true, expectUV) && s.credentialExists(cred.ID, rpIdHash[:]) {
				creds = []ctap2.StoredCredential{c}
				break
			}
		}
		if creds == nil {
			log.Printf("GetAssertion: no valid key handle in allowList for rp=%s", req.RPID)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
			return
		}
	} else {
		var err error
		creds, err = s.cs.FindByRPID(rpIdHash[:])
		if err != nil {
			log.Printf("GetAssertion credstore err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		creds = usableCredentials(creds, false, expectUV)
		if len(creds) == 0 {
			log.Printf("GetAssertion: no credentials for rp=%s", req.RPID)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
			return
		}
	}

	var hmacSecretIn *protocol.HMACSecret
	if req.Extensions != nil {
		hmacSecretIn = req.Extensions.HmacSecret
	}
	hmacSecret, status := s.parseHmacSecret(hmacSecretIn)
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}

	// authenticatorData flags: UP only when the user was actually asked, UV
	// only when the user's identity was actually verified.
	if len(req.AllowList) == 0 && len(creds) == 1 {
		// One resident credential: we know whose passkey this is.
		userAuth.verify.UserName, userAuth.verify.UserDisplayName = creds[0].UserName, creds[0].DisplayName
	}
	authFlags, status := s.authorizeUser(ctx, evt, userAuth, tokenFlags)
	if status != ctap2.StatusOK {
		hmacSecret.clear()
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}
	if creds = usableCredentials(creds, len(req.AllowList) > 0, authFlags&ctap2.AuthFlagUV != 0); len(creds) == 0 {
		// Only if the verifier did not verify after all.
		hmacSecret.clear()
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
		return
	}

	numberOfCredentials := 0
	if len(req.AllowList) == 0 && len(creds) > 1 {
		numberOfCredentials = len(creds)
		s.nextAssertions = &pendingAssertions{
			creds:          creds[1:],
			rpIdHash:       rpIdHash,
			clientDataHash: req.ClientDataHash,
			flags:          authFlags,
			hmacSecret:     hmacSecret,
			expires:        time.Now().Add(getNextAssertionTimeout),
		}
	} else {
		defer hmacSecret.clear()
	}

	encoded, err := s.signAssertion(creds[0], rpIdHash, authFlags, req.ClientDataHash, numberOfCredentials, hmacSecret)
	if err != nil {
		log.Printf("GetAssertion err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	log.Printf("GetAssertion ok: rp=%s credentials=%d", req.RPID, len(creds))
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleGetNextAssertion implements CTAP2 authenticatorGetNextAssertion: it
// returns the next credential matched by the preceding GetAssertion, signed
// over the same clientDataHash with the same flags.
func (s *server) handleGetNextAssertion(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd GetNextAssertion")

	next := s.nextAssertions
	if next == nil || len(next.creds) == 0 || time.Now().After(next.expires) {
		if next != nil {
			next.hmacSecret.clear()
		}
		s.nextAssertions = nil
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNotAllowed, nil)
		return
	}
	cred := next.creds[0]
	next.creds = next.creds[1:]
	if len(next.creds) == 0 {
		s.nextAssertions = nil
		defer next.hmacSecret.clear()
	}

	encoded, err := s.signAssertion(cred, next.rpIdHash, next.flags, next.clientDataHash, 0, next.hmacSecret)
	if err != nil {
		log.Printf("GetNextAssertion err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// signAssertion builds an authenticatorGetAssertion response for cred. A
// resident credential (one with a UserID) includes the user entity; its name
// and displayName only when the user was verified (CTAP 2.1 §6.2.2 step 12).
func (s *server) signAssertion(cred ctap2.StoredCredential, rpIdHash [32]byte, flags byte, clientDataHash []byte, numberOfCredentials int, hmacSecret *hmacSecretRequest) ([]byte, error) {
	extBytes, err := s.assertionExtensionOutputs(cred, rpIdHash[:], flags&ctap2.AuthFlagUV != 0, hmacSecret)
	if err != nil {
		return nil, err
	}
	authDataFlags := flags
	if extBytes != nil {
		authDataFlags |= ctap2.AuthFlagED
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | extensions
	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authDataFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())
	authDataBuf.Write(extBytes)
	authDataBytes := authDataBuf.Bytes()

	// Sign sha256(authData || clientDataHash) per WebAuthn §7.2.
	toSign := make([]byte, len(authDataBytes)+len(clientDataHash))
	copy(toSign, authDataBytes)
	copy(toSign[len(authDataBytes):], clientDataHash)
	digest := sha256.Sum256(toSign)

	sig, err := s.signWithCredential(cred.CredID, rpIdHash[:], digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	response := map[int]interface{}{
		1: map[string]interface{}{"type": "public-key", "id": cred.CredID},
		2: authDataBytes,
		3: sig,
	}
	if cred.UserID != nil {
		user := map[string]interface{}{"id": cred.UserID}
		if flags&ctap2.AuthFlagUV != 0 {
			user["name"] = cred.UserName
			user["displayName"] = cred.DisplayName
		}
		response[4] = user
	}
	if numberOfCredentials > 0 {
		response[5] = numberOfCredentials
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return encoded, nil
}

// handleSelection implements CTAP2 authenticatorSelection: the platform asks
// every connected authenticator for user presence to let the user pick one.
func (s *server) handleSelection(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd Selection")
	token.WriteCtap2Response(ctx, evt, s.awaitUser(ctx, evt, VerifyRequest{Prompt: "FIDO2: select linux-id", Action: ActionSelect}), nil)
}
