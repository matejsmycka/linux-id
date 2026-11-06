package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/pinuv"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
)

// residentCredentialCapacity is the number of discoverable credentials
// getCredsMetadata reports room for. The store is a file and has no hard
// limit; this keeps the reported remaining count meaningful.
const residentCredentialCapacity = 1000

// credMgmtIterationTimeout is how long an enumeration's remaining items stay
// available to the getNext subcommands.
const credMgmtIterationTimeout = 30 * time.Second

// credMgmtRequest is authenticatorCredentialManagement's request. It keeps
// subCommandParams as received, because pinUvAuthParam authenticates their
// exact encoding.
type credMgmtRequest struct {
	SubCommand        protocol.CredentialManagementSubCommand `cbor:"1,keyasint"`
	SubCommandParams  cbor.RawMessage                         `cbor:"2,keyasint,omitempty"`
	PinUvAuthProtocol protocol.PinUvAuthProtocol              `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                                  `cbor:"4,keyasint,omitempty"`
}

// credMgmtIteration is the state of an enumerateRPs or enumerateCredentials
// in progress: the items not yet returned.
type credMgmtIteration struct {
	next    protocol.CredentialManagementSubCommand // the getNext subcommand it serves
	rps     []ctap2.RelyingParty
	creds   []ctap2.StoredCredential
	expires time.Time
}

// handleCredentialManagement implements authenticatorCredentialManagement
// (CTAP 2.1 §6.8) and its CTAP 2.1-PRE alias credentialMgmtPreview.
func (s *server) handleCredentialManagement(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	var req credMgmtRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("CredentialManagement decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	log.Printf("got Ctap2Cmd CredentialManagement subcommand %d", req.SubCommand)

	resp, status := s.credentialManagement(req)
	if status != ctap2.StatusOK || resp == nil {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}
	encoded, err := ctap2Enc.Marshal(resp)
	if err != nil {
		log.Printf("CredentialManagement marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOther, nil)
		return
	}
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// credentialManagement runs one subcommand. A nil response with StatusOK is
// an empty success reply.
func (s *server) credentialManagement(req credMgmtRequest) (*protocol.AuthenticatorCredentialManagementResponse, byte) {
	// Every subcommand other than the matching getNext ends an enumeration.
	iter := s.credMgmtIter
	s.credMgmtIter = nil

	switch req.SubCommand {
	case protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
		protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential:
		return s.credMgmtGetNext(iter, req.SubCommand)
	case protocol.CredentialManagementSubCommandGetCredsMetadata,
		protocol.CredentialManagementSubCommandEnumerateRPsBegin,
		protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
		protocol.CredentialManagementSubCommandDeleteCredential,
		protocol.CredentialManagementSubCommandUpdateUserInformation:
	default:
		return nil, ctap2.StatusInvalidSubcommand
	}

	if status := s.checkCredMgmtAuth(req); status != ctap2.StatusOK {
		return nil, status
	}
	var params protocol.CredentialManagementSubCommandParams
	if len(req.SubCommandParams) > 0 {
		if err := cbor.Unmarshal(req.SubCommandParams, &params); err != nil {
			log.Printf("CredentialManagement params decode err: %s", err)
			return nil, ctap2.StatusInvalidCbor
		}
	}
	// A token whose permissions are bound to an RP may only manage that
	// RP's credentials (§6.8.2–§6.8.6).
	boundRP := s.pinuv.BoundRPID()

	switch req.SubCommand {
	case protocol.CredentialManagementSubCommandGetCredsMetadata:
		if boundRP != "" {
			return nil, ctap2.StatusPinAuthInvalid
		}
		creds, err := s.cs.List()
		if err != nil {
			log.Printf("CredentialManagement credstore err: %s", err)
			return nil, ctap2.StatusOther
		}
		existing := uint(len(creds))
		remaining := uint(max(0, residentCredentialCapacity-len(creds)))
		return &protocol.AuthenticatorCredentialManagementResponse{
			ExistingResidentCredentialsCount:             &existing,
			MaxPossibleRemainingResidentCredentialsCount: &remaining,
		}, ctap2.StatusOK

	case protocol.CredentialManagementSubCommandEnumerateRPsBegin:
		if boundRP != "" {
			return nil, ctap2.StatusPinAuthInvalid
		}
		rps, err := s.cs.RPs()
		if err != nil {
			log.Printf("CredentialManagement credstore err: %s", err)
			return nil, ctap2.StatusOther
		}
		if len(rps) == 0 {
			return nil, ctap2.StatusNoCredentials
		}
		if len(rps) > 1 {
			s.credMgmtIter = &credMgmtIteration{
				next:    protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
				rps:     rps[1:],
				expires: time.Now().Add(credMgmtIterationTimeout),
			}
		}
		resp := rpResponse(rps[0])
		resp.TotalRPs = uint(len(rps))
		return resp, ctap2.StatusOK

	case protocol.CredentialManagementSubCommandEnumerateCredentialsBegin:
		if len(params.RPIDHash) == 0 {
			return nil, ctap2.StatusMissingParameter
		}
		if boundRP != "" {
			h := sha256.Sum256([]byte(boundRP))
			if !bytes.Equal(h[:], params.RPIDHash) {
				return nil, ctap2.StatusPinAuthInvalid
			}
		}
		creds, err := s.cs.FindByRPID(params.RPIDHash)
		if err != nil {
			log.Printf("CredentialManagement credstore err: %s", err)
			return nil, ctap2.StatusOther
		}
		if len(creds) == 0 {
			return nil, ctap2.StatusNoCredentials
		}
		if len(creds) > 1 {
			s.credMgmtIter = &credMgmtIteration{
				next:    protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
				creds:   creds[1:],
				expires: time.Now().Add(credMgmtIterationTimeout),
			}
		}
		resp := s.credentialResponse(creds[0])
		resp.TotalCredentials = uint(len(creds))
		return resp, ctap2.StatusOK

	case protocol.CredentialManagementSubCommandDeleteCredential:
		cred, status := s.credMgmtTarget(params, boundRP)
		if status != ctap2.StatusOK {
			return nil, status
		}
		if _, err := s.cs.Delete(cred.CredID); err != nil {
			if errors.Is(err, ctap2.ErrCredentialNotFound) {
				return nil, ctap2.StatusNoCredentials
			}
			log.Printf("CredentialManagement delete err: %s", err)
			return nil, ctap2.StatusOther
		}
		log.Printf("CredentialManagement: deleted a credential for rp=%s", cred.RPID)
		return nil, ctap2.StatusOK

	case protocol.CredentialManagementSubCommandUpdateUserInformation:
		if len(params.User.ID) == 0 {
			return nil, ctap2.StatusMissingParameter
		}
		cred, status := s.credMgmtTarget(params, boundRP)
		if status != ctap2.StatusOK {
			return nil, status
		}
		if !bytes.Equal(params.User.ID, cred.UserID) {
			return nil, ctap2.StatusInvalidParameter
		}
		if err := s.cs.UpdateUser(cred.CredID, params.User.Name, params.User.DisplayName); err != nil {
			if errors.Is(err, ctap2.ErrCredentialNotFound) {
				return nil, ctap2.StatusNoCredentials
			}
			log.Printf("CredentialManagement update err: %s", err)
			return nil, ctap2.StatusOther
		}
		return nil, ctap2.StatusOK
	}
	return nil, ctap2.StatusInvalidSubcommand
}

// checkCredMgmtAuth verifies pinUvAuthParam = authenticate(pinUvAuthToken,
// subCommand || subCommandParams) and that the token has the cm permission.
func (s *server) checkCredMgmtAuth(req credMgmtRequest) byte {
	if req.PinUvAuthParam == nil {
		return ctap2.StatusPinRequired
	}
	if req.PinUvAuthProtocol == 0 {
		return ctap2.StatusMissingParameter
	}
	if !pinuv.IsSupported(req.PinUvAuthProtocol) {
		return ctap2.StatusInvalidParameter
	}
	msg := append([]byte{byte(req.SubCommand)}, req.SubCommandParams...)
	if err := s.pinuv.Check(req.PinUvAuthProtocol, req.PinUvAuthParam, msg, protocol.PermissionCredentialManagement, ""); err != nil {
		log.Printf("CredentialManagement pinUvAuthParam rejected: %s", err)
		return ctap2.StatusPinAuthInvalid
	}
	return ctap2.StatusOK
}

// credMgmtTarget finds the credential that deleteCredential or
// updateUserInformation names, and checks that boundRP (if any) is its RP.
func (s *server) credMgmtTarget(params protocol.CredentialManagementSubCommandParams, boundRP string) (ctap2.StoredCredential, byte) {
	if len(params.CredentialID.ID) == 0 {
		return ctap2.StoredCredential{}, ctap2.StatusMissingParameter
	}
	cred, err := s.cs.Find(params.CredentialID.ID)
	if errors.Is(err, ctap2.ErrCredentialNotFound) {
		return cred, ctap2.StatusNoCredentials
	}
	if err != nil {
		log.Printf("CredentialManagement credstore err: %s", err)
		return cred, ctap2.StatusOther
	}
	if boundRP != "" && boundRP != cred.RPID {
		return cred, ctap2.StatusPinAuthInvalid
	}
	return cred, ctap2.StatusOK
}

func (s *server) credMgmtGetNext(iter *credMgmtIteration, sub protocol.CredentialManagementSubCommand) (*protocol.AuthenticatorCredentialManagementResponse, byte) {
	if iter == nil || iter.next != sub || time.Now().After(iter.expires) {
		return nil, ctap2.StatusNotAllowed
	}
	var resp *protocol.AuthenticatorCredentialManagementResponse
	if sub == protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP {
		resp = rpResponse(iter.rps[0])
		iter.rps = iter.rps[1:]
	} else {
		resp = s.credentialResponse(iter.creds[0])
		iter.creds = iter.creds[1:]
	}
	if len(iter.rps)+len(iter.creds) > 0 {
		s.credMgmtIter = iter
	}
	return resp, ctap2.StatusOK
}

func rpResponse(rp ctap2.RelyingParty) *protocol.AuthenticatorCredentialManagementResponse {
	return &protocol.AuthenticatorCredentialManagementResponse{
		RP:       credential.PublicKeyCredentialRpEntity{ID: rp.ID, Name: rp.Name},
		RPIDHash: rp.IDHash,
	}
}

func (s *server) credentialResponse(c ctap2.StoredCredential) *protocol.AuthenticatorCredentialManagementResponse {
	resp := &protocol.AuthenticatorCredentialManagementResponse{
		User: credential.PublicKeyCredentialUserEntity{
			ID:          c.UserID,
			Name:        c.UserName,
			DisplayName: c.DisplayName,
		},
		CredentialID: credential.PublicKeyCredentialDescriptor{Type: "public-key", ID: c.CredID},
		CredProtect:  uint(max(1, c.CredProtect)),
	}
	key, err := s.credentialPublicKey(c)
	if err != nil {
		// Still list the credential, so the user can delete it.
		log.Printf("CredentialManagement: public key of a credential for rp=%s: %s", c.RPID, err)
		return resp
	}
	resp.PublicKey = key
	return resp
}

// publicKeyer is implemented by backends that can recover a key handle's
// public key (both real ones do), for legacy credentials stored without it.
type publicKeyer interface {
	PublicKey(keyHandle, applicationParam []byte) (*big.Int, *big.Int, error)
}

// credentialPublicKey returns the credential's stored COSE public key. A
// legacy credential stored before public keys were recorded gets its key
// derived from the key handle, and recorded.
func (s *server) credentialPublicKey(c ctap2.StoredCredential) (cose.Key, error) {
	encoded := c.PublicKey
	if len(encoded) == 0 {
		pk, ok := s.signer.(publicKeyer)
		if !ok {
			return nil, errors.New("no public key stored")
		}
		keyHandle, appParam, err := s.credKey(c.CredID, c.RPIDHash)
		if err != nil {
			return nil, err
		}
		x, y, err := pk.PublicKey(keyHandle, appParam)
		if err != nil {
			return nil, err
		}
		if encoded, err = coseES256PublicKey(x, y); err != nil {
			return nil, err
		}
		if err := s.cs.SetPublicKey(c.CredID, encoded); err != nil {
			log.Printf("CredentialManagement: record public key: %s", err)
		}
	}
	var key cose.Key
	if err := cbor.Unmarshal(encoded, &key); err != nil {
		return nil, fmt.Errorf("decode stored public key: %w", err)
	}
	return key, nil
}

// coseES256PublicKey encodes a P-256 public key as the COSE_Key that
// MakeCredential reports.
func coseES256PublicKey(x, y *big.Int) ([]byte, error) {
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	return ctap2Enc.Marshal(map[int]interface{}{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: xBytes,
		-3: yBytes,
	})
}
