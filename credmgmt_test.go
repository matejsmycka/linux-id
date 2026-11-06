package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/tpm"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
)

const (
	cmMetadata      = protocol.CredentialManagementSubCommandGetCredsMetadata
	cmRPsBegin      = protocol.CredentialManagementSubCommandEnumerateRPsBegin
	cmNextRP        = protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP
	cmCredsBegin    = protocol.CredentialManagementSubCommandEnumerateCredentialsBegin
	cmNextCred      = protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
	cmDelete        = protocol.CredentialManagementSubCommandDeleteCredential
	cmUpdate        = protocol.CredentialManagementSubCommandUpdateUserInformation
	cmProto         = protocol.PinUvAuthProtocolTwo
	cmPermission    = protocol.PermissionCredentialManagement
	cmTestRPAlpha   = "alpha.example"
	cmTestRPBravo   = "bravo.example"
	cmTestRPCharlie = "charlie.example"
)

type cmClient struct {
	t     *testing.T
	s     *server
	tok   []byte
	proto protocol.PinUvAuthProtocol
	cmd   byte
	// mutate, if set, changes the request before it is sent.
	mutate func(map[int]any)
}

func newCMClient(t *testing.T, s *server, perms protocol.Permission, rpID string) *cmClient {
	t.Helper()
	tok, err := s.pinuv.IssueToken(perms, rpID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return &cmClient{t: t, s: s, tok: tok, proto: cmProto, cmd: ctap2.CmdCredentialManagement}
}

// call sends a subcommand, authenticated like a platform does unless it is
// a getNext, and returns the status and decoded response.
func (c *cmClient) call(sub protocol.CredentialManagementSubCommand, params any) (byte, protocol.AuthenticatorCredentialManagementResponse) {
	c.t.Helper()
	req := map[int]any{1: sub}
	var encParams []byte
	if params != nil {
		var err error
		if encParams, err = ctap2Enc.Marshal(params); err != nil {
			c.t.Fatal(err)
		}
		req[2] = cbor.RawMessage(encParams)
	}
	if sub != cmNextRP && sub != cmNextCred {
		req[3] = c.proto
		req[4] = ctapcrypto.Authenticate(c.proto, c.tok, append([]byte{byte(sub)}, encParams...))
	}
	if c.mutate != nil {
		c.mutate(req)
	}
	payload, err := ctap2Enc.Marshal(req)
	if err != nil {
		c.t.Fatal(err)
	}
	resp := &fakeResponder{}
	c.s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: append([]byte{c.cmd}, payload...)})
	w := resp.lastCtap2()
	var out protocol.AuthenticatorCredentialManagementResponse
	if w.status == ctap2.StatusOK && len(w.data) > 0 {
		if err := cbor.Unmarshal(w.data, &out); err != nil {
			c.t.Fatalf("decode response: %s", err)
		}
	}
	return w.status, out
}

func (c *cmClient) mustCall(sub protocol.CredentialManagementSubCommand, params any) protocol.AuthenticatorCredentialManagementResponse {
	c.t.Helper()
	status, resp := c.call(sub, params)
	if status != ctap2.StatusOK {
		c.t.Fatalf("subcommand %d: status 0x%02x", sub, status)
	}
	return resp
}

func rpHashParams(rpID string) map[int]any {
	h := sha256.Sum256([]byte(rpID))
	return map[int]any{1: h[:]}
}

func credParams(credID []byte) map[int]any {
	return map[int]any{2: map[string]any{"type": "public-key", "id": credID}}
}

// newCMServer registers alice and bob at alpha, carol at bravo.
func newCMServer(t *testing.T) (s *server, alice, bob, carol []byte) {
	t.Helper()
	s = newTestServer(t, &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}, &fakePinentry{})
	alice = registerCred(t, s, cmTestRPAlpha, "Alpha", "alice", true)
	bob = registerCred(t, s, cmTestRPAlpha, "Alpha", "bob", true)
	carol = registerCred(t, s, cmTestRPBravo, "Bravo", "carol", true)
	registerCred(t, s, cmTestRPCharlie, "Charlie", "nonresident", false)
	return s, alice, bob, carol
}

func TestCredMgmt_MetadataAndEnumeration(t *testing.T) {
	s, alice, bob, carol := newCMServer(t)
	c := newCMClient(t, s, cmPermission, "")

	md := c.mustCall(cmMetadata, nil)
	if md.ExistingResidentCredentialsCount == nil || *md.ExistingResidentCredentialsCount != 3 {
		t.Errorf("existing = %v, want 3", md.ExistingResidentCredentialsCount)
	}
	if md.MaxPossibleRemainingResidentCredentialsCount == nil || *md.MaxPossibleRemainingResidentCredentialsCount != residentCredentialCapacity-3 {
		t.Errorf("remaining = %v", md.MaxPossibleRemainingResidentCredentialsCount)
	}

	first := c.mustCall(cmRPsBegin, nil)
	if first.TotalRPs != 2 || first.RP.ID != cmTestRPAlpha || first.RP.Name != "Alpha" {
		t.Errorf("first RP = %+v total %d", first.RP, first.TotalRPs)
	}
	if h := sha256.Sum256([]byte(cmTestRPAlpha)); !bytes.Equal(first.RPIDHash, h[:]) {
		t.Error("rpIDHash mismatch")
	}
	second := c.mustCall(cmNextRP, nil)
	if second.RP.ID != cmTestRPBravo || second.TotalRPs != 0 {
		t.Errorf("second RP = %+v total %d", second.RP, second.TotalRPs)
	}
	if status, _ := c.call(cmNextRP, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("past the last RP: 0x%02x", status)
	}

	cred1 := c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha))
	if cred1.TotalCredentials != 2 {
		t.Errorf("totalCredentials = %d", cred1.TotalCredentials)
	}
	cred2 := c.mustCall(cmNextCred, nil)
	got := map[string][]byte{cred1.User.Name: cred1.CredentialID.ID, cred2.User.Name: cred2.CredentialID.ID}
	if !bytes.Equal(got["alice@"+cmTestRPAlpha], alice) || !bytes.Equal(got["bob@"+cmTestRPAlpha], bob) {
		t.Errorf("credentials = %v", got)
	}
	for _, cr := range []protocol.AuthenticatorCredentialManagementResponse{cred1, cred2} {
		if cr.CredentialID.Type != "public-key" || cr.CredProtect != 1 || cr.User.DisplayName == "" || len(cr.User.ID) == 0 {
			t.Errorf("credential response = %+v", cr)
		}
		pub := s.signer.(*fakeSigner).keys[string(keyHandleOf(t, cr.CredentialID.ID))].priv.PublicKey
		key, err := cr.PublicKey.PublicKey()
		if err != nil {
			t.Fatalf("publicKey: %s", err)
		}
		if !key.(*ecdsa.PublicKey).Equal(&pub) {
			t.Error("publicKey does not match the credential's key")
		}
	}
	if status, _ := c.call(cmNextCred, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("past the last credential: 0x%02x", status)
	}

	one := c.mustCall(cmCredsBegin, rpHashParams(cmTestRPBravo))
	if one.TotalCredentials != 1 || !bytes.Equal(one.CredentialID.ID, carol) {
		t.Errorf("bravo = %+v", one)
	}
	if status, _ := c.call(cmCredsBegin, rpHashParams(cmTestRPCharlie)); status != ctap2.StatusNoCredentials {
		t.Errorf("RP without resident credentials: 0x%02x", status)
	}
	if status, _ := c.call(cmCredsBegin, map[int]any{}); status != ctap2.StatusMissingParameter {
		t.Errorf("no rpIDHash: 0x%02x", status)
	}
}

func TestCredMgmt_EmptyStore(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	c := newCMClient(t, s, cmPermission, "")
	md := c.mustCall(cmMetadata, nil)
	if md.ExistingResidentCredentialsCount == nil || *md.ExistingResidentCredentialsCount != 0 {
		t.Errorf("existing = %v, want an explicit 0", md.ExistingResidentCredentialsCount)
	}
	if status, _ := c.call(cmRPsBegin, nil); status != ctap2.StatusNoCredentials {
		t.Errorf("enumerateRPsBegin: 0x%02x", status)
	}
}

func TestCredMgmt_PreviewCommand(t *testing.T) {
	s, _, _, _ := newCMServer(t)
	c := newCMClient(t, s, cmPermission, "")
	c.cmd = ctap2.CmdCredentialManagementPreview
	c.proto = protocol.PinUvAuthProtocolOne
	if r := c.mustCall(cmRPsBegin, nil); r.TotalRPs != 2 {
		t.Errorf("totalRPs = %d", r.TotalRPs)
	}
	c.mustCall(cmNextRP, nil)
}

func TestCredMgmt_DeleteCredential(t *testing.T) {
	s, alice, bob, _ := newCMServer(t)
	c := newCMClient(t, s, cmPermission, "")

	c.mustCall(cmDelete, credParams(alice))
	if r := c.mustCall(cmMetadata, nil); *r.ExistingResidentCredentialsCount != 2 {
		t.Errorf("existing after delete = %d", *r.ExistingResidentCredentialsCount)
	}
	r := c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha))
	if r.TotalCredentials != 1 || !bytes.Equal(r.CredentialID.ID, bob) {
		t.Errorf("alpha after delete = %+v", r)
	}
	if status, _ := c.call(cmDelete, credParams(alice)); status != ctap2.StatusNoCredentials {
		t.Errorf("deleting twice: 0x%02x", status)
	}
	if status, _ := c.call(cmDelete, map[int]any{}); status != ctap2.StatusMissingParameter {
		t.Errorf("no credentialID: 0x%02x", status)
	}

	// The deleted credential no longer signs, even from an allowList.
	resp := &fakeResponder{}
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{},
		makeAssertionCBOR(t, cmTestRPAlpha, []ctap2.CredDescriptor{{Type: "public-key", ID: alice}}, nil))
	if resp.lastCtap2().status != ctap2.StatusNoCredentials {
		t.Errorf("assertion with deleted credential: 0x%02x", resp.lastCtap2().status)
	}
	resp = &fakeResponder{}
	s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{},
		makeAssertionCBOR(t, cmTestRPAlpha, []ctap2.CredDescriptor{{Type: "public-key", ID: bob}}, nil))
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Errorf("assertion with remaining credential: 0x%02x", resp.lastCtap2().status)
	}
}

func TestCredMgmt_UpdateUserInformation(t *testing.T) {
	s, alice, _, _ := newCMServer(t)
	c := newCMClient(t, s, cmPermission, "")

	params := credParams(alice)
	params[3] = map[string]any{"id": []byte("alice"), "name": "alice.renamed"}
	c.mustCall(cmUpdate, params)
	cred, err := s.cs.Find(alice)
	if err != nil {
		t.Fatal(err)
	}
	if cred.UserName != "alice.renamed" || cred.DisplayName != "" {
		t.Errorf("after update: name %q displayName %q (absent displayName must be removed)", cred.UserName, cred.DisplayName)
	}

	params[3] = map[string]any{"id": []byte("mallory"), "name": "x"}
	if status, _ := c.call(cmUpdate, params); status != ctap2.StatusInvalidParameter {
		t.Errorf("mismatched user.id: 0x%02x", status)
	}
	if status, _ := c.call(cmUpdate, credParams(alice)); status != ctap2.StatusMissingParameter {
		t.Errorf("no user: 0x%02x", status)
	}
	params = credParams([]byte("nope"))
	params[3] = map[string]any{"id": []byte("alice")}
	if status, _ := c.call(cmUpdate, params); status != ctap2.StatusNoCredentials {
		t.Errorf("unknown credential: 0x%02x", status)
	}
}

func TestCredMgmt_AuthorizationFailures(t *testing.T) {
	s, alice, _, carol := newCMServer(t)

	t.Run("no pinUvAuthParam", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		c.mutate = func(m map[int]any) { delete(m, 3); delete(m, 4) }
		if status, _ := c.call(cmMetadata, nil); status != ctap2.StatusPinRequired {
			t.Errorf("0x%02x, want PUAT_REQUIRED", status)
		}
	})
	t.Run("no protocol", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		c.mutate = func(m map[int]any) { delete(m, 3) }
		if status, _ := c.call(cmMetadata, nil); status != ctap2.StatusMissingParameter {
			t.Errorf("0x%02x", status)
		}
	})
	t.Run("unsupported protocol", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		c.mutate = func(m map[int]any) { m[3] = 7 }
		if status, _ := c.call(cmMetadata, nil); status != ctap2.StatusInvalidParameter {
			t.Errorf("0x%02x", status)
		}
	})
	t.Run("bad param", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		c.mutate = func(m map[int]any) { m[4] = make([]byte, 32) }
		if status, _ := c.call(cmRPsBegin, nil); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("0x%02x", status)
		}
	})
	t.Run("param over other params", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		other := rpHashParams(cmTestRPBravo)
		c.mutate = func(m map[int]any) {
			enc, _ := ctap2Enc.Marshal(other)
			m[2] = cbor.RawMessage(enc)
		}
		if status, _ := c.call(cmCredsBegin, rpHashParams(cmTestRPAlpha)); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("0x%02x", status)
		}
	})
	t.Run("old token", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		newCMClient(t, s, cmPermission, "")
		if status, _ := c.call(cmMetadata, nil); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("0x%02x", status)
		}
	})
	t.Run("wrong permission", func(t *testing.T) {
		c := newCMClient(t, s, protocol.PermissionGetAssertion|protocol.PermissionMakeCredential, cmTestRPAlpha)
		if status, _ := c.call(cmMetadata, nil); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("metadata: 0x%02x", status)
		}
		if status, _ := c.call(cmDelete, credParams(alice)); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("delete: 0x%02x", status)
		}
	})
	t.Run("RP-bound token", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, cmTestRPAlpha)
		for _, sub := range []protocol.CredentialManagementSubCommand{cmMetadata, cmRPsBegin} {
			if status, _ := c.call(sub, nil); status != ctap2.StatusPinAuthInvalid {
				t.Errorf("subcommand %d with RP-bound token: 0x%02x", sub, status)
			}
		}
		if status, _ := c.call(cmCredsBegin, rpHashParams(cmTestRPBravo)); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("enumerate other RP: 0x%02x", status)
		}
		if r := c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha)); r.TotalCredentials != 2 {
			t.Errorf("enumerate own RP: %d", r.TotalCredentials)
		}
		update := credParams(carol)
		update[3] = map[string]any{"id": []byte("carol"), "name": "x"}
		if status, _ := c.call(cmUpdate, update); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("update other RP: 0x%02x", status)
		}
		if status, _ := c.call(cmDelete, credParams(carol)); status != ctap2.StatusPinAuthInvalid {
			t.Errorf("delete other RP: 0x%02x", status)
		}
		c.mustCall(cmDelete, credParams(alice))
	})
	if _, err := s.cs.Find(carol); err != nil {
		t.Errorf("carol was deleted: %v", err)
	}
	t.Run("unknown subcommand", func(t *testing.T) {
		c := newCMClient(t, s, cmPermission, "")
		if status, _ := c.call(0x42, nil); status != ctap2.StatusInvalidSubcommand {
			t.Errorf("0x%02x", status)
		}
	})
}

func TestCredMgmt_IterationEndedByOtherCommands(t *testing.T) {
	s, _, _, _ := newCMServer(t)
	c := newCMClient(t, s, cmPermission, "")

	c.mustCall(cmRPsBegin, nil)
	resp := &fakeResponder{}
	s.handleCtap2(context.Background(), resp, fidohid.AuthEvent{RawCbor: []byte{ctap2.CmdGetInfo}})
	if status, _ := c.call(cmNextRP, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("getNextRP after GetInfo: 0x%02x", status)
	}

	c.mustCall(cmRPsBegin, nil)
	c.mustCall(cmMetadata, nil)
	if status, _ := c.call(cmNextRP, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("getNextRP after getCredsMetadata: 0x%02x", status)
	}

	c.mustCall(cmRPsBegin, nil)
	if status, _ := c.call(cmNextCred, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("getNextCredential during RP enumeration: 0x%02x", status)
	}
	if status, _ := c.call(cmNextRP, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("the wrong getNext must end the enumeration: 0x%02x", status)
	}

	c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha))
	if status, _ := c.call(cmNextRP, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("getNextRP during credential enumeration: 0x%02x", status)
	}
	c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha))
	c.mustCall(cmNextCred, nil)

	if status, _ := c.call(cmNextCred, nil); status != ctap2.StatusNotAllowed {
		t.Errorf("getNext without an enumeration: 0x%02x", status)
	}
}

// coseKeyOf extracts the credential public key from a MakeCredential
// response's attested credential data.
func coseKeyOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	var top map[int]cbor.RawMessage
	if err := cbor.Unmarshal(payload, &top); err != nil {
		t.Fatal(err)
	}
	var authData []byte
	if err := cbor.Unmarshal(top[2], &authData); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(authData[32+1+4+16:]))
	return authData[32+1+4+16+2+n:]
}

func TestCredMgmt_StoresPublicKeyAndCreated(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true, nextResult: VerifyResult{OK: true}}, &fakePinentry{})
	resp := &fakeResponder{}
	s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, makeMakeCredCBOR(t, cmTestRPAlpha, "Alpha", "alice", true, false))
	if resp.lastCtap2().status != ctap2.StatusOK {
		t.Fatal(resp.lastCtap2().status)
	}
	cred, err := s.cs.Find(extractCredID(t, resp.lastCtap2().data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cred.PublicKey, coseKeyOf(t, resp.lastCtap2().data)) {
		t.Error("stored public key differs from the attested one")
	}
	if cred.Created.IsZero() {
		t.Error("created time not recorded")
	}
}

// A credential whose key cannot be loaded is still listed, without a public
// key, so that it can be deleted.
func TestCredMgmt_UnloadableKeyStillListed(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	h := sha256.Sum256([]byte(cmTestRPAlpha))
	if err := s.cs.Save(ctap2.StoredCredential{CredID: []byte("gone"), RPIDHash: h[:], RPID: cmTestRPAlpha, UserID: []byte("u")}); err != nil {
		t.Fatal(err)
	}
	c := newCMClient(t, s, cmPermission, "")
	r := c.mustCall(cmCredsBegin, rpHashParams(cmTestRPAlpha))
	if !bytes.Equal(r.CredentialID.ID, []byte("gone")) || r.PublicKey != nil {
		t.Errorf("response = %+v", r)
	}
	c.mustCall(cmDelete, credParams([]byte("gone")))
}

func TestGetInfo_CredMgmt(t *testing.T) {
	s := newTestServer(t, &fakeVerifier{performsUV: true}, &fakePinentry{})
	resp := &fakeResponder{}
	s.handleGetInfo(context.Background(), resp, fidohid.AuthEvent{})
	var info protocol.AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(resp.lastCtap2().data, &info); err != nil {
		t.Fatal(err)
	}
	if !info.Options[protocol.OptionCredentialManagement] || !info.Options[protocol.OptionCredentialManagementPreview] {
		t.Errorf("options = %v", info.Options)
	}
	if info.MaxCredentialIdLength != uint(tpm.MaxKeyHandleLength+credIDHeaderLen) {
		t.Errorf("maxCredentialIdLength = %d", info.MaxCredentialIdLength)
	}
}

func TestCredStore_LoadsLegacyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	legacy := `[{"credId":"AQI=","rpIdHash":"AwQ=","rpId":"old.example","rpName":"Old","userId":"BQ==","userName":"u","displayName":"U"}]`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	cs := ctap2.NewCredStoreAt(path)
	creds, err := cs.List()
	if err != nil || len(creds) != 1 || creds[0].RPID != "old.example" || creds[0].CredProtect != 0 {
		t.Fatalf("List = %+v, %v", creds, err)
	}
	if err := cs.UpdateUser([]byte{1, 2}, "v", "V"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, absent := range []string{"publicKey", "credProtect", "created"} {
		if strings.Contains(string(data), absent) {
			t.Errorf("rewritten legacy file gained empty %q: %s", absent, data)
		}
	}
}

// The daemon and the CLI write the same file through separate CredStores;
// the lock keeps every concurrent write.
func TestCredStore_ConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	var wg sync.WaitGroup
	const n = 20
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cs := ctap2.NewCredStoreAt(path)
			h := sha256.Sum256([]byte("rp"))
			if err := cs.Save(ctap2.StoredCredential{CredID: []byte{byte(i)}, RPIDHash: h[:], UserID: []byte{byte(i)}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	creds, err := ctap2.NewCredStoreAt(path).List()
	if err != nil || len(creds) != n {
		t.Fatalf("%d credentials after %d concurrent saves (%v)", len(creds), n, err)
	}
}

func TestCredStore_FindByRPIDNewestFirstAfterUpdate(t *testing.T) {
	cs := ctap2.NewCredStoreAt(filepath.Join(t.TempDir(), "creds.json"))
	h := sha256.Sum256([]byte("rp"))
	for _, id := range []string{"old", "mid", "new"} {
		cs.Save(ctap2.StoredCredential{CredID: []byte(id), RPIDHash: h[:], UserID: []byte(id)})
	}
	cs.UpdateUser([]byte("old"), "renamed", "")
	cs.Delete([]byte("mid"))
	creds, _ := cs.FindByRPID(h[:])
	if len(creds) != 2 || string(creds[0].CredID) != "new" || string(creds[1].CredID) != "old" {
		t.Errorf("order after update/delete: %q, %q", creds[0].CredID, creds[1].CredID)
	}
	if revoked, err := cs.Revoked([]byte("mid")); !revoked || err != nil {
		t.Errorf("deleted credential not revoked: %v %v", revoked, err)
	}
	if revoked, _ := cs.Revoked([]byte("new")); revoked {
		t.Error("live credential revoked")
	}
}

// keyHandleOf returns the backend key handle inside credential ID credID.
func keyHandleOf(t *testing.T, credID []byte) []byte {
	t.Helper()
	p, err := parseCredID(credID)
	if err != nil {
		t.Fatal(err)
	}
	return p.keyHandle
}
