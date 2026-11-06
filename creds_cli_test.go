package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matejsmycka/linux-id/ctap2"
)

func newCLIStore(t *testing.T) *ctap2.CredStore {
	t.Helper()
	cs := ctap2.NewCredStoreAt(filepath.Join(t.TempDir(), "creds.json"))
	add := func(rp, user string, id []byte, created time.Time) {
		h := sha256.Sum256([]byte(rp))
		if err := cs.Save(ctap2.StoredCredential{
			CredID: id, RPIDHash: h[:], RPID: rp, UserID: []byte(user),
			UserName: user + "@" + rp, DisplayName: strings.ToUpper(user) + "\x1b[31m", Created: created,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// TPM credential IDs share their first bytes.
	add("github.com", "alice", []byte("TPM\x7e\x00\x7c\x00\x20one"), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	add("github.com", "bob", []byte("TPM\x7e\x00\x7c\x00\x20two"), time.Time{})
	add("example.org", "carol", []byte("TPM\x7e\x00\x7c\x00\x20three"), time.Time{})
	return cs
}

func runCLI(t *testing.T, cs *ctap2.CredStore, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := credsCLI{cs: cs, stdin: strings.NewReader(stdin), stdout: &out, stderr: &errOut}.run(args)
	return code, out.String(), errOut.String()
}

func TestCredsCLI_List(t *testing.T) {
	cs := newCLIStore(t)
	code, out, _ := runCLI(t, cs, "", "list")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"github.com", "example.org", "alice@github.com", "ALICE?[31m", "2026-01-0", shortID([]byte("TPM\x7e\x00\x7c\x00\x20two"))} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("list printed a terminal escape from a user name")
	}

	code, out, _ = runCLI(t, cs, "", "list", "--json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got []credJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json output: %s\n%s", err, out)
	}
	if len(got) != 3 || got[0].RPID != "github.com" || got[0].Created.IsZero() || !got[1].Created.IsZero() ||
		got[0].CredentialID != base64.RawURLEncoding.EncodeToString([]byte("TPM\x7e\x00\x7c\x00\x20one")) || got[0].CredProtect != 1 {
		t.Errorf("--json = %+v", got)
	}

	empty := ctap2.NewCredStoreAt(filepath.Join(t.TempDir(), "none.json"))
	if code, out, _ := runCLI(t, empty, "", "list"); code != 0 || !strings.Contains(out, "no passkeys") {
		t.Errorf("empty store: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, empty, "", "list", "--json"); code != 0 || strings.TrimSpace(out) != "[]" {
		t.Errorf("empty store --json: %d %q", code, out)
	}
}

func TestCredsCLI_DeleteByIDPrefix(t *testing.T) {
	cs := newCLIStore(t)
	bob := []byte("TPM\x7e\x00\x7c\x00\x20two")
	prefix := shortID(bob)[:6]

	code, out, _ := runCLI(t, cs, "no\n", "delete", prefix)
	if code == 0 || !strings.Contains(out, "nothing deleted") {
		t.Errorf("declined: %d %q", code, out)
	}
	if creds, _ := cs.List(); len(creds) != 3 {
		t.Fatal("deleted despite declining")
	}

	code, out, _ = runCLI(t, cs, "yes\n", "delete", prefix)
	if code != 0 || !strings.Contains(out, "bob@github.com") {
		t.Errorf("confirmed: %d %q", code, out)
	}
	if _, err := cs.Find(bob); err == nil {
		t.Error("bob still stored")
	}
	if revoked, _ := cs.Revoked(bob); !revoked {
		t.Error("bob not revoked")
	}
	if creds, _ := cs.List(); len(creds) != 2 {
		t.Errorf("%d credentials left, want 2", len(creds))
	}
}

func TestCredsCLI_DeleteByRPWithYes(t *testing.T) {
	cs := newCLIStore(t)
	code, _, errOut := runCLI(t, cs, "", "delete", "-y", "github.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	creds, _ := cs.List()
	if len(creds) != 1 || creds[0].RPID != "example.org" {
		t.Errorf("left = %+v", creds)
	}
}

func TestCredsCLI_DeleteByFullCredentialIDAndErrors(t *testing.T) {
	cs := newCLIStore(t)
	// Every ID shares the TPM prefix, so a base64url prefix of it is ambiguous.
	common := base64.RawURLEncoding.EncodeToString([]byte("TPM\x7e\x00\x7c"))
	if code, _, errOut := runCLI(t, cs, "", "delete", "-y", common); code == 0 || !strings.Contains(errOut, "matches 3") {
		t.Errorf("ambiguous prefix: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, cs, "", "delete", "-y", "nothing.example"); code == 0 || !strings.Contains(errOut, "no credential") {
		t.Errorf("no match: %d %q", code, errOut)
	}
	if code, _, _ := runCLI(t, cs, "", "delete", "-y", "ab"); code != 2 {
		t.Errorf("too short prefix: %d", code)
	}
	full := base64.RawURLEncoding.EncodeToString([]byte("TPM\x7e\x00\x7c\x00\x20three"))
	if code, _, errOut := runCLI(t, cs, "", "delete", full, "-y"); code != 0 {
		t.Errorf("full credential ID: %d %s", code, errOut)
	}
	if creds, _ := cs.List(); len(creds) != 2 {
		t.Errorf("%d left", len(creds))
	}
	for _, args := range [][]string{{}, {"frobnicate"}, {"delete"}, {"list", "extra"}, {"list", "--bogus"}} {
		if code, _, _ := runCLI(t, cs, "", args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}
