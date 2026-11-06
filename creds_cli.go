package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matejsmycka/linux-id/ctap2"
)

const credsUsage = `usage: linux-id [--credstore FILE] creds list [--json]
       linux-id [--credstore FILE] creds delete [-y] <credential-id-prefix | rp-id>

list    show the discoverable credentials (passkeys) in the store
delete  delete the credentials of an RP, or the one whose ID starts with the
        given prefix (as shown by list, or its full base64url credential ID);
        asks for confirmation unless -y is given
`

// runCredsCLI implements `linux-id creds`, which manages the credential
// store file directly. The store belongs to the user running it, so no user
// verification is involved. It returns the process exit code.
func runCredsCLI(args []string) int {
	return credsCLI{
		cs:     ctap2.NewCredStoreAt(*credStorePath),
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}.run(args)
}

type credsCLI struct {
	cs             *ctap2.CredStore
	stdin          io.Reader
	stdout, stderr io.Writer
}

func (c credsCLI) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.stderr, credsUsage)
		return 2
	}
	var (
		asJSON, yes bool
		rest        []string
	)
	for _, a := range args[1:] {
		switch a {
		case "--json", "-json":
			asJSON = true
		case "-y", "--yes", "-yes":
			yes = true
		case "-h", "--help", "-help":
			fmt.Fprint(c.stdout, credsUsage)
			return 0
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(c.stderr, "unknown flag %s\n%s", a, credsUsage)
				return 2
			}
			rest = append(rest, a)
		}
	}
	switch {
	case args[0] == "list" && len(rest) == 0 && !yes:
		return c.list(asJSON)
	case args[0] == "delete" && len(rest) == 1 && !asJSON:
		return c.delete(rest[0], yes)
	}
	fmt.Fprint(c.stderr, credsUsage)
	return 2
}

// shortID is the identifier list shows for a credential. Credential IDs of
// the TPM backend all begin with the same bytes, so it is derived from a
// hash of the ID rather than a prefix of it.
func shortID(credID []byte) string {
	h := sha256.Sum256(credID)
	return hex.EncodeToString(h[:6])
}

type credJSON struct {
	ID           string    `json:"id"`
	CredentialID string    `json:"credentialId"` // base64url, as WebAuthn shows it
	RPID         string    `json:"rpId"`
	RPName       string    `json:"rpName,omitempty"`
	UserID       string    `json:"userId"` // base64url
	UserName     string    `json:"userName,omitempty"`
	DisplayName  string    `json:"displayName,omitempty"`
	Created      time.Time `json:"created,omitzero"`
	CredProtect  int       `json:"credProtect"`
}

func (c credsCLI) list(asJSON bool) int {
	creds, err := c.cs.List()
	if err != nil {
		fmt.Fprintf(c.stderr, "read %s: %s\n", c.cs.Path(), err)
		return 1
	}
	if asJSON {
		out := make([]credJSON, 0, len(creds))
		for _, cr := range creds {
			out = append(out, credJSON{
				ID:           shortID(cr.CredID),
				CredentialID: base64.RawURLEncoding.EncodeToString(cr.CredID),
				RPID:         cr.RPID,
				RPName:       cr.RPName,
				UserID:       base64.RawURLEncoding.EncodeToString(cr.UserID),
				UserName:     cr.UserName,
				DisplayName:  cr.DisplayName,
				Created:      cr.Created,
				CredProtect:  max(1, cr.CredProtect),
			})
		}
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(c.stderr, err)
			return 1
		}
		return 0
	}
	if len(creds) == 0 {
		fmt.Fprintf(c.stdout, "no passkeys in %s\n", c.cs.Path())
		return 0
	}
	c.table(creds)
	return 0
}

func (c credsCLI) table(creds []ctap2.StoredCredential) {
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tRP\tUSER\tDISPLAY NAME\tCREATED")
	for _, cr := range creds {
		created := "-"
		if !cr.Created.IsZero() {
			created = cr.Created.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", shortID(cr.CredID), orDash(printable(cr.RPID)), orDash(printable(cr.UserName)), orDash(printable(cr.DisplayName)), created)
	}
	tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printable keeps names set by websites from injecting terminal control
// sequences or breaking the table.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

// matchCreds selects the credentials of RP id arg, or else the one whose
// short ID or base64url credential ID starts with arg.
func matchCreds(creds []ctap2.StoredCredential, arg string) ([]ctap2.StoredCredential, error) {
	var byRP, byID []ctap2.StoredCredential
	for _, cr := range creds {
		if cr.RPID == arg {
			byRP = append(byRP, cr)
		}
		if strings.HasPrefix(shortID(cr.CredID), strings.ToLower(arg)) ||
			strings.HasPrefix(base64.RawURLEncoding.EncodeToString(cr.CredID), arg) {
			byID = append(byID, cr)
		}
	}
	switch {
	case len(byRP) > 0:
		return byRP, nil
	case len(byID) == 1:
		return byID, nil
	case len(byID) > 1:
		return nil, fmt.Errorf("%q matches %d credentials; give a longer prefix", arg, len(byID))
	}
	return nil, fmt.Errorf("no credential or relying party matches %q", arg)
}

func (c credsCLI) delete(arg string, yes bool) int {
	creds, err := c.cs.List()
	if err != nil {
		fmt.Fprintf(c.stderr, "read %s: %s\n", c.cs.Path(), err)
		return 1
	}
	if len(arg) < 4 && !strings.Contains(arg, ".") {
		fmt.Fprintln(c.stderr, "give at least 4 characters of the credential ID")
		return 2
	}
	targets, err := matchCreds(creds, arg)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 1
	}
	if !yes {
		fmt.Fprintf(c.stdout, "Delete %d passkey(s)? They stop working on these sites for good.\n", len(targets))
		c.table(targets)
		fmt.Fprint(c.stdout, "Type 'yes' to delete: ")
		answer, _ := bufio.NewReader(c.stdin).ReadString('\n')
		if a := strings.TrimSpace(strings.ToLower(answer)); a != "yes" && a != "y" {
			fmt.Fprintln(c.stdout, "nothing deleted")
			return 1
		}
	}
	failed := 0
	for _, t := range targets {
		if _, err := c.cs.Delete(t.CredID); err != nil {
			fmt.Fprintf(c.stderr, "delete %s: %s\n", shortID(t.CredID), err)
			failed++
			continue
		}
		fmt.Fprintf(c.stdout, "deleted %s (%s, %s)\n", shortID(t.CredID), printable(t.RPID), orDash(printable(t.UserName)))
	}
	if failed > 0 {
		return 1
	}
	return 0
}
