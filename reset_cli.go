package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/tpm"
)

const resetUsage = `usage: linux-id [--credstore FILE] reset [-y]

Erase this authenticator: every passkey and security key credential it ever
created stops working, the passkey list is emptied and the PIN is removed.
A running linux-id service notices and drops its tokens too. Asks for
confirmation unless -y is given.
`

// runResetCLI implements `linux-id reset`: it moves the TPM's generation
// counter on and clears the user's files. Like `linux-id creds`, it acts for
// the user who owns them, so no user verification is involved. It returns
// the process exit code.
func runResetCLI(args []string) int {
	if *backend != "tpm" {
		fmt.Fprintln(os.Stderr, "reset: only the tpm backend keeps state between runs; restart a memory backend instead")
		return 2
	}
	t, err := tpm.New(*device)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reset: open tpm:", err)
		return 1
	}
	return resetCLI{
		gens:   t,
		cs:     ctap2.NewCredStoreAt(*credStorePath),
		pin:    pinStoreNextTo(*credStorePath, t),
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}.run(args)
}

type resetCLI struct {
	gens           generationBackend
	cs             *ctap2.CredStore
	pin            *pinStore
	stdin          io.Reader
	stdout, stderr io.Writer
}

func (c resetCLI) run(args []string) int {
	yes := false
	for _, a := range args {
		switch a {
		case "-y", "--yes", "-yes":
			yes = true
		case "-h", "--help", "-help":
			fmt.Fprint(c.stdout, resetUsage)
			return 0
		default:
			fmt.Fprintf(c.stderr, "unknown argument %s\n%s", a, resetUsage)
			return 2
		}
	}
	if !yes {
		n := "its"
		if creds, err := c.cs.List(); err == nil {
			n = fmt.Sprintf("its %d stored", len(creds))
		}
		fmt.Fprintf(c.stdout, "Reset linux-id? All credentials it created, including %s passkeys, stop working for good, and the PIN is removed.\n", n)
		fmt.Fprint(c.stdout, "Type 'reset' to continue: ")
		answer, _ := bufio.NewReader(c.stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "reset" {
			fmt.Fprintln(c.stdout, "nothing changed")
			return 1
		}
	}
	err := resetStores(c.gens, c.cs, c.pin)
	if err != nil {
		fmt.Fprintln(c.stderr, "reset:", err)
		return 1
	}
	fmt.Fprintln(c.stdout, "linux-id reset: all credentials retired, passkey list emptied, PIN removed")
	return 0
}
