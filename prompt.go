package main

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"
	"unicode"

	"github.com/matejsmycka/linux-id/notify"
)

// notifyingVerifier shows a desktop notification while the inner verifier
// waits for the user, saying what is being approved, with a Cancel action
// that declines the request. It is for verifiers with no window of their own
// (fprintd). A notification that cannot be shown never fails the request.
type notifyingVerifier struct {
	inner    UserVerifier
	notifier notify.Notifier
}

func newNotifyingVerifier(inner UserVerifier, n notify.Notifier) *notifyingVerifier {
	return &notifyingVerifier{inner: inner, notifier: n}
}

func (v *notifyingVerifier) PerformsUV() bool { return v.inner.PerformsUV() }

var errUserDeclined = errors.New("declined from the notification")

func (v *notifyingVerifier) VerifyUser(ctx context.Context, req VerifyRequest) (<-chan VerifyResult, error) {
	msg := promptMessage(req)
	// Let the notification expire with the request in case it is never
	// closed (the process dies).
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		msg.Expire = time.Until(deadline)
	}
	n, err := v.notifier.Show(msg)
	if err != nil {
		log.Printf("notify: %s; asking without a notification", err)
		return v.inner.VerifyUser(ctx, req)
	}

	innerCtx, cancel := context.WithCancel(ctx)
	onRetry := req.OnRetry
	req.OnRetry = func() {
		retry := msg
		retry.Body = "Not recognised — try again"
		if hasDeadline {
			retry.Expire = time.Until(deadline)
		}
		n.Update(retry)
		if onRetry != nil {
			onRetry()
		}
	}
	innerCh, err := v.inner.VerifyUser(innerCtx, req)
	if err != nil {
		cancel()
		n.Close()
		return nil, err
	}

	out := make(chan VerifyResult, 1)
	go func() {
		defer cancel()
		select {
		case r := <-innerCh:
			n.Close()
			out <- r
		case <-n.Cancelled():
			log.Print("verifier: declined from the notification")
			n.Close()
			cancel()
			// Let the verifier stop (fprintd releases the sensor) before
			// answering, so the next request does not find it busy.
			select {
			case <-innerCh:
			case <-ctx.Done():
			}
			out <- VerifyResult{OK: false, Reason: ReasonUserDeclined, Error: errUserDeclined}
		case <-ctx.Done():
			// Host cancel or timeout: withdraw the prompt now, then pass on
			// whatever the verifier makes of it.
			n.Close()
			out <- <-innerCh
		}
	}()
	return out, nil
}

// maxNameLen bounds the RP ID and user name shown in a notification.
const maxNameLen = 64

// promptMessage is the notification for req.
func promptMessage(req VerifyRequest) notify.Message {
	rp := displayText(req.RPID)
	user := displayText(req.UserName)
	if user == "" {
		user = displayText(req.UserDisplayName)
	}
	msg := notify.Message{Cancelable: true}
	const touch = "Touch the fingerprint sensor"
	switch {
	case req.Action == ActionRegister && rp != "":
		msg.Title = "Create a passkey for " + rp
		msg.Body = touch + " to save a passkey"
	case req.Action == ActionSignIn && rp != "":
		msg.Title = "Sign in to " + rp
		msg.Body = touch + " to use your passkey"
	case req.Action == ActionReset:
		msg.Title = "Reset linux-id"
		msg.Body = touch + " to erase all passkeys and the PIN"
		return msg
	case req.Action == ActionManage:
		msg.Title = "Manage passkeys"
		msg.Body = touch + " to manage the passkeys on linux-id"
		return msg
	case req.Action == ActionSelect:
		msg.Title = "Use linux-id"
		msg.Body = touch + " to choose this security key"
		return msg
	default:
		msg.Title = "linux-id"
		msg.Body = touch + " to continue"
		return msg
	}
	if user != "" {
		msg.Body += " for " + user
	}
	return msg
}

// displayText makes host-supplied text safe to show on one line: control and
// format characters (line breaks, bidi overrides that could make one name
// look like another, zero-width characters) are dropped and it is cut at
// maxNameLen runes.
func displayText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxNameLen {
		s = string(r[:maxNameLen-1]) + "…"
	}
	return s
}
