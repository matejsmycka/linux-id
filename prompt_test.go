package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/notify"
)

// fakeNotifier records notifications instead of talking to the session bus.
type fakeNotifier struct {
	mu      sync.Mutex
	showErr error
	shown   []*fakeNotification
}

func (f *fakeNotifier) Show(msg notify.Message) (notify.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.showErr != nil {
		return nil, f.showErr
	}
	n := &fakeNotification{msgs: []notify.Message{msg}, cancelled: make(chan struct{}), closedCh: make(chan struct{})}
	f.shown = append(f.shown, n)
	return n, nil
}

func (f *fakeNotifier) only(t *testing.T) *fakeNotification {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.shown) != 1 {
		t.Fatalf("notifications shown = %d, want 1", len(f.shown))
	}
	return f.shown[0]
}

type fakeNotification struct {
	mu        sync.Mutex
	msgs      []notify.Message
	closes    int
	cancelled chan struct{}
	closedCh  chan struct{}
}

func (n *fakeNotification) Update(msg notify.Message) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, msg)
}

func (n *fakeNotification) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closes++
	if n.closes == 1 {
		close(n.closedCh)
	}
}

func (n *fakeNotification) Cancelled() <-chan struct{} { return n.cancelled }

// pressCancel simulates the user picking the Cancel action.
func (n *fakeNotification) pressCancel() { close(n.cancelled) }

func (n *fakeNotification) last() notify.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.msgs[len(n.msgs)-1]
}

// waitClosed fails the test unless the notification is withdrawn soon. The
// close can follow the result by a moment when the request's context ends
// first.
func (n *fakeNotification) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-n.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("notification was not closed")
	}
}

// scanVerifier behaves like the fprintd verifier: it blocks until it is
// given a result or its context ends, and reports its context's end as a
// failure.
type scanVerifier struct {
	mu      sync.Mutex
	result  chan VerifyResult
	lastCtx context.Context
	reqs    []VerifyRequest
	stopped chan struct{}
	stop    sync.Once
}

func newScanVerifier() *scanVerifier {
	return &scanVerifier{result: make(chan VerifyResult, 1), stopped: make(chan struct{})}
}

func (v *scanVerifier) VerifyUser(ctx context.Context, req VerifyRequest) (<-chan VerifyResult, error) {
	v.mu.Lock()
	v.lastCtx = ctx
	v.reqs = append(v.reqs, req)
	v.mu.Unlock()
	out := make(chan VerifyResult, 1)
	go func() {
		select {
		case r := <-v.result:
			out <- r
		case <-ctx.Done():
			v.stop.Do(func() { close(v.stopped) })
			out <- VerifyResult{OK: false, Error: errors.New("scan cancelled")}
		}
	}()
	return out, nil
}

func (v *scanVerifier) PerformsUV() bool { return true }

func (v *scanVerifier) lastReq() VerifyRequest {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reqs[len(v.reqs)-1]
}

// waitStarted waits until VerifyUser has been called n times.
func (v *scanVerifier) waitStarted(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v.mu.Lock()
		got := len(v.reqs)
		v.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("verifier not started")
}

func newNotifyingServer(t *testing.T, inner UserVerifier, n notify.Notifier) *server {
	return newTestServer(t, newNotifyingVerifier(inner, n), &fakePinentry{})
}

func TestPromptMessage(t *testing.T) {
	cases := []struct {
		name      string
		req       VerifyRequest
		wantTitle string
		wantBody  string
	}{
		{
			name:      "register with user",
			req:       VerifyRequest{RPID: "github.com", Action: ActionRegister, UserName: "alice@example.com", UserDisplayName: "Alice"},
			wantTitle: "Create a passkey for github.com",
			wantBody:  "Touch the fingerprint sensor to save a passkey for alice@example.com",
		},
		{
			name:      "register with display name only",
			req:       VerifyRequest{RPID: "github.com", Action: ActionRegister, UserDisplayName: "Alice"},
			wantTitle: "Create a passkey for github.com",
			wantBody:  "Touch the fingerprint sensor to save a passkey for Alice",
		},
		{
			name:      "sign in with known user",
			req:       VerifyRequest{RPID: "github.com", Action: ActionSignIn, UserName: "alice@example.com"},
			wantTitle: "Sign in to github.com",
			wantBody:  "Touch the fingerprint sensor to use your passkey for alice@example.com",
		},
		{
			name:      "sign in, user unknown",
			req:       VerifyRequest{RPID: "github.com", Action: ActionSignIn},
			wantTitle: "Sign in to github.com",
			wantBody:  "Touch the fingerprint sensor to use your passkey",
		},
		{
			name:      "select",
			req:       VerifyRequest{Action: ActionSelect},
			wantTitle: "Use linux-id",
			wantBody:  "Touch the fingerprint sensor to choose this security key",
		},
		{
			name:      "unspecified",
			req:       VerifyRequest{Prompt: "FIDO2 something"},
			wantTitle: "linux-id",
			wantBody:  "Touch the fingerprint sensor to continue",
		},
		{
			name:      "host-supplied text is cleaned",
			req:       VerifyRequest{RPID: "github.com", Action: ActionSignIn, UserName: "  ev‮il\nname\t "},
			wantTitle: "Sign in to github.com",
			wantBody:  "Touch the fingerprint sensor to use your passkey for evilname",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := promptMessage(tc.req)
			if msg.Title != tc.wantTitle || msg.Body != tc.wantBody {
				t.Errorf("got %q / %q\nwant %q / %q", msg.Title, msg.Body, tc.wantTitle, tc.wantBody)
			}
			if !msg.Cancelable {
				t.Error("prompt is not cancelable")
			}
		})
	}
}

func TestDisplayText_Truncates(t *testing.T) {
	got := displayText(strings.Repeat("é", 100))
	if n := len([]rune(got)); n != maxNameLen {
		t.Errorf("len = %d runes, want %d", n, maxNameLen)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("%q does not end in an ellipsis", got)
	}
}

// The notification is shown while the scan runs and withdrawn as soon as it
// succeeds.
func TestNotify_ClosedOnSuccess(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	done := make(chan byte)
	go func() {
		done <- s.awaitUser(context.Background(), fidohid.AuthEvent{}, VerifyRequest{RPID: "github.com", Action: ActionSignIn})
	}()
	inner.waitStarted(t, 1)
	note := n.only(t)
	if got := note.last().Title; got != "Sign in to github.com" {
		t.Errorf("title = %q", got)
	}
	if note.last().Expire <= 0 || note.last().Expire > userActionTimeout {
		t.Errorf("expire = %v, want within the request timeout", note.last().Expire)
	}
	inner.result <- VerifyResult{OK: true}
	if got := <-done; got != ctap2.StatusOK {
		t.Fatalf("status = 0x%02x, want OK", got)
	}
	note.waitClosed(t)
}

func TestNotify_ClosedOnFailure(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	inner.result <- VerifyResult{OK: false, Reason: ReasonNoMatch}
	if got := s.awaitUser(context.Background(), fidohid.AuthEvent{}, VerifyRequest{RPID: "a.example", Action: ActionSignIn}); got != ctap2.StatusUVInvalid {
		t.Fatalf("status = 0x%02x, want UV_INVALID", got)
	}
	n.only(t).waitClosed(t)
}

// Cancel in the notification stops the scan and answers OPERATION_DENIED
// (the user declined), not KEEPALIVE_CANCEL (the host cancelled).
func TestNotify_CancelActionDenies(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	done := make(chan byte)
	go func() {
		done <- s.awaitUser(context.Background(), fidohid.AuthEvent{}, VerifyRequest{RPID: "github.com", Action: ActionSignIn})
	}()
	inner.waitStarted(t, 1)
	note := n.only(t)
	note.pressCancel()

	select {
	case got := <-done:
		if got != ctap2.StatusOperationDenied {
			t.Fatalf("status = 0x%02x, want OPERATION_DENIED (0x%02x)", got, ctap2.StatusOperationDenied)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not finish after Cancel")
	}
	select {
	case <-inner.stopped:
	default:
		t.Error("scan was not stopped before the answer")
	}
	note.waitClosed(t)
}

// Cancel through the whole GetAssertion handler.
func TestNotify_CancelActionDeniesGetAssertion(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)
	credID := newKeyHandle(t, s, "github.com")

	resp := &fakeResponder{}
	done := make(chan struct{})
	go func() {
		s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{},
			makeAssertionCBOR(t, "github.com", []ctap2.CredDescriptor{{Type: "public-key", ID: credID}}, nil))
		close(done)
	}()
	inner.waitStarted(t, 1)
	n.only(t).pressCancel()
	<-done
	if got := resp.lastCtap2().status; got != ctap2.StatusOperationDenied {
		t.Fatalf("status = 0x%02x, want OPERATION_DENIED", got)
	}
}

// newKeyHandle creates a non-resident credential for rp directly, without a
// MakeCredential, so tests that count notifications do not see a registration one.
func newKeyHandle(t *testing.T, s *server, rp string) []byte {
	t.Helper()
	h := rpIDHash(rp)
	kh, _, _, err := s.newCredential(h[:], credOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return kh
}

// A host cancel (CTAPHID_CANCEL cancels the request's context) withdraws the
// notification and still answers KEEPALIVE_CANCEL.
func TestNotify_ClosedOnHostCancel(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan byte)
	go func() {
		done <- s.awaitUser(ctx, fidohid.AuthEvent{}, VerifyRequest{RPID: "github.com", Action: ActionSignIn})
	}()
	inner.waitStarted(t, 1)
	cancel()
	if got := <-done; got != ctap2.StatusKeepaliveCancel {
		t.Fatalf("status = 0x%02x, want KEEPALIVE_CANCEL", got)
	}
	n.only(t).waitClosed(t)
}

func TestNotify_ClosedOnTimeout(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if got := s.awaitUser(ctx, fidohid.AuthEvent{}, VerifyRequest{RPID: "github.com", Action: ActionSignIn}); got != ctap2.StatusUserActionTimeout {
		t.Fatalf("status = 0x%02x, want USER_ACTION_TIMEOUT", got)
	}
	n.only(t).waitClosed(t)
}

// With no session bus or notification daemon the request goes ahead without
// a notification.
func TestNotify_UnavailableStillVerifies(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{showErr: errors.New("no session bus")}
	s := newNotifyingServer(t, inner, n)

	inner.result <- VerifyResult{OK: true}
	if got := s.awaitUser(context.Background(), fidohid.AuthEvent{}, VerifyRequest{RPID: "github.com", Action: ActionSignIn}); got != ctap2.StatusOK {
		t.Fatalf("status = 0x%02x, want OK", got)
	}
	if len(inner.reqs) != 1 {
		t.Fatalf("verifier called %d times, want 1", len(inner.reqs))
	}
}

// A finger that does not match updates the same notification.
func TestNotify_RetryUpdatesNotification(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	called := false
	done := make(chan byte)
	go func() {
		done <- s.awaitUser(context.Background(), fidohid.AuthEvent{}, VerifyRequest{
			RPID: "github.com", Action: ActionSignIn, OnRetry: func() { called = true },
		})
	}()
	inner.waitStarted(t, 1)
	inner.lastReq().OnRetry()
	note := n.only(t)
	if got := note.last(); got.Title != "Sign in to github.com" || got.Body != "Not recognised — try again" || !got.Cancelable {
		t.Errorf("after retry: %+v", got)
	}
	if !called {
		t.Error("caller's OnRetry was not called")
	}
	inner.result <- VerifyResult{OK: true}
	<-done
	note.waitClosed(t)
}

// MakeCredential and a GetAssertion with one resident credential show the
// account; with several resident credentials no account is named.
func TestNotify_HandlersDescribeRequest(t *testing.T) {
	inner := newScanVerifier()
	n := &fakeNotifier{}
	s := newNotifyingServer(t, inner, n)

	register := func(user string) {
		inner.result <- VerifyResult{OK: true}
		resp := &fakeResponder{}
		s.handleMakeCredential(context.Background(), resp, fidohid.AuthEvent{}, makeMakeCredCBOR(t, "github.com", "GitHub", user, true, false))
		if resp.lastCtap2().status != ctap2.StatusOK {
			t.Fatalf("register %s: 0x%02x", user, resp.lastCtap2().status)
		}
	}
	assert := func() {
		inner.result <- VerifyResult{OK: true}
		resp := &fakeResponder{}
		s.handleGetAssertion(context.Background(), resp, fidohid.AuthEvent{}, makeAssertionCBOR(t, "github.com", nil, nil))
		if resp.lastCtap2().status != ctap2.StatusOK {
			t.Fatalf("assert: 0x%02x", resp.lastCtap2().status)
		}
	}
	lastMsg := func() notify.Message {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.shown[len(n.shown)-1].last()
	}

	register("alice")
	if got := lastMsg(); got.Title != "Create a passkey for github.com" || got.Body != "Touch the fingerprint sensor to save a passkey for alice@github.com" {
		t.Errorf("register: %q / %q", got.Title, got.Body)
	}
	assert()
	if got := lastMsg(); got.Title != "Sign in to github.com" || got.Body != "Touch the fingerprint sensor to use your passkey for alice@github.com" {
		t.Errorf("one credential: %q / %q", got.Title, got.Body)
	}
	register("bob")
	assert()
	if got := lastMsg(); got.Title != "Sign in to github.com" || got.Body != "Touch the fingerprint sensor to use your passkey" {
		t.Errorf("two credentials: %q / %q", got.Title, got.Body)
	}
	if req := inner.lastReq(); req.Prompt != "FIDO2 Authenticate: github.com" {
		t.Errorf("pinentry prompt changed: %q", req.Prompt)
	}
}
