package fprintd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestProcessVerifyStatus(t *testing.T) {
	cases := []struct {
		name         string
		body         []interface{}
		wantMatched  bool
		wantTerminal bool
		wantErrIs    error  // expected sentinel; checked with errors.Is if non-nil
		wantErrMsg   string // expected substring of err.Error(); checked if non-empty
	}{
		{
			name:         "verify-match terminal success",
			body:         []interface{}{"verify-match", true},
			wantMatched:  true,
			wantTerminal: true,
		},
		{
			name:         "verify-no-match terminal failure",
			body:         []interface{}{"verify-no-match", true},
			wantTerminal: true,
			wantErrIs:    ErrNoMatch,
		},
		{
			name:         "verify-disconnected terminal failure",
			body:         []interface{}{"verify-disconnected", true},
			wantTerminal: true,
			wantErrMsg:   "verify-disconnected",
		},
		{
			name: "verify-retry-scan non-terminal",
			body: []interface{}{"verify-retry-scan", false},
		},
		{
			name: "verify-swipe-too-short non-terminal",
			body: []interface{}{"verify-swipe-too-short", false},
		},
		{
			name: "verify-finger-not-centered non-terminal",
			body: []interface{}{"verify-finger-not-centered", false},
		},
		{
			name: "empty body — defensive",
			body: []interface{}{},
		},
		{
			name: "single-element body — defensive",
			body: []interface{}{"verify-match"},
		},
		{
			name: "wrong type on result — defensive",
			body: []interface{}{42, false},
		},
		{
			name: "wrong type on done — defensive",
			body: []interface{}{"verify-match", "yes"},
		},
		{
			name: "nil body",
			body: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, terminal, err := processVerifyStatus(tc.body)
			if matched != tc.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tc.wantMatched)
			}
			if terminal != tc.wantTerminal {
				t.Errorf("terminal = %v, want %v", terminal, tc.wantTerminal)
			}
			if tc.wantErrIs == nil && tc.wantErrMsg == "" && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if tc.wantErrIs != nil {
				if err == nil {
					t.Errorf("err = nil, want %v", tc.wantErrIs)
				} else if !errors.Is(err, tc.wantErrIs) {
					t.Errorf("errors.Is(err, %v) = false; err = %v", tc.wantErrIs, err)
				}
			}
			if tc.wantErrMsg != "" {
				if err == nil {
					t.Errorf("err = nil, want substring %q", tc.wantErrMsg)
				} else if !contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("err = %q, want substring %q", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestWaitForVerifyResult(t *testing.T) {
	feed := func(bodies ...[]interface{}) <-chan *dbus.Signal {
		ch := make(chan *dbus.Signal, len(bodies))
		for _, b := range bodies {
			ch <- &dbus.Signal{Body: b}
		}
		return ch
	}

	t.Run("success on first signal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitForVerifyResult(ctx, feed([]interface{}{"verify-match", true}))
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("no-match returns ErrNoMatch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitForVerifyResult(ctx, feed([]interface{}{"verify-no-match", true}))
		if !errors.Is(err, ErrNoMatch) {
			t.Errorf("err = %v, want ErrNoMatch", err)
		}
	})

	t.Run("non-terminal scan then success", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitForVerifyResult(ctx, feed(
			[]interface{}{"verify-retry-scan", false},
			[]interface{}{"verify-swipe-too-short", false},
			[]interface{}{"verify-match", true},
		))
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("non-terminal scans then no-match", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitForVerifyResult(ctx, feed(
			[]interface{}{"verify-finger-not-centered", false},
			[]interface{}{"verify-no-match", true},
		))
		if !errors.Is(err, ErrNoMatch) {
			t.Errorf("err = %v, want ErrNoMatch", err)
		}
	})

	t.Run("disconnected returns wrapped error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitForVerifyResult(ctx, feed([]interface{}{"verify-disconnected", true}))
		if err == nil {
			t.Errorf("err = nil, want disconnect error")
		}
		if errors.Is(err, ErrNoMatch) {
			t.Errorf("disconnect must not be reported as no-match")
		}
	})

	t.Run("context deadline returns timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		empty := make(chan *dbus.Signal)
		err := waitForVerifyResult(ctx, empty)
		if err == nil {
			t.Errorf("err = nil, want timeout error")
		}
	})
}

func TestVerifyPresence_CachesRecentSuccess(t *testing.T) {
	fp := New()
	calls := 0
	orig := verifyFingerprintFunc
	defer func() { verifyFingerprintFunc = orig }()
	verifyFingerprintFunc = func() error {
		calls++
		return nil
	}

	ch1, err := fp.VerifyPresence()
	if err != nil {
		t.Fatalf("first VerifyPresence: %s", err)
	}
	r1 := <-ch1
	if !r1.OK {
		t.Fatalf("first result not OK: %+v", r1)
	}
	if calls != 1 {
		t.Fatalf("after first call, calls = %d, want 1", calls)
	}

	ch2, err := fp.VerifyPresence()
	if err != nil {
		t.Fatalf("second VerifyPresence: %s", err)
	}
	r2 := <-ch2
	if !r2.OK {
		t.Fatalf("second result not OK: %+v", r2)
	}
	if calls != 1 {
		t.Errorf("cached call still invoked verifyFingerprintFunc; calls = %d, want 1", calls)
	}
}

func TestVerifyPresence_DoesNotCacheFailure(t *testing.T) {
	fp := New()
	calls := 0
	orig := verifyFingerprintFunc
	defer func() { verifyFingerprintFunc = orig }()
	verifyFingerprintFunc = func() error {
		calls++
		return ErrNoMatch
	}

	ch1, _ := fp.VerifyPresence()
	r1 := <-ch1
	if r1.OK {
		t.Fatalf("first result must not be OK; got %+v", r1)
	}
	if !errors.Is(r1.Error, ErrNoMatch) {
		t.Errorf("first result error = %v, want ErrNoMatch", r1.Error)
	}

	ch2, _ := fp.VerifyPresence()
	r2 := <-ch2
	if r2.OK {
		t.Errorf("second result must not be OK from cache after a failure; got %+v", r2)
	}
	if calls != 2 {
		t.Errorf("failure must not be cached; verifyFingerprintFunc called %d times, want 2", calls)
	}
}

func TestVerifyPresence_CacheExpires(t *testing.T) {
	fp := New()
	calls := 0
	orig := verifyFingerprintFunc
	defer func() { verifyFingerprintFunc = orig }()
	verifyFingerprintFunc = func() error {
		calls++
		return nil
	}

	ch1, _ := fp.VerifyPresence()
	<-ch1
	if calls != 1 {
		t.Fatalf("after first call, calls = %d, want 1", calls)
	}

	fp.mu.Lock()
	fp.lastSuccessAt = time.Now().Add(-2 * uvCacheTTL)
	fp.mu.Unlock()

	ch2, _ := fp.VerifyPresence()
	<-ch2
	if calls != 2 {
		t.Errorf("expired cache should not short-circuit; calls = %d, want 2", calls)
	}
}

func TestProcessVerifyStatus_NoPanicOnAnyBody(t *testing.T) {
	bodies := [][]interface{}{
		nil,
		{},
		{nil, nil},
		{nil, false},
		{"verify-match", nil},
		{[]byte("not a string"), 0},
		{struct{}{}, struct{}{}},
		{0, 0, 0, 0, 0},
		{"verify-match", true, "extra", "stuff"},
	}
	for i, b := range bodies {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("body #%d panicked: %v", i, r)
				}
			}()
			processVerifyStatus(b)
		}()
	}
}
