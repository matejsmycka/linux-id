package fprintd

import "testing"

// processVerifyStatus is the pure-data heart of verifyFingerprint(): it
// interprets one fprintd VerifyStatus signal body. The wrapping
// verifyFingerprint() needs a real D-Bus connection so it can't be unit-tested,
// but the signal interpretation logic can — and it's where the historical
// crash-on-malformed-signal lives, so it's worth pinning.
func TestProcessVerifyStatus(t *testing.T) {
	cases := []struct {
		name         string
		body         []interface{}
		wantMatched  bool
		wantTerminal bool
		wantErrMsg   string // empty = expect nil error
	}{
		{
			// fprintd reports a successful match. Verification ends, the caller
			// returns nil.
			name:         "verify-match terminal success",
			body:         []interface{}{"verify-match", true},
			wantMatched:  true,
			wantTerminal: true,
		},
		{
			// fprintd reports a final no-match (the user's finger doesn't match
			// any enrolled template). Verification ends with an error.
			name:         "verify-no-match terminal failure",
			body:         []interface{}{"verify-no-match", true},
			wantTerminal: true,
			wantErrMsg:   "fingerprint verification failed: verify-no-match",
		},
		{
			// Sensor disconnected mid-scan — fatal.
			name:         "verify-disconnected terminal failure",
			body:         []interface{}{"verify-disconnected", true},
			wantTerminal: true,
			wantErrMsg:   "fingerprint verification failed: verify-disconnected",
		},
		{
			// User scanned too quickly / partially — sensor wants another try.
			// Non-terminal: fprintd is still verifying, the loop must keep waiting.
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
			// Malformed body: empty. Old code would panic on body[0]. New code
			// must treat this as a non-terminal status and keep waiting.
			name: "empty body — defensive",
			body: []interface{}{},
		},
		{
			// Malformed body: only one element. Old code would panic on body[1].
			name: "single-element body — defensive",
			body: []interface{}{"verify-match"},
		},
		{
			// Malformed body: wrong type on element 0. The type assertion now
			// uses the comma-ok form so it returns "" rather than panicking.
			// Treated as non-terminal.
			name: "wrong type on result — defensive",
			body: []interface{}{42, false},
		},
		{
			// Malformed body: wrong type on element 1. done becomes false.
			// Treated as non-terminal.
			name: "wrong type on done — defensive",
			body: []interface{}{"verify-match", "yes"},
		},
		{
			// nil body. Slice length 0 → defensive non-terminal.
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
			if tc.wantErrMsg == "" && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if tc.wantErrMsg != "" {
				if err == nil {
					t.Errorf("err = nil, want %q", tc.wantErrMsg)
				} else if err.Error() != tc.wantErrMsg {
					t.Errorf("err = %q, want %q", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

// TestProcessVerifyStatus_NoPanicOnAnyBody is a smoke check: the function
// must never panic regardless of body contents. Catches any future regression
// that re-introduces unguarded type assertions.
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
