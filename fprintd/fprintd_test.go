package fprintd

import (
	"errors"
	"testing"
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
