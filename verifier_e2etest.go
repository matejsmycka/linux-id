//go:build e2etest

package main

import (
	"context"
	"errors"
)

// approveVerifier approves every request as if the user had verified, so
// end-to-end tests can drive the real uhid transport with libfido2. It is only
// compiled with -tags e2etest.
type approveVerifier struct{}

func (approveVerifier) VerifyUser(context.Context, VerifyRequest) (<-chan VerifyResult, error) {
	ch := make(chan VerifyResult, 1)
	ch <- VerifyResult{OK: true}
	return ch, nil
}

func (approveVerifier) PerformsUV() bool { return true }

func init() { testVerifiers["e2e-approve"] = func() UserVerifier { return approveVerifier{} } }

// denyVerifier answers every verification with a fingerprint no-match, so
// end-to-end tests can drive the UV retry counter and the PIN fallback.
type denyVerifier struct{}

func (denyVerifier) VerifyUser(context.Context, VerifyRequest) (<-chan VerifyResult, error) {
	ch := make(chan VerifyResult, 1)
	ch <- VerifyResult{Reason: ReasonNoMatch, Error: errors.New("e2e: fingerprint did not match")}
	return ch, nil
}

func (denyVerifier) PerformsUV() bool { return true }

// unavailableVerifier behaves like fprintd without a usable sensor.
type unavailableVerifier struct{}

func (unavailableVerifier) VerifyUser(context.Context, VerifyRequest) (<-chan VerifyResult, error) {
	return nil, errors.New("e2e: no fingerprint devices found")
}

func (unavailableVerifier) PerformsUV() bool { return true }

func init() {
	testVerifiers["e2e-deny"] = func() UserVerifier { return denyVerifier{} }
	testVerifiers["e2e-unavailable"] = func() UserVerifier { return unavailableVerifier{} }
}
