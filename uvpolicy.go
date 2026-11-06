package main

import (
	"context"
	"log"
	"sync"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
)

// maxUVRetries is the built-in UV (fingerprint) retry counter's start value.
// Each failed verification request decrements it (fprintd itself allows a few
// scans per request); at zero, built-in UV is blocked until a correct PIN or
// the next power cycle (daemon restart), and platforms fall back to the PIN.
const maxUVRetries = 3

// uvRetryCounter is the uvRetries counter of CTAP 2.1 §6.5.2.2 for this run
// of the daemon. Its zero value is a full counter.
type uvRetryCounter struct {
	mu       sync.Mutex
	failures int
}

func (c *uvRetryCounter) remaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(maxUVRetries-c.failures, 0)
}

// fail records a failed verification and returns the retries left.
func (c *uvRetryCounter) fail() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures < maxUVRetries {
		c.failures++
	}
	return maxUVRetries - c.failures
}

func (c *uvRetryCounter) reset() {
	c.mu.Lock()
	c.failures = 0
	c.mu.Unlock()
}

// uvBlocked reports whether built-in UV is blocked. The counter only blocks
// while a PIN is set: without a PIN there is nothing to fall back to, and
// blocking would only lock the user out until the daemon restarts.
func (s *server) uvBlocked() bool {
	return s.pin.isSet() && s.uv.remaining() <= 0
}

// uvOutcome classifies one built-in user verification.
type uvOutcome int

const (
	uvMatched     uvOutcome = iota
	uvNoMatch               // the finger did not match
	uvUnavailable           // the verifier is unusable (no sensor, D-Bus error, ...)
	uvAbandoned             // the user declined, or the request timed out or was cancelled
)

// performBuiltInUV verifies the user with the built-in verifier once and
// maintains the UV retry counter. status is what awaitUser would answer.
func (s *server) performBuiltInUV(ctx context.Context, evt fidohid.AuthEvent, req VerifyRequest) (uvOutcome, byte) {
	res, status := s.awaitResult(ctx, evt, s.verifier, req)
	switch {
	case status == ctap2.StatusOK:
		s.uv.reset()
		return uvMatched, status
	case res.Reason == ReasonNoMatch:
		if s.pin.isSet() {
			log.Printf("uv: fingerprint did not match, %d UV retries left", s.uv.fail())
		}
		return uvNoMatch, status
	case res.Reason == ReasonUnavailable:
		log.Printf("uv: built-in verifier unusable: %v", res.Error)
		return uvUnavailable, status
	}
	return uvAbandoned, status
}

// awaitPresence collects user presence (not verification). With a
// fingerprint verifier any deliberate touch of the sensor is presence, so a
// non-matching finger is accepted too; this is what makes the PIN a real
// fallback when the fingerprint is not recognised. If the verifier is
// unusable, the presence fallback (a pinentry confirmation) asks instead.
func (s *server) awaitPresence(ctx context.Context, evt fidohid.AuthEvent, req VerifyRequest) byte {
	res, status := s.awaitResult(ctx, evt, s.verifier, req)
	switch {
	case status == ctap2.StatusOK:
		if s.verifier.PerformsUV() {
			s.uv.reset()
		}
		return status
	case res.Reason == ReasonNoMatch:
		log.Print("uv: non-matching finger accepted as user presence")
		return ctap2.StatusOK
	case res.Reason == ReasonUnavailable && s.presence != nil:
		log.Printf("uv: verifier unusable (%v), asking for presence instead", res.Error)
		_, status = s.awaitResult(ctx, evt, s.presence, req)
		return status
	}
	return status
}
