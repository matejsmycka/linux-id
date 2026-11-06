package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidohid"
)

// resetWindow is how long after power-up authenticatorReset is accepted
// (CTAP 2.1 §6.6). For linux-id, power-up is the daemon starting, which is
// also when its virtual device appears: `systemctl --user restart linux-id`
// is the "remove and re-insert your security key" platforms ask for.
const resetWindow = 10 * time.Second

// handleReset implements authenticatorReset: after a fresh user
// verification, every credential stops working and the PIN is removed.
func (s *server) handleReset(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd Reset")
	if s.now().Sub(s.startedAt) > resetWindow {
		log.Printf("Reset refused: only accepted within %s of start (restart linux-id, then retry)", resetWindow)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNotAllowed, nil)
		return
	}
	// The built-in verifier, not the presence fallback: with fprintd only
	// the enrolled finger can erase the passkeys.
	status := s.awaitUser(ctx, evt, VerifyRequest{
		Prompt: "FIDO2: RESET linux-id, erasing all passkeys and the PIN",
		Action: ActionReset,
		Fresh:  true,
	})
	if status != ctap2.StatusOK {
		token.WriteCtap2Response(ctx, evt, status, nil)
		return
	}
	if err := s.resetAuthenticator(); err != nil {
		log.Printf("Reset: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOther, nil)
		return
	}
	log.Print("Reset: all credentials retired, PIN removed")
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, nil)
}

// resetAuthenticator resets the stores and this daemon's protocol state.
func (s *server) resetAuthenticator() error {
	if s.gens == nil {
		return errNoGeneration
	}
	resetErr := resetStores(s.gens, s.cs, s.pin)
	// Whatever got done, pick up the generation now in force.
	s.resetVolatile()
	s.genSecret = nil
	if err := s.refreshGeneration(); err != nil && resetErr == nil {
		resetErr = err
	}
	return resetErr
}

// resetStores moves to the next credential generation, which retires every
// credential, then empties the credential store and removes the PIN. The
// generation moves first: once it has, the reset has happened even if
// tidying the files fails.
func resetStores(gens generationBackend, cs *ctap2.CredStore, pin *pinStore) error {
	// Retire legacy credentials first: a reset interrupted after this but
	// before the generation moves still leaves them invalid.
	if err := gens.RetireLegacy(); err != nil {
		return fmt.Errorf("retire legacy credentials: %w", err)
	}
	if _, err := gens.NextGeneration(); err != nil {
		return fmt.Errorf("next credential generation: %w", err)
	}
	if err := cs.Wipe(); err != nil {
		return fmt.Errorf("credentials retired, but the store could not be emptied: %w", err)
	}
	if err := pin.clear(); err != nil {
		return fmt.Errorf("credentials retired, but the PIN could not be removed: %w", err)
	}
	return nil
}

// resetVolatile drops the state a power cycle drops: the key agreement key
// and any pinUvAuthToken, the consecutive PIN mismatch and UV retry counters,
// and enumerations in progress.
func (s *server) resetVolatile() {
	if err := s.pinuv.Reset(); err != nil {
		log.Printf("reset pin/uv state: %s", err)
	}
	s.uv.reset()
	s.pin.resetPowerCycle()
	s.nextAssertions = nil
	s.credMgmtIter = nil
}

// syncGeneration notices a reset made outside this daemon (`linux-id reset`)
// on the next request.
func (s *server) syncGeneration() {
	if err := s.refreshGeneration(); err != nil {
		log.Printf("credential generation unreadable: %s", err)
	}
}

func (s *server) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock()
}
