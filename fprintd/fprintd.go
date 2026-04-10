package fprintd

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

var ErrNoMatch = errors.New("fprintd: fingerprint did not match an enrolled finger")

type Result struct {
	OK    bool
	Error error
}

type Fprintd struct {
	mu     sync.Mutex
	active chan Result
}

func New() *Fprintd { return &Fprintd{} }

// VerifyPresence starts a fingerprint scan. If one is already in progress,
// returns the same result channel (deduplication for browser retries).
func (f *Fprintd) VerifyPresence() (chan Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.active != nil {
		return f.active, nil
	}

	ch := make(chan Result, 1)
	f.active = ch
	go func() {
		err := verifyFingerprint()
		result := Result{OK: err == nil, Error: err}
		f.mu.Lock()
		f.active = nil
		f.mu.Unlock()
		ch <- result
	}()
	return ch, nil
}

func verifyFingerprint() error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()

	manager := conn.Object("net.reactivated.Fprint",
		dbus.ObjectPath("/net/reactivated/Fprint/Manager"))
	var devices []dbus.ObjectPath
	if err := manager.Call("net.reactivated.Fprint.Manager.GetDevices", 0).Store(&devices); err != nil {
		return err
	}
	if len(devices) == 0 {
		return fmt.Errorf("no fingerprint devices found")
	}

	device := conn.Object("net.reactivated.Fprint", devices[0])

	// Subscribe to VerifyStatus signals BEFORE VerifyStart so the first
	// status update from the sensor cannot race ahead of our channel.
	// Scoping by sender + object path keeps the match strict.
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender("net.reactivated.Fprint"),
		dbus.WithMatchInterface("net.reactivated.Fprint.Device"),
		dbus.WithMatchMember("VerifyStatus"),
		dbus.WithMatchObjectPath(devices[0]),
	); err != nil {
		return err
	}
	sigCh := make(chan *dbus.Signal, 4)
	conn.Signal(sigCh)

	if err := device.Call("net.reactivated.Fprint.Device.Claim", 0, "").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.Release", 0)

	if err := device.Call("net.reactivated.Fprint.Device.VerifyStart", 0, "any").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.VerifyStop", 0)

	for {
		select {
		case sig := <-sigCh:
			matched, terminal, err := processVerifyStatus(sig.Body)
			if matched {
				return nil
			}
			if terminal {
				return err
			}
			// non-terminal status (e.g. "verify-retry-scan") — keep waiting
		case <-time.After(30 * time.Second):
			return fmt.Errorf("fingerprint verification timed out")
		}
	}
}

// processVerifyStatus interprets a single fprintd VerifyStatus signal body.
//
// Returns:
//   - matched=true  → verification succeeded; caller should return nil
//   - terminal=true → verification ended (success or failure); caller should
//     return err (nil on success, non-nil on failure)
//   - matched=false, terminal=false → non-terminal status (e.g. verify-retry-scan,
//     malformed signal). Caller should keep waiting.
//
// Defensive against malformed signals: a body shorter than 2 elements or with
// the wrong types is treated as non-terminal so a single garbage signal cannot
// crash the daemon.
func processVerifyStatus(body []interface{}) (matched, terminal bool, err error) {
	if len(body) < 2 {
		return false, false, nil
	}
	result, _ := body[0].(string)
	done, _ := body[1].(bool)
	if !done {
		// Either non-terminal status or wrong types on the booleans.
		// Either way: keep waiting for the next signal.
		return false, false, nil
	}
	if result == "verify-match" {
		return true, true, nil
	}
	if result == "verify-no-match" {
		return false, true, ErrNoMatch
	}
	return false, true, fmt.Errorf("fingerprint verification failed: %s", result)
}
