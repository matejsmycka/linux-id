package fprintd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

var ErrNoMatch = errors.New("fprintd: fingerprint did not match an enrolled finger")

const (
	maxAttempts   = 3
	attemptGap    = 500 * time.Millisecond
	settleDelay   = 100 * time.Millisecond
	totalDeadline = 30 * time.Second
)

func drainSignals(ch <-chan *dbus.Signal) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

type Result struct {
	OK    bool
	Error error
}

type Fprintd struct {
	mu     sync.Mutex
	active chan Result
}

func New() *Fprintd { return &Fprintd{} }

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

	ctx, cancel := context.WithTimeout(context.Background(), totalDeadline)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("fprintd: attempt %d/%d (previous: no-match), restarting verify", attempt, maxAttempts)
			device.Call("net.reactivated.Fprint.Device.VerifyStop", 0)
			select {
			case <-time.After(attemptGap):
			case <-ctx.Done():
				return fmt.Errorf("fingerprint verification timed out")
			}
			if err := device.Call("net.reactivated.Fprint.Device.VerifyStart", 0, "any").Err; err != nil {
				return fmt.Errorf("VerifyStart on attempt %d: %w", attempt, err)
			}
		} else {
			log.Printf("fprintd: attempt %d/%d, awaiting fingerprint", attempt, maxAttempts)
		}

		select {
		case <-time.After(settleDelay):
		case <-ctx.Done():
			return fmt.Errorf("fingerprint verification timed out")
		}
		if dropped := drainSignals(sigCh); dropped > 0 {
			log.Printf("fprintd: drained %d phantom signal(s) before attempt %d", dropped, attempt)
		}

		err := waitForVerifyResult(ctx, sigCh)
		if err == nil {
			log.Printf("fprintd: attempt %d/%d matched", attempt, maxAttempts)
			return nil
		}
		if !errors.Is(err, ErrNoMatch) {
			log.Printf("fprintd: attempt %d/%d terminal failure: %v", attempt, maxAttempts, err)
			return err
		}
		lastErr = err
	}
	log.Printf("fprintd: all %d attempts exhausted with no match", maxAttempts)
	return lastErr
}

func waitForVerifyResult(ctx context.Context, sigCh <-chan *dbus.Signal) error {
	for {
		select {
		case sig := <-sigCh:
			if len(sig.Body) >= 2 {
				name, _ := sig.Body[0].(string)
				done, _ := sig.Body[1].(bool)
				log.Printf("fprintd: signal %q done=%v", name, done)
			}
			matched, terminal, err := processVerifyStatus(sig.Body)
			if matched {
				return nil
			}
			if terminal {
				return err
			}
		case <-ctx.Done():
			return fmt.Errorf("fingerprint verification timed out")
		}
	}
}

func processVerifyStatus(body []interface{}) (matched, terminal bool, err error) {
	if len(body) < 2 {
		return false, false, nil
	}
	result, _ := body[0].(string)
	done, _ := body[1].(bool)
	if !done {
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
