package fprintd

import (
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

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
	if err := device.Call("net.reactivated.Fprint.Device.Claim", 0, "").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.Release", 0)

	if err := device.Call("net.reactivated.Fprint.Device.VerifyStart", 0, "any").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.VerifyStop", 0)

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("net.reactivated.Fprint.Device"),
		dbus.WithMatchMember("VerifyStatus"),
	); err != nil {
		return err
	}

	sigCh := make(chan *dbus.Signal, 1)
	conn.Signal(sigCh)

	for {
		select {
		case sig := <-sigCh:
			result := sig.Body[0].(string)
			done := sig.Body[1].(bool)
			if result == "verify-match" {
				return nil
			}
			if done {
				return fmt.Errorf("fingerprint verification failed: %s", result)
			}
			// non-terminal status (e.g. "verify-retry-scan") — keep waiting
		case <-time.After(30 * time.Second):
			return fmt.Errorf("fingerprint verification timed out")
		}
	}
}
