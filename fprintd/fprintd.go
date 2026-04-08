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

	// This ensures we are "online" before the hardware triggers
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender("net.reactivated.Fprint"),
		dbus.WithMatchInterface("net.reactivated.Fprint.Device"),
		dbus.WithMatchMember("VerifyStatus"),
		dbus.WithMatchObjectPath(devices[0]), // Be specific to the device path
	); err != nil {
		return err
	}

	sigCh := make(chan *dbus.Signal, 10) // Buffer for multiple scan attempts
	conn.Signal(sigCh)

	if err := device.Call("net.reactivated.Fprint.Device.Claim", 0, "").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.Release", 0)

	fmt.Println(">>> [Sensor Active] Please scan your finger...")
	if err := device.Call("net.reactivated.Fprint.Device.VerifyStart", 0, "any").Err; err != nil {
		return err
	}
	defer device.Call("net.reactivated.Fprint.Device.VerifyStop", 0)

	tryCount := 0

	for {
		select {
		case sig := <-sigCh:
			if len(sig.Body) < 2 {
				continue
			}

			result, _ := sig.Body[0].(string)
			done, _ := sig.Body[1].(bool)

			if done {
				if result == "verify-match" {
					return nil
				}

				tryCount++
				fmt.Printf(">>> [Scan Result] %s (Attempt %d/3)\n", result, tryCount)

				if tryCount >= 3 {
					return fmt.Errorf("fingerprint verification failed after %d attempts", tryCount)
				}

				// Reset the sensor
				fmt.Println("Resetting sensor for next attempt...")
				device.Call("net.reactivated.Fprint.Device.VerifyStop", 0)
				time.Sleep(500 * time.Millisecond)

				if err := device.Call("net.reactivated.Fprint.Device.VerifyStart", 0, "any").Err; err != nil {
					return fmt.Errorf("failed to restart: %w", err)
				}
			}

		case <-time.After(30 * time.Second):
			return fmt.Errorf("fingerprint verification timed out")
		}
	}
}
