package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/matejsmycka/linux-id/tpm"
)

// maxPINRetries is the persistent PIN retry counter's maximum (CTAP 2.1
// §6.5.2.2: at most 8).
const maxPINRetries = 8

// maxConsecutivePINMismatches is how many wrong PINs in a row block PIN use
// until the next power cycle (daemon restart), CTAP 2.1 §6.5.5.7.1.
const maxConsecutivePINMismatches = 3

const pinFileVer = 2

// PINSealer keeps the PIN in the backend. SealPIN turns a pinHash into an
// opaque object that only the backend can check a pinHash against; on the
// TPM it is a DA-protected sealed object (tpm/pin.go).
type PINSealer interface {
	SealPIN(pinHash []byte) ([]byte, error)
	CheckPIN(blob, pinHash []byte) (bool, error)
}

// pinFile is the on-disk PIN state, pin.json next to the credential store
// (filepath.Join(filepath.Dir(--credstore), "pin.json")), mode 0600:
//
//	{
//	  "version": 2,
//	  "object":  "<base64, the PIN object from PINSealer.SealPIN>",
//	  "retries": 8
//	}
//
// The object is only usable with the backend (the TPM): the file holds no
// form of the PIN that can be checked without it. pinHash is
// LEFT(SHA-256(PIN), 16), the only form of the PIN the authenticator ever
// receives (CTAP 2.1 §6.5.5.5). "retries" is the persistent pinRetries
// counter. No file means no PIN is set. The file is replaced atomically
// (temp file + rename).
type pinFile struct {
	Version int    `json:"version"`
	Object  []byte `json:"object"`
	Retries int    `json:"retries"`
}

// errPINNotSet is returned by pinStore operations that need a PIN.
var errPINNotSet = errors.New("pin: no PIN set")

// pinStore holds the authenticator's PIN: the persistent part in a file and
// the per power cycle consecutive mismatch counter in memory. The file is
// read on every operation, so removing it (e.g. a reset) takes effect
// immediately.
type pinStore struct {
	path   string
	sealer PINSealer

	mu         sync.Mutex
	mismatches int // consecutive, since the daemon started
}

func newPINStore(path string, sealer PINSealer) *pinStore {
	return &pinStore{path: path, sealer: sealer}
}

// pinStoreNextTo returns the PIN store for the credential store at credPath,
// so --credstore isolation also isolates the PIN.
func pinStoreNextTo(credPath string, sealer PINSealer) *pinStore {
	return newPINStore(filepath.Join(filepath.Dir(credPath), "pin.json"), sealer)
}

func (p *pinStore) load() (*pinFile, error) {
	data, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errPINNotSet
	}
	if err != nil {
		return nil, fmt.Errorf("pin: read %s: %w", p.path, err)
	}
	var f pinFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("pin: parse %s: %w", p.path, err)
	}
	if f.Version != pinFileVer || len(f.Object) == 0 || f.Retries < 0 || f.Retries > maxPINRetries {
		return nil, fmt.Errorf("pin: %s is malformed", p.path)
	}
	return &f, nil
}

func (p *pinStore) save(f *pinFile) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pin-*.json") // created 0600
	if err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pin: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pin: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pin: close: %w", err)
	}
	if err := os.Rename(tmp.Name(), p.path); err != nil {
		return fmt.Errorf("pin: rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// isSet reports whether a PIN is set. A PIN file that cannot be read counts
// as set, so a damaged file fails closed instead of silently dropping the
// PIN requirement.
func (p *pinStore) isSet() bool {
	if p == nil {
		return false
	}
	_, err := p.load()
	return !errors.Is(err, errPINNotSet)
}

// state returns the PIN retry counter and whether PIN use is blocked until
// the next power cycle. Without a PIN the counter is at its maximum.
func (p *pinStore) state() (retries int, powerCycle bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.load()
	if errors.Is(err, errPINNotSet) {
		return maxPINRetries, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return f.Retries, p.mismatches >= maxConsecutivePINMismatches, nil
}

// clear removes the PIN (authenticatorReset).
func (p *pinStore) clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mismatches = 0
	if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// resetPowerCycle forgets the consecutive mismatches, as a power cycle does.
func (p *pinStore) resetPowerCycle() {
	p.mu.Lock()
	p.mismatches = 0
	p.mu.Unlock()
}

// set stores pinHash as the new PIN, in a new PIN object, and resets the
// retry counter. It is used by both setPIN and changePIN.
func (p *pinStore) set(pinHash []byte) error {
	obj, err := p.sealer.SealPIN(pinHash)
	if err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	f := &pinFile{Version: pinFileVer, Object: obj, Retries: maxPINRetries}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.save(f)
}

// pinCheck is the outcome of pinStore.verify.
type pinCheck int

const (
	pinOK          pinCheck = iota
	pinMismatch             // wrong PIN, retries left, not auth-blocked
	pinBlocked              // retries exhausted: PIN_BLOCKED
	pinAuthBlocked          // too many consecutive mismatches: PIN_AUTH_BLOCKED
)

// precheck reports whether PIN verification may be attempted at all, without
// consuming a retry: errPINNotSet, pinBlocked, pinAuthBlocked or pinOK.
func (p *pinStore) precheck() (pinCheck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.load()
	if err != nil {
		return 0, err
	}
	if f.Retries <= 0 {
		return pinBlocked, nil
	}
	if p.mismatches >= maxConsecutivePINMismatches {
		return pinAuthBlocked, nil
	}
	return pinOK, nil
}

// verify checks pinHash (nil if the platform's pinHashEnc did not decrypt)
// against the stored PIN following CTAP 2.1 §6.5.5.7.1: the retry counter is
// decremented and persisted before comparing, and restored to its maximum
// on a match. The comparison is the backend's: on the TPM, a wrong PIN also
// counts towards the TPM's dictionary attack lockout, and while the TPM is
// locked out no PIN is checked (PIN_AUTH_BLOCKED, no retry used).
func (p *pinStore) verify(pinHash []byte) (pinCheck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.load()
	if err != nil {
		return 0, err
	}
	if f.Retries <= 0 {
		return pinBlocked, nil
	}
	if p.mismatches >= maxConsecutivePINMismatches {
		return pinAuthBlocked, nil
	}
	f.Retries--
	if err := p.save(f); err != nil {
		return 0, err
	}
	match := false
	if len(pinHash) == 16 {
		match, err = p.sealer.CheckPIN(f.Object, pinHash)
		if errors.Is(err, tpm.ErrPINLockout) {
			f.Retries++
			if err := p.save(f); err != nil {
				return 0, err
			}
			return pinAuthBlocked, nil
		}
		if err != nil {
			return 0, err
		}
	}
	if !match {
		p.mismatches++
		switch {
		case f.Retries <= 0:
			return pinBlocked, nil
		case p.mismatches >= maxConsecutivePINMismatches:
			return pinAuthBlocked, nil
		}
		return pinMismatch, nil
	}
	p.mismatches = 0
	f.Retries = maxPINRetries
	if err := p.save(f); err != nil {
		return 0, err
	}
	return pinOK, nil
}
