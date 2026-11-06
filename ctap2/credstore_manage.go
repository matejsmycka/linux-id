package ctap2

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrCredentialNotFound is returned when no stored credential has the
// requested ID.
var ErrCredentialNotFound = errors.New("credstore: no such credential")

// lock takes an exclusive advisory lock that serialises load-modify-store
// cycles between the daemon and the `linux-id creds` CLI, which may write
// the same file. Readers need no lock: the file is replaced atomically.
func (cs *CredStore) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(cs.path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(cs.path+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("credstore: lock: %w", err)
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

// modify runs fn on the stored credentials under the lock and stores the
// result.
func (cs *CredStore) modify(fn func([]StoredCredential) ([]StoredCredential, error)) error {
	unlock, err := cs.lock()
	if err != nil {
		return err
	}
	defer unlock()
	creds, err := cs.load()
	if err != nil {
		return err
	}
	creds, err = fn(creds)
	if err != nil {
		return err
	}
	return cs.store(creds)
}

// Path returns the file the store is backed by.
func (cs *CredStore) Path() string { return cs.path }

// List returns all stored credentials, oldest first.
func (cs *CredStore) List() ([]StoredCredential, error) {
	return cs.load()
}

// RelyingParty summarises the stored credentials of one relying party.
type RelyingParty struct {
	ID     string
	Name   string
	IDHash []byte
	Count  int
}

// RPs returns the relying parties that have stored credentials, in the order
// their first credential was stored. Name is taken from the most recent
// credential that has one.
func (cs *CredStore) RPs() ([]RelyingParty, error) {
	creds, err := cs.load()
	if err != nil {
		return nil, err
	}
	return relyingParties(creds), nil
}

func relyingParties(creds []StoredCredential) []RelyingParty {
	var rps []RelyingParty
	index := map[string]int{}
	for _, c := range creds {
		key := string(c.RPIDHash)
		j, ok := index[key]
		if !ok {
			j = len(rps)
			index[key] = j
			rps = append(rps, RelyingParty{ID: c.RPID, IDHash: c.RPIDHash})
		}
		rp := &rps[j]
		rp.Count++
		if c.RPName != "" {
			rp.Name = c.RPName
		}
		if rp.ID == "" {
			rp.ID = c.RPID
		}
	}
	return rps
}

// Find returns the stored credential with the given ID.
func (cs *CredStore) Find(credID []byte) (StoredCredential, error) {
	creds, err := cs.load()
	if err != nil {
		return StoredCredential{}, err
	}
	for _, c := range creds {
		if bytes.Equal(c.CredID, credID) {
			return c, nil
		}
	}
	return StoredCredential{}, ErrCredentialNotFound
}

// Delete removes the credential with the given ID and revokes its key
// handle, so it stops working even where a relying party still presents it
// in an allowList. It returns the deleted entry.
func (cs *CredStore) Delete(credID []byte) (StoredCredential, error) {
	var deleted StoredCredential
	err := cs.modify(func(creds []StoredCredential) ([]StoredCredential, error) {
		i := slices.IndexFunc(creds, func(c StoredCredential) bool { return bytes.Equal(c.CredID, credID) })
		if i < 0 {
			return nil, ErrCredentialNotFound
		}
		deleted = creds[i]
		// Revoke first: a credential that is gone from the list but still
		// works would be worse than one that lingers in the list.
		if err := cs.revoke(credID); err != nil {
			return nil, err
		}
		return slices.Delete(creds, i, i+1), nil
	})
	return deleted, err
}

// UpdateUser replaces the user name and display name of the credential with
// the given ID (CTAP 2.1 §6.8.6). Empty values remove them.
func (cs *CredStore) UpdateUser(credID []byte, name, displayName string) error {
	return cs.update(credID, func(c *StoredCredential) {
		c.UserName = name
		c.DisplayName = displayName
	})
}

// SetPublicKey records the COSE public key of a credential that was stored
// without one.
func (cs *CredStore) SetPublicKey(credID, coseKey []byte) error {
	return cs.update(credID, func(c *StoredCredential) { c.PublicKey = coseKey })
}

func (cs *CredStore) update(credID []byte, fn func(*StoredCredential)) error {
	return cs.modify(func(creds []StoredCredential) ([]StoredCredential, error) {
		for i := range creds {
			if bytes.Equal(creds[i].CredID, credID) {
				fn(&creds[i])
				return creds, nil
			}
		}
		return nil, ErrCredentialNotFound
	})
}

// revokedPath is the file listing SHA-256 digests of deleted credential IDs,
// next to the credential file: creds.json → creds-revoked.json.
// Wipe empties the store and its list of deleted credentials. It is used by
// authenticatorReset, which retires every credential anyway.
func (cs *CredStore) Wipe() error {
	unlock, err := cs.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := cs.store(nil); err != nil {
		return err
	}
	if err := os.Remove(cs.revokedPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (cs *CredStore) revokedPath() string {
	return strings.TrimSuffix(cs.path, filepath.Ext(cs.path)) + "-revoked.json"
}

func (cs *CredStore) loadRevoked() ([][]byte, error) {
	data, err := os.ReadFile(cs.revokedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var digests [][]byte
	if err := json.Unmarshal(data, &digests); err != nil {
		return nil, err
	}
	return digests, nil
}

// revoke records credID as deleted. The caller holds the lock.
func (cs *CredStore) revoke(credID []byte) error {
	digests, err := cs.loadRevoked()
	if err != nil {
		return err
	}
	d := sha256.Sum256(credID)
	if slices.ContainsFunc(digests, func(x []byte) bool { return bytes.Equal(x, d[:]) }) {
		return nil
	}
	data, err := json.MarshalIndent(append(digests, d[:]), "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(cs.revokedPath(), data)
}

// Revoked reports whether credID belongs to a deleted credential. Callers
// should treat an error as revoked, so that a damaged file cannot resurrect
// deleted credentials.
func (cs *CredStore) Revoked(credID []byte) (bool, error) {
	digests, err := cs.loadRevoked()
	if err != nil {
		return true, err
	}
	d := sha256.Sum256(credID)
	return slices.ContainsFunc(digests, func(x []byte) bool { return bytes.Equal(x, d[:]) }), nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
