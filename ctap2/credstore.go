package ctap2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// StoredCredential is a resident credential entry persisted to disk.
type StoredCredential struct {
	CredID      []byte `json:"credId"`
	RPIDHash    []byte `json:"rpIdHash"`
	RPID        string `json:"rpId"`
	RPName      string `json:"rpName"`
	UserID      []byte `json:"userId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	// PublicKey is the credential public key as a COSE_Key. Credentials
	// created before it was recorded lack it; it is then derived from the
	// key handle.
	PublicKey []byte `json:"publicKey,omitempty"`
	// CredProtect is the credProtect level (1–3); 0 means absent, which is
	// userVerificationOptional (1).
	CredProtect int `json:"credProtect,omitempty"`
	// Created is when the credential was made; zero when unknown.
	Created time.Time `json:"created,omitzero"`
}

// CredStore persists resident credentials in a JSON file, by default
// ~/.config/linux-id/creds.json.
type CredStore struct {
	path string
}

// DefaultCredStorePath returns ~/.config/linux-id/creds.json.
func DefaultCredStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "linux-id", "creds.json")
}

// NewCredStore returns a CredStore backed by DefaultCredStorePath.
func NewCredStore() *CredStore {
	return NewCredStoreAt(DefaultCredStorePath())
}

// NewCredStoreAt returns a CredStore backed by the file at path.
func NewCredStoreAt(path string) *CredStore {
	return &CredStore{path: path}
}

func (cs *CredStore) load() ([]StoredCredential, error) {
	data, err := os.ReadFile(cs.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var creds []StoredCredential
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

func (cs *CredStore) store(creds []StoredCredential) error {
	if err := os.MkdirAll(filepath.Dir(cs.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	tmp := cs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, cs.path)
}

// Save adds c as the most recent credential. An existing credential with the
// same CredID, or for the same user account (RPIDHash and UserID) at the same
// relying party, is replaced, as CTAP 2.1 §6.1.2 step 18 requires.
func (cs *CredStore) Save(c StoredCredential) error {
	unlock, err := cs.lock()
	if err != nil {
		return err
	}
	defer unlock()
	creds, err := cs.load()
	if err != nil {
		return err
	}
	kept := creds[:0]
	for _, existing := range creds {
		sameCred := bytes.Equal(existing.CredID, c.CredID)
		sameUser := bytes.Equal(existing.RPIDHash, c.RPIDHash) && bytes.Equal(existing.UserID, c.UserID)
		if !sameCred && !sameUser {
			kept = append(kept, existing)
		}
	}
	return cs.store(append(kept, c))
}

// FindByRPID returns all credentials whose RPIDHash matches, most recently
// created first.
func (cs *CredStore) FindByRPID(rpIdHash []byte) ([]StoredCredential, error) {
	creds, err := cs.load()
	if err != nil {
		return nil, err
	}
	var result []StoredCredential
	for i := len(creds) - 1; i >= 0; i-- {
		if bytes.Equal(creds[i].RPIDHash, rpIdHash) {
			result = append(result, creds[i])
		}
	}
	return result, nil
}
