package ctap2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
}

// CredStore persists resident credentials at ~/.config/linux-id/creds.json.
type CredStore struct {
	path string
}

// NewCredStore returns a CredStore backed by ~/.config/linux-id/creds.json.
func NewCredStore() *CredStore {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return &CredStore{path: filepath.Join(home, ".config", "linux-id", "creds.json")}
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

// Save appends c to the store. A new resident credential for the same RP and
// user replaces the older one: after an RP-side deletion and re-registration,
// returning the orphaned credential first would make discoverable login fail.
func (cs *CredStore) Save(c StoredCredential) error {
	creds, err := cs.load()
	if err != nil {
		return err
	}
	for i, existing := range creds {
		sameCredential := bytes.Equal(existing.CredID, c.CredID)
		sameAccount := bytes.Equal(existing.RPIDHash, c.RPIDHash) && bytes.Equal(existing.UserID, c.UserID)
		if sameCredential || sameAccount {
			creds[i] = c
			return cs.store(creds)
		}
	}
	return cs.store(append(creds, c))
}

// FindByRPID returns all credentials whose RPIDHash matches.
func (cs *CredStore) FindByRPID(rpIdHash []byte) ([]StoredCredential, error) {
	creds, err := cs.load()
	if err != nil {
		return nil, err
	}
	var result []StoredCredential
	for _, c := range creds {
		if bytes.Equal(c.RPIDHash, rpIdHash) {
			result = append(result, c)
		}
	}
	return result, nil
}

