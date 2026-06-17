package store

import (
	"acme-client/client"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type FileStore struct {
	directory string
}

func NewFileStore(directory string) (*FileStore, error) {
	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(directory, 0700)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", directory, err)
		}
		return &FileStore{directory: directory}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", directory)
	}

	return &FileStore{directory: directory}, nil
}

func (f FileStore) Load(meta client.AccountMetadata) (*client.Account, error) {
	filename := getFilename(meta)
	path := filepath.Join(f.directory, filename)
	accountData, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, client.ErrAccountDoesNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var account client.Account
	if err = json.Unmarshal(accountData, &account); err != nil {
		return nil, fmt.Errorf("failed to unmarshal account: %w", err)
	}

	if account.Email != meta.Email || account.ACMEDirectoryURL != meta.ACMEDirectoryURL {
		return nil, errors.New("account does not match metadata")
	}

	if account.Key == nil {
		return nil, errors.New("account does not have a key")
	}

	if account.Registration == nil {
		return nil, errors.New("account does not have a registration")
	}

	return &account, nil
}

func (f FileStore) Save(account *client.Account) error {
	accountData, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}
	filename := getFilename(account.AccountMetadata)
	path := filepath.Join(f.directory, filename)
	err = os.WriteFile(path, accountData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

// just hash account/ACME dir to get something unique
func getFilename(meta client.AccountMetadata) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s", meta.Email, meta.ACMEDirectoryURL)))
	return fmt.Sprintf("%x.json", hash)
}
