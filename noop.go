package secrets

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// NoopVault is a simple in-memory vault for testing.
// It stores plaintext secrets in memory with no encryption.
type NoopVault struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func NewNoopVault() *NoopVault {
	return &NoopVault{
		secrets: make(map[string][]byte),
	}
}

func (v *NoopVault) Put(ctx context.Context, scope SecretScope, plaintext []byte) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}

	id := uuid.New().String()
	ref := RefPrefix + id

	v.mu.Lock()
	defer v.mu.Unlock()

	v.secrets[ref] = append([]byte(nil), plaintext...)
	return ref, nil
}

func (v *NoopVault) Get(ctx context.Context, ref string) ([]byte, error) {
	if !IsVaultRef(ref) {
		return nil, ErrInvalidRef
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	plaintext, ok := v.secrets[ref]
	if !ok {
		return nil, ErrNotFound
	}

	return append([]byte(nil), plaintext...), nil
}

func (v *NoopVault) Rotate(ctx context.Context, ref string, plaintext []byte) error {
	if !IsVaultRef(ref) {
		return ErrInvalidRef
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if _, ok := v.secrets[ref]; !ok {
		return ErrNotFound
	}

	v.secrets[ref] = append([]byte(nil), plaintext...)
	return nil
}

func (v *NoopVault) Delete(ctx context.Context, ref string) error {
	if !IsVaultRef(ref) {
		return ErrInvalidRef
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	delete(v.secrets, ref)
	return nil
}
