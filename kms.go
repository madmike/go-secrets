package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// KEKProvider wraps the master key encryption/decryption (Key Encryption Key).
// In production, this would use cloud.google.com/go/kms or AWS KMS.
// For now, we use local AES-GCM with a master key from config.
type KEKProvider interface {
	// Encrypt wraps a DEK with the master key.
	Encrypt(ctx interface{}, plainDEK []byte) (wrapped []byte, kekID string, err error)

	// Decrypt unwraps a DEK with the master key.
	Decrypt(ctx interface{}, wrappedDEK []byte, kekID string) (plainDEK []byte, err error)
}

// LocalKEK implements KEKProvider using local AES-GCM.
// masterKey must be 32 bytes (AES-256).
type LocalKEK struct {
	masterKey []byte
	kekID     string
}

func NewLocalKEK(masterKeyBase64 string) (*LocalKEK, error) {
	masterKey, err := base64.StdEncoding.DecodeString(masterKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return &LocalKEK{
		masterKey: masterKey,
		kekID:     "local-aes-256-dev",
	}, nil
}

func (k *LocalKEK) Encrypt(ctx interface{}, plainDEK []byte) (wrapped []byte, kekID string, err error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrKMSError, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrKMSError, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrKMSError, err)
	}

	wrapped = gcm.Seal(nonce, nonce, plainDEK, nil)
	return wrapped, k.kekID, nil
}

func (k *LocalKEK) Decrypt(ctx interface{}, wrappedDEK []byte, kekID string) (plainDEK []byte, err error) {
	if kekID != k.kekID {
		return nil, fmt.Errorf("%w: unknown KEK ID '%s'", ErrKMSError, kekID)
	}

	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKMSError, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKMSError, err)
	}

	nonceSize := gcm.NonceSize()
	if len(wrappedDEK) < nonceSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short", ErrKMSError)
	}

	nonce, ciphertext := wrappedDEK[:nonceSize], wrappedDEK[nonceSize:]
	plainDEK, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	return plainDEK, nil
}
