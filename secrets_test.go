package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLocalKEKEncryptDecrypt tests the master key wrap/unwrap round-trip.
func TestLocalKEKEncryptDecrypt(t *testing.T) {
	// Generate a valid 32-byte master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterKeyB64 := base64.StdEncoding.EncodeToString(masterKey)

	kek, err := NewLocalKEK(masterKeyB64)
	require.NoError(t, err)

	plainDEK := []byte("plaintext-dek-32bytes-long---")
	require.Len(t, plainDEK, 32)

	// Encrypt
	wrapped, kekID, err := kek.Encrypt(nil, plainDEK)
	require.NoError(t, err)
	require.NotNil(t, wrapped)
	require.Equal(t, "local-aes-256-dev", kekID)

	// Decrypt
	unwrapped, err := kek.Decrypt(nil, wrapped, kekID)
	require.NoError(t, err)
	require.Equal(t, plainDEK, unwrapped)
}

// TestLocalKEKInvalidKeyLength tests master key validation.
func TestLocalKEKInvalidKeyLength(t *testing.T) {
	tests := []struct {
		name      string
		keyLen    int
		shouldErr bool
	}{
		{"16-byte (too short)", 16, true},
		{"24-byte (too short)", 24, true},
		{"32-byte (valid)", 32, false},
		{"64-byte (too long)", 64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			b64 := base64.StdEncoding.EncodeToString(key)
			_, err := NewLocalKEK(b64)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLocalKEKDecryptWrongKEKID tests that decryption fails with unknown KEK ID.
func TestLocalKEKDecryptWrongKEKID(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterKeyB64 := base64.StdEncoding.EncodeToString(masterKey)

	kek, err := NewLocalKEK(masterKeyB64)
	require.NoError(t, err)

	plainDEK := []byte("plaintext-dek-32bytes-long---")
	wrapped, _, err := kek.Encrypt(nil, plainDEK)
	require.NoError(t, err)

	// Try to decrypt with wrong KEK ID
	_, err = kek.Decrypt(nil, wrapped, "wrong-kek-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "KMS error")
}

// TestLocalKEKDecryptTamperedData tests that tampered wrapped DEK is detected.
func TestLocalKEKDecryptTamperedData(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterKeyB64 := base64.StdEncoding.EncodeToString(masterKey)

	kek, err := NewLocalKEK(masterKeyB64)
	require.NoError(t, err)

	plainDEK := []byte("plaintext-dek-32bytes-long---")
	wrapped, kekID, err := kek.Encrypt(nil, plainDEK)
	require.NoError(t, err)

	// Tamper with the wrapped DEK
	if len(wrapped) > 0 {
		wrapped[0] ^= 0xFF
	}

	// Decryption should fail
	_, err = kek.Decrypt(nil, wrapped, kekID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")
}

// TestEncryptWithDEKRoundTrip tests DEK-level encryption round-trip.
func TestEncryptWithDEKRoundTrip(t *testing.T) {
	dek := []byte("encryption-key-32bytes-long-!!")
	plaintext := []byte("my secret data to encrypt")

	ciphertext, nonce, err := encryptWithDEK(dek, plaintext)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
	require.NotNil(t, nonce)
	require.NotEmpty(t, ciphertext)

	// Ciphertext should be different from plaintext
	require.NotEqual(t, plaintext, ciphertext)

	// Decrypt it back
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestSecretScopeValidation tests SecretScope.Validate() for all kinds.
func TestSecretScopeValidation(t *testing.T) {
	tests := []struct {
		name      string
		scope     SecretScope
		shouldErr bool
	}{
		{
			"valid bot_token",
			SecretScope{TenantID: "t1", Kind: "bot_token"},
			false,
		},
		{
			"valid llm_api_key",
			SecretScope{TenantID: "t1", Kind: "llm_api_key"},
			false,
		},
		{
			"valid oauth_access",
			SecretScope{TenantID: "t1", Kind: "oauth_access", OwnerID: "user-123"},
			false,
		},
		{
			"valid oauth_refresh",
			SecretScope{TenantID: "t1", Kind: "oauth_refresh"},
			false,
		},
		{
			"valid webhook_secret",
			SecretScope{Kind: "webhook_secret"},
			false,
		},
		{
			"valid telegram_bot_token",
			SecretScope{TenantID: "t1", Kind: "telegram_bot_token"},
			false,
		},
		{
			"valid whatsapp_access_token",
			SecretScope{TenantID: "t1", Kind: "whatsapp_access_token"},
			false,
		},
		{
			"valid marketplace_key",
			SecretScope{Kind: "marketplace_key"},
			false,
		},
		{
			"valid api_secret",
			SecretScope{TenantID: "t1", Kind: "api_secret"},
			false,
		},
		{
			"missing kind",
			SecretScope{TenantID: "t1"},
			true,
		},
		{
			"invalid kind",
			SecretScope{TenantID: "t1", Kind: "unknown_kind"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scope.Validate()
			if tt.shouldErr {
				require.Error(t, err)
				require.True(t, errors.Is(err, ErrInvalidScope))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestIsVaultRef tests the vault reference prefix validation.
func TestIsVaultRef(t *testing.T) {
	tests := []struct {
		ref      string
		expected bool
	}{
		{"vault://db/abc-123", true},
		{"vault://db/", false}, // empty after prefix
		{"vault://db", false},   // no trailing /
		{"http://db/abc", false},
		{"", false},
		{"vault://other/abc", false},
	}

	for _, tt := range tests {
		result := IsVaultRef(tt.ref)
		require.Equal(t, tt.expected, result, "IsVaultRef(%q)", tt.ref)
	}
}

// TestNoopVault tests the no-op vault implementation (always returns same ref).
func TestNoopVault(t *testing.T) {
	vault := NewNoopVault()
	ctx := context.Background()
	scope := SecretScope{TenantID: "t1", Kind: "bot_token"}

	// Put should return the plaintext as-is
	ref, err := vault.Put(ctx, scope, []byte("secret"))
	require.NoError(t, err)
	require.NotEmpty(t, ref)

	// Get should return the plaintext
	plaintext, err := vault.Get(ctx, ref)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), plaintext)

	// Rotate should not error
	err = vault.Rotate(ctx, ref, []byte("new-secret"))
	require.NoError(t, err)

	// Delete should not error
	err = vault.Delete(ctx, ref)
	require.NoError(t, err)
}

// TestFactoryNoopBackend tests vault factory with noop backend.
func TestFactoryNoopBackend(t *testing.T) {
	cfg := Config{Backend: "noop"}
	vault, err := New(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, vault)

	ctx := context.Background()
	scope := SecretScope{TenantID: "t1", Kind: "bot_token"}
	ref, err := vault.Put(ctx, scope, []byte("test"))
	require.NoError(t, err)
	require.NotEmpty(t, ref)
}

// TestFactoryDBBackendMissingPool tests vault factory with db backend but no pool.
func TestFactoryDBBackendMissingPool(t *testing.T) {
	cfg := Config{
		Backend:         "db",
		MasterKeyBase64: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	vault, err := New(cfg, nil)
	require.Error(t, err)
	require.Nil(t, vault)
	require.Contains(t, err.Error(), "requires a pgxpool")
}

// TestFactoryUnknownBackend tests vault factory with unknown backend.
func TestFactoryUnknownBackend(t *testing.T) {
	cfg := Config{Backend: "unknown"}
	vault, err := New(cfg, nil)
	require.Error(t, err)
	require.Nil(t, vault)
	require.Contains(t, err.Error(), "unknown secrets backend")
}

// Needed imports for cipher operations in test
import (
	"crypto/aes"
	"crypto/cipher"
)
