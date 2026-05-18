package secrets

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("secret not found")
	ErrInvalidRef    = errors.New("invalid secret reference")
	ErrInvalidScope  = errors.New("invalid secret scope")
	ErrDecryptFailed = errors.New("decryption failed")
	ErrKMSError      = errors.New("KMS error")
)

type SecretScope struct {
	TenantID string // empty = platform-scoped
	Kind     string // "bot_token" | "llm_api_key" | "oauth_access" | "oauth_refresh" | "webhook_secret" | "marketplace_key" | "telegram_bot_token" | "whatsapp_access_token" | "api_secret"
	OwnerID  string // optional FK (e.g. messenger_account_id) for audit
}

func (s SecretScope) Validate() error {
	if s.Kind == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalidScope)
	}
	validKinds := map[string]bool{
		"bot_token":           true,
		"llm_api_key":         true,
		"oauth_access":        true,
		"oauth_refresh":       true,
		"webhook_secret":      true,
		"marketplace_key":     true,
		"telegram_bot_token":  true,
		"whatsapp_access_token": true,
		"api_secret":          true,
	}
	if !validKinds[s.Kind] {
		return fmt.Errorf("%w: unknown kind '%s'", ErrInvalidScope, s.Kind)
	}
	return nil
}

// Vault is the interface for storing and retrieving secrets.
type Vault interface {
	// Put stores a plaintext secret and returns a vault reference string.
	Put(ctx context.Context, scope SecretScope, plaintext []byte) (ref string, err error)

	// Get retrieves the plaintext from a vault reference.
	Get(ctx context.Context, ref string) (plaintext []byte, err error)

	// Rotate re-encrypts an existing secret with new plaintext.
	Rotate(ctx context.Context, ref string, plaintext []byte) error

	// Delete removes a secret from the vault.
	Delete(ctx context.Context, ref string) error
}

// RefPrefix is the prefix for all vault references.
const RefPrefix = "vault://db/"

// IsVaultRef checks if a string is a valid vault reference.
func IsVaultRef(s string) bool {
	if len(s) <= len(RefPrefix) {
		return false
	}
	return s[:len(RefPrefix)] == RefPrefix
}
