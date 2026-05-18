package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	db "github.com/madmike/go-db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBVault implements Vault using Postgres with envelope encryption.
// Each secret is stored with:
//   - ciphertext (encrypted with a per-row DEK)
//   - dek_wrapped (DEK wrapped with the master key)
//   - kek_id (which master key wrapped the DEK)
//   - nonce (for the DEK-level encryption)
type DBVault struct {
	pool *pgxpool.Pool
	kek  KEKProvider
}

type secretRow struct {
	ID         string     `db:"id"`
	TenantID   *string    `db:"tenant_id"`
	Kind       string     `db:"kind"`
	OwnerID    *string    `db:"owner_id"`
	Ciphertext []byte     `db:"ciphertext"`
	DEKWrapped []byte     `db:"dek_wrapped"`
	KEKID      string     `db:"kek_id"`
	Nonce      []byte     `db:"nonce"`
	CreatedAt  time.Time  `db:"created_at"`
	RotatedAt  *time.Time `db:"rotated_at"`
}

func NewDBVault(pool *pgxpool.Pool, kek KEKProvider) *DBVault {
	return &DBVault{pool: pool, kek: kek}
}

func (v *DBVault) Put(ctx context.Context, scope SecretScope, plaintext []byte) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}

	id := uuid.New().String()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", fmt.Errorf("failed to generate DEK: %w", err)
	}

	wrappedDEK, kekID, err := v.kek.Encrypt(ctx, dek)
	if err != nil {
		return "", err
	}

	ciphertext, nonce, err := encryptWithDEK(dek, plaintext)
	if err != nil {
		return "", err
	}

	var tenantIDPtr *string
	if scope.TenantID != "" {
		tenantIDPtr = &scope.TenantID
	}
	var ownerIDPtr *string
	if scope.OwnerID != "" {
		ownerIDPtr = &scope.OwnerID
	}

	const q = `INSERT INTO platform.secrets
		(id, tenant_id, kind, owner_id, ciphertext, dek_wrapped, kek_id, nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	if _, err := v.pool.Exec(ctx, q,
		id, tenantIDPtr, scope.Kind, ownerIDPtr,
		ciphertext, wrappedDEK, kekID, nonce,
	); err != nil {
		return "", fmt.Errorf("failed to insert secret: %w", err)
	}

	return RefPrefix + id, nil
}

func (v *DBVault) Get(ctx context.Context, ref string) ([]byte, error) {
	if !IsVaultRef(ref) {
		return nil, ErrInvalidRef
	}

	id := ref[len(RefPrefix):]

	const q = `SELECT id, tenant_id, kind, owner_id, ciphertext, dek_wrapped, kek_id, nonce, created_at, rotated_at
		FROM platform.secrets WHERE id = $1`

	var row secretRow
	if err := db.ScanOne(ctx, v.pool, &row, q, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	dek, err := v.kek.Decrypt(ctx, row.DEKWrapped, row.KEKID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, row.Nonce, row.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	return plaintext, nil
}

func (v *DBVault) Rotate(ctx context.Context, ref string, plaintext []byte) error {
	if !IsVaultRef(ref) {
		return ErrInvalidRef
	}

	id := ref[len(RefPrefix):]

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("failed to generate DEK: %w", err)
	}

	wrappedDEK, kekID, err := v.kek.Encrypt(ctx, dek)
	if err != nil {
		return err
	}

	ciphertext, nonce, err := encryptWithDEK(dek, plaintext)
	if err != nil {
		return err
	}

	const q = `UPDATE platform.secrets
		SET ciphertext = $1, dek_wrapped = $2, kek_id = $3, nonce = $4, rotated_at = now()
		WHERE id = $5`

	tag, err := v.pool.Exec(ctx, q, ciphertext, wrappedDEK, kekID, nonce, id)
	if err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (v *DBVault) Delete(ctx context.Context, ref string) error {
	if !IsVaultRef(ref) {
		return ErrInvalidRef
	}

	id := ref[len(RefPrefix):]

	tag, err := v.pool.Exec(ctx, `DELETE FROM platform.secrets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func encryptWithDEK(dek, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}
