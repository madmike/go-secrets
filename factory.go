package secrets

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Backend         string // "db", "noop"
	MasterKeyBase64 string // for KEK
}

// New returns a Vault. For backend="db", pool must be non-nil and point at the
// Postgres instance hosting platform.secrets.
func New(cfg Config, pool *pgxpool.Pool) (Vault, error) {
	switch cfg.Backend {
	case "db":
		if pool == nil {
			return nil, fmt.Errorf("db vault backend requires a pgxpool")
		}
		kek, err := NewLocalKEK(cfg.MasterKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to create KEK: %w", err)
		}
		return NewDBVault(pool, kek), nil

	case "noop":
		return NewNoopVault(), nil

	default:
		return nil, fmt.Errorf("unknown secrets backend: %s", cfg.Backend)
	}
}
