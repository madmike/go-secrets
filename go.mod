module github.com/madmike/go-secrets

go 1.25.5

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.5
	github.com/madmike/go-db v0.0.0-00010101000000-000000000000
)

require (
	github.com/georgysavva/scany/v2 v2.1.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)

replace github.com/madmike/go-db => ../db

replace github.com/madmike/go-infra => ../infra
