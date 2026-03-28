-- +goose Up
CREATE TABLE "accounts" (
	id text NOT NULL,
	active bool NOT NULL,
	name text NOT NULL DEFAULT '',
	created_at int8 NOT NULL,
	derivation int8 NOT NULL,
	npub blob,
	client_pubkey_fp text UNIQUE,
	CONSTRAINT accounts_pk PRIMARY KEY (id),
	CONSTRAINT accounts_derivation_unique UNIQUE (derivation)
);

CREATE TABLE "seeds" (
	active bool NOT NULL,
	unit text NOT NULL,
	id text NOT NULL,
	created_at int8 NOT NULL,
	input_fee_ppk int NOT NULL DEFAULT 0,
	version int NOT NULL,
	legacy bool NOT NULL DEFAULT FALSE,
	account_id text NOT NULL,
	derivation_path text NOT NULL,
	amounts TEXT NOT NULL, -- JSON array of uint64 values (e.g. [1,2,4])
	final_expiry int8,
	CONSTRAINT seeds_pk PRIMARY KEY (id),
	CONSTRAINT seeds_unique UNIQUE (id),
	CONSTRAINT fk_seeds_account FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_seed_id ON seeds (id);
CREATE INDEX IF NOT EXISTS idx_seed_account_id ON seeds (account_id);
CREATE INDEX IF NOT EXISTS idx_accounts_id ON accounts (id);
CREATE INDEX IF NOT EXISTS idx_accounts_client_pubkey_fp ON accounts (client_pubkey_fp);

-- +goose Down
DROP TABLE IF EXISTS seeds;
DROP TABLE IF EXISTS accounts;
DROP INDEX idx_seed_id;
DROP INDEX idx_seed_account_id;
DROP INDEX idx_accounts_id;
DROP INDEX idx_accounts_client_pubkey_fp;
