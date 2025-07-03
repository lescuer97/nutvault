-- +goose Up

CREATE TABLE accounts (
	active bool NOT NULL,
	npub blob NOT NULL,
	id text NOT NULL,
	derivation int8 NOT NULL,
	created_at int8 NOT NULL,
	signature blob NOT NULL,
	CONSTRAINT id_pk PRIMARY KEY (id),
	CONSTRAINT derivation_unique UNIQUE (derivation)
);


CREATE TABLE auth_tokens (
	id text NOT NULL,
	account_id text NOT NULL,
	active bool NOT NULL,
	token text NOT NULL,
	created_at int8 NOT NULL,
	signature blob NOT NULL,
	CONSTRAINT id_pk PRIMARY KEY (id),
	CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE TABLE seeds (
	active bool NOT NULL,
	unit text NOT NULL,
	id text NOT NULL,
	created_at int8 NOT NULL,
	input_fee_ppk int NOT NULL DEFAULT 0,
	version int NOT NULL,
	legacy bool NOT NULL DEFAULT FALSE,
	amounts TEXT NOT NULL,
	account_id TEXT NOT NULL,
	CONSTRAINT seeds_pk PRIMARY KEY (id),
	CONSTRAINT seeds_unique UNIQUE (id)
	CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_seed_account_id ON seeds (account_id);
CREATE INDEX IF NOT EXISTS idx_account_id ON accounts (id);
CREATE INDEX IF NOT EXISTS idx_account_npub ON accounts (npub);
CREATE INDEX IF NOT EXISTS idx_auth_token_token ON auth_tokens (token);

-- +goose Down
DROP TABLE IF EXISTS seeds;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS auth_tokens;
DROP INDEX idx_seed_account_id;
DROP INDEX idx_account_id;
DROP INDEX idx_account_npub;
DROP INDEX idx_auth_token_token;
