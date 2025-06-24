-- +goose Up
CREATE TABLE accounts (
	active bool NOT NULL,
	npub blob NOT NULL,
	id text NOT NULL,
	derivation text NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_account_id ON accounts (id);
CREATE INDEX IF NOT EXISTS idx_account_npub ON accounts (npub);
CREATE INDEX IF NOT EXISTS idx_auth_token_id ON auth_tokens (id);

-- +goose Down
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS auth_tokens;
DROP INDEX idx_account_id;
DROP INDEX idx_account_npub;
DROP INDEX idx_auth_token_id;
