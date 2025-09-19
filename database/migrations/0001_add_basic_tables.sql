-- +goose Up
CREATE TABLE keys (
    active bool NOT NULL,
    npub blob NOT NULL,
    id text NOT NULL,
    name text NOT NULL,
    derivation int8 NOT NULL,
    created_at int8 NOT NULL,
    -- signature column removed pending implementation
    client_pubkey_fp TEXT UNIQUE NOT NULL,
    CONSTRAINT id_pk PRIMARY KEY (id),
    CONSTRAINT derivation_unique UNIQUE (derivation)
);


-- auth_tokens table removed: auth-token based authentication is deprecated in favor of mTLS fingerprint mapping.

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
	final_expiry int8 NOT NULL,
	CONSTRAINT seeds_pk PRIMARY KEY (id),
	CONSTRAINT seeds_unique UNIQUE (id)
	CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES keys(id)
);

CREATE INDEX IF NOT EXISTS idx_seed_account_id ON seeds (account_id);
CREATE INDEX IF NOT EXISTS idx_keys_id ON keys (id);
CREATE INDEX IF NOT EXISTS idx_keys_npub ON keys (npub);
CREATE INDEX IF NOT EXISTS idx_keys_client_pubkey_fp ON keys (client_pubkey_fp);
-- index on auth_tokens removed

-- +goose Down
DROP TABLE IF EXISTS seeds;
DROP TABLE IF EXISTS keys;
DROP INDEX idx_seed_account_id;
DROP INDEX idx_keys_id;
DROP INDEX idx_keys_npub;
DROP INDEX IF EXISTS idx_keys_client_pubkey_fp;
