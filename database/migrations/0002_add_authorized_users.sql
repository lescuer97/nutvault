-- +goose Up
CREATE TABLE authorized_npubs (
    active bool NOT NULL,
    npub blob NOT NULL,
    max_signer int8 NOT NULL,
    created_at int8 NOT NULL,
    deativated_at int8 NOT NULL,
    CONSTRAINT npub_unique UNIQUE (npub)
);

CREATE INDEX IF NOT EXISTS idx_authorized_npubs_npub ON seeds (npub);

-- +goose Down
DROP TABLE IF EXISTS authorized_npubs;
DROP INDEX idx_authorized_npubs_npub;
