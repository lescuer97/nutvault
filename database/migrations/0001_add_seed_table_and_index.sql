-- +goose Up
CREATE TABLE "seeds" (
	active bool NOT NULL,
	unit text NOT NULL,
	id text NOT NULL,
	created_at int8 NOT NULL,
	input_fee_ppk int NOT NULL DEFAULT 0,
	version int NOT NULL,
	legacy bool NOT NULL DEFAULT FALSE,
	max_order int4 NOT NULL,
	CONSTRAINT seeds_pk PRIMARY KEY (id),
	CONSTRAINT seeds_unique UNIQUE (id)
);
CREATE INDEX IF NOT EXISTS idx_seed_id ON seeds (id);

-- +goose Down
DROP TABLE IF EXISTS seeds;
DROP INDEX idx_seed_id;
