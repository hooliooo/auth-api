-- `name` is the organization's unique, DNS-compatible identifier in the domain, and the
-- constraint is what lets the repository report a duplicate as AlreadyExists.
-- `version` is BIGINT because Postgres has no unsigned integers.
CREATE TABLE IF NOT EXISTS organization_entity (
  id           UUID        PRIMARY KEY,
  name         VARCHAR(100) NOT NULL UNIQUE,
  display_name VARCHAR(100) NOT NULL,
  description  TEXT,
  is_enabled   BOOLEAN      NOT NULL DEFAULT TRUE,
  version      BIGINT       NOT NULL DEFAULT 0,
  created_at   TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
  updated_at   TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS organization_attribute (
  id              UUID PRIMARY KEY,
  key             TEXT NOT NULL,
  value           TEXT NOT NULL,
  organization_id UUID NOT NULL REFERENCES organization_entity(id) ON DELETE CASCADE,

  UNIQUE (organization_id, key, value)
);

-- Transactional outbox. Events are written here in the same transaction as the aggregate
-- that produced them, and published from here by a separate processor.
--
-- Column names and types are the contract of the `outbox` crate
-- (github.com/hooliooo/outbox), which will take over reading and publishing. Ids are
-- VARCHAR(36) and timestamps are zone-less because that crate binds ids as strings and uses
-- time::PrimitiveDateTime in UTC; writers must store UTC explicitly.
CREATE TABLE IF NOT EXISTS outbox_message (
    id                    VARCHAR(36)  PRIMARY KEY,
    aggregate_id          VARCHAR(36)  NOT NULL,
    aggregate_type        VARCHAR(255) NOT NULL,
    subject               VARCHAR(255) NOT NULL,
    payload               JSONB        NOT NULL,
    status                VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    created_at            TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    published_at          TIMESTAMP,
    retry_count           INT          NOT NULL DEFAULT 0,
    last_error            TEXT,
    processing_started_at TIMESTAMP,
    lease_token           VARCHAR(36),

    CONSTRAINT outbox_message_status_check
        CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED'))
);

-- Claim query: WHERE status = $1 AND retry_count < $2 ORDER BY created_at ASC.
-- Composite so it resolves as an ordered index scan, partial so it stays the size of the
-- backlog rather than the table, which is mostly PUBLISHED rows awaiting retention.
CREATE INDEX IF NOT EXISTS outbox_message_claim_idx
    ON outbox_message (status, created_at)
    WHERE status IN ('PENDING', 'FAILED');

-- Cleanup: WHERE status = 'PUBLISHED' AND published_at < $1
CREATE INDEX IF NOT EXISTS outbox_message_cleanup_idx
    ON outbox_message (published_at)
    WHERE status = 'PUBLISHED';

-- Stale recovery: WHERE status = 'PROCESSING' AND processing_started_at < $1
CREATE INDEX IF NOT EXISTS outbox_message_stale_idx
    ON outbox_message (processing_started_at)
    WHERE status = 'PROCESSING';

-- For tracing what was emitted for an aggregate.
CREATE INDEX IF NOT EXISTS outbox_message_aggregate_id_idx
    ON outbox_message (aggregate_id);
