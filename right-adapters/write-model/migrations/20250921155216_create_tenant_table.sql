CREATE TABLE IF NOT EXISTS organization_entity (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organization_attribute (
  id UUID PRIMARY KEY,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  organization_id UUID NOT NULL REFERENCES organization_entity(id) ON DELETE CASCADE
);
